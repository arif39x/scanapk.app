import json
import logging
import os
import shutil
import sqlite3
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

from dotenv import load_dotenv
from fastapi import BackgroundTasks, FastAPI, File, Header, HTTPException, UploadFile, Depends, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

load_dotenv()

_SCANAPK_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "scanapk-backend")
sys.path.insert(0, _SCANAPK_DIR)

from scanapk_backend.core.hash_db import init_db
from scanapk_backend.core.scan_apk import scan_apk
from scanapk_backend.core.scoring import calculate_risk
from scanapk_backend.core.models import get_models
from scanapk_backend.core.agent import analyse
from scanapk_backend.report.generator import build_report, _verdict

logger = logging.getLogger(__name__)

UPLOAD_DIR = Path("uploads")
UPLOAD_DIR.mkdir(exist_ok=True)
DB_PATH = Path("jobs.db")

MAX_FILE_SIZE = 200 * 1024 * 1024
SCAN_RATE_LIMIT = os.environ.get("SCANAPK_RATE_LIMIT", "10/minute")

limiter = Limiter(key_func=get_remote_address)

app = FastAPI(
    title="ScanAPK API",
    version="1.0.0",
    description="Backend API for Android APK malware analysis",
)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

API_KEY = os.environ.get("SCANAPK_API_KEY")


def verify_api_key(authorization: str | None = Header(None)):
    if not API_KEY:
        return True
    if not authorization:
        raise HTTPException(status_code=401, detail="Missing Authorization header")
    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Invalid Authorization header")
    if authorization.removeprefix("Bearer ") != API_KEY:
        raise HTTPException(status_code=403, detail="Invalid API key")
    return True


conn = sqlite3.connect(str(DB_PATH), check_same_thread=False)
conn.row_factory = sqlite3.Row
conn.execute("""
    CREATE TABLE IF NOT EXISTS jobs (
        job_id TEXT PRIMARY KEY,
        status TEXT NOT NULL DEFAULT 'pending',
        created_at TEXT NOT NULL,
        started_at TEXT,
        completed_at TEXT,
        filename TEXT,
        result TEXT,
        error TEXT
    )
""")
conn.commit()


def _init_job(job_id: str, filename: str | None):
    now = datetime.now(timezone.utc).isoformat()
    conn.execute(
        "INSERT INTO jobs (job_id, status, created_at, filename) VALUES (?, ?, ?, ?)",
        (job_id, "pending", now, filename),
    )
    conn.commit()


def _update_job(job_id: str, **kwargs):
    cols = ", ".join(f"{k} = ?" for k in kwargs)
    vals = list(kwargs.values()) + [job_id]
    conn.execute(f"UPDATE jobs SET {cols} WHERE job_id = ?", vals)
    conn.commit()


def _get_job(job_id: str) -> dict | None:
    row = conn.execute("SELECT * FROM jobs WHERE job_id = ?", (job_id,)).fetchone()
    if row is None:
        return None
    d = dict(row)
    if d["result"]:
        d["result"] = json.loads(d["result"])
    return d


def _delete_job(job_id: str):
    conn.execute("DELETE FROM jobs WHERE job_id = ?", (job_id,))
    conn.commit()


def _run_scan(job_id: str, apk_path: str):
    try:
        now = datetime.now(timezone.utc).isoformat()
        _update_job(job_id, status="running", started_at=now)

        static_info = scan_apk(apk_path, verbose=False)
        if static_info is None:
            _update_job(job_id, status="failed", error="Failed to scan APK")
            return

        evidence = {}
        deterministic_score = calculate_risk(static_info, evidence)

        ai_result = {}
        if get_models():
            try:
                ai_result = analyse(
                    apk_path=apk_path,
                    static_info=static_info,
                    evidence=evidence,
                    deterministic=deterministic_score,
                    verbose=False,
                )
            except Exception as e:
                logger.warning("AI analysis failed: %s", e)

        final_assessment = dict(deterministic_score)
        if ai_result and ai_result.get("risk_score", -1) >= 0:
            final_assessment["key_findings"] = ai_result.get(
                "key_findings", final_assessment["key_findings"]
            )
            final_assessment["recommendations"] = ai_result.get(
                "recommendations", final_assessment["recommendations"]
            )
            final_assessment["malware_family"] = ai_result.get("malware_family")
            final_assessment["threat_types"] = ai_result.get("threat_types", [])
            final_assessment["iocs"] = ai_result.get("iocs", {"urls": [], "ips": [], "apis": []})

        final_assessment["verdict"] = _verdict(final_assessment.get("severity", ""))

        report = build_report(static_info, final_assessment, deterministic_score)

        report_path = UPLOAD_DIR / job_id / "report.json"
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text(json.dumps(report, indent=2))

        now = datetime.now(timezone.utc).isoformat()
        _update_job(
            job_id,
            status="completed",
            completed_at=now,
            result=json.dumps({
                "risk_score": deterministic_score.get("risk_score"),
                "severity": deterministic_score.get("severity"),
                "verdict": final_assessment["verdict"],
                "malware_family": final_assessment.get("malware_family"),
            }),
        )
    except Exception as e:
        logger.exception("Scan failed for job %s", job_id)
        _update_job(job_id, status="failed", error=str(e))
    finally:
        uploaded_apk = Path(apk_path)
        if uploaded_apk.exists():
            uploaded_apk.unlink(missing_ok=True)


@app.on_event("startup")
def startup():
    init_db()


@app.on_event("shutdown")
def shutdown():
    conn.close()


@app.get("/health")
def health():
    return {
        "status": "ok",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@app.post("/api/v1/scan", status_code=202)
@limiter.limit(SCAN_RATE_LIMIT)
async def submit_scan(
    request: Request,
    apk: UploadFile = File(...),
    bg: BackgroundTasks = BackgroundTasks(),
    _=Depends(verify_api_key),
):
    if not apk.filename or not apk.filename.endswith(".apk"):
        raise HTTPException(status_code=400, detail="Only .apk files are accepted")

    content = await apk.read()
    if len(content) > MAX_FILE_SIZE:
        raise HTTPException(
            status_code=400,
            detail=f"File exceeds max size of {MAX_FILE_SIZE // (1024*1024)} MB",
        )

    job_id = str(uuid.uuid4())
    job_dir = UPLOAD_DIR / job_id
    job_dir.mkdir(parents=True)

    apk_path = str(job_dir / "original.apk")
    with open(apk_path, "wb") as f:
        f.write(content)

    _init_job(job_id, apk.filename)
    bg.add_task(_run_scan, job_id, apk_path)

    return {"job_id": job_id, "status": "pending"}


@app.get("/api/v1/scan/{job_id}")
def get_scan_status(job_id: str, _=Depends(verify_api_key)):
    job = _get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")

    resp = {
        "job_id": job["job_id"],
        "status": job["status"],
        "created_at": job["created_at"],
        "filename": job["filename"],
    }
    for field in ("started_at", "completed_at"):
        if job.get(field):
            resp[field] = job[field]
    if job.get("result"):
        resp["result"] = job["result"]
    if job.get("error"):
        resp["error"] = job["error"]
    return resp


@app.get("/api/v1/scan/{job_id}/report")
def get_report(job_id: str, _=Depends(verify_api_key)):
    report_path = UPLOAD_DIR / job_id / "report.json"
    if not report_path.exists():
        job = _get_job(job_id)
        if not job:
            raise HTTPException(status_code=404, detail="Job not found")
        if job["status"] in ("running", "pending"):
            raise HTTPException(status_code=409, detail="Scan still in progress")
        raise HTTPException(status_code=404, detail="Report not found")
    return JSONResponse(content=json.loads(report_path.read_text()))


@app.get("/api/v1/scan/{job_id}/report/summary")
def get_report_summary(job_id: str, _=Depends(verify_api_key)):
    report_path = UPLOAD_DIR / job_id / "report.json"
    if not report_path.exists():
        job = _get_job(job_id)
        if not job:
            raise HTTPException(status_code=404, detail="Job not found")
        if job["status"] in ("running", "pending"):
            raise HTTPException(status_code=409, detail="Scan still in progress")
        raise HTTPException(status_code=404, detail="Report not found")

    report = json.loads(report_path.read_text())
    se = report.get("static_evidence", {})
    return {
        "app": report.get("app", {}),
        "assessment": report.get("assessment", {}),
        "verdict": report.get("verdict", "UNKNOWN"),
        "summary": {
            "yara_match_count": len(se.get("yara_matches", [])),
            "dangerous_permission_count": len(se.get("dangerous_permissions", [])),
            "suspicious_api_count": len(se.get("suspicious_apis", [])),
            "url_count": len(se.get("embedded_urls", [])),
            "ip_count": len(se.get("embedded_ips", [])),
            "tracker_count": len(se.get("tracker_detection", {}).get("trackers", [])),
            "native_lib_count": len(se.get("native_libs", [])),
            "exfiltration_chain_count": len(se.get("exfiltration_chains", [])),
        },
    }


@app.delete("/api/v1/scan/{job_id}")
def delete_scan(job_id: str, _=Depends(verify_api_key)):
    job_dir = UPLOAD_DIR / job_id
    if job_dir.exists():
        shutil.rmtree(job_dir)
    _delete_job(job_id)
    return {"status": "deleted"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
