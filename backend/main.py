import json
import os
import shutil
import sys
import uuid
from datetime import datetime
from pathlib import Path

from dotenv import load_dotenv
from fastapi import BackgroundTasks, FastAPI, File, HTTPException, UploadFile
from fastapi.responses import JSONResponse

load_dotenv()

_SCANAPK_DIR = os.path.join(os.path.dirname(__file__), "..", "scanapk")
sys.path.insert(0, _SCANAPK_DIR)

from core.hash_db import init_db
from core.scan_apk import scan_apk
from core.scoring import calculate_risk
from report.generator import build_report

UPLOAD_DIR = Path("uploads")
UPLOAD_DIR.mkdir(exist_ok=True)

app = FastAPI(
    title="ScanAPK API",
    version="1.0.0",
    description="Backend API for Android APK malware analysis",
)

JOBS: dict[str, dict] = {}


def _verdict(severity: str) -> str:
    return {"CLEAN": "INSTALL", "LOW": "REVIEW"}.get(severity.upper(), "DO_NOT_INSTALL")


def _run_scan(job_id: str, apk_path: str):
    try:
        JOBS[job_id]["status"] = "running"
        JOBS[job_id]["started_at"] = datetime.utcnow().isoformat()

        static_info = scan_apk(apk_path)
        if static_info is None:
            JOBS[job_id]["status"] = "failed"
            JOBS[job_id]["error"] = f"Failed to scan APK"
            return

        evidence = {}
        deterministic_score = calculate_risk(static_info, evidence)

        ai_result = {}
        from core.models import get_models
        if get_models():
            try:
                from core.agent import analyse
                ai_result = analyse(
                    apk_path=apk_path,
                    static_info=static_info,
                    evidence=evidence,
                    deterministic=deterministic_score,
                )
            except Exception:
                pass

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

        JOBS[job_id]["status"] = "completed"
        JOBS[job_id]["completed_at"] = datetime.utcnow().isoformat()
        JOBS[job_id]["result"] = {
            "risk_score": deterministic_score.get("risk_score"),
            "severity": deterministic_score.get("severity"),
            "verdict": final_assessment["verdict"],
            "malware_family": final_assessment.get("malware_family"),
        }
    except Exception as e:
        JOBS[job_id]["status"] = "failed"
        JOBS[job_id]["error"] = str(e)


@app.on_event("startup")
def startup():
    init_db()


@app.get("/health")
def health():
    return {
        "status": "ok",
        "timestamp": datetime.utcnow().isoformat(),
    }


@app.post("/api/v1/scan", status_code=202)
async def submit_scan(apk: UploadFile = File(...), bg: BackgroundTasks = BackgroundTasks()):
    job_id = str(uuid.uuid4())
    job_dir = UPLOAD_DIR / job_id
    job_dir.mkdir(parents=True)

    apk_path = str(job_dir / "original.apk")
    with open(apk_path, "wb") as f:
        shutil.copyfileobj(apk.file, f)

    JOBS[job_id] = {
        "job_id": job_id,
        "status": "pending",
        "created_at": datetime.utcnow().isoformat(),
        "filename": apk.filename,
        "result": None,
        "error": None,
    }

    bg.add_task(_run_scan, job_id, apk_path)

    return {"job_id": job_id, "status": "pending"}


@app.get("/api/v1/scan/{job_id}")
def get_scan_status(job_id: str):
    job = JOBS.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")

    resp = {
        "job_id": job["job_id"],
        "status": job["status"],
        "created_at": job["created_at"],
        "filename": job["filename"],
    }
    if job.get("started_at"):
        resp["started_at"] = job["started_at"]
    if job.get("completed_at"):
        resp["completed_at"] = job["completed_at"]
    if job.get("result"):
        resp["result"] = job["result"]
    if job.get("error"):
        resp["error"] = job["error"]

    return resp


@app.get("/api/v1/scan/{job_id}/report")
def get_report(job_id: str):
    report_path = UPLOAD_DIR / job_id / "report.json"
    if not report_path.exists():
        job = JOBS.get(job_id)
        if not job:
            raise HTTPException(status_code=404, detail="Job not found")
        if job["status"] == "running" or job["status"] == "pending":
            raise HTTPException(status_code=409, detail="Scan still in progress")
        raise HTTPException(status_code=404, detail="Report not found")

    return JSONResponse(content=json.loads(report_path.read_text()))


@app.get("/api/v1/scan/{job_id}/report/summary")
def get_report_summary(job_id: str):
    report_path = UPLOAD_DIR / job_id / "report.json"
    if not report_path.exists():
        job = JOBS.get(job_id)
        if not job:
            raise HTTPException(status_code=404, detail="Job not found")
        if job["status"] == "running" or job["status"] == "pending":
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
def delete_scan(job_id: str):
    job_dir = UPLOAD_DIR / job_id
    if job_dir.exists():
        shutil.rmtree(job_dir)
    JOBS.pop(job_id, None)
    return {"status": "deleted"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
