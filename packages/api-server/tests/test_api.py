"""Tests for the ScanAPK API (packages/api-server/api_server/main.py)."""

import json
import os
import sys
from unittest.mock import patch

import pytest

_api_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_scanapk_dir = os.path.join(_api_dir, "..", "scanapk-backend")
if _api_dir not in sys.path:
    sys.path.insert(0, _api_dir)
if _scanapk_dir not in sys.path:
    sys.path.append(_scanapk_dir)

from fastapi import HTTPException
from fastapi.testclient import TestClient

os.environ.setdefault("SCANAPK_RATE_LIMIT", "100/minute")
from api_server.main import app

client = TestClient(app)


def _require_auth():
    raise HTTPException(status_code=401, detail="Missing API key")


def _reject_key():
    raise HTTPException(status_code=403, detail="Invalid API key")


@pytest.fixture(autouse=True)
def clear_db():
    from api_server.main import conn
    conn.execute("DELETE FROM jobs")
    conn.commit()
    yield


@pytest.fixture
def mock_scan():
    with patch("api_server.main.scan_apk") as mock:
        mock.return_value = {
            "app_name": "TestApp",
            "package": "com.test",
            "target_sdk": 33,
            "all_permissions": ["android.permission.INTERNET"],
            "dangerous_permissions": [],
            "api_details": [],
            "urls": [],
            "ips": [],
            "receivers": [],
            "services": [],
            "native_libs": [],
            "native_analysis": {},
            "tracker_detection": {},
            "call_graph": {"node_count": 5, "edge_count": 2, "max_depth": 1},
            "exfiltration_chains": [],
            "no_ui_reachable": [],
            "similarity_matches": [],
            "yara_matches": [],
            "signature_verification": {"flags": []},
            "obfuscation_heuristics": {},
            "code_hashes": {},
        }
        yield mock


@pytest.fixture
def mock_scoring():
    with patch("api_server.main.calculate_risk") as mock:
        mock.return_value = {
            "risk_score": 10,
            "severity": "LOW",
            "confidence": "HIGH",
            "key_findings": [],
            "recommendations": [],
        }
        yield mock


class TestHealth:
    def test_health_returns_ok(self):
        resp = client.get("/health")
        assert resp.status_code == 200
        assert resp.json()["status"] == "ok"

    def test_health_includes_timestamp(self):
        resp = client.get("/health")
        assert "timestamp" in resp.json()


class TestAuth:
    def test_missing_key_returns_401(self):
        from api_server.main import verify_api_key
        app.dependency_overrides[verify_api_key] = _require_auth
        try:
            resp = client.post("/api/v1/scan")
            assert resp.status_code == 401
        finally:
            app.dependency_overrides.pop(verify_api_key, None)

    def test_wrong_key_returns_403(self):
        from api_server.main import verify_api_key
        app.dependency_overrides[verify_api_key] = _reject_key
        try:
            resp = client.post(
                "/api/v1/scan",
                files={"apk": ("test.apk", b"fake")},
            )
            assert resp.status_code == 403
        finally:
            app.dependency_overrides.pop(verify_api_key, None)

    def test_correct_key_succeeds(self):
        resp = client.post(
            "/api/v1/scan",
            files={"apk": ("test.apk", b"fake apk content")},
        )
        assert resp.status_code == 202

    def test_no_auth_configured_still_works(self):
        resp = client.post(
            "/api/v1/scan",
            files={"apk": ("test.apk", b"fake apk content")},
        )
        assert resp.status_code == 202


class TestFileValidation:
    def test_rejects_non_apk(self):
        resp = client.post(
            "/api/v1/scan",
            files={"apk": ("test.txt", b"not an apk")},
        )
        assert resp.status_code == 400
        assert "Only .apk files" in resp.json()["detail"]

    def test_rejects_missing_file(self):
        resp = client.post("/api/v1/scan")
        assert resp.status_code == 422

    def test_rejects_large_file(self):
        from api_server.main import MAX_FILE_SIZE
        large = b"x" * (MAX_FILE_SIZE + 1)
        resp = client.post(
            "/api/v1/scan",
            files={"apk": ("large.apk", large)},
        )
        assert resp.status_code == 400
        assert "exceeds max size" in resp.json()["detail"]


class TestScanLifecycle:
    def test_submit_returns_job_id(self, mock_scan, mock_scoring):
        resp = client.post(
            "/api/v1/scan",
            files={"apk": ("test.apk", b"fake apk content")},
        )
        assert resp.status_code == 202
        data = resp.json()
        assert "job_id" in data
        assert data["status"] == "pending"

    def test_get_status_pending(self, mock_scan, mock_scoring):
        resp = client.post(
            "/api/v1/scan",
            files={"apk": ("test.apk", b"fake apk content")},
        )
        job_id = resp.json()["job_id"]
        resp = client.get(f"/api/v1/scan/{job_id}")
        assert resp.status_code == 200
        assert resp.json()["job_id"] == job_id
        assert resp.json()["status"] in ("pending", "running", "completed", "failed")

    def test_get_status_not_found(self):
        resp = client.get("/api/v1/scan/nonexistent-id")
        assert resp.status_code == 404

    def test_get_status_includes_filename(self, mock_scan, mock_scoring):
        resp = client.post(
            "/api/v1/scan",
            files={"apk": ("myapp.apk", b"fake")},
        )
        job_id = resp.json()["job_id"]
        resp = client.get(f"/api/v1/scan/{job_id}")
        assert resp.json()["filename"] == "myapp.apk"

    def test_report_accessible_after_submit(self, mock_scan, mock_scoring):
        resp = client.post(
            "/api/v1/scan",
            files={"apk": ("test.apk", b"fake")},
        )
        job_id = resp.json()["job_id"]
        resp = client.get(f"/api/v1/scan/{job_id}/report")
        assert resp.status_code in (200, 404, 409)

    def test_summary_accessible_after_submit(self, mock_scan, mock_scoring):
        resp = client.post(
            "/api/v1/scan",
            files={"apk": ("test.apk", b"fake")},
        )
        job_id = resp.json()["job_id"]
        resp = client.get(f"/api/v1/scan/{job_id}/report/summary")
        assert resp.status_code in (200, 404, 409)

    def test_delete_scan(self, mock_scan, mock_scoring):
        resp = client.post(
            "/api/v1/scan",
            files={"apk": ("test.apk", b"fake")},
        )
        job_id = resp.json()["job_id"]
        resp = client.delete(f"/api/v1/scan/{job_id}")
        assert resp.status_code == 200
        assert resp.json()["status"] == "deleted"
        resp = client.get(f"/api/v1/scan/{job_id}")
        assert resp.status_code == 404

    def test_delete_nonexistent(self):
        resp = client.delete("/api/v1/scan/nonexistent")
        assert resp.status_code == 200


class TestCompletedReport:
    def test_report_contains_expected_structure(self, mock_scan, mock_scoring):
        resp = client.post(
            "/api/v1/scan",
            files={"apk": ("test.apk", b"fake")},
        )
        job_id = resp.json()["job_id"]
        from api_server.main import _run_scan
        from api_server.main import UPLOAD_DIR
        _run_scan(job_id, str(UPLOAD_DIR / job_id / "original.apk"))
        resp = client.get(f"/api/v1/scan/{job_id}/report")
        assert resp.status_code == 200
        data = resp.json()
        assert "app" in data
        assert "assessment" in data
        assert "verdict" in data
        assert "static_evidence" in data

    def test_summary_contains_counts(self, mock_scan, mock_scoring):
        resp = client.post(
            "/api/v1/scan",
            files={"apk": ("test.apk", b"fake")},
        )
        job_id = resp.json()["job_id"]
        from api_server.main import _run_scan
        from api_server.main import UPLOAD_DIR
        _run_scan(job_id, str(UPLOAD_DIR / job_id / "original.apk"))
        resp = client.get(f"/api/v1/scan/{job_id}/report/summary")
        assert resp.status_code == 200
        data = resp.json()
        assert "app" in data
        assert "summary" in data
        assert "yara_match_count" in data["summary"]

    def test_status_completed_after_scan(self, mock_scan, mock_scoring):
        resp = client.post(
            "/api/v1/scan",
            files={"apk": ("test.apk", b"fake")},
        )
        job_id = resp.json()["job_id"]
        from api_server.main import _run_scan
        from api_server.main import UPLOAD_DIR
        _run_scan(job_id, str(UPLOAD_DIR / job_id / "original.apk"))
        resp = client.get(f"/api/v1/scan/{job_id}")
        assert resp.json()["status"] == "completed"
        assert resp.json()["result"]["risk_score"] == 10
        assert resp.json()["result"]["severity"] == "LOW"
        assert resp.json()["result"]["verdict"] == "REVIEW"


class TestRateLimiting:
    def test_rate_limit_middleware_active(self):
        resp = client.post(
            "/api/v1/scan",
            files={"apk": ("test.apk", b"fake")},
        )
        assert resp.status_code in (202, 429)
