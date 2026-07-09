"""Tests for report/generator.py — JSON report structure and required fields."""

from scanapk_backend.report.generator import build_report, _verdict


class TestBuildReport:
    """Structural tests for build_report() output."""

    REQUIRED_TOP_LEVEL = {"schema_version", "generated_at", "verdict", "app", "assessment", "deterministic_score", "static_evidence"}

    REQUIRED_APP = {"name", "package", "target_sdk"}

    REQUIRED_ASSESSMENT = {"risk_score", "severity", "confidence", "key_findings", "recommendations"}

    REQUIRED_EVIDENCE = {
        "dangerous_permissions", "suspicious_apis", "embedded_urls",
        "embedded_ips", "receivers", "services", "native_libs",
        "native_analysis", "tracker_detection", "call_graph",
        "exfiltration_chains", "no_ui_reachable", "code_hashes",
        "similarity_matches", "yara_matches", "signature_verification",
        "obfuscation_heuristics",
    }

    def make_static(self, **overrides):
        base = {
            "app_name": "TestApp",
            "package": "com.test.app",
            "target_sdk": 33,
            "dangerous_permissions": [],
            "suspicious_apis": [],
            "urls": [],
            "ips": [],
            "receivers": [],
            "services": [],
            "native_libs": [],
            "native_analysis": {},
            "tracker_detection": {},
            "call_graph": {},
            "exfiltration_chains": [],
            "no_ui_reachable": [],
            "code_hashes": {},
            "similarity_matches": [],
            "yara_matches": [],
            "signature_verification": {},
            "obfuscation_heuristics": {},
        }
        base.update(overrides)
        return base

    def test_required_top_level_keys(self):
        static = self.make_static()
        assessment = {"risk_score": 0, "severity": "CLEAN", "confidence": "HIGH", "key_findings": [], "recommendations": []}
        deterministic = {"risk_score": 0, "severity": "CLEAN"}
        report = build_report(static, assessment, deterministic)
        assert self.REQUIRED_TOP_LEVEL.issubset(report.keys()), f"Missing keys: {self.REQUIRED_TOP_LEVEL - report.keys()}"

    def test_required_app_keys(self):
        report = build_report(self.make_static(), {"risk_score": 0}, {"risk_score": 0})
        app = report.get("app", {})
        assert self.REQUIRED_APP.issubset(app.keys()), f"Missing app keys: {self.REQUIRED_APP - app.keys()}"

    def test_required_assessment_keys(self):
        assessment = {"risk_score": 15, "severity": "LOW", "confidence": "HIGH", "key_findings": [], "recommendations": []}
        report = build_report(self.make_static(), assessment, {"risk_score": 15, "severity": "LOW"})
        a = report.get("assessment", {})
        assert self.REQUIRED_ASSESSMENT.issubset(a.keys()), f"Missing assessment keys: {self.REQUIRED_ASSESSMENT - a.keys()}"

    def test_required_static_evidence_keys(self):
        report = build_report(self.make_static(), {"risk_score": 0}, {"risk_score": 0})
        se = report.get("static_evidence", {})
        missing = self.REQUIRED_EVIDENCE - se.keys()
        assert not missing, f"Missing static_evidence keys: {missing}"

    def test_schema_version(self):
        report = build_report(self.make_static(), {"risk_score": 0}, {"risk_score": 0})
        assert report["schema_version"] == "1.0"

    def test_generated_at_is_int(self):
        report = build_report(self.make_static(), {"risk_score": 0}, {"risk_score": 0})
        assert isinstance(report["generated_at"], int)

    def test_verdict_mapping(self):
        for sev, expected in [("CLEAN", "INSTALL"), ("LOW", "REVIEW"), ("MEDIUM", "DO_NOT_INSTALL"), ("HIGH", "DO_NOT_INSTALL"), ("CRITICAL", "DO_NOT_INSTALL")]:
            a = {"risk_score": 0, "severity": sev}
            report = build_report(self.make_static(), a, a)
            assert report["verdict"] == expected, f"Severity {sev} gave verdict {report['verdict']}"

    def test_assessment_fallback_to_deterministic(self):
        """When assessment has no risk_score, fall back to deterministic."""
        static = self.make_static()
        assessment = {"severity": "HIGH"}
        deterministic = {"risk_score": 75, "severity": "HIGH"}
        report = build_report(static, assessment, deterministic)
        # assessment should be deterministic since assessment has no valid risk_score
        a = report["assessment"]
        assert a.get("risk_score", -1) >= 0 or a is deterministic


class TestVerdict:
    def test_install(self):
        assert _verdict("CLEAN") == "INSTALL"

    def test_review(self):
        assert _verdict("LOW") == "REVIEW"

    def test_do_not_install(self):
        assert _verdict("MEDIUM") == "DO_NOT_INSTALL"
        assert _verdict("HIGH") == "DO_NOT_INSTALL"
        assert _verdict("CRITICAL") == "DO_NOT_INSTALL"
        assert _verdict("") == "DO_NOT_INSTALL"
        assert _verdict("UNKNOWN") == "DO_NOT_INSTALL"
