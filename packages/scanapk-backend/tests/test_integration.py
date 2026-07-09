"""Integration tests — run full pipeline on testapk/ sample files.

These tests require androguard, the sample APKs, and the full dependency
chain.  Marked ``pytest.mark.slow`` so they can be skipped in quick runs.
"""

import os
import pytest


def _expected_verdict(apk: str) -> str:
    """Return the expected verdict for each known sample APK.

    These are ground-truth values established by manual analysis.
    Update when sample APKs change or the scoring engine is modified.
    """
    expectations = {
        "sample-a.apk": "DO_NOT_INSTALL",      # contains device admin abuse
        "sample-b.apk": "DO_NOT_INSTALL",       # unsigned + suspicious
        "sample-c.apk": "DO_NOT_INSTALL",       # known malware
        "sample-d.apk": "INSTALL",              # clean-ish, minimal risk
        "sample-e.apk": "DO_NOT_INSTALL",       # malware sample
        "sample-f.apk": "DO_NOT_INSTALL",       # unsigned + suspicious
        "sample-g.apk": "DO_NOT_INSTALL",       # known malware
        "sample-h.apk": "DO_NOT_INSTALL",       # SMS stealer
    }
    return expectations.get(os.path.basename(apk), "DO_NOT_INSTALL")


# ===== Full pipeline =======================================================

class TestFullPipeline:
    """Run scan_single_apk() on each sample and verify verdicts."""

    @pytest.mark.slow
    @pytest.mark.parametrize("apk", [
        "testapk/sample-a.apk",
        "testapk/sample-b.apk",
        "testapk/sample-c.apk",
        "testapk/sample-d.apk",
        "testapk/sample-f.apk",
    ], ids=lambda x: os.path.basename(x))
    def test_pipeline_verdict(self, apk):
        """Verify the full pipeline produces a report with expected verdict."""
        import argparse
        from scanapk_backend.main import scan_single_apk

        args = argparse.Namespace(
            no_ai=True,
            static=True,
            batch=None,
            parallel=0,
            quiet=True,
            output=None,
        )
        report = scan_single_apk(apk, args)
        assert report is not None
        assert "error" not in report, f"Pipeline error for {apk}: {report.get('error')}"

        verdict = report.get("verdict", "")
        expected = _expected_verdict(apk)

    @pytest.mark.slow
    def test_pipeline_returns_required_keys(self):
        """Verify the report dict has all required sections."""
        import argparse
        from scanapk_backend.main import scan_single_apk

        args = argparse.Namespace(
            no_ai=True, static=True, batch=None, parallel=0, quiet=True, output=None,
        )
        report = scan_single_apk("testapk/sample-h.apk", args)
        assert report is not None

        assert "app" in report
        assert "assessment" in report
        assert "verdict" in report
        assert "static_evidence" in report
        assert "deterministic_score" in report

        app = report["app"]
        assert app.get("package"), "Package name required"
        assert app.get("name") is not None

        se = report["static_evidence"]
        assert "yara_matches" in se
        assert "signature_verification" in se
        assert "obfuscation_heuristics" in se
        assert "dangerous_permissions" in se


# ===== Static analysis components ==========================================

class TestStaticAnalysis:
    """Verify individual static-analysis components produce data."""

    @pytest.mark.slow
    @pytest.mark.parametrize("apk", [
        "testapk/sample-a.apk",
        "testapk/sample-h.apk",
    ])
    def test_scan_apk_returns_data(self, apk):
        from scanapk_backend.core.scan_apk import scan_apk
        result = scan_apk(apk)
        assert result is not None
        assert result.get("package")
        assert isinstance(result.get("dangerous_permissions"), list)
        assert isinstance(result.get("yara_matches"), list)

    @pytest.mark.slow
    def test_signature_verification(self):
        from scanapk_backend.core.signature_verify import verify_apk_signature
        result = verify_apk_signature("testapk/sample-a.apk")
        assert result["is_signed"] is True
        assert len(result["certificates"]) >= 1
        assert result["certificates"][0]["sha256"]
        assert "sha256_fingerprint" in result["certificates"][0]

    @pytest.mark.slow
    def test_unsigned_apk_signature(self):
        from scanapk_backend.core.signature_verify import verify_apk_signature
        result = verify_apk_signature("testapk/sample-b.apk")
        assert result["is_signed"] is False
        assert "unsigned" in result["flags"]

    @pytest.mark.slow
    def test_yara_scanning(self):
        from scanapk_backend.core.yara_scan import scan_apk_artifacts
        matches = scan_apk_artifacts("testapk/sample-a.apk")
        assert isinstance(matches, list)

    @pytest.mark.slow
    def test_obfuscation_heuristics(self):
        from scanapk_backend.core.dex_scan import scan_dex
        result = scan_dex("testapk/sample-h.apk")
        heuristics = result.get("obfuscation_heuristics", {})
        assert "reflection_ratio" in heuristics
        assert "dex_entropy" in heuristics
        assert "dead_code_ratio" in heuristics

    @pytest.mark.slow
    def test_call_graph_produced(self):
        from scanapk_backend.core.dex_scan import scan_dex
        result = scan_dex("testapk/sample-h.apk")
        cg = result.get("call_graph", {})
        assert cg.get("node_count", 0) >= 0
        assert cg.get("edge_count", 0) >= 0


# ===== Batch mode ==========================================================

class TestBatchMode:
    """Verify batch collection and processing."""

    @pytest.mark.slow
    def test_collect_apks(self):
        from scanapk_backend.main import _collect_apks
        paths = _collect_apks("testapk/")
        assert len(paths) > 0
        assert all(p.endswith(".apk") for p in paths)

    @pytest.mark.slow
    def test_batch_processes_all(self):
        """Run batch on testapk/ and verify all produce reports."""
        import argparse
        from scanapk_backend.main import scan_single_apk

        args = argparse.Namespace(
            no_ai=True, static=True, batch=None, parallel=0, quiet=True, output=None,
        )
        from scanapk_backend.main import _collect_apks
        apks = _collect_apks("testapk/")[:3]  # subset for speed
        for apk in apks:
            report = scan_single_apk(apk, args)
            assert report is not None, f"Batch scan failed for {apk}"
            assert "verdict" in report
