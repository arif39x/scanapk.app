"""Tests for core/knowledge_graph.py — triple formation from evidence."""

from scanapk_backend.core.knowledge_graph import build_graph


class TestBuildGraphStructure:
    """Verify the overall structure and format of the knowledge graph."""

    def test_returns_string(self):
        result = build_graph("/path/to.apk", {"package": "com.test", "app_name": "Test"})
        assert isinstance(result, str)
        assert len(result) > 0

    def test_includes_app_triple(self):
        result = build_graph("/path/to.apk", {
            "package": "com.test",
            "app_name": "Test App",
            "target_sdk": 33,
        })
        assert "APP:" in result
        assert "com.test" in result
        assert "Test App" in result

    def test_includes_total_triple_count(self):
        result = build_graph("/path/to.apk", {"package": "com.test", "app_name": "T"})
        assert "# Total:" in result

    def test_triple_format(self):
        """Every data line should be KEY: value | ..."""
        result = build_graph("/path/to.apk", {"package": "com.test", "app_name": "T"})
        lines = result.strip().split("\n")
        for line in lines:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            assert ":" in line, f"Line missing colon separator: {line!r}"
            key = line.split(":")[0].strip()
            assert key.isupper() or key == "# Total", f"Unexpected key format: {key!r}"


class TestGraphContent:
    """Verify specific content in the knowledge graph."""

    def test_findings_included(self):
        static_info = {
            "package": "com.test",
            "app_name": "Test",
        }
        deterministic = {
            "key_findings": ["Found suspicious API getDeviceId", "High risk score"],
        }
        result = build_graph("/x.apk", static_info, deterministic=deterministic)
        assert "Found suspicious API getDeviceId" in result
        assert "High risk score" in result

    def test_permissions_included(self):
        static_info = {
            "package": "com.test",
            "app_name": "Test",
            "dangerous_permissions": [
                "android.permission.READ_SMS",
                "android.permission.CAMERA",
            ],
        }
        result = build_graph("/x.apk", static_info)
        assert "PERM:" in result
        assert "READ_SMS" in result
        assert "CAMERA" in result

    def test_apis_included(self):
        static_info = {
            "package": "com.test",
            "app_name": "Test",
            "suspicious_apis": ["getDeviceId", "sendTextMessage"],
        }
        result = build_graph("/x.apk", static_info)
        assert "API:" in result
        assert "getDeviceId" in result
        assert "sendTextMessage" in result

    def test_urls_and_ips(self):
        static_info = {
            "package": "com.test",
            "app_name": "Test",
            "urls": [{"url": "https://evil.com"}],
            "ips": [{"ip": "10.0.0.5"}],
        }
        result = build_graph("/x.apk", static_info)
        assert "https://evil.com" in result
        assert "10.0.0.5" in result

    def test_deterministic_risk_included(self):
        static_info = {"package": "com.test", "app_name": "Test"}
        deterministic = {"risk_score": 75, "severity": "HIGH"}
        result = build_graph("/x.apk", static_info, deterministic=deterministic)
        assert "RISK:" in result
        assert "75" in result
        assert "HIGH" in result

    def test_native_analysis_included(self):
        static_info = {
            "package": "com.test",
            "app_name": "Test",
            "native_analysis": {
                "suspicious_findings": [{"category": "shell_exec", "symbol": "system"}],
            },
        }
        result = build_graph("/x.apk", static_info)
        assert "NATIVE:" in result
        assert "shell_exec" in result

    def test_exfiltration_chains(self):
        static_info = {
            "package": "com.test",
            "app_name": "Test",
            "exfiltration_chains": [
                {"source": "Main.getDeviceId", "sink": "sendTextMessage", "chain_length": 3},
            ],
        }
        result = build_graph("/x.apk", static_info)
        assert "EXFIL:" in result
        assert "getDeviceId" in result
        assert "sendTextMessage" in result

    def test_evidence_included(self):
        static_info = {"package": "com.test", "app_name": "Test"}
        evidence = {
            "frida_hits": [{"detail": "SMS sent to 555-0100"}],
            "detected_techniques": [
                {"technique": "Dropper / Two-Stage", "confidence": "HIGH",
                 "indicators": ["DexClassLoader"]}
            ],
        }
        result = build_graph("/x.apk", static_info, evidence=evidence)
        assert "FRIDA:" in result
        assert "TECH:" in result
        assert "Dropper" in result


class TestSanitization:
    """Verify that special characters in FINDING / PERM / API triples are
    sanitized (the header and APP line are intentionally raw)."""

    def test_pipe_replaced_in_findings(self):
        """Pipes in findings (which go through _san) become '/'."""
        static_info = {"package": "com.test", "app_name": "Test"}
        deterministic = {"key_findings": ["malware|trojan|banking"]}
        result = build_graph("/x.apk", static_info, deterministic=deterministic)
        assert "malware/trojan/banking" in result
        assert "malware|trojan|banking" not in result

    def test_newline_replaced_in_findings(self):
        static_info = {"package": "com.test", "app_name": "Test"}
        deterministic = {"key_findings": ["malware\ntrojan"]}
        result = build_graph("/x.apk", static_info, deterministic=deterministic)
        assert "\ntrojan" not in result

    def test_san_truncates_long_values(self):
        long_val = "A" * 500
        static_info = {"package": "com.test", "app_name": "Test",
                       "dangerous_permissions": [long_val]}
        result = build_graph("/x.apk", static_info)
        # The perm value goes through _san which truncates at 200
        perm_lines = [l for l in result.split("\n") if l.startswith("PERM:")]
        assert any(len(l) <= 250 for l in perm_lines)


class TestEdgeCases:
    def test_empty_static_info(self):
        result = build_graph("/x.apk", {})
        assert "APP:" in result
        assert "# Total:" in result

    def test_none_values(self):
        result = build_graph("/x.apk", {"package": None, "app_name": None})
        assert "APP:" in result
