"""Tests for core/dex_scan.py — DEX analysis with mocked / real APK data."""

import re
import pytest

from scanapk_backend.core.dex_scan import (
    _URL_PATTERN,
    _IP_PATTERN,
    _SUSPICIOUS_METHODS,
    _STRING_FALLBACK_APIS,
)


# ===== URL / IP pattern extraction ==========================================

class TestUrlPattern:
    def test_basic_url(self):
        assert _URL_PATTERN.findall("https://evil.com/path")

    def test_url_with_query(self):
        urls = _URL_PATTERN.findall("Download at http://example.com/?id=123&key=abc")
        assert len(urls) == 1
        assert "http://example.com/" in urls[0]

    def test_https_url(self):
        urls = _URL_PATTERN.findall("https://c2.malware.io/beacon")
        assert len(urls) == 1
        assert "https://c2.malware.io/beacon" in urls[0]

    def test_no_false_positive_short(self):
        assert not _URL_PATTERN.findall("http://a.co")  # less than 8 chars after scheme

    def test_multiple_urls(self):
        urls = _URL_PATTERN.findall("a https://first.com/path b http://second.net/data c")
        assert len(urls) >= 2


class TestIpPattern:
    def test_ipv4(self):
        ips = _IP_PATTERN.findall("connect to 192.168.1.1:8080")
        assert "192.168.1.1:8080" in ips

    def test_ipv4_no_port(self):
        ips = _IP_PATTERN.findall("server at 10.0.0.5")
        assert "10.0.0.5" in ips

    def test_not_an_ip(self):
        assert not _IP_PATTERN.findall("no numbers here at all")

    def test_multiple_ips(self):
        ips = _IP_PATTERN.findall("first 10.0.0.1 and second 172.16.0.1:443")
        assert len(ips) == 2


# ===== Suspicious method definitions ========================================

class TestSuspiciousMethods:
    """Verify that the suspicious method table has the expected format."""

    def test_all_entries_have_required_fields(self):
        for entry in _SUSPICIOUS_METHODS:
            assert len(entry) == 4, f"Entry {entry} should have 4 elements"
            label, category, class_pat, method_pat = entry
            assert isinstance(label, str) and label
            assert isinstance(category, str) and category
            assert isinstance(class_pat, str) and class_pat
            assert isinstance(method_pat, str) and method_pat

    def test_categories_are_known(self):
        known_categories = {
            "data_theft", "sms_intercept", "crypto", "shell_exec",
            "network", "ransomware", "persistence",
        }
        categories = {e[1] for e in _SUSPICIOUS_METHODS}
        unknown = categories - known_categories
        assert not unknown, f"Unknown categories: {unknown}"

    def test_no_duplicate_labels(self):
        labels = [e[0] for e in _SUSPICIOUS_METHODS]
        assert len(labels) == len(set(labels)), f"Duplicate labels found"


class TestFallbackApis:
    """Verify fallback API string detection table."""

    def test_all_values_have_known_category(self):
        known_categories = {
            "data_theft", "sms_intercept", "crypto", "shell_exec",
            "network", "ransomware", "persistence",
        }
        for api, category in _STRING_FALLBACK_APIS.items():
            assert category in known_categories, f"Unknown category {category} for {api}"

    def test_detection_by_substring(self):
        """Verify fallback detection works on real strings."""
        for api, category in _STRING_FALLBACK_APIS.items():
            assert api in _STRING_FALLBACK_APIS


# ===== Integration test with sample APKs ====================================

class TestSampleApkDexScan:
    """Run scan_dex on real sample APKs and verify basic properties."""

    @pytest.mark.slow
    @pytest.mark.parametrize("apk", [
        "testapk/sample-a.apk",
        "testapk/sample-b.apk",
        "testapk/sample-h.apk",
    ])
    def test_scan_dex_returns_expected_keys(self, apk):
        from scanapk_backend.core.dex_scan import scan_dex
        result = scan_dex(apk)
        assert isinstance(result, dict)
        assert "suspicious_apis" in result
        assert "urls" in result
        assert "ips" in result
        assert "api_details" in result
        assert "call_graph" in result
        assert "receivers" in result
        assert isinstance(result["suspicious_apis"], list)
        assert isinstance(result["urls"], list)

    @pytest.mark.slow
    def test_sample_h_sms_stealer_detection(self):
        """sample-h.apk is expected to have SMS-stealer characteristics."""
        from scanapk_backend.core.dex_scan import scan_dex
        result = scan_dex("testapk/sample-h.apk")
        apis = set(result.get("suspicious_apis", []))
        # Should have SMS-related APIs
        sms_apis = {"sendTextMessage", "getDeviceId", "getAllContacts"}
        assert apis & sms_apis, f"Expected SMS-stealer APIs, found: {apis}"

    @pytest.mark.slow
    def test_sample_h_has_receivers(self):
        from scanapk_backend.core.dex_scan import scan_dex
        result = scan_dex("testapk/sample-h.apk")
        assert len(result.get("receivers", [])) > 0
