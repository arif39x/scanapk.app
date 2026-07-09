"""Unit tests for core/scoring.py — each scoring function in isolation."""

from scanapk_backend.core.scoring import (
    _severity,
    _score_permissions,
    _score_apis,
    _score_urls_ips,
    _score_evidence,
    _score_call_graph,
    _score_similarity,
    _score_native,
    _score_trackers,
    _score_pcap,
    _score_yara,
    _score_signature,
    _score_obfuscation,
    calculate_risk,
)
from scanapk_backend.report.generator import _verdict


# ===== _severity ===========================================================

class TestSeverity:
    def test_clean(self):
        assert _severity(0) == "CLEAN"
        assert _severity(20) == "CLEAN"

    def test_low(self):
        assert _severity(21) == "LOW"
        assert _severity(40) == "LOW"

    def test_medium(self):
        assert _severity(41) == "MEDIUM"
        assert _severity(60) == "MEDIUM"

    def test_high(self):
        assert _severity(61) == "HIGH"
        assert _severity(80) == "HIGH"

    def test_critical(self):
        assert _severity(81) == "CRITICAL"
        assert _severity(100) == "CRITICAL"


# ===== _verdict ============================================================

class TestVerdict:
    def test_install(self):
        assert _verdict("CLEAN") == "INSTALL"
        assert _verdict("LOW") == "REVIEW"

    def test_do_not_install(self):
        assert _verdict("MEDIUM") == "DO_NOT_INSTALL"
        assert _verdict("HIGH") == "DO_NOT_INSTALL"
        assert _verdict("CRITICAL") == "DO_NOT_INSTALL"
        assert _verdict("UNKNOWN") == "DO_NOT_INSTALL"


# ===== _score_permissions ==================================================

class TestScorePermissions:
    def test_empty(self):
        score, findings = _score_permissions([])
        assert score == 0
        assert findings == []

    def test_internet_only(self):
        score, findings = _score_permissions(
            ["android.permission.INTERNET"]
        )
        assert score == 2
        assert len(findings) == 1
        assert "INTERNET" in findings[0]

    def test_critical_permissions(self):
        score, findings = _score_permissions([
            "android.permission.BIND_DEVICE_ADMIN",
            "android.permission.BIND_ACCESSIBILITY_SERVICE",
        ])
        assert score == 22  # 12 + 10
        assert len(findings) == 2

    def test_capped_at_40(self):
        many = ["android.permission.BIND_DEVICE_ADMIN"] * 10
        score, findings = _score_permissions(many)
        assert score == 40  # capped


# ===== _score_apis =========================================================

class TestScoreApis:
    def test_empty(self):
        score, cats, findings = _score_apis([])
        assert score == 0
        assert cats == set()
        assert findings == []

    def test_single_api(self):
        score, cats, findings = _score_apis([
            {"api": "getDeviceId", "category": "data_theft", "total_callers": 1}
        ])
        assert score >= 8  # base data_theft score
        assert "data_theft" in cats

    def test_combo_bonus(self):
        score, cats, findings = _score_apis([
            {"api": "getDeviceId", "category": "data_theft", "total_callers": 1},
            {"api": "Cipher", "category": "crypto", "total_callers": 1},
        ])
        assert score > 14  # 8 + 6 = 14 base, + 15 combo = 29
        assert "data_theft" in cats
        assert "crypto" in cats

    def test_pair_bonus(self):
        score, cats, findings = _score_apis([
            {"api": "getDeviceId", "category": "data_theft", "total_callers": 1},
            {"api": "sendTextMessage", "category": "sms_intercept", "total_callers": 1},
        ])
        assert score >= 8 + 10 + 15  # data_theft(8) + sms_intercept(10) + pair(15)
        assert "getDeviceId" in findings[0]

    def test_capped_at_50(self):
        many = [{"api": f"api{i}", "category": "data_theft", "total_callers": 1}
                for i in range(20)]
        score, cats, findings = _score_apis(many)
        assert score == 50


# ===== _score_urls_ips =====================================================

class TestScoreUrlsIps:
    def test_empty(self):
        score, findings = _score_urls_ips([], [])
        assert score == 0

    def test_urls_only(self):
        score, findings = _score_urls_ips(
            [{"url": "http://evil.com"}] * 3, []
        )
        assert score == 6  # 3 * 2

    def test_ips_only(self):
        score, findings = _score_urls_ips(
            [], [{"ip": "10.0.0.1"}] * 4
        )
        assert score == 8  # 4 * 2

    def test_capped_at_10(self):
        score, findings = _score_urls_ips(
            [{"url": "http://a.com"}] * 10,
            [{"ip": "10.0.0.1"}] * 10,
        )
        assert score == 10


# ===== _score_call_graph ===================================================

class TestScoreCallGraph:
    def test_empty(self):
        score, findings = _score_call_graph({})
        assert score == 0

    def test_clean_static_info(self, clean_static_info):
        score, findings = _score_call_graph(clean_static_info)
        assert score == 0

    def test_excessive_depth(self):
        info = {"call_graph": {"max_depth": 25}}
        score, findings = _score_call_graph(info)
        assert score == 5

    def test_exfil_chains(self):
        info = {
            "exfiltration_chains": [
                {"source": "a", "sink": "b", "chain_length": 3},
                {"source": "c", "sink": "d", "chain_length": 5},
            ]
        }
        score, findings = _score_call_graph(info)
        assert score == 10  # 2 * 5

    def test_no_ui_reachable(self):
        info = {
            "no_ui_reachable": [{"entry_point": "onReceive", "reachable_methods": 3}],
            "exfiltration_chains": [],
            "call_graph": {},
        }
        score, findings = _score_call_graph(info)
        assert score == 4  # 1 * 4

    def test_capped_at_20(self):
        info = {
            "call_graph": {"max_depth": 30},
            "exfiltration_chains": [{"s": "a", "t": "b"}] * 10,
            "no_ui_reachable": [{"entry_point": "x"}] * 10,
        }
        score, findings = _score_call_graph(info)
        assert score == 20


# ===== _score_similarity ===================================================

class TestScoreSimilarity:
    def test_no_matches(self, clean_static_info):
        score, findings = _score_similarity(clean_static_info)
        assert score == 0

    def test_high_score(self):
        info = {"similarity_matches": [
            {"known_package": "com.malware", "combined_score": 95, "known_label": "malicious"}
        ]}
        score, findings = _score_similarity(info)
        assert score == 20

    def test_medium_score(self):
        info = {"similarity_matches": [
            {"known_package": "com.malware", "combined_score": 75, "known_label": "suspicious"}
        ]}
        score, findings = _score_similarity(info)
        assert score == 15

    def test_low_score(self):
        info = {"similarity_matches": [
            {"known_package": "com.malware", "combined_score": 50, "known_label": "unknown"}
        ]}
        score, findings = _score_similarity(info)
        assert score == 5


# ===== _score_evidence =====================================================

class TestScoreEvidence:
    def test_empty(self):
        score, cats, findings = _score_evidence({})
        assert score == 0

    def test_frida_hits(self, evidence_dynamic):
        score, cats, findings = _score_evidence(evidence_dynamic)
        assert score >= 10  # SMS(10) + CRYPTO(8) = 18 pre-cap ... let's compute
        assert cats  # should have categories

    def test_techniques(self):
        ev = {
            "detected_techniques": [
                {"technique": "Dropper / Two-Stage Payload", "confidence": "HIGH"}
            ]
        }
        score, cats, findings = _score_evidence(ev)
        assert score == 20  # Dropper HIGH = 20

    def test_capped_at_30(self):
        ev = {
            "frida_hits": [
                {"detail": "DEXLOAD"} for _ in range(10)
            ],
            "detected_techniques": [
                {"technique": "Dropper / Two-Stage Payload", "confidence": "HIGH"}
            ],
        }
        score, cats, findings = _score_evidence(ev)
        assert score <= 30


# ===== _score_native =======================================================

class TestScoreNative:
    def test_no_native(self, clean_static_info):
        score, findings = _score_native(clean_static_info)
        assert score == 0

    def test_suspicious_native(self):
        info = {
            "native_analysis": {
                "suspicious_findings": [
                    {"category": "shell_exec", "symbol": "system"},
                    {"category": "anti_debug", "symbol": "ptrace"},
                ],
                "high_entropy_sections": [],
                "jni_functions": [],
            }
        }
        score, findings = _score_native(info)
        assert score == 15  # shell_exec(7) + anti_debug(8)

    def test_high_entropy(self):
        info = {
            "native_analysis": {
                "suspicious_findings": [],
                "high_entropy_sections": [{"name": ".packed", "entropy": 7.9}],
                "jni_functions": [],
            }
        }
        score, findings = _score_native(info)
        assert score == 6

    def test_capped_at_25(self):
        info = {
            "native_analysis": {
                "suspicious_findings": [
                    {"category": "shell_exec", "symbol": "a"},
                    {"category": "anti_debug", "symbol": "b"},
                    {"category": "anti_vm", "symbol": "c"},
                    {"category": "dynamic_loading", "symbol": "d"},
                ],
                "high_entropy_sections": [{"name": ".x"} for _ in range(5)],
            }
        }
        score, findings = _score_native(info)
        assert score == 25


# ===== _score_trackers =====================================================

class TestScoreTrackers:
    def test_no_trackers(self, clean_static_info):
        score, findings = _score_trackers(clean_static_info)
        assert score == 0

    def test_with_trackers(self):
        info = {
            "tracker_detection": {
                "trackers": [
                    {"name": "GoogleAnalytics", "categories": ["Analytics"], "risk_score": 4},
                ]
            }
        }
        score, findings = _score_trackers(info)
        assert score == 4

    def test_high_risk_bonus(self):
        info = {
            "tracker_detection": {
                "trackers": [
                    {"name": f"T{i}", "categories": ["Advertisement"], "risk_score": 8}
                    for i in range(5)
                ]
            }
        }
        score, findings = _score_trackers(info)
        assert score >= 8 + 5 + 5  # first 4 from risk scores, bonus +5


# ===== _score_pcap =========================================================

class TestScorePcap:
    def test_no_pcap(self):
        score, findings = _score_pcap({})
        assert score == 0

    def test_malicious_findings(self, evidence_dynamic):
        score, findings = _score_pcap(evidence_dynamic)
        assert score > 0
        assert any("evil.com" in f for f in findings)
        assert score <= 20

    def test_large_data_volume(self, evidence_dynamic):
        score, findings = _score_pcap(evidence_dynamic)
        assert any("Large data" in f for f in findings)

    def test_capped_at_20(self):
        ev = {
            "pcap_analysis": {
                "findings": [
                    {"type": "known_malicious_domain", "severity": "HIGH", "detail": "x"}
                    for _ in range(10)
                ],
                "data_volume": [
                    {"destination": "x", "bytes_recv": 2_000_000} for _ in range(5)
                ],
            }
        }
        score, findings = _score_pcap(ev)
        assert score == 20


# ===== _score_yara =========================================================

class TestScoreYara:
    def test_no_matches(self, clean_static_info):
        score, findings = _score_yara(clean_static_info)
        assert score == 0

    def test_yara_matches(self):
        info = {
            "yara_matches": [
                {
                    "rule": "test_rule",
                    "meta": {"severity": 5, "category": "ransomware"},
                    "matches": [],
                    "source": "dex",
                    "rule_file": "test.yar",
                }
            ]
        }
        score, findings = _score_yara(info)
        # sev5=15 + ransomware category bonus=5 = 20, then total>=20 triggers +5 = 25
        assert score == 25
        assert "test_rule" in findings[0]

    def test_multiple_rules(self, malicious_static_info):
        score, findings = _score_yara(malicious_static_info)
        assert score >= 10  # sev4=10 + sms_stealer bonus=4 = 14


# ===== _score_signature ====================================================

class TestScoreSignature:
    def test_no_flags(self, clean_static_info):
        score, findings = _score_signature(clean_static_info)
        assert score == 0

    def test_unsigned(self):
        info = {"signature_verification": {"flags": ["unsigned"]}}
        score, findings = _score_signature(info)
        assert score == 18  # unsigned(15) + cap bonus(3)

    def test_multiple_flags(self, malicious_static_info):
        score, findings = _score_signature(malicious_static_info)
        # self_signed(5) + weak_hash(8) = 13, total>=10 → +3 = 16
        assert score == 16

    def test_expired(self):
        info = {"signature_verification": {"flags": ["expired_certificate", "no_v2_v3_signing"]}}
        score, findings = _score_signature(info)
        assert score == 16  # expired(10) + no_v2v3(3) + cap bonus(3)


# ===== _score_obfuscation ==================================================

class TestScoreObfuscation:
    def test_no_heuristics(self, clean_static_info):
        score, findings = _score_obfuscation(clean_static_info)
        assert score == 0

    def test_moderate_obfuscation(self, malicious_static_info):
        score, findings = _score_obfuscation(malicious_static_info)
        assert score > 0

    def test_heavy_packed(self):
        info = {
            "obfuscation_heuristics": {
                "reflection_ratio": 0.45, "reflection_callers": 120,
                "string_encryption_weight": 12, "encryption_api_callers": 8,
                "dynamic_loading_callers": 4,
                "dex_entropy": 7.8,
                "dead_code_ratio": 0.70, "dead_code_count": 500,
            }
        }
        score, findings = _score_obfuscation(info)
        assert score == 25  # all HIGH (5*8=40) + combo(5) = 45, capped at 25

    def test_empty_heuristics(self):
        score, findings = _score_obfuscation({})
        assert score == 0


# ===== calculate_risk (integration) ========================================

class TestCalculateRisk:
    def test_clean_apk(self, clean_static_info):
        result = calculate_risk(clean_static_info)
        assert result["risk_score"] <= 20
        assert result["severity"] in ("CLEAN", "LOW")
        assert result["confidence"] == "HIGH"
        assert isinstance(result["key_findings"], list)
        assert isinstance(result["recommendations"], list)

    def test_malicious_apk(self, malicious_static_info):
        result = calculate_risk(malicious_static_info)
        assert result["risk_score"] >= 40
        assert result["severity"] in ("MEDIUM", "HIGH", "CRITICAL")
        assert len(result["key_findings"]) > 0

    def test_malicious_with_evidence(self, malicious_static_info, evidence_dynamic):
        result = calculate_risk(malicious_static_info, evidence_dynamic)
        assert result["risk_score"] >= 50
        assert result["severity"] in ("HIGH", "CRITICAL")

    def test_score_range(self, malicious_static_info, evidence_dynamic):
        result = calculate_risk(malicious_static_info, evidence_dynamic)
        assert 0 <= result["risk_score"] <= 100

    def test_verdict_consistency(self, malicious_static_info):
        result = calculate_risk(malicious_static_info)
        verdict = _verdict(result["severity"])
        if result["risk_score"] >= 41:
            assert verdict == "DO_NOT_INSTALL"
