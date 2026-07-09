import pytest


# ---------------------------------------------------------------------------
# Sample static_info dicts used across multiple test modules
# ---------------------------------------------------------------------------

@pytest.fixture
def clean_static_info():
    return {
        "all_permissions": ["android.permission.INTERNET"],
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
    }


@pytest.fixture
def malicious_static_info():
    return {
        "all_permissions": [
            "android.permission.BIND_DEVICE_ADMIN",
            "android.permission.READ_SMS",
            "android.permission.SEND_SMS",
            "android.permission.RECEIVE_SMS",
            "android.permission.INTERNET",
        ],
        "api_details": [
            {"api": "getDeviceId", "category": "data_theft", "total_callers": 3},
            {"api": "sendTextMessage", "category": "sms_intercept", "total_callers": 2},
            {"api": "Cipher", "category": "crypto", "total_callers": 1},
            {"api": "Runtime.exec", "category": "shell_exec", "total_callers": 2},
        ],
        "urls": [
            {"url": "https://evil.com/payload", "methods": []},
            {"url": "https://malware.example/c2", "methods": []},
            {"url": "https://steal.data/exfil", "methods": []},
        ],
        "ips": [
            {"ip": "10.0.0.1", "methods": []},
            {"ip": "192.168.1.1", "methods": []},
        ],
        "receivers": ["com.evil.SmsReceiver"],
        "services": ["com.evil.DataService"],
        "native_libs": ["lib/armeabi-v7a/libnative.so"],
        "native_analysis": {
            "suspicious_findings": [
                {"category": "shell_exec", "symbol": "system"},
                {"category": "anti_debug", "symbol": "ptrace"},
            ],
            "high_entropy_sections": [{"name": ".packed", "entropy": 7.8}],
            "jni_functions": ["Java_com_evil_native_check"],
        },
        "tracker_detection": {
            "trackers": [
                {"name": "GoogleAnalytics", "categories": ["Analytics"], "risk_score": 4},
                {"name": "Mixpanel", "categories": ["Analytics"], "risk_score": 4},
            ]
        },
        "call_graph": {"node_count": 100, "edge_count": 350, "max_depth": 15},
        "exfiltration_chains": [
            {"source": "Main.getDeviceId", "sink": "sendTextMessage", "chain_length": 3},
            {"source": "Main.getLastKnownLocation", "sink": "openConnection", "chain_length": 5},
        ],
        "no_ui_reachable": [{"entry_point": "onReceive", "reachable_methods": 3}],
        "similarity_matches": [
            {"known_package": "com.malware.known", "combined_score": 92, "known_label": "malicious"}
        ],
        "yara_matches": [
            {
                "rule": "android_sms_interceptor",
                "tags": [],
                "meta": {"severity": 4, "category": "sms_stealer"},
                "matches": [],
                "source": "dex",
                "rule_file": "android_malware.yar",
            }
        ],
        "signature_verification": {
            "flags": ["self_signed", "weak_hash_algorithm"],
        },
        "obfuscation_heuristics": {
            "reflection_ratio": 0.12,
            "reflection_callers": 12,
            "string_encryption_weight": 4,
            "encryption_api_callers": 2,
            "dynamic_loading_callers": 1,
            "dex_entropy": 6.2,
            "dead_code_ratio": 0.30,
            "dead_code_count": 30,
        },
    }


@pytest.fixture
def evidence_dynamic():
    return {
        "frida_hits": [
            {"detail": "SMS sent to 555-0100"},
            {"detail": "CRYPTO Cipher.doFinal observed"},
            {"detail": "DEXLOAD DexClassLoader invoked"},
        ],
        "detected_techniques": [
            {"technique": "Delayed Execution", "confidence": "HIGH"},
        ],
        "pcap_analysis": {
            "findings": [
                {"type": "known_malicious_domain", "severity": "HIGH", "detail": "evil.com"},
                {"type": "beaconing", "severity": "HIGH", "detail": "periodic heartbeat"},
            ],
            "data_volume": [{"destination": "evil.com", "bytes_recv": 2_000_000}],
            "dns_queries": [{"domain": "a.com"}, {"domain": "b.com"}] * 15,
        },
    }
