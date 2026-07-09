"""Deterministic risk scoring engine.

Calculates an APK risk score from static analysis + dynamic evidence.
Runs before the AI agent so the verdict is never empty or purely LLM-dependent.
"""

from __future__ import annotations

_PERM_CRITICAL: dict[str, int] = {
    "android.permission.BIND_DEVICE_ADMIN": 12,
    "android.permission.BIND_ACCESSIBILITY_SERVICE": 10,
}

_PERM_HIGH: dict[str, int] = {
    "android.permission.READ_SMS": 8,
    "android.permission.RECEIVE_SMS": 8,
    "android.permission.READ_CONTACTS": 7,
    "android.permission.READ_PHONE_STATE": 7,
    "android.permission.ACCESS_FINE_LOCATION": 7,
    "android.permission.RECORD_AUDIO": 7,
    "android.permission.CAMERA": 7,
    "android.permission.PROCESS_OUTGOING_CALLS": 7,
    "android.permission.BIND_NOTIFICATION_LISTENER_SERVICE": 7,
    "android.permission.READ_MEDIA_IMAGES": 5,
    "android.permission.READ_MEDIA_VIDEO": 5,
    "android.permission.READ_MEDIA_AUDIO": 5,
}

_PERM_MEDIUM: dict[str, int] = {
    "android.permission.SEND_SMS": 6,
    "android.permission.ACCESS_COARSE_LOCATION": 5,
    "android.permission.WRITE_EXTERNAL_STORAGE": 5,
    "android.permission.READ_EXTERNAL_STORAGE": 5,
    "android.permission.REQUEST_INSTALL_PACKAGES": 6,
    "android.permission.REQUEST_DELETE_PACKAGES": 5,
}

_PERM_LOW: dict[str, int] = {
    "android.permission.INTERNET": 2,
    "android.permission.RECEIVE_BOOT_COMPLETED": 4,
    "android.permission.QUERY_ALL_PACKAGES": 3,
    "android.permission.SYSTEM_ALERT_WINDOW": 4,
    "android.permission.REQUEST_IGNORE_BATTERY_OPTIMIZATIONS": 3,
}

_PERM_ALL: dict[str, int] = {**_PERM_CRITICAL, **_PERM_HIGH, **_PERM_MEDIUM, **_PERM_LOW}

_API_CATEGORY_BASE: dict[str, int] = {
    "data_theft": 8,
    "sms_intercept": 10,
    "crypto": 6,
    "shell_exec": 7,
    "network": 4,
    "ransomware": 15,
    "persistence": 5,
}

_STRING_API_WEIGHTS: dict[str, int] = {
    "su ": 6,
    "/system/bin/sh": 6,
    "BIND_DEVICE_ADMIN": 10,
    "RECEIVE_BOOT_COMPLETED": 4,
    "PACKAGE_REPLACED": 3,
    "RECEIVE_SMS": 5,
    "READ_SMS": 5,
    "getAllContacts": 5,
}

_COMBO_BONUSES: list[tuple[set[str], int, str]] = [
    ({"data_theft", "crypto"}, 15, "Data theft combined with encryption"),
    ({"data_theft", "network"}, 10, "Data theft with network capability"),
    ({"data_theft", "sms_intercept"}, 12, "Device info theft with SMS interception"),
    ({"sms_intercept", "crypto"}, 10, "SMS interception with encryption"),
    ({"shell_exec", "crypto"}, 10, "Shell execution with encryption"),
    ({"ransomware", "persistence"}, 8, "Ransomware with persistence"),
    ({"data_theft", "persistence"}, 6, "Persistent data theft capability"),
    ({"shell_exec", "network"}, 6, "Shell execution with network capability"),
]

_API_PAIR_BONUSES: list[tuple[set[str], int, str]] = [
    ({"getDeviceId", "sendTextMessage"}, 15, "Device ID exfiltrated via SMS"),
    ({"getImei", "sendTextMessage"}, 15, "IMEI exfiltrated via SMS"),
    ({"getLastKnownLocation", "HttpURLConnection"}, 10, "Location sent over HTTP"),
    ({"getLastKnownLocation", "OkHttpClient"}, 10, "Location sent via OkHttp"),
    ({"Runtime.exec", "Cipher"}, 10, "Encrypted process execution"),
    ({"lockNow", "wipeData"}, 20, "Remote wipe capability"),
    ({"lockNow", "RECEIVE_BOOT_COMPLETED"}, 10, "Ransomware with boot persistence"),
    ({"Cipher", "HttpURLConnection"}, 8, "Encrypted network communication"),
    ({"Cipher", "OkHttpClient"}, 8, "Encrypted network communication"),
]

_FRIDA_PREFIX_SCORES: dict[str, int] = {
    "SMS": 10,
    "CRYPTO": 8,
    "NET": 5,
    "DEXLOAD": 15,
    "FILE": 5,
    "PROCESS": 7,
    "LOCATION": 8,
    "ACCESSIBILITY": 10,
    "NOTIFICATION": 5,
    "DEVICE_ADMIN": 12,
    "REFLECTION": 7,
    "DYNAMIC": 10,
    "TIMER": 2,
}

_TRACKER_CATEGORY_RISK: dict[str, int] = {
    "Crash reporting": 2,
    "Analytics": 4,
    "Identification": 6,
    "Advertisement": 8,
    "Location": 10,
    "Profiling": 10,
}

_NATIVE_CATEGORY_SCORES: dict[str, int] = {
    "anti_debug": 8,
    "anti_vm": 7,
    "dynamic_loading": 6,
    "network": 5,
    "shell_exec": 7,
    "process_control": 4,
    "memory_manipulation": 5,
    "file_access": 3,
}

_TECHNIQUE_SCORES: dict[str, dict[str, int]] = {
    "Delayed Execution": {"HIGH": 10, "MEDIUM": 6},
    "Dropper / Two-Stage Payload": {"HIGH": 20, "MEDIUM": 12},
    "Dropper / Two-Stage": {"HIGH": 20, "MEDIUM": 12},
    "Payload Download": {"HIGH": 12, "MEDIUM": 8},
}


def _severity(score: int) -> str:
    if score >= 81:
        return "CRITICAL"
    if score >= 61:
        return "HIGH"
    if score >= 41:
        return "MEDIUM"
    if score >= 21:
        return "LOW"
    return "CLEAN"


def _score_permissions(all_perms: list[str]) -> tuple[int, list[str]]:
    findings: list[str] = []
    total = 0
    for p in all_perms:
        w = _PERM_ALL.get(p, 0)
        if w:
            total += w
            findings.append(f"Permission: {p.split('.')[-1]} (+{w})")
    return min(total, 40), findings


def _score_apis(api_details: list[dict]) -> tuple[int, set[str], list[str]]:
    findings: list[str] = []
    total = 0
    categories: set[str] = set()
    apis: set[str] = set()

    for d in api_details:
        label = d["api"]
        cat = d.get("category", "")
        if cat in _API_CATEGORY_BASE:
            bonus = d.get("total_callers", 1)
            points = _API_CATEGORY_BASE[cat] + min(bonus - 1, 3)
            total += points
            categories.add(cat)
            apis.add(label)
            findings.append(f"API: {label} ({cat}, +{points})")
        else:
            w = _STRING_API_WEIGHTS.get(label, 0)
            if w:
                total += w
                apis.add(label)
                findings.append(f"API: {label} (string, +{w})")

    # Category combo bonuses
    for needed, bonus, desc in _COMBO_BONUSES:
        if needed.issubset(categories):
            total += bonus
            findings.append(f"Combo: {desc} (+{bonus})")

    # Specific API pair bonuses
    for needed, bonus, desc in _API_PAIR_BONUSES:
        if needed.issubset(apis):
            total += bonus
            findings.append(f"Pair: {desc} (+{bonus})")

    return min(total, 50), categories, findings


def _score_urls_ips(urls: list, ips: list) -> tuple[int, list[str]]:
    findings: list[str] = []
    total = min(len(urls), 5) * 2 + min(len(ips), 5) * 2
    if urls:
        findings.append(f"URLs: {len(urls)} embedded URLs (+{min(len(urls), 5) * 2})")
    if ips:
        findings.append(f"IPs: {len(ips)} embedded IPs (+{min(len(ips), 5) * 2})")
    return min(total, 10), findings


def _score_evidence(evidence: dict) -> tuple[int, list[str], list[str]]:
    findings: list[str] = []
    categories: set[str] = set()
    total = 0

    frida_hits = evidence.get("frida_hits", []) or []
    for h in frida_hits:
        detail = h.get("detail", "") if isinstance(h, dict) else str(h)
        for prefix, score in _FRIDA_PREFIX_SCORES.items():
            if detail.upper().startswith(prefix):
                total += score
                findings.append(f"Frida: {detail[:60]} (+{score})")
                categories.add(f"frida_{prefix.lower()}")
                break
    total = min(total, 30)

    techniques = evidence.get("detected_techniques", []) or []
    for t in techniques:
        name = t.get("technique", "")
        conf = t.get("confidence", "MEDIUM")
        tscores = _TECHNIQUE_SCORES.get(name, {})
        points = tscores.get(conf, tscores.get("MEDIUM", 5))
        total += points
        findings.append(f"Technique: {name} ({conf}, +{points})")
        categories.add(f"tech_{name.lower().replace(' ', '_')}")

    return min(total, 30), list(categories), findings


def _score_call_graph(static_info: dict) -> tuple[int, list[str]]:
    findings: list[str] = []
    total = 0

    cg = static_info.get("call_graph", {}) or {}
    max_depth = cg.get("max_depth", 0)
    if max_depth > 20:
        total += 5
        findings.append(f"Excessive call depth ({max_depth}) (+5)")
    elif max_depth > 10:
        total += 3
        findings.append(f"Deep call chains ({max_depth}) (+3)")

    chains = static_info.get("exfiltration_chains", []) or []
    if chains:
        pts = min(len(chains) * 5, 15)
        total += pts
        findings.append(f"Data exfiltration chain{'s' if len(chains) > 1 else ''} ({len(chains)}) (+{pts})")

    no_ui = static_info.get("no_ui_reachable", []) or []
    if no_ui:
        pts = min(len(no_ui) * 4, 12)
        total += pts
        findings.append(f"Dangerous API reachable without user interaction ({len(no_ui)}) (+{pts})")

    return min(total, 20), findings


def _score_similarity(static_info: dict) -> tuple[int, list[str]]:
    """Score based on code-similarity matches against known malware."""
    findings: list[str] = []
    matches = static_info.get("similarity_matches", []) or []
    if not matches:
        return 0, findings

    best = matches[0]
    score = best.get("combined_score", 0)
    label = best.get("known_label", "unknown")
    known_pkg = best.get("known_package", "?")

    if score >= 90:
        pts = 20
    elif score >= 75:
        pts = 15
    elif score >= 60:
        pts = 10
    else:
        pts = 5

    findings.append(
        f"Code similarity: {score}% match with {known_pkg} "
        f"(label: {label}) (+{pts})"
    )
    return pts, findings


def _score_native(static_info: dict) -> tuple[int, list[str]]:
    findings: list[str] = []
    total = 0

    native = static_info.get("native_analysis", {}) or {}
    suspicious = native.get("suspicious_findings", []) or []

    # Score unique suspicious categories found in native libs
    seen_cats: set[str] = set()
    for f in suspicious:
        cat = f.get("category", "")
        if cat in seen_cats or cat not in _NATIVE_CATEGORY_SCORES:
            continue
        seen_cats.add(cat)
        pts = _NATIVE_CATEGORY_SCORES[cat]
        total += pts
        findings.append(f"Native: {cat} (+{pts})")

    # Check for beaconing combo: socket + connect symbols
    all_symbols = [f["symbol"].lower() for f in suspicious if "symbol" in f]
    if "socket" in all_symbols and "connect" in all_symbols:
        total += 5
        findings.append("Native: socket+connect beaconing combo (+5)")

    # Check for anti-analysis combo: open + /proc/self/maps
    all_strings = [f.get("string", "") for f in suspicious if "string" in f]
    has_proc_maps = any("/proc/self/maps" in s for s in all_strings)
    has_open = "open" in all_symbols
    if has_open and has_proc_maps:
        total += 5
        findings.append("Native: open()+read(/proc/self/maps) anti-analysis (+5)")

    # Score high-entropy sections (packed payload)
    high_entropy = native.get("high_entropy_sections", []) or []
    if high_entropy:
        pts = min(len(high_entropy) * 6, 15)
        total += pts
        findings.append(f"Native: {len(high_entropy)} high-entropy packed section(s) (+{pts})")

    return min(total, 25), findings


_PCAP_FINDING_SCORES: dict[str, int] = {
    "known_malicious_domain": 15,
    "beaconing": 12,
    "suspicious_tld": 5,
    "large_transfer": 6,
    "non_http_protocol": 4,
    "rapid_connections": 3,
}


def _score_pcap(evidence: dict) -> tuple[int, list[str]]:
    findings: list[str] = []
    total = 0

    pcap = evidence.get("pcap_analysis", {}) or {}
    pcap_findings = pcap.get("findings", []) or []

    for f in pcap_findings:
        ftype = f.get("type", "")
        severity = f.get("severity", "LOW")
        base = _PCAP_FINDING_SCORES.get(ftype, 2)
        points = int(base * 1.5) if severity == "HIGH" else base
        total += points
        findings.append(f"PCAP: {f.get('detail', '')[:80]} (+{points})")

    data_volume = pcap.get("data_volume", []) or []
    for dv in data_volume:
        recv = dv.get("bytes_recv", 0)
        if recv > 1024 * 1024:
            total += 8
            findings.append(
                f"PCAP: Large data received from {dv['destination']} "
                f"({recv / 1024:.0f} KB) (+8)"
            )
            break

    dns_queries = pcap.get("dns_queries", []) or []
    unique_domains = len({q["domain"] for q in dns_queries if "domain" in q})
    if unique_domains > 20:
        total += 4
        findings.append(f"PCAP: {unique_domains} unique DNS queries — broad domain reach (+4)")

    return min(total, 20), findings


_YARA_SEVERITY_SCORES = {
    5: 15,
    4: 10,
    3: 6,
    2: 3,
    1: 1,
}

_YARA_CATEGORY_BONUS = {
    "ransomware": 5,
    "banking_trojan": 5,
    "exploit": 4,
    "dropper": 3,
    "spyware": 3,
    "sms_stealer": 4,
    "phishing": 2,
    "data_theft": 2,
}


_SIGNATURE_FLAG_SCORES: dict[str, int] = {
    "unsigned": 15,
    "weak_hash_algorithm": 8,
    "expired_certificate": 10,
    "certificate_not_yet_valid": 5,
    "self_signed": 5,
    "unknown_signer": 3,
    "tampered_duplicate_ids": 10,
    "no_v2_v3_signing": 3,
    "debug_signer": 2,
}


_OBFUSCATION_THRESHOLDS = {
    "reflection_ratio": {"HIGH": 0.30, "MEDIUM": 0.15, "LOW": 0.05},
    "string_encryption_weight": {"HIGH": 10, "MEDIUM": 5, "LOW": 3},
    "dynamic_loading_callers": {"HIGH": 3, "MEDIUM": 2, "LOW": 1},
    "dex_entropy": {"HIGH": 7.5, "MEDIUM": 6.5, "LOW": 5.5},
    "dead_code_ratio": {"HIGH": 0.60, "MEDIUM": 0.35, "LOW": 0.15},
}

_OBFUSCATION_SCORES = {
    "HIGH": 8,
    "MEDIUM": 4,
    "LOW": 2,
}


def _score_obfuscation(static_info: dict) -> tuple[int, list[str]]:
    findings: list[str] = []
    heuristics = static_info.get("obfuscation_heuristics", {}) or {}
    if not heuristics:
        return 0, findings

    total = 0
    severity_count: dict[str, int] = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
    details: list[str] = []

    # Reflection ratio
    rr = heuristics.get("reflection_ratio", 0)
    rc = heuristics.get("reflection_callers", 0)
    if rr >= _OBFUSCATION_THRESHOLDS["reflection_ratio"]["HIGH"]:
        sever = "HIGH"
    elif rr >= _OBFUSCATION_THRESHOLDS["reflection_ratio"]["MEDIUM"]:
        sever = "MEDIUM"
    elif rr >= _OBFUSCATION_THRESHOLDS["reflection_ratio"]["LOW"]:
        sever = "LOW"
    else:
        sever = None
    if sever:
        pts = _OBFUSCATION_SCORES[sever]
        total += pts
        severity_count[sever] += 1
        details.append(
            f"Obfuscation: reflection ratio {rr:.1%} ({rc} callers) [{sever}] (+{pts})"
        )

    # String encryption
    sew = heuristics.get("string_encryption_weight", 0)
    if sew >= _OBFUSCATION_THRESHOLDS["string_encryption_weight"]["HIGH"]:
        sever = "HIGH"
    elif sew >= _OBFUSCATION_THRESHOLDS["string_encryption_weight"]["MEDIUM"]:
        sever = "MEDIUM"
    elif sew >= _OBFUSCATION_THRESHOLDS["string_encryption_weight"]["LOW"]:
        sever = "LOW"
    else:
        sever = None
    if sever:
        pts = _OBFUSCATION_SCORES[sever]
        total += pts
        severity_count[sever] += 1
        ec = heuristics.get("encryption_api_callers", 0)
        details.append(
            f"Obfuscation: string encryption weight {sew} "
            f"({ec} base64/cipher callers) [{sever}] (+{pts})"
        )

    # Dynamic loading
    dl = heuristics.get("dynamic_loading_callers", 0)
    if dl >= _OBFUSCATION_THRESHOLDS["dynamic_loading_callers"]["HIGH"]:
        sever = "HIGH"
    elif dl >= _OBFUSCATION_THRESHOLDS["dynamic_loading_callers"]["MEDIUM"]:
        sever = "MEDIUM"
    elif dl >= _OBFUSCATION_THRESHOLDS["dynamic_loading_callers"]["LOW"]:
        sever = "LOW"
    else:
        sever = None
    if sever:
        pts = _OBFUSCATION_SCORES[sever]
        total += pts
        severity_count[sever] += 1
        details.append(
            f"Obfuscation: {dl} dynamic loader(s) [{sever}] (+{pts})"
        )

    # DEX entropy
    de = heuristics.get("dex_entropy", 0)
    if de >= _OBFUSCATION_THRESHOLDS["dex_entropy"]["HIGH"]:
        sever = "HIGH"
    elif de >= _OBFUSCATION_THRESHOLDS["dex_entropy"]["MEDIUM"]:
        sever = "MEDIUM"
    elif de >= _OBFUSCATION_THRESHOLDS["dex_entropy"]["LOW"]:
        sever = "LOW"
    else:
        sever = None
    if sever:
        pts = _OBFUSCATION_SCORES[sever]
        total += pts
        severity_count[sever] += 1
        extra = " — packed/encrypted DEX" if de >= 7.5 else ""
        details.append(
            f"Obfuscation: DEX entropy {de}{extra} [{sever}] (+{pts})"
        )

    # Dead code ratio
    dc = heuristics.get("dead_code_ratio", 0)
    dc_count = heuristics.get("dead_code_count", 0)
    if dc >= _OBFUSCATION_THRESHOLDS["dead_code_ratio"]["HIGH"]:
        sever = "HIGH"
    elif dc >= _OBFUSCATION_THRESHOLDS["dead_code_ratio"]["MEDIUM"]:
        sever = "MEDIUM"
    elif dc >= _OBFUSCATION_THRESHOLDS["dead_code_ratio"]["LOW"]:
        sever = "LOW"
    else:
        sever = None
    if sever:
        pts = _OBFUSCATION_SCORES[sever]
        total += pts
        severity_count[sever] += 1
        details.append(
            f"Obfuscation: dead code ratio {dc:.1%} ({dc_count} methods) [{sever}] (+{pts})"
        )

    # Combo bonus: packed APKs hit multiple heuristics simultaneously
    if severity_count.get("HIGH", 0) >= 3:
        total += 5
        details.append(
            f"Obfuscation: {severity_count['HIGH']} high-severity indicators — "
            f"heavy packing/obfuscation (+5)"
        )
    elif severity_count.get("HIGH", 0) >= 1 and severity_count.get("MEDIUM", 0) >= 2:
        total += 3
        details.append("Obfuscation: mixed high/medium obfuscation indicators (+3)")

    findings.extend(details)
    return min(total, 25), findings


def _score_signature(static_info: dict) -> tuple[int, list[str]]:
    findings: list[str] = []
    sig_info = static_info.get("signature_verification", {}) or {}
    if not sig_info:
        return 0, findings

    flags = sig_info.get("flags", []) or []
    total = sum(_SIGNATURE_FLAG_SCORES.get(f, 0) for f in set(flags))

    if flags:
        for f in sorted(set(flags)):
            pts = _SIGNATURE_FLAG_SCORES.get(f, 0)
            if pts:
                label = f.replace("_", " ").title()
                findings.append(f"Signature: {label} (+{pts})")

    if total >= 10:
        findings.append(
            f"Signature: APK signing is compromised or untrusted (+3)"
        )
        total += 3

    return min(total, 30), findings


def _score_yara(static_info: dict) -> tuple[int, list[str]]:
    findings: list[str] = []
    matches = static_info.get("yara_matches", []) or []
    if not matches:
        return 0, findings

    seen_rules: set[str] = set()
    seen_categories: dict[str, int] = {}
    total = 0

    for m in matches:
        rule_name = m.get("rule", "")
        if rule_name in seen_rules:
            continue
        seen_rules.add(rule_name)

        meta = m.get("meta", {})
        sev = int(meta.get("severity", 2))
        cat = meta.get("category", "unknown")

        score = _YARA_SEVERITY_SCORES.get(sev, 2)
        total += score
        seen_categories[cat] = seen_categories.get(cat, 0) + 1
        findings.append(
            f"YARA: {rule_name} (severity={sev}) "
            f"[{cat}] (+{score})"
        )

    for cat, count in seen_categories.items():
        bonus = _YARA_CATEGORY_BONUS.get(cat, 0)
        if bonus and count >= 1:
            total += bonus
            findings.append(
                f"YARA category: {cat} ({count} rule(s)) (+{bonus})"
            )

    if total >= 20:
        findings.append(
            f"YARA: {len(seen_rules)} signature matches — "
            f"strong malicious indicator (+5)"
        )
        total += 5

    return min(total, 35), findings


def _score_trackers(static_info: dict) -> tuple[int, list[str]]:
    findings: list[str] = []
    total = 0

    td = static_info.get("tracker_detection", {}) or {}
    trackers = td.get("trackers", []) or []
    if not trackers:
        return 0, findings

    seen_cats: set[str] = set()
    high_risk_count = 0

    for t in trackers:
        name = t.get("name", "?")
        risk = t.get("risk_score", 4)
        cats = t.get("categories", [])
        if not cats:
            cats = ["Unknown"]

        label = ", ".join(cats)
        is_new_category = any(c not in seen_cats for c in cats)

        if is_new_category:
            total += risk
            seen_cats.update(cats)
            findings.append(f"Tracker: {name} ({label}, +{risk})")
        else:
            total += max(risk // 2, 1)
            findings.append(f"Tracker: {name} ({label}, +{max(risk // 2, 1)})")

        if any(c in ("Advertisement", "Location", "Profiling") for c in cats):
            high_risk_count += 1

    if high_risk_count >= 5:
        total += 5
        findings.append(f"Tracker: {high_risk_count} high-risk trackers — systematic tracking (+5)")

    return min(total, 20), findings


def calculate_risk(static_info: dict, evidence: dict | None = None) -> dict:
    all_perms = static_info.get("all_permissions", []) or []
    api_details = static_info.get("api_details", []) or []
    urls = static_info.get("urls", []) or []
    ips = static_info.get("ips", []) or []
    evidence = evidence or {}

    all_findings: list[str] = []
    total = 0

    p_score, p_findings = _score_permissions(all_perms)
    total += p_score
    all_findings.extend(p_findings)

    a_score, categories, a_findings = _score_apis(api_details)
    total += a_score
    all_findings.extend(a_findings)

    u_score, u_findings = _score_urls_ips(urls, ips)
    total += u_score
    all_findings.extend(u_findings)

    e_score, e_cats, e_findings = _score_evidence(evidence)
    total += e_score
    all_findings.extend(e_findings)

    cg_score, cg_findings = _score_call_graph(static_info)
    total += cg_score
    all_findings.extend(cg_findings)

    sim_score, sim_findings = _score_similarity(static_info)
    total += sim_score
    all_findings.extend(sim_findings)

    n_score, n_findings = _score_native(static_info)
    total += n_score
    all_findings.extend(n_findings)

    t_score, t_findings = _score_trackers(static_info)
    total += t_score
    all_findings.extend(t_findings)

    y_score, y_findings = _score_yara(static_info)
    total += y_score
    all_findings.extend(y_findings)

    sg_score, sg_findings = _score_signature(static_info)
    total += sg_score
    all_findings.extend(sg_findings)

    ob_score, ob_findings = _score_obfuscation(static_info)
    total += ob_score
    all_findings.extend(ob_findings)

    pc_score, pc_findings = _score_pcap(evidence)
    total += pc_score
    all_findings.extend(pc_findings)

    total = min(total, 100)
    sev = _severity(total)

    findings = all_findings[:15]
    recommendations = _recommendations(sev, categories, evidence, static_info)

    return {
        "risk_score": total,
        "severity": sev,
        "confidence": "HIGH",
        "key_findings": findings,
        "recommendations": recommendations,
    }


def _recommendations(
    severity: str,
    categories: set[str],
    evidence: dict,
    static_info: dict | None = None,
) -> list[str]:
    base = {
        "CLEAN": ["No significant risk indicators detected."],
        "LOW": ["Review suspicious API usage in context.", "Check if embedded URLs belong to known services."],
        "MEDIUM": [
            "Investigate data-theft related APIs and permission usage.",
            "Review network destinations for C2 indicators.",
            "Check for obfuscation or reflection patterns.",
        ],
        "HIGH": [
            "Immediate review required — multiple high-risk indicators present.",
            "Analyze shell execution and encryption usage in context.",
            "Cross-reference embedded IPs with threat intelligence feeds.",
        ],
        "CRITICAL": [
            "CRITICAL — Do not install on any device.",
            "Ransomware or device-administration abuse indicators detected.",
            "Data exfiltration via SMS/network likely — escalate to incident response.",
        ],
    }.get(severity, ["Review APK for suspicious behavior."])

    techniques = evidence.get("detected_techniques", []) or []
    for t in techniques:
        name = t.get("technique", "")
        if "Dropper" in name:
            base.append("Dynamic code loading detected — run in sandbox for deeper analysis.")
        if "Delayed" in name:
            base.append("App uses time-based evasion — extend monitoring window.")

    # YARA-based recommendations
    if static_info:
        yara_matches = static_info.get("yara_matches", []) or []
        yara_categories = set()
        for m in yara_matches:
            cat = m.get("meta", {}).get("category", "")
            if cat:
                yara_categories.add(cat.lower())
        if "ransomware" in yara_categories:
            base.append("YARA: Ransomware signatures matched — do not install.")
        if "banking_trojan" in yara_categories:
            base.append("YARA: Banking trojan patterns detected — credential theft likely.")
        if "exploit" in yara_categories:
            base.append("YARA: Root/exploit payload signatures matched.")
        if "dropper" in yara_categories:
            base.append("YARA: Dynamic loading/dropper signatures — payload likely embedded.")

    return base[:5]
