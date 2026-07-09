import os
from androguard.core.apk import APK
from scanapk_backend.core.dex_scan import scan_dex
from scanapk_backend.core.code_similarity import compute_all_hashes
from scanapk_backend.core.hash_db import init_db as init_hash_db
from scanapk_backend.core.hash_db import search_similar, log_scan, get_known_count
from scanapk_backend.core.yara_scan import scan_apk_artifacts as yara_scan_apk
from scanapk_backend.core.signature_verify import verify_apk_signature

DANGEROUS_PERMISSIONS = {
    "android.permission.READ_SMS",
    "android.permission.RECEIVE_SMS",
    "android.permission.SEND_SMS",
    "android.permission.READ_PHONE_STATE",
    "android.permission.READ_CONTACTS",
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.ACCESS_COARSE_LOCATION",
    "android.permission.RECORD_AUDIO",
    "android.permission.CAMERA",
    "android.permission.WRITE_EXTERNAL_STORAGE",
    "android.permission.READ_EXTERNAL_STORAGE",
    "android.permission.PROCESS_OUTGOING_CALLS",
    "android.permission.BIND_ACCESSIBILITY_SERVICE",
    "android.permission.SYSTEM_ALERT_WINDOW",
    "android.permission.BIND_NOTIFICATION_LISTENER_SERVICE",
    "android.permission.QUERY_ALL_PACKAGES",
    "android.permission.REQUEST_INSTALL_PACKAGES",
    "android.permission.REQUEST_DELETE_PACKAGES",
    "android.permission.RECEIVE_BOOT_COMPLETED",
    "android.permission.BIND_DEVICE_ADMIN",
    "android.permission.READ_MEDIA_IMAGES",
    "android.permission.READ_MEDIA_VIDEO",
    "android.permission.READ_MEDIA_AUDIO",
    "android.permission.INTERNET",
    "android.permission.REQUEST_IGNORE_BATTERY_OPTIMIZATIONS",
}


def scan_apk(apk_path: str, verbose: bool = True) -> dict | None:
    if not os.path.exists(apk_path):
        if verbose:
            print(f"File not found: {apk_path}")
        return None

    if verbose:
        print(f"\nStarting static scan: {os.path.basename(apk_path)}")
        print("-" * 50)

    try:
        a = APK(apk_path)
    except Exception as e:
        if verbose:
            print(f"Error parsing APK: {e}")
        return None

    app_name = a.get_app_name()
    package = a.get_package()
    target_sdk = a.get_target_sdk_version()

    if verbose:
        print(f"App name   : {app_name}")
        print(f"Package    : {package}")
        print(f"Target SDK : {target_sdk}")

    all_perms = a.get_permissions()
    dangerous_found = [p for p in all_perms if p in DANGEROUS_PERMISSIONS]

    if verbose:
        print(f"\nPermissions: {len(all_perms)} total, {len(dangerous_found)} dangerous")
        for p in dangerous_found:
            print(f"  \u26a0  {p}")

    if verbose:
        print("\nRunning DEX analysis...")
    dex_results = scan_dex(apk_path)
    if verbose:
        print(f"  Suspicious APIs  : {len(dex_results['suspicious_apis'])}")
        print(f"  Embedded URLs    : {len(dex_results['urls'])}")
        print(f"  Embedded IPs     : {len(dex_results['ips'])}")
        native_analysis = dex_results.get("native_analysis", {}) or {}
        suspicious_native = native_analysis.get("suspicious_findings", []) or []
        high_entropy = native_analysis.get("high_entropy_sections", []) or []
        total_jni = len(native_analysis.get("jni_functions", []) or [])
        print(f"  Native libs      : {len(dex_results['native_libs'])}")
        if suspicious_native:
            categories = set(f["category"] for f in suspicious_native if "category" in f)
            print(f"  Native suspicions: {len(suspicious_native)} finding(s)")
            for cat in sorted(categories):
                print(f"    \u26a0  {cat}")
        if high_entropy:
            print(f"  High-entropy sec : {len(high_entropy)} section(s) — possible packing")
        if total_jni:
            print(f"  JNI functions    : {total_jni}")
        tracker_detection = dex_results.get("tracker_detection", {}) or {}
        trackers = tracker_detection.get("trackers", []) or []
        if trackers:
            cats = set()
            for t in trackers:
                cats.update(t.get("categories", []))
            print(f"  Trackers         : {len(trackers)} detected ({', '.join(sorted(cats))})")
        print(f"  Broadcast recv   : {len(dex_results['receivers'])}")
        cg = dex_results.get("call_graph") or {}
        if cg.get("node_count", 0) > 0:
            print(f"  Call graph nodes : {cg['node_count']}")
            print(f"  Call graph edges : {cg.get('edge_count', 0)}")
            print(f"  Max call depth   : {cg.get('max_depth', 0)}")
        chains = dex_results.get("exfiltration_chains") or []
        if chains:
            print(f"  Exfil chains     : {len(chains)}")
        no_ui = dex_results.get("no_ui_reachable") or []
        if no_ui:
            print(f"  No-UI reachable  : {len(no_ui)}")

    if verbose:
        print("\nRunning code similarity analysis...")
    init_hash_db()
    known_count = get_known_count()
    if verbose:
        print(f"  Known hashes in DB : {known_count}")

    dex_raw = dex_results.get("_dex_raw", b"")
    analysis = dex_results.get("_analysis")
    code_hashes: dict = {}
    similarity_matches: list[dict] = []
    if analysis and dex_raw:
        code_hashes = compute_all_hashes(dex_raw, analysis, package)
        if verbose:
            print(f"  imphash : {code_hashes.get('imphash', 'N/A')}")
            print(f"  ssdeep  : {code_hashes.get('ssdeep', 'N/A')[:50]}...")
            print(f"  tlsh    : {code_hashes.get('tlsh', 'N/A')[:50]}...")

        if known_count > 0 and code_hashes.get("imphash"):
            similarity_matches = search_similar(code_hashes)
            if similarity_matches and verbose:
                print(f"  Similarity matches : {len(similarity_matches)}")
                for m in similarity_matches[:3]:
                    print(f"    - {m['known_package']} "
                          f"(score: {m['combined_score']}, "
                          f"label: {m['known_label']})")
            elif verbose:
                print("  No similar known samples found.")

        log_scan(package, app_name, code_hashes, similarity_matches)
    elif verbose:
        print("  Skipped (no DEX data).")

    if verbose:
        print("\nRunning YARA signature scanning...")
    yara_matches = yara_scan_apk(apk_path)
    if yara_matches:
        by_category: dict[str, int] = {}
        for m in yara_matches:
            cat = m.get("meta", {}).get("category", "unknown")
            by_category[cat] = by_category.get(cat, 0) + 1
        if verbose:
            print(f"  YARA matches    : {len(yara_matches)} total")
            for cat, count in sorted(by_category.items()):
                print(f"    - {cat}: {count}")
    elif verbose:
        print("  No YARA signature matches.")

    oh = dex_results.get("obfuscation_heuristics", {}) or {}
    if oh and verbose:
        flags = []
        if oh.get("reflection_ratio", 0) > 0.15:
            flags.append(f"reflection {oh['reflection_ratio']:.0%}")
        if oh.get("string_encryption_weight", 0) >= 5:
            flags.append(f"string_encryption")
        if oh.get("dynamic_loading_callers", 0) >= 1:
            flags.append(f"dynamic_loading")
        if oh.get("dex_entropy", 0) >= 6.5:
            flags.append(f"high_entropy({oh['dex_entropy']})")
        if oh.get("dead_code_ratio", 0) >= 0.35:
            flags.append(f"dead_code({oh['dead_code_ratio']:.0%})")
        if flags:
            print(f"  Obfuscation heuristics: {', '.join(flags)}")

    if verbose:
        print("\nVerifying APK signature & certificates...")
    sig_info = verify_apk_signature(apk_path)
    if sig_info["is_signed"]:
        if verbose:
            n_certs = len(sig_info["certificates"])
            schemes = [k for k, v in sig_info["schemes"].items() if v]
            print(f"  Signed           : YES ({', '.join(schemes)})")
            print(f"  Certificates     : {n_certs}")
            if n_certs:
                c = sig_info["certificates"][0]
                print(f"  Subject          : {c['subject']}")
                print(f"  Issuer           : {c['issuer']}")
                print(f"  SHA-256          : {c['sha256_fingerprint']}")
                known = c.get("known_signer_name")
                if known:
                    print(f"  Known signer     : {known} ({c['known_signer_org']})")
                if c.get("expired"):
                    print(f"  \u26a0  Certificate EXPIRED (was valid until {c['not_valid_after']})")
                if c.get("weak_hash_algorithm"):
                    print(f"  \u26a0  Weak hash algorithm: {c['hash_algorithm']}")
    elif verbose:
        print(f"  Signed           : NO")
    if sig_info["flags"] and verbose:
        for flag in sig_info["flags"]:
            print(f"  \u26a0  {flag.replace('_', ' ').title()}")

    dex_results.pop("_dex_raw", None)
    dex_results.pop("_analysis", None)
    return {
        "app_name": app_name,
        "package": package,
        "target_sdk": target_sdk,
        "all_permissions": all_perms,
        "dangerous_permissions": dangerous_found,
        "code_hashes": code_hashes,
        "similarity_matches": similarity_matches,
        "yara_matches": yara_matches,
        "signature_verification": sig_info,
        **dex_results,
    }
