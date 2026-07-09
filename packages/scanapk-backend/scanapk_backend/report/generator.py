import json
import os
import time

REPORT_DIR = os.path.dirname(os.path.abspath(__file__))


def _verdict(severity: str) -> str:
    return {"CLEAN": "INSTALL", "LOW": "REVIEW"}.get(severity.upper(), "DO_NOT_INSTALL")


def build_report(static_info: dict, assessment: dict, deterministic: dict) -> dict:
    severity = assessment.get("severity", "") or deterministic.get("severity", "")
    return {
        "schema_version": "1.0",
        "generated_at": int(time.time()),
        "verdict": _verdict(severity),
        "app": {
            "name": static_info.get("app_name"),
            "package": static_info.get("package"),
            "target_sdk": static_info.get("target_sdk"),
        },
        "assessment": assessment if assessment.get("risk_score", -1) >= 0 else deterministic,
        "deterministic_score": deterministic,
        "static_evidence": {
            "dangerous_permissions": static_info.get("dangerous_permissions", []),
            "suspicious_apis": static_info.get("suspicious_apis", []),
            "embedded_urls": static_info.get("urls", []),
            "embedded_ips": static_info.get("ips", []),
            "receivers": static_info.get("receivers", []),
            "services": static_info.get("services", []),
            "native_libs": static_info.get("native_libs", []),
            "native_analysis": static_info.get("native_analysis", {}),
            "tracker_detection": static_info.get("tracker_detection", {}),
            "call_graph": static_info.get("call_graph", {}),
            "exfiltration_chains": static_info.get("exfiltration_chains", []),
            "no_ui_reachable": static_info.get("no_ui_reachable", []),
            "code_hashes": static_info.get("code_hashes", {}),
            "similarity_matches": static_info.get("similarity_matches", []),
            "yara_matches": static_info.get("yara_matches", []),
            "signature_verification": static_info.get("signature_verification", {}),
            "obfuscation_heuristics": static_info.get("obfuscation_heuristics", {}),
        },
    }


def generate(
    static_info: dict,
    assessment: dict,
    deterministic: dict | None = None,
    output_dir: str = REPORT_DIR,
) -> str:
    deterministic = deterministic or {}
    report = build_report(static_info, assessment, deterministic)
    os.makedirs(output_dir, exist_ok=True)

    pkg = static_info.get("package", "unknown").replace(".", "_")
    ts = int(time.time())
    filename = f"report_{pkg}_{ts}.json"
    path = os.path.join(output_dir, filename)

    with open(path, "w") as f:
        json.dump(report, f, indent=2)

    _print_summary(report)
    return path


def generate_from_report(report: dict, output_dir: str = REPORT_DIR,
                         quiet: bool = False) -> str:
    os.makedirs(output_dir, exist_ok=True)

    pkg = report.get("app", {}).get("package", "unknown").replace(".", "_")
    ts = report.get("generated_at", int(time.time()))
    filename = f"report_{pkg}_{ts}.json"
    path = os.path.join(output_dir, filename)

    with open(path, "w") as f:
        json.dump(report, f, indent=2)

    if not quiet:
        _print_summary(report)
    return path


def _print_summary(report: dict):
    a = report.get("assessment") or report.get("deterministic_score", {})
    score = a.get("risk_score", "?")
    severity = a.get("severity", "?")
    family = a.get("malware_family") or "unknown"
    pkg = report.get("app", {}).get("package", "?")

    bar_filled = int(score / 5) if isinstance(score, int) else 0
    bar = "█" * bar_filled + "░" * (20 - bar_filled)

    print("\n" + "=" * 60)
    print(f"  INVESTIGATION REPORT — {pkg}")
    print("=" * 60)
    print(f"  Risk score : [{bar}] {score}/100")
    print(f"  Severity   : {severity}")
    print(f"  Verdict    : {_verdict(severity)}")
    print(f"  Family     : {family}")
    print(f"  Confidence : {a.get('confidence', '?')}")
    se = report.get("static_evidence", {})
    yara_count = len(se.get("yara_matches", []))
    if yara_count:
        print(f"  YARA matches : {yara_count}")
    print()
    print("  Key findings:")
    for finding in a.get("key_findings", []):
        print(f"    \u2022 {finding}")
    print()
    print("  Recommendations:")
    for rec in a.get("recommendations", []):
        print(f"    \u2192 {rec}")
    print("=" * 60)
