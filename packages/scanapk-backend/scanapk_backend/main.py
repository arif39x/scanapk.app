import argparse
import atexit
import contextlib
import json
import os
import sys
import tempfile
import time
from concurrent.futures import ProcessPoolExecutor, as_completed
from pathlib import Path

from dotenv import load_dotenv
load_dotenv()

# Track temporary files for cleanup
_temp_files: list[str] = []


def _cleanup_temp():
    for p in _temp_files:
        try:
            if os.path.isfile(p):
                os.unlink(p)
            elif os.path.isdir(p):
                import shutil
                shutil.rmtree(p, ignore_errors=True)
        except Exception:
            pass


atexit.register(_cleanup_temp)


@contextlib.contextmanager
def _suppress_stdout():
    with open(os.devnull, "w") as devnull:
        old_stdout = sys.stdout
        sys.stdout = devnull
        try:
            yield
        finally:
            sys.stdout = old_stdout


HASHDB_OPS = {"hashdb_init", "hashdb_import", "hashdb_export", "hashdb_count"}


def _handle_hashdb(args: argparse.Namespace) -> None:
    from scanapk_backend.core.hash_db import import_json, export_json, init_db, get_known_count

    if args.hashdb_init:
        init_db()
        print(f"  Initialised — {get_known_count()} known records.")
        return
    if args.hashdb_import:
        count = import_json(args.hashdb_import)
        print(f"  Imported {count} records.")
        return
    if args.hashdb_export:
        count = export_json(args.hashdb_export)
        print(f"  Exported {count} records.")
        return
    if args.hashdb_count:
        init_db()
        print(f"  Known hash records: {get_known_count()}")
        return


def _verdict(severity: str) -> str:
    return {"CLEAN": "INSTALL", "LOW": "REVIEW"}.get(severity.upper(), "DO_NOT_INSTALL")


def _verbose(args: argparse.Namespace) -> bool:
    return not (args.batch or args.parallel or args.quiet)


def scan_single_apk(apk_path: str, args: argparse.Namespace) -> dict:
    """Run the full analysis pipeline for one APK. Returns a report dict."""
    from scanapk_backend.core.scan_apk import scan_apk
    from scanapk_backend.core.scoring import calculate_risk
    from scanapk_backend.report.generator import build_report

    apk_path = os.path.expanduser(apk_path)

    if args.quiet:
        with _suppress_stdout():
            static_info = scan_apk(apk_path)
    else:
        static_info = scan_apk(apk_path)
    if static_info is None:
        return {"error": f"Failed to scan {apk_path}", "verdict": "ERROR"}

    evidence = {}
    if not args.static and not (args.batch or args.parallel):
        choice = input(
            "\nInstall and run in emulator for dynamic analysis? (y/n): "
        ).strip().lower()
        if choice == "y":
            from scanapk_backend.core.apkdeploy import deploy_to_emulator
            if deploy_to_emulator(apk_path, static_info["package"]):
                from monitor import start_all
                evidence = start_all(
                    static_info["package"],
                    observe_secs=args.observe,
                )
            else:
                print("Emulator deployment failed — continuing with static results only.")
    elif _verbose(args):
        print("\n[Static-only mode] Skipping emulator.")

    if _verbose(args):
        print("\nRunning deterministic risk assessment...")
    deterministic_score = calculate_risk(static_info, evidence)
    if _verbose(args):
        print(f"  Risk score: {deterministic_score['risk_score']}/100 "
              f"({deterministic_score['severity']})")

    ai_result = {}
    if not args.no_ai and _verbose(args):
        from scanapk_backend.core.models import get_models
        if not get_models():
            print("\nNo OpenRouter API keys found in .env.")
            skip = input("Skip AI analysis? (y/n): ").strip().lower()
            if skip != "y":
                key = input("Paste your OpenRouter API key: ").strip()
                os.environ["OPENROUTER_API_KEY"] = key

        if get_models():
            print("\nRunning agentic analysis...")
            try:
                from scanapk_backend.core.agent import analyse
                ai_result = analyse(
                    apk_path=apk_path,
                    static_info=static_info,
                    evidence=evidence,
                    deterministic=deterministic_score,
                )
            except Exception as e:
                print(f"  AI analysis failed: {e}")
    elif not args.no_ai:
        from scanapk_backend.core.models import get_models
        if get_models():
            try:
                from scanapk_backend.core.agent import analyse
                ai_result = analyse(
                    apk_path=apk_path,
                    static_info=static_info,
                    evidence=evidence,
                    deterministic=deterministic_score,
                )
            except Exception:
                pass

    final_assessment = dict(deterministic_score)
    if ai_result and ai_result.get("risk_score", -1) >= 0:
        final_assessment["key_findings"] = ai_result.get(
            "key_findings", final_assessment["key_findings"]
        )
        final_assessment["recommendations"] = ai_result.get(
            "recommendations", final_assessment["recommendations"]
        )
        final_assessment["malware_family"] = ai_result.get("malware_family")
        final_assessment["threat_types"] = ai_result.get("threat_types", [])
        final_assessment["iocs"] = ai_result.get("iocs", {"urls": [], "ips": [], "apis": []})

    return build_report(static_info, final_assessment, deterministic_score)


def _human_report(report: dict):
    a = report["assessment"]
    score = a.get("risk_score", "?")
    severity = a.get("severity", "?")
    family = a.get("malware_family") or "unknown"
    pkg = report["app"].get("package", "?")
    name = report["app"].get("name", "?")

    bar_filled = int(score / 5) if isinstance(score, int) else 0
    bar = "█" * bar_filled + "░" * (20 - bar_filled)

    print("\n" + "=" * 60)
    print(f"  INVESTIGATION REPORT — {pkg}")
    print("=" * 60)
    print(f"  App name   : {name}")
    print(f"  Risk score : [{bar}] {score}/100")
    print(f"  Severity   : {severity}")
    print(f"  Verdict    : {_verdict(severity)}")
    print(f"  Family     : {family}")
    print(f"  Confidence : {a.get('confidence', '?')}")
    print()
    print("  Key findings:")
    for finding in a.get("key_findings", []):
        print(f"    \u2022 {finding}")
    print()
    print("  Recommendations:")
    for rec in a.get("recommendations", []):
        print(f"    \u2192 {rec}")
    print("=" * 60)


def _summary_line(report: dict, apk_path: str):
    a = report["assessment"]
    pkg = report["app"].get("package", "?")
    score = a.get("risk_score", "?")
    severity = a.get("severity", "?")
    verdict = report.get("verdict", _verdict(severity))
    family = a.get("malware_family") or "unknown"
    print(f"{pkg},{verdict},{score},{severity},{family},{apk_path}")


def _write_json(report: dict, path: str):
    if path == "-":
        json.dump(report, sys.stdout, indent=2)
        sys.stdout.write("\n")
        sys.stdout.flush()
    else:
        os.makedirs(os.path.dirname(os.path.abspath(path)) or ".", exist_ok=True)
        with open(path, "w") as f:
            json.dump(report, f, indent=2)
        print(f"JSON report saved to: {path}")


def _save_report(report: dict, args: argparse.Namespace, apk_path: str, quiet: bool = False):
    """Persist report to disk according to --output or default."""
    if args.output:
        base = os.path.splitext(os.path.basename(apk_path))[0]
        pkg = report.get("app", {}).get("package", base)
        out = args.output.replace("{pkg}", pkg).replace("{apk}", base)
        _write_json(report, out)
    else:
        from scanapk_backend.report.generator import generate_from_report
        generate_from_report(report, quiet=quiet)


def _collect_apks(directory: str) -> list[str]:
    d = os.path.expanduser(directory)
    if not os.path.isdir(d):
        print(f"Directory not found: {d}")
        sys.exit(1)
    paths = sorted(str(p) for p in Path(d).glob("*.apk"))
    paths.extend(sorted(str(p) for p in Path(d).glob("*.aab")))
    if not paths:
        print(f"No .apk or .aab files found in {d}")
        sys.exit(0)
    return paths


def _resolve_inputs(paths: list[str]) -> list[tuple[str, str]]:
    """Normalise input paths to concrete APK file(s).

    Returns ``[(original_path, resolved_apk_path), ...]`` so callers
    can map results back to the user-supplied name.
    """
    resolved: list[tuple[str, str]] = []
    for p in paths:
        p = os.path.expanduser(p)
        if not os.path.isfile(p):
            print(f"File not found: {p}")
            sys.exit(1)

        from scanapk_backend.core.bundle_utils import is_aab, convert_aab
        from scanapk_backend.core.merge_apks import merge_apks_temp

        if is_aab(p):
            apk = convert_aab(p)
            _temp_files.append(apk)
            resolved.append((p, apk))
        elif p.endswith(".apk"):
            resolved.append((p, p))
        else:
            print(f"Unsupported file type: {p}")
            sys.exit(1)

    # If multiple APKs were given, merge them into one
    if len(resolved) > 1:
        merged = merge_apks_temp([r[1] for r in resolved])
        _temp_files.append(merged)
        label = " + ".join(os.path.basename(r[0]) for r in resolved)
        resolved = [(label, merged)]

    return resolved


def main():
    parser = argparse.ArgumentParser(description="APK Malware Analyser")
    parser.add_argument("apk", nargs="*", help="Path to APK/AAB file(s) — multiple = split APKs")
    parser.add_argument("--static", action="store_true",
                        help="Static analysis only — skip emulator and dynamic monitoring")
    parser.add_argument("--observe", type=int, default=60,
                        help="Seconds to monitor the running app (default: 60)")
    parser.add_argument("--no-ai", action="store_true",
                        help="Skip AI analysis (produces evidence-only report)")

    # Pipeline-friendly flags
    parser.add_argument("--batch", metavar="DIR",
                        help="Scan all .apk files in a directory")
    parser.add_argument("--parallel", type=int, metavar="N", default=0,
                        help="Process N APKs concurrently (requires --batch)")
    parser.add_argument("--output", metavar="FILE",
                        help="Write JSON report to FILE (use '-' for stdout; "
                             "supports {pkg} and {apk} placeholders)")
    parser.add_argument("--exit-code", action="store_true",
                        help="Return exit code 1 if any verdict is DO_NOT_INSTALL")
    parser.add_argument("--summary", action="store_true",
                        help="Print one-line CSV summary per APK instead of full report")

    hdb = parser.add_argument_group("hash database")
    hdb.add_argument("--hashdb-init", action="store_true", help="Initialise hash DB")
    hdb.add_argument("--hashdb-import", metavar="FILE", help="Import known hashes from JSON")
    hdb.add_argument("--hashdb-export", metavar="FILE", help="Export known hashes to JSON")
    hdb.add_argument("--hashdb-count", action="store_true", help="Show number of known records")
    args = parser.parse_args()

    if args.hashdb_init or args.hashdb_import or args.hashdb_export or args.hashdb_count:
        _handle_hashdb(args)
        return

    args.quiet = (args.output == "-") or bool(args.batch)

    # ── Batch mode ──────────────────────────────────────────────────────
    if args.batch:
        raw_paths = _collect_apks(args.batch)
        apk_paths = _resolve_inputs(raw_paths)
        args.static = True
        reports: list[tuple[str, dict]] = []

        quiet_progress = args.output == "-"
        if args.parallel and args.parallel > 1:
            n_workers = min(args.parallel, len(apk_paths), os.cpu_count() or 4)
            print(f"Scanning {len(apk_paths)} APKs with {n_workers} workers...",
                  file=sys.stderr if quiet_progress else None)
            with ProcessPoolExecutor(max_workers=n_workers) as pool:
                fut_map = {}
                for orig, resolved in apk_paths:
                    fut_map[pool.submit(scan_single_apk, resolved, args)] = orig
                for fut in as_completed(fut_map):
                    orig = fut_map[fut]
                    try:
                        report = fut.result()
                    except Exception as e:
                        report = {"error": str(e), "verdict": "ERROR"}
                    reports.append((orig, report))
            reports.sort(key=lambda x: raw_paths.index(x[0]))
        else:
            for orig, resolved in apk_paths:
                report = scan_single_apk(resolved, args)
                reports.append((orig, report))

        is_json_stdout = args.output == "-"
        any_do_not_install = False
        for apk_path, report in reports:
            if "error" in report:
                print(f"  \u2716 {apk_path}: {report['error']}", file=sys.stderr)
                continue

            if args.summary:
                _summary_line(report, apk_path)
            elif not is_json_stdout:
                print(f"\n{'#' * 60}", file=sys.stderr)
                print(f"#  {os.path.basename(apk_path)}", file=sys.stderr)
                print(f"{'#' * 60}", file=sys.stderr)
                _human_report(report)

            _save_report(report, args, apk_path, quiet=(args.summary or is_json_stdout))

            if report.get("verdict") == "DO_NOT_INSTALL":
                any_do_not_install = True

        if args.exit_code and any_do_not_install:
            sys.exit(1)
        return

    # ── Single-APK mode ─────────────────────────────────────────────────
    inputs = args.apk
    if not inputs:
        raw = input("Enter path to APK/AAB file(s): ").strip()
        inputs = raw.split()

    resolved = _resolve_inputs(inputs)
    apk_label = resolved[0][0]
    apk_path = resolved[0][1]

    if len(resolved) > 1:
        print(f"Analysing {len(resolved)} split APKs merged into one.")

    report = scan_single_apk(apk_path, args)
    if "error" in report:
        print(report["error"])
        sys.exit(1)

    is_json_stdout = args.output == "-"
    if args.summary:
        _summary_line(report, apk_label)
    elif not is_json_stdout:
        _human_report(report)

    _save_report(report, args, apk_label, quiet=(args.summary or is_json_stdout))

    if args.exit_code and report.get("verdict") == "DO_NOT_INSTALL":
        sys.exit(1)


if __name__ == "__main__":
    main()
