import os
import re
import threading
import time

MONITOR_DIR = os.path.expanduser("~/scanapk_monitor")
DEFAULT_OBSERVE_SECS = 60


def start_all(package_name: str, observe_secs: int = DEFAULT_OBSERVE_SECS) -> dict:
    from . import frida_monitor, logcat_monitor, mitm_monitor

    print("\n" + "=" * 50)
    print(" Starting monitoring suite")
    print("=" * 50)

    frida_monitor.install()
    mitm_monitor.install()

    frida_monitor.push_server()

    print("  [1/5] Starting mitmproxy...", flush=True)
    mitm_monitor.start()
    print("  [2/5] Installing CA cert...", flush=True)
    mitm_monitor.install_cert()
    print("  [3/5] Setting proxy...", flush=True)
    mitm_monitor.set_proxy()
    print("  [4/5] Starting logcat...", flush=True)
    logcat_monitor.start()
    print("  [5/5] Attaching Frida hooks...", flush=True)
    frida_monitor.attach(package_name)

    frida_log = os.path.join(MONITOR_DIR, "frida_hooks.log")
    mitm_log = os.path.join(MONITOR_DIR, "mitmproxy.log")
    lc_log = os.path.join(MONITOR_DIR, "logcat_monitor.log")

    print("\n" + "-" * 50)
    print(" Monitoring active!")
    print(f"  Frida hooks:   {frida_log}")
    print(f"  mitmproxy:     {mitm_log}")
    print(f"  Logcat:        {lc_log}")
    print("-" * 50)

    print(f"\n  Observing for {observe_secs}s — interact with the app...")
    print(f"  Live hooks will appear below:\n")

    _tail_with_countdown(frida_log, observe_secs)

    frida_monitor.stop()
    logcat_monitor.stop()
    mitm_monitor.stop()

    print("\n  Collecting evidence from logs...")
    evidence = collect_evidence()
    print(f"  Evidence collected: {sum(len(v) for v in evidence.values())} items")
    return evidence


def collect_evidence() -> dict:
    evidence = {
        "frida_hits": _parse_frida_log(),
        "network_requests": _parse_mitm_log(),
        "logcat_hits": _parse_logcat(),
    }

    patterns = _detect_techniques(evidence)
    if patterns:
        evidence["detected_techniques"] = patterns

    _enrich_with_pcap(evidence)

    return evidence


def _enrich_with_pcap(evidence: dict):
    try:
        from core import pcap_analysis

        result = pcap_analysis.analyze_pcap()
        if "error" not in result:
            evidence["pcap_analysis"] = result
            pcap_findings = result.get("findings", [])
            if pcap_findings:
                print(
                    f"  PCAP analysis: {result['packet_count']} packets, "
                    f"{len(pcap_findings)} finding(s)"
                )
                for f in pcap_findings[:5]:
                    print(f"    \u26a0 {f['detail'][:100]}")
        else:
            err = result.get("error", "unknown error")
            if err not in ("pcap file not found",):
                print(f"  \u26a0 PCAP analysis: {err}")
    except Exception as exc:
        print(f"  \u26a0 PCAP analysis error: {exc}")


# ── Live tail during observation ──────────────────────────────────────────

def _tail_with_countdown(log_path: str, seconds: int):
    """Show countdown + live Frida hooks as they're written to the log."""
    stop_event = threading.Event()

    def tail():
        if not os.path.isfile(log_path):
            # Wait for file to exist
            for _ in range(10):
                if os.path.isfile(log_path) or stop_event.is_set():
                    break
                time.sleep(0.5)
        try:
            with open(log_path, errors="replace") as f:
                f.seek(0, os.SEEK_END)
                while not stop_event.is_set():
                    line = f.readline()
                    if line:
                        line = line.strip()
                        if line:
                            print(f"    \u2192 {line[:150]}", flush=True)
                    else:
                        time.sleep(0.2)
        except Exception:
            pass

    t = threading.Thread(target=tail, daemon=True)
    t.start()

    for remaining in range(seconds, 0, -1):
        if remaining <= 10 or remaining % 10 == 0:
            print(f"  [{remaining:3d}s] ", end="", flush=True)
        time.sleep(1)

    stop_event.set()
    t.join(timeout=2)
    print()


# ── Log parsers ───────────────────────────────────────────────────────────

def _parse_frida_log() -> list[dict]:
    path = os.path.join(MONITOR_DIR, "frida_hooks.log")
    hits = []
    if not os.path.isfile(path):
        return hits
    pattern = re.compile(r"\[MALMON\]\s+(.+)")
    with open(path, errors="replace") as f:
        for line in f:
            m = pattern.search(line)
            if m:
                hits.append({"type": "frida", "detail": m.group(1).strip()})
    return hits


def _parse_mitm_log() -> list[dict]:
    path = os.path.join(MONITOR_DIR, "mitmproxy.log")
    requests = []
    if not os.path.isfile(path):
        return requests
    url_pattern = re.compile(r"(GET|POST|PUT|DELETE|PATCH)\s+(https?://\S+)")
    with open(path, errors="replace") as f:
        for line in f:
            m = url_pattern.search(line)
            if m:
                requests.append({"method": m.group(1), "url": m.group(2)})
    seen = set()
    unique = []
    for r in requests:
        key = r["method"] + r["url"]
        if key not in seen:
            seen.add(key)
            unique.append(r)
    return unique


_SUSPICIOUS_LOGCAT = re.compile(
    r"SmsManager|sendTextMessage|Cipher\.doFinal|Runtime\.exec|"
    r"DevicePolicyManager|lockNow|wipeData|NotificationListenerService|"
    r"getLastKnownLocation|getDeviceId|READ_CONTACTS|INSTALL_PACKAGES",
    re.IGNORECASE,
)


def _parse_logcat() -> list[str]:
    path = os.path.join(MONITOR_DIR, "logcat_monitor.log")
    hits = []
    if not os.path.isfile(path):
        return hits
    with open(path, errors="replace") as f:
        for line in f:
            if _SUSPICIOUS_LOGCAT.search(line):
                hits.append(line.strip()[:200])
    return hits[:100]


def _detect_techniques(evidence: dict) -> list[dict]:
    findings = []
    frida = evidence.get("frida_hits", []) or []
    network = evidence.get("network_requests", []) or []
    logcat = evidence.get("logcat_hits", []) or []

    details = [h.get("detail", str(h)) if isinstance(h, dict) else str(h) for h in frida]

    # ── Delayed Execution Detection ──────────────────────────────────

    timer_hits = [d for d in details if d.startswith("TIMER")]
    ui_hits = [d for d in details if d.startswith("UI")]
    suspicious_hits = [
        d for d in details
        if any(k in d for k in ("NET ", "DEXLOAD ", "SMS ", "CRYPTO ", "FILE "))
    ]

    if timer_hits or ui_hits:
        # Check if timers/UI events precede suspicious activity
        if suspicious_hits:
            findings.append({
                "technique": "Delayed Execution",
                "confidence": "HIGH",
                "evidence": {
                    "timers": timer_hits[:5],
                    "ui_events": ui_hits[:5],
                    "subsequent_suspicious": suspicious_hits[:5],
                },
                "indicators": [
                    "App registers timers/delays alongside suspicious APIs",
                    "Suspicious activity following user-interaction events suggests time-based evasion",
                ],
            })
        elif len(timer_hits) >= 3:
            findings.append({
                "technique": "Delayed Execution (suspected)",
                "confidence": "MEDIUM",
                "evidence": {"timers": timer_hits[:8]},
                "indicators": [
                    "Multiple timer/delay mechanisms detected without clear benign purpose",
                ],
            })

    # ── Dropper / Two-Stage Detection ─────────────────────────────────

    dexload_hits = [d for d in details if d.startswith("DEXLOAD")]
    network_urls = [r.get("url", "") for r in network]

    if dexload_hits:
        # Check if DEX loading is from network-sourced paths
        dex_from_network = [
            d for d in dexload_hits
            if any(d.startswith("DEXLOAD DexClassLoader") and "http" in d.lower())
        ]
        inmemory_hits = [d for d in dexload_hits if "InMemoryDexClassLoader" in d]
        reflection_hits = [d for d in details if "Method.invoke" in d or "Class.forName" in d]

        indicators = []
        if inmemory_hits:
            indicators.append("In-memory DEX loading — common payload injection technique")
        if dex_from_network:
            indicators.append("DEX class loader sourcing from network path")
        if reflection_hits and dexload_hits:
            indicators.append("Reflection used alongside dynamic class loading — typical dropper pattern")
        if dexload_hits:
            indicators.append("Runtime DEX loading detected — app can execute code not in the original APK")

        findings.append({
            "technique": "Dropper / Two-Stage Payload",
            "confidence": "HIGH" if (inmemory_hits or dex_from_network) else "MEDIUM",
            "evidence": {
                "dex_loads": dexload_hits[:8],
                "reflection_calls": reflection_hits[:5],
                "network_requests": network_urls[:5],
            },
            "indicators": indicators,
        })

    # ── Payload Download Detection ────────────────────────────────────

    large_downloads = [d for d in details if "largePayload" in d or "largeResponse" in d]
    download_manager = [d for d in details if "DownloadManager" in d]

    if large_downloads or download_manager:
        findings.append({
            "technique": "Payload Download",
            "confidence": "MEDIUM",
            "evidence": {
                "large_downloads": large_downloads[:5],
                "download_manager": download_manager[:5],
            },
            "indicators": [
                "App downloads large payloads — may fetch additional code or data",
            ],
        })

    return findings
