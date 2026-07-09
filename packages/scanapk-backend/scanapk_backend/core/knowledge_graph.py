def _san(val: str, maxlen: int = 200) -> str:
    return str(val).replace("|", "/").replace("\n", " ")[:maxlen]


def build_graph(
    apk_path: str,
    static_info: dict,
    evidence: dict | None = None,
    deterministic: dict | None = None,
) -> str:
    lines: list[str] = []
    pkg = static_info.get("package", "?")
    app_name = static_info.get("app_name", "?")
    target_sdk = static_info.get("target_sdk", "?")

    lines.append(f"# Knowledge Graph — {app_name} ({pkg})")
    lines.append("")

    lines.append(f"APP: {pkg} | {app_name} | targetSdk={target_sdk}")

    if deterministic:
        score = deterministic.get("risk_score", "?")
        sev = deterministic.get("severity", "?")
        lines.append(f"RISK: score={score}/100 | severity={sev}")
        for finding in (deterministic.get("key_findings") or [])[:10]:
            lines.append(f"  FINDING: {_san(finding)}")

    dangerous = static_info.get("dangerous_permissions") or []
    for p in dangerous:
        lines.append(f"PERM: {_san(p)} | dangerous")

    for a in (static_info.get("suspicious_apis") or [])[:30]:
        lines.append(f"API: {_san(a)}")

    for u in (static_info.get("urls") or [])[:20]:
        url_str = u["url"] if isinstance(u, dict) else u
        lines.append(f"URL: {_san(url_str)}")

    for ip in (static_info.get("ips") or [])[:10]:
        ip_str = ip["ip"] if isinstance(ip, dict) else ip
        lines.append(f"IP: {_san(ip_str)}")

    for r in static_info.get("receivers") or []:
        lines.append(f"RECV: {_san(r)}")
    for s in static_info.get("services") or []:
        lines.append(f"SVC: {_san(s)}")

    for lib in (static_info.get("native_libs") or [])[:15]:
        lines.append(f"LIB: {_san(lib)}")

    native_analysis = static_info.get("native_analysis") or {}
    for f in (native_analysis.get("suspicious_findings") or [])[:15]:
        symbol = _san(f.get("symbol") or f.get("string") or "?")
        cat = f.get("category", "?")
        lines.append(f"NATIVE: {symbol} | {cat}")
    for sec in (native_analysis.get("high_entropy_sections") or [])[:5]:
        lines.append(f"NATIVE: packed section {_san(sec.get('section','?'))} | entropy={sec.get('entropy','?')}")
    for jni in (native_analysis.get("jni_functions") or [])[:5]:
        lines.append(f"NATIVE: JNI {_san(jni.get('function','?'))} | {jni.get('instructions_count',0)} insns")

    tracker_detection = static_info.get("tracker_detection") or {}
    for t in (tracker_detection.get("trackers") or [])[:20]:
        name = _san(t.get("name", "?"))
        cats = ", ".join(t.get("categories", []))
        risk = t.get("risk_score", "?")
        lines.append(f"TRACKER: {name} | categories={cats} | risk={risk}")

    for s in (static_info.get("raw_strings_sample") or [])[:10]:
        lines.append(f"STR: {_san(s)}")

    cg = static_info.get("call_graph") or {}
    if cg.get("node_count", 0) > 0:
        lines.append(f"CG: nodes={cg['node_count']} edges={cg.get('edge_count', 0)} depth={cg.get('max_depth', 0)}")
    for chain in (static_info.get("exfiltration_chains") or [])[:5]:
        lines.append(f"EXFIL: {_san(chain.get('source', '?'))} -> {_san(chain.get('sink', '?'))} (depth={chain.get('chain_length', '?')})")
    for n in (static_info.get("no_ui_reachable") or [])[:3]:
        lines.append(f"NOUI: {_san(n.get('entry_point', '?'))} reaches {n.get('reachable_methods', 0)} dangerous method(s)")

    if evidence:
        for h in (evidence.get("frida_hits") or [])[:15]:
            detail = _san(h if isinstance(h, str) else h.get("detail", str(h)))
            lines.append(f"FRIDA: {detail}")

        for r in (evidence.get("network_requests") or [])[:10]:
            method = _san(r.get("method", "?"))
            url = _san(r.get("url", str(r)))
            lines.append(f"NET: {method} | {url}")

        for l in (evidence.get("logcat_hits") or [])[:10]:
            lines.append(f"LOGCAT: {_san(l)}")

        detected = evidence.get("detected_techniques") or []
        for dt in detected:
            technique = _san(dt.get("technique", "?"))
            confidence = _san(dt.get("confidence", "?"))
            lines.append(f"TECH: {technique} | confidence={confidence}")
            for ind in (dt.get("indicators") or [])[:3]:
                lines.append(f"  INDICATOR: {_san(ind)}")

    lines.append(f"\n# Total: {len(lines) - 2} triples")
    return "\n".join(lines)
