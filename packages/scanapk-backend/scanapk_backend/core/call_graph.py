import logging
from collections import deque

logger = logging.getLogger(__name__)

_EXFILTRATION_SOURCES = {
    "getDeviceId", "getSubscriberId", "getImei", "getImsi",
    "getLine1Number", "getLastKnownLocation", "getLatitude",
    "getLongitude", "getAllContacts",
}

_EXFILTRATION_SINKS = {
    "openConnection", "write", "sendTextMessage", "sendMultipartTextMessage",
    "HttpURLConnection", "OkHttpClient",
}

_NO_UI_METHOD_NAMES = {
    "onReceive",
    "onStartCommand",
    "onBind",
    "query",
    "insert",
    "update",
    "delete",
}


def _method_key(ma):
    try:
        m = ma.get_method()
        cls = m.get_class_name() if hasattr(m, 'get_class_name') else '?'
        name = m.get_name() if hasattr(m, 'get_name') else ma.name
        desc = m.get_descriptor() if hasattr(m, 'get_descriptor') else ''
    except Exception:
        cls = '?'
        name = getattr(ma, 'name', '?')
        desc = ''
    return f"{cls}->{name}{desc}"


def _short_name(key: str) -> str:
    parts = key.split("->")
    if len(parts) == 2:
        cls = parts[0].rsplit("/", 1)[-1].rstrip(";")
        return f"{cls}.{parts[1]}"
    return key


def _gather_methods(analysis, dangerous_api_names: set):
    """Single pass through methods to collect all metadata."""
    internal_keys: set[str] = set()
    ma_by_key: dict[str, object] = {}
    callees: dict[str, set[str]] = {}
    callers: dict[str, set[str]] = {}
    source_methods: set[str] = set()
    sink_methods: set[str] = set()
    entry_methods: set[str] = set()
    dangerous_methods: set[str] = set()

    for ma in analysis.get_methods():
        if ma.is_external():
            continue
        key = _method_key(ma)
        internal_keys.add(key)
        ma_by_key[key] = ma

        if ma.name in _NO_UI_METHOD_NAMES:
            entry_methods.add(key)

        callees.setdefault(key, set())
        try:
            for _ca, callee_ma, _ in ma.get_xref_to():
                n = callee_ma.name
                if n in _EXFILTRATION_SOURCES:
                    source_methods.add(key)
                if n in _EXFILTRATION_SINKS:
                    sink_methods.add(key)
                if n in dangerous_api_names:
                    dangerous_methods.add(key)

                if callee_ma.is_external():
                    continue
                ck = _method_key(callee_ma)
                if ck in internal_keys:
                    callees[key].add(ck)
                    callers.setdefault(ck, set()).add(key)
        except Exception:
            continue

    return internal_keys, ma_by_key, callees, callers, source_methods, sink_methods, entry_methods, dangerous_methods


def _compute_depth(internal_keys, callees, callers) -> int:
    roots = internal_keys - set(callers.keys())
    depths = {}
    q = deque()
    for r in roots:
        depths[r] = 0
        q.append(r)
    while q:
        cur = q.popleft()
        nd = depths[cur] + 1
        for c in callees.get(cur, set()):
            if c not in depths:
                depths[c] = nd
                q.append(c)
    return max(depths.values()) if depths else 0


def _find_exfil_chains(callees, source_methods, sink_methods) -> list[dict]:
    if not source_methods or not sink_methods:
        return []

    chains = []
    seen_sinks: set[str] = set()
    visited: set[str] = set(source_methods)
    origin: dict[str, str] = {s: s for s in source_methods}
    depth_map: dict[str, int] = {s: 0 for s in source_methods}
    q = deque(source_methods)

    while q:
        cur = q.popleft()
        nd = depth_map[cur] + 1
        if nd > 15:
            continue
        for c in callees.get(cur, set()):
            if c not in visited:
                visited.add(c)
                origin[c] = origin[cur]
                depth_map[c] = nd
                q.append(c)
            if c in sink_methods and c not in seen_sinks:
                seen_sinks.add(c)
                chains.append({
                    "source": _short_name(origin[c]),
                    "sink": _short_name(c),
                    "chain_length": nd,
                })
    return chains


def _find_no_ui_reachable(callees, entry_methods, dangerous_methods) -> list[dict]:
    if not entry_methods or not dangerous_methods:
        return []

    remaining = set(dangerous_methods)
    visited: set[str] = set(entry_methods)
    q = deque((e, 0) for e in entry_methods)
    reached = 0

    while q:
        cur, depth = q.popleft()
        if cur in remaining:
            reached += 1
            remaining.discard(cur)
        if depth >= 20:
            continue
        for c in callees.get(cur, set()):
            if c not in visited:
                visited.add(c)
                q.append((c, depth + 1))

    if reached:
        return [{"entry_point": f"{len(entry_methods)} non-UI handler(s)", "reachable_methods": reached}]
    return []


def _compute_dead_code(internal_keys, callees, callers) -> tuple[int, float]:
    """Count methods unreachable from any root (entry point)."""
    roots = internal_keys - set(callers.keys())
    reachable: set[str] = set()
    q = deque(roots)
    while q:
        cur = q.popleft()
        if cur in reachable:
            continue
        reachable.add(cur)
        for c in callees.get(cur, set()):
            if c not in reachable:
                q.append(c)

    total = len(internal_keys)
    dead = total - len(reachable)
    ratio = dead / total if total > 0 else 0.0
    return dead, ratio


def analyze_call_graph(analysis, api_details):
    """Run all call graph analyses and return a result dict."""
    dangerous_api_names = {d["api"] for d in api_details}

    try:
        internal_keys, _ma_by_key, callees, callers, source_methods, sink_methods, entry_methods, dangerous_methods = _gather_methods(
            analysis, dangerous_api_names
        )
    except Exception as e:
        logger.warning("Call graph gather failed: %s", e)
        return {
            "call_graph": {"node_count": 0, "edge_count": 0, "max_depth": 0},
            "exfiltration_chains": [],
            "no_ui_reachable": [],
            "dead_code_count": 0,
            "dead_code_ratio": 0.0,
        }

    if not internal_keys:
        return {
            "call_graph": {"node_count": 0, "edge_count": 0, "max_depth": 0},
            "exfiltration_chains": [],
            "no_ui_reachable": [],
            "dead_code_count": 0,
            "dead_code_ratio": 0.0,
        }

    max_depth = _compute_depth(internal_keys, callees, callers)
    edge_count = sum(len(c) for c in callees.values())
    dead_count, dead_ratio = _compute_dead_code(internal_keys, callees, callers)

    exfil_chains = _find_exfil_chains(callees, source_methods, sink_methods)
    no_ui = _find_no_ui_reachable(callees, entry_methods, dangerous_methods)

    return {
        "call_graph": {
            "node_count": len(internal_keys),
            "edge_count": edge_count,
            "max_depth": max_depth,
        },
        "exfiltration_chains": exfil_chains,
        "no_ui_reachable": no_ui,
        "dead_code_count": dead_count,
        "dead_code_ratio": round(dead_ratio, 4),
    }
