import json
import logging
import os
import re
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

_TRACKER_FILE = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "..", "data", "trackers.json"
)

_TRACKER_CATEGORY_RISK: dict[str, int] = {
    "Crash reporting": 2,
    "Analytics": 4,
    "Identification": 6,
    "Advertisement": 8,
    "Location": 10,
    "Profiling": 10,
}

_tracker_cache: list[dict] | None = None


def _load_tracker_list() -> list[dict]:
    global _tracker_cache
    if _tracker_cache is not None:
        return _tracker_cache

    path = os.path.abspath(_TRACKER_FILE)
    if not os.path.isfile(path):
        logger.warning("Tracker list not found at %s", path)
        _tracker_cache = []
        return _tracker_cache

    try:
        with open(path) as f:
            data = json.load(f)
        if isinstance(data, dict) and "trackers" in data:
            data = data["trackers"]
        if isinstance(data, dict):
            data = list(data.values())
        _tracker_cache = data
        logger.debug("Loaded %d trackers from %s", len(data), path)
    except Exception as e:
        logger.error("Failed to load tracker list: %s", e)
        _tracker_cache = []

    return _tracker_cache


def _extract_class_names(analysis) -> set[str]:
    names: set[str] = set()
    try:
        for cls in analysis.get_classes():
            raw = cls.name or ""
            if raw.startswith("L") and raw.endswith(";"):
                names.add(raw[1:-1].replace("/", "."))
            else:
                names.add(raw.replace("/", "."))
    except Exception as e:
        logger.debug("Error extracting class names: %s", e)
    return names


def _extract_domains(urls: list) -> set[str]:
    domains: set[str] = set()
    for entry in urls:
        url_str = entry["url"] if isinstance(entry, dict) else str(entry)
        try:
            parsed = urlparse(url_str)
            host = parsed.hostname
            if host:
                domains.add(host)
        except Exception:
            pass
    return domains


def _match_code_signature(sig: str, haystack: set[str]) -> bool:
    if not sig:
        return False
    for prefix in sig.split("|"):
        prefix = prefix.strip()
        if not prefix:
            continue
        if any(item.startswith(prefix) for item in haystack):
            return True
    return False


def _match_network_signature(sig: str, domains: set[str]) -> bool:
    if not sig:
        return False
    parts = sig.split("|")
    for part in parts:
        domain = part.strip().replace(r"\.", ".")
        if not domain:
            continue
        if any(domain in d for d in domains):
            return True
    return False


def detect_trackers(analysis, all_strings: list[str], urls: list) -> dict:
    trackers = _load_tracker_list()
    if not trackers:
        return {"trackers": [], "tracker_count": 0}

    class_names = _extract_class_names(analysis)
    search_set: set[str] = class_names | set(all_strings)
    domains = _extract_domains(urls)

    matched: list[dict] = []
    seen_names: set[str] = set()

    for t in trackers:
        name = t.get("name", "")
        if not name or name in seen_names:
            continue

        code_sig = t.get("code_signature", "")
        net_sig = t.get("network_signature", "")

        code_match = _match_code_signature(code_sig, search_set)
        net_match = _match_network_signature(net_sig, domains)

        if code_match or net_match:
            seen_names.add(name)
            cats = t.get("categories", [])
            risk = max(
                (_TRACKER_CATEGORY_RISK.get(c, 4) for c in cats),
                default=4,
            )
            matched.append({
                "name": name,
                "categories": cats,
                "risk_score": risk,
                "code_match": code_match,
                "net_match": net_match,
                "code_signature": code_sig,
                "network_signature": net_sig,
            })

    matched.sort(key=lambda x: x["risk_score"], reverse=True)
    return {"trackers": matched, "tracker_count": len(matched)}
