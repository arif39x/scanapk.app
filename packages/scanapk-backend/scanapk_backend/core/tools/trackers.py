from .base import get_static, as_json
from scanapk_backend.core.tracker_detection import detect_trackers


def handle_list_trackers(apk_path: str, **_kw) -> str:
    data = get_static(apk_path)
    result = detect_trackers(data.analysis, data.all_strings, data.urls)
    trackers = result.get("trackers", [])
    summary = {
        "total_trackers": len(trackers),
        "trackers": [
            {
                "name": t["name"],
                "categories": t.get("categories", []),
                "risk_score": t.get("risk_score", 4),
                "code_match": t.get("code_match", False),
                "net_match": t.get("net_match", False),
            }
            for t in trackers
        ],
    }
    return as_json(summary)


HANDLERS = {
    "list_trackers": handle_list_trackers,
}

DEFINITIONS = [
    {
        "type": "function",
        "function": {
            "name": "list_trackers",
            "description": (
                "Detect known third-party trackers (analytics, advertising, profiling, "
                "location, identification, crash reporting SDKs) embedded in the APK. "
                "Matches against the Exodus Privacy tracker list using DEX class names "
                "and network signatures."
            ),
            "parameters": {"type": "object", "properties": {}},
        },
    },
]
