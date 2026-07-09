import re
import warnings

from .base import get_static, as_json


def handle_search_strings(apk_path: str, pattern: str = "", **_kw) -> str:
    if not pattern:
        return as_json({"count": 0, "matches": [], "error": "pattern is required"})
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", FutureWarning)
            regex = re.compile(pattern, re.IGNORECASE)
    except re.error as e:
        return as_json({"count": 0, "matches": [], "error": str(e)})

    data = get_static(apk_path)
    matches = []
    seen = set()
    for s in data.all_strings:
        if regex.search(s) and s not in seen:
            seen.add(s)
            matches.append(s[:200])
    return as_json({"count": len(matches), "matches": matches[:50]})


def handle_get_raw_strings(apk_path: str, keyword: str = "", **_kw) -> str:
    data = get_static(apk_path)
    results = []
    seen = set()
    for s in data.all_strings:
        if not keyword or keyword.lower() in s.lower():
            if s not in seen and len(s) > 3:
                seen.add(s)
                results.append(s[:200])
    return as_json({"count": len(results), "strings": results[:40]})


HANDLERS = {
    "search_strings": handle_search_strings,
    "get_raw_strings": handle_get_raw_strings,
}

DEFINITIONS = [
    {
        "type": "function",
        "function": {
            "name": "search_strings",
            "description": "Search DEX bytecode strings with a regex pattern. Use this to find suspicious strings, class names, or API references.",
            "parameters": {
                "type": "object",
                "properties": {
                    "pattern": {
                        "type": "string",
                        "description": "Regex pattern to search for in DEX strings",
                    },
                },
                "required": ["pattern"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_raw_strings",
            "description": "Get raw DEX strings, optionally filtered by keyword",
            "parameters": {
                "type": "object",
                "properties": {
                    "keyword": {
                        "type": "string",
                        "description": "Optional keyword to filter strings",
                    },
                },
            },
        },
    },
]
