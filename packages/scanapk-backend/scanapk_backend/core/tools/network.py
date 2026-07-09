from .base import get_static, as_json


def handle_extract_network_indicators(apk_path: str, **_kw) -> str:
    data = get_static(apk_path)
    return as_json({
        "urls": data.urls[:30],
        "ips": data.ips[:20],
    })


HANDLERS = {
    "extract_network_indicators": handle_extract_network_indicators,
}

DEFINITIONS = [
    {
        "type": "function",
        "function": {
            "name": "extract_network_indicators",
            "description": "Extract all embedded URLs and IP addresses from DEX bytecode",
            "parameters": {"type": "object", "properties": {}},
        },
    },
]
