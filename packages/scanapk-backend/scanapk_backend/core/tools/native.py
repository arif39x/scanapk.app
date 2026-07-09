from .base import get_static, as_json
from scanapk_backend.core.native_analysis import analyze_native


def handle_list_native_libs(apk_path: str, **_kw) -> str:
    data = get_static(apk_path)
    libs = [f for f in data.apk.get_files() if f.endswith(".so")]

    native_analysis = analyze_native(data.apk)
    suspicious = native_analysis.get("suspicious_findings", []) or []
    high_entropy = native_analysis.get("high_entropy_sections", []) or []
    jni = native_analysis.get("jni_functions", []) or []

    summary = {
        "count": len(libs),
        "libraries": [
            {
                "path": f,
                "suspicious_findings": [
                    s for s in suspicious if s.get("library") == f.split("/")[-1]
                ],
            }
            for f in libs
        ],
        "suspicious_categories": list(set(
            f.get("category", "") for f in suspicious if "category" in f
        )),
        "high_entropy_sections": high_entropy,
        "jni_functions": [
            {
                "library": j.get("library"),
                "function": j.get("function"),
                "instructions_count": j.get("instructions_count", 0),
            }
            for j in jni[:10]
        ],
    }
    return as_json(summary)


HANDLERS = {
    "list_native_libs": handle_list_native_libs,
}

DEFINITIONS = [
    {
        "type": "function",
        "function": {
            "name": "list_native_libs",
            "description": (
                "List and analyze bundled native (.so) libraries. "
                "Returns ELF header info, imported/exported symbols, "
                "suspicious API usage (ptrace, dlopen, socket, etc.), "
                "high-entropy sections (packed payloads), and JNI function disassembly."
            ),
            "parameters": {"type": "object", "properties": {}},
        },
    },
]
