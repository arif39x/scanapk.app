import json

from . import permissions, strings, network, manifest, native, apis, trackers

_TOOL_MODULES = [permissions, strings, network, manifest, native, apis, trackers]

TOOL_DEFINITIONS = []
TOOL_HANDLERS = {}

for mod in _TOOL_MODULES:
    TOOL_DEFINITIONS.extend(mod.DEFINITIONS)
    TOOL_HANDLERS.update(mod.HANDLERS)


def execute_tool(name: str, apk_path: str, **kwargs) -> str:
    handler = TOOL_HANDLERS.get(name)
    if not handler:
        return json.dumps({"error": f"Unknown tool: {name}"})
    return handler(apk_path, **kwargs)


__all__ = ["TOOL_DEFINITIONS", "TOOL_HANDLERS", "execute_tool"]
