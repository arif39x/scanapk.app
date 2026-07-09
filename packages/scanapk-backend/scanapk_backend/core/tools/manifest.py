from .base import load_apk, as_json


def handle_list_manifest_components(apk_path: str, **_kw) -> str:
    a = load_apk(apk_path)
    exported_activities = []
    for activity in a.get_activities():
        if a.get_intent_filters("activity", activity):
            exported_activities.append(activity)
    return as_json({
        "receivers": a.get_receivers(),
        "services": a.get_services(),
        "exported_activities": exported_activities,
        "all_activities": a.get_activities(),
    })


def handle_get_app_info(apk_path: str, **_kw) -> str:
    a = load_apk(apk_path)
    return as_json({
        "app_name": a.get_app_name(),
        "package": a.get_package(),
        "target_sdk": a.get_target_sdk_version(),
        "min_sdk": a.get_min_sdk_version(),
        "version": a.get_androidversion_name(),
        "version_code": a.get_androidversion_code(),
    })


HANDLERS = {
    "list_manifest_components": handle_list_manifest_components,
    "get_app_info": handle_get_app_info,
}

DEFINITIONS = [
    {
        "type": "function",
        "function": {
            "name": "list_manifest_components",
            "description": "List receivers, services, and activities from the manifest",
            "parameters": {"type": "object", "properties": {}},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_app_info",
            "description": "Get basic app info: name, package, SDK versions",
            "parameters": {"type": "object", "properties": {}},
        },
    },
]
