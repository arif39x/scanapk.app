from .base import load_apk, as_json


_DANGEROUS_SHORT = (
    "READ_SMS",
    "RECEIVE_SMS",
    "SEND_SMS",
    "READ_PHONE_STATE",
    "READ_CONTACTS",
    "ACCESS_FINE_LOCATION",
    "ACCESS_COARSE_LOCATION",
    "RECORD_AUDIO",
    "CAMERA",
    "WRITE_EXTERNAL_STORAGE",
    "READ_EXTERNAL_STORAGE",
    "BIND_ACCESSIBILITY_SERVICE",
    "SYSTEM_ALERT_WINDOW",
    "BIND_NOTIFICATION_LISTENER_SERVICE",
    "BIND_DEVICE_ADMIN",
    "REQUEST_INSTALL_PACKAGES",
    "REQUEST_DELETE_PACKAGES",
)


def handle_list_permissions(apk_path: str, **_kw) -> str:
    a = load_apk(apk_path)
    perms = a.get_permissions()
    dangerous = [
        p for p in perms
        if p.startswith("android.permission.") and p.split(".")[-1] in _DANGEROUS_SHORT
    ]
    return as_json({
        "total": len(perms),
        "dangerous_count": len(dangerous),
        "dangerous": dangerous,
        "all": perms,
    })


HANDLERS = {
    "list_permissions": handle_list_permissions,
}

DEFINITIONS = [
    {
        "type": "function",
        "function": {
            "name": "list_permissions",
            "description": "List all APK permissions, highlighting dangerous ones",
            "parameters": {"type": "object", "properties": {}},
        },
    },
]
