from .base import get_static, as_json

_SUSPICIOUS_METHODS = [
    ("getDeviceId",             "data_theft",    r"Landroid/telephony/TelephonyManager",        r"getDeviceId"),
    ("getSubscriberId",         "data_theft",    r"Landroid/telephony/TelephonyManager",        r"getSubscriberId"),
    ("getImei",                 "data_theft",    r"Landroid/telephony/TelephonyManager",        r"getImei"),
    ("getImsi",                 "data_theft",    r"Landroid/telephony/TelephonyManager",        r"getImsi"),
    ("getLine1Number",          "data_theft",    r"Landroid/telephony/TelephonyManager",        r"getLine1Number"),
    ("getLastKnownLocation",    "data_theft",    r"Landroid/location/LocationManager",          r"getLastKnownLocation"),
    ("getLatitude",             "data_theft",    r"Landroid/location/Location",                 r"getLatitude"),
    ("getLongitude",            "data_theft",    r"Landroid/location/Location",                 r"getLongitude"),
    ("sendTextMessage",         "sms_intercept", r"Landroid/telephony/SmsManager",              r"sendTextMessage"),
    ("sendMultipartTextMessage","sms_intercept", r"Landroid/telephony/SmsManager",              r"sendMultipartTextMessage"),
    ("abortBroadcast",          "sms_intercept", r"Landroid/content/BroadcastReceiver",         r"abortBroadcast"),
    ("Cipher",                  "crypto",        r"Ljavax/crypto/Cipher",                       r".*"),
    ("SecretKeySpec",           "crypto",        r"Ljavax/crypto/spec/SecretKeySpec",           r".*"),
    ("IvParameterSpec",         "crypto",        r"Ljavax/crypto/spec/IvParameterSpec",         r".*"),
    ("Runtime.exec",            "shell_exec",    r"Ljava/lang/Runtime",                         r"exec"),
    ("ProcessBuilder",          "shell_exec",    r"Ljava/lang/ProcessBuilder",                  r".*"),
    ("ServerSocket",            "network",       r"Ljava/net/ServerSocket",                     r".*"),
    ("DatagramSocket",          "network",       r"Ljava/net/DatagramSocket",                   r".*"),
    ("HttpURLConnection",       "network",       r"Ljava/net/HttpURLConnection",                r".*"),
    ("OkHttpClient",            "network",       r"Lokhttp3/OkHttpClient",                      r".*"),
    ("lockNow",                 "ransomware",    r"Landroid/app/admin/DevicePolicyManager",     r"lockNow"),
    ("wipeData",                "ransomware",    r"Landroid/app/admin/DevicePolicyManager",     r"wipeData"),
    ("setPasswordQuality",      "ransomware",    r"Landroid/app/admin/DevicePolicyManager",     r"setPasswordQuality"),
    ("setComponentEnabledSetting","persistence", r"Landroid/content/pm/PackageManager",         r"setComponentEnabledSetting"),
]

_STRING_FALLBACK_APIS = {
    "getAllContacts":       "data_theft",
    "RECEIVE_SMS":          "sms_intercept",
    "READ_SMS":             "sms_intercept",
    "su ":                  "shell_exec",
    "/system/bin/sh":       "shell_exec",
    "BIND_DEVICE_ADMIN":    "ransomware",
    "PACKAGE_REPLACED":     "persistence",
    "RECEIVE_BOOT_COMPLETED": "persistence",
}


def _detect_xref(analysis, seen: set[str]) -> list[dict]:
    results = []
    for label, category, class_pat, method_pat in _SUSPICIOUS_METHODS:
        if label in seen:
            continue
        for ma in analysis.find_methods(classname=class_pat, methodname=method_pat, no_external=False):
            callers = ma.get_xref_from()
            if callers:
                seen.add(label)
                caller_list = [
                    {"class": ca.name, "method": meth_ma.name}
                    for ca, meth_ma, _ in callers
                ]
                results.append({
                    "api": label,
                    "category": category,
                    "detection": "xref",
                    "callers": caller_list[:20],
                    "total_callers": len(callers),
                })
                break
    return results


def handle_search_suspicious_apis(apk_path: str, **_kw) -> str:
    data = get_static(apk_path)
    seen: set[str] = set()

    api_details = _detect_xref(data.analysis, seen)

    for s in data.all_strings:
        for api, category in _STRING_FALLBACK_APIS.items():
            if api in s and api not in seen:
                seen.add(api)
                api_details.append({
                    "api": api,
                    "category": category,
                    "detection": "string_fallback",
                })

    by_cat: dict[str, list[str]] = {}
    for d in api_details:
        by_cat.setdefault(d["category"], []).append(d["api"])
    return as_json({k: v for k, v in by_cat.items() if v})


HANDLERS = {
    "search_suspicious_apis": handle_search_suspicious_apis,
}

DEFINITIONS = [
    {
        "type": "function",
        "function": {
            "name": "search_suspicious_apis",
            "description": "Search for categories of suspicious API calls (data theft, SMS intercept, crypto, shell exec, ransomware, persistence)",
            "parameters": {"type": "object", "properties": {}},
        },
    },
]
