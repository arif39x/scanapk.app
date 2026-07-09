import re
import logging

try:
    from loguru import logger as loguru_logger
    loguru_logger.disable("androguard")
except ImportError:
    pass

from androguard.core.apk import APK
from androguard.core.dex import DEX
from androguard.core.analysis.analysis import Analysis
from scanapk_backend.core.call_graph import analyze_call_graph
from scanapk_backend.core.native_analysis import analyze_native
from scanapk_backend.core.tracker_detection import detect_trackers
from scanapk_backend.core.obfuscation_heuristics import compute_heuristics

logger = logging.getLogger(__name__)

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

_URL_PATTERN = re.compile(
    r"https?://[A-Za-z0-9\-._~:/?#\[\]@!$&'()*+,;=%]{8,}"
)
_IP_PATTERN = re.compile(
    r"\b(?:\d{1,3}\.){3}\d{1,3}(?::\d{2,5})?\b"
)


def _build_analysis(apk_path: str) -> tuple[APK, Analysis, list[str]]:
    a = APK(apk_path)
    analysis = Analysis()
    all_strings: list[str] = []
    for raw_dex in a.get_all_dex():
        try:
            dex = DEX(raw_dex)
            analysis.add(dex)
            all_strings.extend(dex.get_strings())
        except Exception as e:
            logger.warning("Skipping bad DEX: %s", e)
    analysis.create_xref()
    return a, analysis, all_strings


def _detect_xref_apis(analysis: Analysis) -> list[dict]:
    results: list[dict] = []
    seen: set[str] = set()
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
    return results, seen


def _detect_fallback_apis(all_strings: list[str], xref_seen: set[str]) -> list[dict]:
    results: list[dict] = []
    seen: set[str] = set(xref_seen)
    for s in all_strings:
        for api, category in _STRING_FALLBACK_APIS.items():
            if api in s and api not in seen:
                seen.add(api)
                results.append({
                    "api": api,
                    "category": category,
                    "detection": "string_fallback",
                })
    return results


def _extract_indicators(
    all_strings: list[str],
    analysis: Analysis,
) -> tuple[list[dict], list[dict], list[str]]:
    string_analysis = analysis.get_strings_analysis()
    seen_urls: set[str] = set()
    seen_ips: set[str] = set()
    urls: list[dict] = []
    ips: list[dict] = []
    raw_hits: list[str] = []

    for s in all_strings:
        sa = string_analysis.get(s)
        xrefs = list(sa.get_xref_from()) if sa else []

        for url in _URL_PATTERN.findall(s):
            if url not in seen_urls:
                seen_urls.add(url)
                urls.append({
                    "url": url,
                    "methods": [
                        {"class": ca.name, "method": ma.name}
                        for ca, ma in xrefs[:5]
                    ],
                })

        for ip in _IP_PATTERN.findall(s):
            if ip not in seen_ips:
                seen_ips.add(ip)
                ips.append({
                    "ip": ip,
                    "methods": [
                        {"class": ca.name, "method": ma.name}
                        for ca, ma in xrefs[:5]
                    ],
                })

        if len(raw_hits) < 30 and (xrefs or _URL_PATTERN.search(s) or _IP_PATTERN.search(s)):
            raw_hits.append(s[:120])

    return urls, ips, raw_hits


def scan_dex(apk_path: str) -> dict:
    result: dict = {
        "suspicious_apis": [],
        "urls": [],
        "ips": [],
        "receivers": [],
        "services": [],
        "activities": [],
        "native_libs": [],
        "raw_strings_sample": [],
        "api_details": [],
    }

    try:
        a, analysis, all_strings = _build_analysis(apk_path)
    except Exception as e:
        logger.error("Failed to build Analysis: %s", e)
        return result

    result["receivers"] = a.get_receivers()
    result["services"] = a.get_services()
    for activity in a.get_activities():
        if a.get_intent_filters("activity", activity):
            result["activities"].append(activity)
    result["native_libs"] = [f for f in a.get_files() if f.endswith(".so")]

    api_details, xref_seen = _detect_xref_apis(analysis)
    api_details.extend(_detect_fallback_apis(all_strings, xref_seen))

    result["api_details"] = api_details
    result["suspicious_apis"] = [d["api"] for d in api_details]

    urls, ips, raw_hits = _extract_indicators(all_strings, analysis)
    result["urls"] = urls
    result["ips"] = ips
    result["raw_strings_sample"] = raw_hits

    # Collect raw DEX bytes (used by code similarity and obfuscation heuristics)
    dex_raw = b""
    try:
        for raw_dex in a.get_all_dex():
            dex_raw += bytes(raw_dex)
    except Exception:
        pass
    result["_dex_raw"] = dex_raw
    result["_analysis"] = analysis

    cg_results = analyze_call_graph(analysis, api_details)
    result["call_graph"] = cg_results["call_graph"]
    result["exfiltration_chains"] = cg_results["exfiltration_chains"]
    result["no_ui_reachable"] = cg_results["no_ui_reachable"]

    result["obfuscation_heuristics"] = compute_heuristics(
        analysis, all_strings, dex_raw, cg_results,
    )

    result["native_analysis"] = analyze_native(a)
    result["tracker_detection"] = detect_trackers(analysis, all_strings, urls)

    return result
