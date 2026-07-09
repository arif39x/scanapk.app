import os
import subprocess
import time

MONITOR_DIR = os.path.expanduser("~/scanapk_monitor")
_logcat_proc = None

SUSPICIOUS_PATTERNS = (
    "SmsManager|sendTextMessage|Cipher|doFinal|Runtime\\.exec|"
    "ProcessBuilder|HttpURLConnection|URL\\.openConnection|"
    "DevicePolicyManager|lockNow|wipeData|crash|ANR|"
    "NotificationListenerService|onNotificationPosted|"
    "ACCESS_FINE_LOCATION|getLastKnownLocation|"
    "getDeviceId|getSubscriberId|READ_CONTACTS"
)


def start():
    global _logcat_proc

    os.makedirs(MONITOR_DIR, exist_ok=True)
    log_path = os.path.join(MONITOR_DIR, "logcat_monitor.log")
    log_fd = open(log_path, "w")

    print("  Starting logcat monitor...", flush=True)
    _logcat_proc = subprocess.Popen(
        ["adb", "logcat", "-v", "brief", "-T", "1"],
        stdout=log_fd,
        stderr=subprocess.STDOUT,
        text=True,
    )

    print(f"  Logcat log: {log_path}", flush=True)
    return True


def stop():
    global _logcat_proc
    if _logcat_proc:
        _logcat_proc.terminate()
        _logcat_proc.wait(timeout=5)
        print("  logcat monitor stopped", flush=True)
