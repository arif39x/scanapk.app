import os
import shutil
import subprocess
import sys
import tempfile
import time

from androguard.core.apk import APK

EMULATOR_NAME = "scanapk_test"
SYSTEM_IMAGE = "system-images;android-30;default;x86_64"

MONKEY_EVENTS = 500
BOOT_SETTLE_SECS = 4

_DANGEROUS_PERMISSIONS = {
    "android.permission.READ_SMS",
    "android.permission.RECEIVE_SMS",
    "android.permission.SEND_SMS",
    "android.permission.READ_PHONE_STATE",
    "android.permission.READ_CONTACTS",
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.ACCESS_COARSE_LOCATION",
    "android.permission.RECORD_AUDIO",
    "android.permission.CAMERA",
    "android.permission.WRITE_EXTERNAL_STORAGE",
    "android.permission.READ_EXTERNAL_STORAGE",
    "android.permission.PROCESS_OUTGOING_CALLS",
    "android.permission.BIND_ACCESSIBILITY_SERVICE",
    "android.permission.SYSTEM_ALERT_WINDOW",
    "android.permission.BIND_NOTIFICATION_LISTENER_SERVICE",
    "android.permission.QUERY_ALL_PACKAGES",
    "android.permission.REQUEST_INSTALL_PACKAGES",
    "android.permission.REQUEST_DELETE_PACKAGES",
    "android.permission.BIND_DEVICE_ADMIN",
    "android.permission.READ_MEDIA_IMAGES",
    "android.permission.READ_MEDIA_VIDEO",
    "android.permission.READ_MEDIA_AUDIO",
}


def _run(cmd, **kwargs):
    return subprocess.run(cmd, capture_output=True, text=True, **kwargs)


def _sdk_path():
    for var in ("ANDROID_HOME", "ANDROID_SDK_ROOT"):
        path = os.environ.get(var)
        if path and os.path.isdir(path):
            return path
    candidates = [
        os.path.expanduser("~/Android/Sdk"),
        os.path.expanduser("~/.android/sdk"),
        "/opt/android-sdk",
        "/usr/lib/android-sdk",
    ]
    for c in candidates:
        if os.path.isdir(c):
            return c
    return os.path.expanduser("~/Android/Sdk")


def _emulator_path():
    sdk = _sdk_path()
    return shutil.which("emulator") or os.path.join(sdk, "emulator", "emulator")

def _emulator_headless_path():
    sdk = _sdk_path()
    return os.path.join(
        sdk, "emulator", "qemu", "linux-x86_64", "qemu-system-x86_64-headless"
    )


def _avdmanager_path():
    sdk = _sdk_path()
    candidates = [
        shutil.which("avdmanager"),
        os.path.join(sdk, "cmdline-tools", "latest", "bin", "avdmanager"),
        os.path.join(sdk, "tools", "bin", "avdmanager"),
    ]
    for c in candidates:
        if c and os.path.isfile(c):
            return c
    return None


def _sdkmanager_path():
    sdk = _sdk_path()
    candidates = [
        shutil.which("sdkmanager"),
        os.path.join(sdk, "cmdline-tools", "latest", "bin", "sdkmanager"),
        os.path.join(sdk, "tools", "bin", "sdkmanager"),
    ]
    for c in candidates:
        if c and os.path.isfile(c):
            return c
    return None


def _env():
    env = os.environ.copy()
    env["ANDROID_HOME"] = _sdk_path()
    return env


def _adb():
    adb = shutil.which("adb")
    if not adb:
        adb = os.path.join(_sdk_path(), "platform-tools", "adb")
    return adb


def _find_apksigner():
    sdk = _sdk_path()
    apksigner = shutil.which("apksigner")
    if apksigner:
        return apksigner
    build_tools_dir = os.path.join(sdk, "build-tools")
    if os.path.isdir(build_tools_dir):
        versions = sorted(os.listdir(build_tools_dir), reverse=True)
        for v in versions:
            candidate = os.path.join(build_tools_dir, v, "apksigner")
            if os.path.isfile(candidate):
                return candidate
    return None


def _ensure_debug_keystore():
    keystore = os.path.expanduser("~/.android/debug.keystore")
    if os.path.isfile(keystore):
        return keystore
    os.makedirs(os.path.dirname(keystore), exist_ok=True)
    keytool = shutil.which("keytool")
    if not keytool:
        return None
    _run([
        keytool, "-genkey", "-v",
        "-keystore", keystore,
        "-alias", "androiddebugkey",
        "-keyalg", "RSA", "-keysize", "2048",
        "-validity", "10000",
        "-storepass", "android",
        "-keypass", "android",
        "-dname", "CN=Android Debug, O=Android, C=US",
    ])
    return keystore if os.path.isfile(keystore) else None


def _is_signed(apk_path):
    try:
        a = APK(apk_path)
        return a.is_signed_v1() or a.is_signed_v2() or a.is_signed_v3()
    except Exception:
        return False


def _sign_apk(apk_path):
    if _is_signed(apk_path):
        return apk_path

    print(f"  APK is not signed — signing with debug key...")
    apksigner = _find_apksigner()
    if not apksigner:
        print("  Warning: apksigner not found, cannot sign APK.")
        return apk_path

    keystore = _ensure_debug_keystore()
    if not keystore:
        print("  Warning: cannot create debug keystore, cannot sign APK.")
        return apk_path

    fd, signed_path = tempfile.mkstemp(suffix=".apk")
    os.close(fd)

    result = _run([
        apksigner, "sign",
        "--ks", keystore,
        "--ks-pass", "pass:android",
        "--ks-key-alias", "androiddebugkey",
        "--out", signed_path,
        apk_path,
    ])

    if result.returncode != 0:
        print(f"  Warning: APK signing failed ({result.stderr.strip()[:120]})")
        os.unlink(signed_path)
        return apk_path

    print(f"  Signed APK created at {os.path.basename(signed_path)}")
    return signed_path


def emulator_running():
    result = _run([_adb(), "devices"])
    for line in result.stdout.splitlines():
        if "emulator" in line and "device" in line:
            return True
    return False


def wait_for_boot(timeout=180):
    print("  Waiting for emulator to boot...", end="", flush=True)
    start = time.time()
    while time.time() - start < timeout:
        result = _run([_adb(), "shell", "getprop", "sys.boot_completed"])
        if result.stdout.strip() == "1":
            print(f" done ({int(time.time() - start)}s)")
            return True
        time.sleep(5)
        print(".", end="", flush=True)
    print(" timeout!")
    return False


def install_sdk():
    sdk = _sdk_path()
    print("Android SDK not found. Setting up automatically...")

    url = "https://dl.google.com/android/repository/commandlinetools-linux-11076708_latest.zip"
    zip_path = os.path.join(sdk, "cmdline-tools.zip")
    os.makedirs(sdk, exist_ok=True)

    print("  Downloading command-line tools...", flush=True)
    import urllib.request

    urllib.request.urlretrieve(url, zip_path)

    print("  Extracting...", flush=True)
    import shutil
    import zipfile

    extract_dir = os.path.join(sdk, "cmdline-tools")
    if os.path.isdir(extract_dir):
        shutil.rmtree(extract_dir)
    with zipfile.ZipFile(zip_path, "r") as zf:
        zf.extractall(extract_dir)
    src = os.path.join(extract_dir, "cmdline-tools")
    dst = os.path.join(extract_dir, "latest")
    if os.path.isdir(dst):
        shutil.rmtree(dst)
    shutil.move(src, dst)
    os.remove(zip_path)

    sdkmanager = _sdkmanager_path()
    os.chmod(sdkmanager, 0o755)

    print("  Accepting licenses...", flush=True)
    subprocess.run(
        f"yes 2>/dev/null | '{sdkmanager}' --licenses",
        shell=True,
        env=_env(),
        capture_output=True,
    )

    print("  Installing platform-tools and emulator...", flush=True)
    subprocess.run(
        [sdkmanager, "platform-tools", "emulator"], env=_env(), capture_output=True
    )

    avdmanager = _avdmanager_path()
    if avdmanager:
        os.chmod(avdmanager, 0o755)

    print(f"  SDK ready at {sdk}", flush=True)
    return True


def ensure_sdk():
    has_emulator = _emulator_path() and os.path.isfile(_emulator_path())
    has_headless = _emulator_headless_path() and os.path.isfile(_emulator_headless_path())
    if (has_emulator or has_headless) and _avdmanager_path():
        return True
    return install_sdk()


def ensure_avd():
    avdmanager = _avdmanager_path()
    result = _run([avdmanager, "list", "avd", "-c"], env=_env())
    if EMULATOR_NAME in result.stdout:
        return True

    sdkmanager = _sdkmanager_path()
    print(f"  Installing system image {SYSTEM_IMAGE}...", flush=True)
    subprocess.run([sdkmanager, SYSTEM_IMAGE], env=_env(), capture_output=True)

    print(f"  Creating AVD '{EMULATOR_NAME}'...", flush=True)
    result = _run(
        [
            avdmanager,
            "create",
            "avd",
            "-n",
            EMULATOR_NAME,
            "-k",
            SYSTEM_IMAGE,
            "-d",
            "Nexus 5X",
        ],
        env=_env(),
        input="no",
    )
    return result.returncode == 0


def _emulator_booted():
    result = _run([_adb(), "shell", "getprop", "sys.boot_completed"], timeout=10)
    return result and result.stdout.strip() == "1"


def start_emulator():
    print("\n" + "=" * 50)
    print(" Starting Android Emulator")
    print("=" * 50)

    if emulator_running():
        if _emulator_booted():
            print("-> Found running emulator — reusing it.")
            _spoof_build_props()
            return True
        print("-> Emulator is running but not fully booted — waiting...")
        if wait_for_boot():
            _spoof_build_props()
            return True
        print("-> Running emulator seems stuck — recycling.")
        _run([_adb(), "emu", "kill"])
        time.sleep(5)

    ensure_sdk()
    ensure_avd()

    emulator = _emulator_path()
    headless = False
    if not emulator or not os.path.isfile(emulator):
        emulator = _emulator_headless_path()
        if emulator and os.path.isfile(emulator):
            headless = True
            print("  Warning: only headless emulator found — no GUI window will appear.", flush=True)

    if not emulator or not os.path.isfile(emulator):
        print("  Error: no emulator binary found.", flush=True)
        return False

    print(f"  Launching emulator: {emulator}", flush=True)
    log_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "emulator.log")
    with open(log_path, "a") as log:
        subprocess.Popen(
            [
                emulator,
                "-avd",
                EMULATOR_NAME,
                "-no-audio",
                "-gpu",
                "swiftshader_indirect",
                "-memory",
                "2048",
            ],
            stdout=log,
            stderr=log,
            env=_env(),
        )

    time.sleep(10)

    if not wait_for_boot():
        print("-> Failed to boot emulator")
        return False

    _spoof_build_props()

    print("-> Emulator is ready")
    return True


def _spoof_build_props():
    print("  Spoofing build properties...", end="", flush=True)
    try:
        props = [
            ("ro.product.manufacturer", "samsung"),
            ("ro.product.model", "SM-G991B"),
            ("ro.product.brand", "samsung"),
            ("ro.product.name", "beyond1"),
            ("ro.build.fingerprint", "samsung/beyond1/beyond1:11/RP1A.200720.012/G991BXXU3CUID:user/release-keys"),
            ("ro.build.tags", "release-keys"),
            ("ro.build.type", "user"),
            ("ro.debuggable", "0"),
            ("ro.secure", "1"),
            ("ro.product.device", "beyond1"),
        ]
        for key, value in props:
            _run([_adb(), "shell", "setprop", key, value])
        print(" -> Build props spoofed")
    except Exception as e:
        print(f" -> Warning: build prop spoofing failed ({e})")


def _find_launchable_activity(apk_path):
    try:
        a = APK(apk_path)
        for activity in a.get_activities():
            filters = a.get_intent_filters("activity", activity)
            if not filters:
                continue
            actions = filters.get("action", [])
            categories = filters.get("category", [])
            if (
                "android.intent.action.MAIN" in actions
                and "android.intent.category.LAUNCHER" in categories
            ):
                pkg = a.get_package()
                if activity.startswith("."):
                    activity = pkg + activity
                return f"{pkg}/{activity}"
    except Exception:
        pass
    return None


def _get_dangerous_permissions(apk_path):
    try:
        a = APK(apk_path)
        return [p for p in a.get_permissions() if p in _DANGEROUS_PERMISSIONS]
    except Exception:
        return []


def _has_boot_receiver(apk_path):
    try:
        a = APK(apk_path)
        receivers = a.get_receivers()
        for r in receivers:
            filters = a.get_intent_filters("receiver", r)
            if not filters:
                continue
            actions = filters.get("action", [])
            if "android.intent.action.BOOT_COMPLETED" in actions:
                return True
        perms = a.get_permissions()
        if "android.permission.RECEIVE_BOOT_COMPLETED" in perms:
            return True
    except Exception:
        pass
    return False


def _already_installed(package_name: str) -> bool:
    result = _run([_adb(), "shell", "pm", "list", "packages", package_name], timeout=10)
    return bool(result and package_name in result.stdout)


def deploy_to_emulator(apk_path, package_name):
    if not start_emulator():
        return False

    deploy_apk = _sign_apk(apk_path)
    is_temp = deploy_apk != apk_path

    if _already_installed(package_name):
        print(f"  {package_name} already installed — skipping reinstall.")
    else:
        print(f"  Installing {os.path.basename(deploy_apk)}...")
        install_proc = _run([_adb(), "install", "-r", deploy_apk], timeout=60)
        if install_proc and "Success" in install_proc.stdout:
            print("-> Installation successful!")
        else:
            err = (install_proc.stdout + install_proc.stderr) if install_proc else "command timed out"
            print(f"-> Installation failed.\nADB: {err}")
            if is_temp:
                os.unlink(deploy_apk)
            return False

    if is_temp:
        os.unlink(deploy_apk)

    launched = False
    try:
        launch_target = _find_launchable_activity(apk_path)
        if launch_target:
            print(f"  Phase 1: Launching via explicit intent ({launch_target})...")
            launch_proc = _run(
                [
                    _adb(),
                    "shell",
                    "am",
                    "start",
                    "-n",
                    launch_target,
                ]
            )
            launched = launch_proc.returncode == 0
            if launched:
                print("-> Phase 1: App launched via explicit intent.")
            else:
                print(
                    f"-> Phase 1: Explicit intent failed ({launch_proc.stderr.strip()}). Falling back to monkey."
                )
        else:
            print("  Phase 1: No launchable activity found, falling back to monkey.")
    except Exception as e:
        print(f"-> Phase 1: Error resolving activity ({e}). Falling back to monkey.")

    if not launched:
        try:
            print("  Phase 1: Launching via monkey fallback...")
            launch_proc = _run(
                [
                    _adb(),
                    "shell",
                    "monkey",
                    "-p",
                    package_name,
                    "-c",
                    "android.intent.category.LAUNCHER",
                    "1",
                ]
            )
            launched = launch_proc.returncode == 0
            if launched:
                print("-> Phase 1: App launched via monkey.")
            else:
                print(
                    f"-> Phase 1: Monkey launch failed ({launch_proc.stderr.strip()})"
                )
        except Exception as e:
            print(f"-> Phase 1: Monkey fallback error ({e})")

    if not launched:
        print("-> Phase 1: Could not launch the app.")
        return False

    try:
        print(f"  Phase 2: Waiting {BOOT_SETTLE_SECS}s for app to settle...")
        time.sleep(BOOT_SETTLE_SECS)
        print("-> Phase 2: Settle delay complete.")
    except Exception as e:
        print(f"-> Phase 2: Settle delay error ({e})")

    try:
        print(f"  Phase 3: Running monkey with {MONKEY_EVENTS} random events...")
        monkey_cmd = [
            _adb(),
            "shell",
            "monkey",
            "-p",
            package_name,
            "--pct-touch",
            "40",
            "--pct-motion",
            "20",
            "--pct-nav",
            "10",
            "--throttle",
            "150",
            "--ignore-crashes",
            "--ignore-timeouts",
            "--ignore-security-exceptions",
            str(MONKEY_EVENTS),
        ]
        monkey_proc = _run(monkey_cmd, timeout=120)
        if monkey_proc.returncode == 0:
            print("-> Phase 3: Monkey interaction complete.")
        else:
            stderr = monkey_proc.stderr.strip()
            if "No events generated" in stderr:
                print(
                    "-> Phase 3: Monkey finished (no injectable events, UI may be blocked)."
                )
            else:
                print(f"-> Phase 3: Monkey exited with warnings ({stderr[:200]})")
    except subprocess.TimeoutExpired:
        print("-> Phase 3: Monkey timed out after 120s — continuing.")
    except Exception as e:
        print(f"-> Phase 3: Monkey error ({e})")

    try:
        dangerous = _get_dangerous_permissions(apk_path)
        if dangerous:
            print(f"  Phase 4: Granting {len(dangerous)} dangerous permission(s)...")
            granted = 0
            for perm in dangerous:
                result = _run(
                    [
                        _adb(),
                        "shell",
                        "pm",
                        "grant",
                        package_name,
                        perm,
                    ]
                )
                if result.returncode == 0:
                    granted += 1
            print(f"-> Phase 4: Granted {granted}/{len(dangerous)} permission(s).")
        else:
            print("  Phase 4: No dangerous permissions to grant.")
    except Exception as e:
        print(f"-> Phase 4: Permission grant error ({e})")

    try:
        if _has_boot_receiver(apk_path):
            print("  Phase 5: Sending BOOT_COMPLETED broadcast...")
            broadcast_proc = _run(
                [
                    _adb(),
                    "shell",
                    "am",
                    "broadcast",
                    "-a",
                    "android.intent.action.BOOT_COMPLETED",
                    "-p",
                    package_name,
                ]
            )
            if broadcast_proc.returncode == 0:
                print("-> Phase 5: BOOT_COMPLETED broadcast sent.")
            else:
                print(f"-> Phase 5: Broadcast failed ({broadcast_proc.stderr.strip()})")
        else:
            print("  Phase 5: No BOOT_COMPLETED receiver — skipping.")
    except Exception as e:
        print(f"-> Phase 5: Broadcast error ({e})")

    print("-> Interaction phases complete. App is running on the emulator.")
    return True
