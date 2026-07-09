import glob
import itertools
import os
import shutil
import subprocess
import sys
import time

FRIDA_VER = "17.12.0"
FRIDA_URL = (
    f"https://github.com/frida/frida/releases/download/{FRIDA_VER}/"
    f"frida-server-{FRIDA_VER}-android-x86_64.xz"
)
FRIDA_BIN = f"frida-server-{FRIDA_VER}-android-x86_64"
MONITOR_DIR = os.path.expanduser("~/scanapk_monitor")
HOOKS_DIR = os.path.join(os.path.dirname(__file__), "frida_hooks")
_frida_proc = None


def _get_hook_files():
    return sorted(glob.glob(os.path.join(HOOKS_DIR, "*.js")))


def _adb():
    adb = shutil.which("adb")
    if not adb:
        adb = os.path.expanduser("~/Android/Sdk/platform-tools/adb")
    return adb


def _run(cmd, **kwargs):
    kwargs.setdefault("timeout", 15)
    try:
        return subprocess.run(cmd, capture_output=True, text=True, **kwargs)
    except subprocess.TimeoutExpired:
        print(f"  \u26a0 Command timed out: {' '.join(cmd[:4])}...")
        return None


def install():
    if shutil.which("frida"):
        return True
    print("  Installing frida-tools...", flush=True)
    result = subprocess.run(
        [sys.executable, "-m", "pip", "install", "frida-tools"],
        capture_output=True,
        text=True,
    )
    return result.returncode == 0


def download_server():
    os.makedirs(MONITOR_DIR, exist_ok=True)
    local_path = os.path.join(MONITOR_DIR, FRIDA_BIN)
    if os.path.isfile(local_path):
        return local_path

    print("  Downloading frida-server...", flush=True)
    import lzma
    import urllib.request

    xz_path = local_path + ".xz"
    urllib.request.urlretrieve(FRIDA_URL, xz_path)
    with lzma.open(xz_path) as f_in, open(local_path, "wb") as f_out:
        f_out.write(f_in.read())
    os.remove(xz_path)
    os.chmod(local_path, 0o755)
    return local_path


def _frida_already_on_emulator(local_path: str) -> bool:
    local_size = os.path.getsize(local_path)
    result = _run(
        [_adb(), "shell", "ls", "-l", "/data/local/tmp/frida-server"],
        timeout=10,
    )
    if not result or result.returncode != 0:
        return False
    parts = result.stdout.split()
    if len(parts) < 5:
        return False
    try:
        remote_size = int(parts[4])
        return remote_size == local_size
    except (ValueError, IndexError):
        return False


def _frida_already_running() -> bool:
    result = _run([_adb(), "shell", "pidof", "frida-server"], timeout=5)
    return bool(result and result.stdout.strip())


def push_server(timeout: int = 120):
    local_path = download_server()

    if _frida_already_on_emulator(local_path):
        print("  frida-server already on emulator — skipping push.", flush=True)
        if _frida_already_running():
            print("  frida-server already running.", flush=True)
            return
        print("  Starting existing frida-server...", flush=True)
        _run([_adb(), "shell", "chmod", "755", "/data/local/tmp/frida-server"])
        _run([_adb(), "shell", "killall", "frida-server"])
        _run(
            [
                _adb(),
                "shell",
                "setsid",
                "/data/local/tmp/frida-server",
                ">",
                "/dev/null",
                "2>&1",
                "&",
            ]
        )
        time.sleep(3)
        print("  frida-server running on emulator", flush=True)
        return

    size_mb = os.path.getsize(local_path) / (1024 * 1024)
    print(f"  Pushing frida-server ({size_mb:.0f} MB) to emulator...", flush=True)
    print(f"  (This can take 30-90s over emulator ADB)", flush=True)

    start = time.time()
    spinner = itertools.cycle("⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏")

    proc = subprocess.Popen(
        [_adb(), "push", local_path, "/data/local/tmp/frida-server"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    while True:
        try:
            proc.wait(timeout=1)
            break
        except subprocess.TimeoutExpired:
            elapsed = time.time() - start
            if elapsed > timeout:
                proc.kill()
                print(
                    f"\n  \u2716 Timed out after {timeout}s — emulator ADB may be unresponsive"
                )
                print("    Run 'adb devices' to check connectivity")
                return
            print(f"\r    {next(spinner)} {elapsed:.0f}s", end="", flush=True)

    elapsed = time.time() - start
    print(f"\r  \u2713 Done in {elapsed:.1f}s", flush=True)
    print("\r  Setting up frida-server...", end="", flush=True)

    _run([_adb(), "shell", "chmod", "755", "/data/local/tmp/frida-server"])
    _run([_adb(), "shell", "killall", "frida-server"])

    _run(
        [
            _adb(),
            "shell",
            "setsid",
            "/data/local/tmp/frida-server",
            ">",
            "/dev/null",
            "2>&1",
            "&",
        ]
    )
    time.sleep(3)
    print("\r  \u2713 frida-server running on emulator", flush=True)


def attach(package_name):
    """Attach Frida hooks to a running app."""
    global _frida_proc

    hook_files = _get_hook_files()
    if not hook_files:
        print(f"  No hook scripts found in {HOOKS_DIR}")
        return False

    pid = None
    for _ in range(10):
        result = _run([_adb(), "shell", "pidof", package_name])
        if result and result.stdout.strip():
            pid = result.stdout.strip().split()[0]
            break
        time.sleep(1)

    if not pid:
        print(f"  Could not find PID for {package_name}")
        return False

    if not _frida_already_running():
        print("  Frida server not running, restarting...")
        push_server(timeout=30)
        time.sleep(2)

    log_path = os.path.join(MONITOR_DIR, "frida_hooks.log")
    log_fd = open(log_path, "w")

    venv_frida = os.path.join(os.path.dirname(sys.executable), "frida")
    if not os.path.isfile(venv_frida):
        venv_frida = "frida"

    print(f"  Attaching {len(hook_files)} Frida hook scripts to {package_name} (PID: {pid})...", flush=True)
    cmd = [venv_frida, "-U", "-p", pid]
    for f in hook_files:
        cmd.extend(["-l", f])
    _frida_proc = subprocess.Popen(
        cmd,
        stdout=log_fd,
        stderr=subprocess.STDOUT,
        text=True,
    )
    print(f"  Frida log: {log_path}", flush=True)
    return True


def stop():
    global _frida_proc
    if _frida_proc:
        _frida_proc.terminate()
        _frida_proc.wait(timeout=5)
    _run([_adb(), "shell", "killall", "frida-server"])
    print("  Frida stopped", flush=True)
