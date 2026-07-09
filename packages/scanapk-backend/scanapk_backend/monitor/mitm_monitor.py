import os
import shutil
import signal
import subprocess
import sys
import threading
import time

MONITOR_DIR = os.path.expanduser("~/scanapk_monitor")
_mitm_proc = None
_tcpdump_proc = None
_sniff_thread = None
_sniff_stop = threading.Event()
_ADB_TIMEOUT = 15


def _adb():
    adb = shutil.which("adb")
    if not adb:
        adb = os.path.expanduser("~/Android/Sdk/platform-tools/adb")
    return adb


def _run(cmd, **kwargs):
    kwargs.setdefault("timeout", _ADB_TIMEOUT)
    try:
        return subprocess.run(cmd, capture_output=True, text=True, **kwargs)
    except subprocess.TimeoutExpired:
        print(
            f"  \u26a0 Command timed out after {_ADB_TIMEOUT}s: {' '.join(cmd[:3])}..."
        )
        return None


def install():
    if shutil.which("mitmdump"):
        pass  # already installed
    else:
        print("  Installing mitmproxy...", flush=True)
        try:
            result = subprocess.run(
                [sys.executable, "-m", "pip", "install", "mitmproxy"],
                capture_output=True,
                text=True,
                timeout=120,
            )
            if result.returncode != 0:
                print("  \u2716 mitmproxy install failed")
                return False
        except subprocess.TimeoutExpired:
            print("  \u2716 mitmproxy install timed out")
            return False

    if not shutil.which("tcpdump"):
        print("  Installing tcpdump for pcap capture...", flush=True)
        try:
            subprocess.run(
                ["sudo", "apt-get", "install", "-y", "tcpdump"],
                capture_output=True,
                text=True,
                timeout=60,
            )
        except Exception:
            print("  \u26a0 Could not install tcpdump (pcap capture unavailable)")
    return True


def start():
    global _mitm_proc

    os.makedirs(MONITOR_DIR, exist_ok=True)
    log_path = os.path.join(MONITOR_DIR, "mitmproxy.log")
    flow_path = os.path.join(MONITOR_DIR, "traffic.flow")

    print("  Starting mitmdump on port 8080...", flush=True)
    _mitm_proc = subprocess.Popen(
        [
            "mitmdump",
            "--listen-port",
            "8080",
            "-w",
            flow_path,
            "--set",
            "block_global=false",
        ],
        stdout=open(log_path, "w"),
        stderr=subprocess.STDOUT,
        text=True,
    )
    time.sleep(2)
    print(f"  Traffic log: {log_path}", flush=True)

    _start_pcap()
    return True


def pcap_path() -> str | None:
    path = os.path.join(MONITOR_DIR, "traffic.pcap")
    return path if os.path.isfile(path) else None


def _start_pcap():
    global _tcpdump_proc, _sniff_thread, _sniff_stop
    pcap_file = os.path.join(MONITOR_DIR, "traffic.pcap")

    tcpdump = shutil.which("tcpdump")
    if tcpdump:
        try:
            _tcpdump_proc = subprocess.Popen(
                [
                    tcpdump,
                    "-i", "any",
                    "-n",
                    "-s", "0",
                    "port", "8080",
                    "-w", pcap_file,
                ],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                preexec_fn=os.setpgrp,
            )
            time.sleep(0.5)
            if _tcpdump_proc.poll() is not None:
                _tcpdump_proc = subprocess.Popen(
                    [
                        tcpdump,
                        "-i", "lo",
                        "-n",
                        "-s", "0",
                        "port", "8080",
                        "-w", pcap_file,
                    ],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    preexec_fn=os.setpgrp,
                )
                time.sleep(0.5)
                if _tcpdump_proc.poll() is not None:
                    _tcpdump_proc = None
                    raise PermissionError("tcpdump permission denied")
            print(f"  PCAP capture (tcpdump): {pcap_file}", flush=True)
            return
        except Exception as e:
            _tcpdump_proc = None
            print(f"  \u26a0 tcpdump failed ({e})", flush=True)

    _sniff_stop.clear()
    _sniff_thread = _start_scapy_sniff(pcap_file)
    if _sniff_thread:
        print(f"  PCAP capture (scapy): {pcap_file}", flush=True)
    else:
        print("  \u26a0 PCAP capture unavailable", flush=True)


def _start_scapy_sniff(pcap_file: str) -> threading.Thread | None:
    try:
        from scapy.all import AsyncSniffer, conf
        from scapy.layers.inet import IP, TCP, UDP

        scapy_filter = "port 8080"

        def _sniff_worker():
            try:
                sniffer = AsyncSniffer(
                    filter=scapy_filter,
                    prn=None,
                    store=True,
                    timeout=None,
                )
                sniffer.start()
                _sniff_stop.wait()
                sniffer.stop()
                pkts = sniffer.results
                if pkts:
                    from scapy.all import wrpcap
                    wrpcap(pcap_file, pkts)
            except Exception:
                pass

        t = threading.Thread(target=_sniff_worker, daemon=True)
        t.start()
        return t
    except ImportError:
        return None


def _cert_hash_on_host(cert_path: str) -> str | None:
    try:
        result = subprocess.run(
            [
                "openssl",
                "x509",
                "-inform",
                "PEM",
                "-subject_hash_old",
                "-in",
                cert_path,
            ],
            capture_output=True,
            text=True,
            timeout=10,
        )
        return result.stdout.strip().split("\n")[0] if result.stdout.strip() else None
    except Exception:
        return None


def install_cert():
    ca_cert_cer = os.path.expanduser("~/.mitmproxy/mitmproxy-ca-cert.cer")
    ca_cert_pem = os.path.expanduser("~/.mitmproxy/mitmproxy-ca-cert.pem")

    pem_source = ca_cert_pem if os.path.isfile(ca_cert_pem) else ca_cert_cer

    if not os.path.isfile(pem_source):
        print("  \u26a0 mitmproxy CA cert not found — run mitmproxy once to generate")
        print("    HTTPS decryption unavailable, but monitoring continues")
        return False

    print("  Installing mitmproxy CA cert on emulator...", flush=True)

    if pem_source == ca_cert_cer:
        try:
            subprocess.run(
                [
                    "openssl",
                    "x509",
                    "-inform",
                    "DER",
                    "-in",
                    ca_cert_cer,
                    "-out",
                    "/tmp/mitmproxy-ca-cert.pem",
                ],
                capture_output=True,
                timeout=10,
            )
            pem_source = "/tmp/mitmproxy-ca-cert.pem"
        except Exception:
            print("  \u26a0 Host openssl missing — HTTPS decryption unavailable")
            print("    Install openssl: sudo apt install openssl")
            return False

    cert_hash = _cert_hash_on_host(pem_source)
    if not cert_hash:
        try:
            import hashlib

            with open(pem_source, "rb") as f:
                pem_data = f.read()
            import subprocess as sp

            result = sp.run(
                [
                    "openssl",
                    "x509",
                    "-inform",
                    "PEM",
                    "-subject_hash_old",
                    "-in",
                    pem_source,
                ],
                capture_output=True,
                text=True,
                timeout=10,
            )
            cert_hash = (
                result.stdout.strip().split("\n")[0] if result.stdout.strip() else None
            )
        except Exception:
            pass
        if not cert_hash:
            print("  \u26a0 Failed to compute cert hash — HTTPS decryption unavailable")
            return False

    _run([_adb(), "push", pem_source, f"/data/local/tmp/{cert_hash}.0"])
    _run([_adb(), "shell", "mount", "-o", "remount,rw", "/system"])
    _run(
        [
            _adb(),
            "shell",
            f"cp /data/local/tmp/{cert_hash}.0 /system/etc/security/cacerts/",
        ]
    )
    _run(
        [_adb(), "shell", "chmod", "644", f"/system/etc/security/cacerts/{cert_hash}.0"]
    )
    print("  CA cert installed", flush=True)
    return True


def set_proxy():
    print("  Setting emulator proxy to 10.0.2.2:8080...", flush=True)
    _run([_adb(), "shell", "settings", "put", "global", "http_proxy", "10.0.2.2:8080"])


def unset_proxy():
    _run([_adb(), "shell", "settings", "delete", "global", "http_proxy"])


def stop():
    global _mitm_proc, _tcpdump_proc, _sniff_thread

    _sniff_stop.set()
    if _sniff_thread:
        _sniff_thread.join(timeout=3)
        _sniff_thread = None

    if _tcpdump_proc:
        try:
            pgid = os.getpgid(_tcpdump_proc.pid)
            os.killpg(pgid, signal.SIGTERM)
            _tcpdump_proc.wait(timeout=5)
        except Exception:
            _tcpdump_proc.terminate()
            _tcpdump_proc.wait(timeout=3)
        _tcpdump_proc = None
        print("  tcpdump stopped", flush=True)

    if _mitm_proc:
        _mitm_proc.terminate()
        _mitm_proc.wait(timeout=5)
        _mitm_proc = None
    unset_proxy()
    print("  mitmdump stopped", flush=True)
