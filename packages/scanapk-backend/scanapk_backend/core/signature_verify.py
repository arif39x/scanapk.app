import json
import logging
import os
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path

logger = logging.getLogger(__name__)

WEAK_HASH_ALGOS = {"md5", "sha1"}
KNOWN_SIGNERS_PATH = Path(__file__).resolve().parent.parent / "data" / "known_signers.json"

_known_signers_cache: dict[str, dict] | None = None


def _load_known_signers() -> dict[str, dict]:
    global _known_signers_cache
    if _known_signers_cache is not None:
        return _known_signers_cache

    try:
        with open(KNOWN_SIGNERS_PATH) as f:
            data = json.load(f)
    except Exception as e:
        logger.warning("Failed to load known_signers.json: %s", e)
        _known_signers_cache = {}
        return _known_signers_cache

    by_fp: dict[str, dict] = {}
    for entry in data.get("signers", []):
        fp = entry.get("sha256", "").upper().replace(" ", "")
        if fp:
            by_fp[fp] = entry
    _known_signers_cache = by_fp
    return by_fp


def _format_name(name) -> str:
    try:
        return name.human_friendly
    except Exception:
        pass
    try:
        native = name.native
        if isinstance(native, dict):
            return ", ".join(f"{k}={v}" for k, v in native.items())
    except Exception:
        pass
    return str(name)


def _parse_cert_info(cert) -> dict:
    sha256_fp = cert.sha256.hex().upper()
    sha256_display = " ".join(sha256_fp[i:i+2] for i in range(0, len(sha256_fp), 2))

    hash_algo = (cert.hash_algo or "").lower()
    weak_algo = hash_algo in WEAK_HASH_ALGOS

    now = datetime.now(timezone.utc)
    not_before = cert.not_valid_before
    not_after = cert.not_valid_after
    expired = not_after is not None and not_after < now
    not_yet_valid = not_before is not None and not_before > now

    self_signed = str(getattr(cert, "self_signed", "unknown")).lower()

    pk = cert.public_key
    key_algo = getattr(pk, "algorithm", "?")
    key_bits = getattr(pk, "bit_size", 0)

    known_signers = _load_known_signers()
    known_entry = known_signers.get(sha256_fp)
    known_name = known_entry.get("name") if known_entry else None
    known_org = known_entry.get("org") if known_entry else None
    known_type = known_entry.get("type") if known_entry else None

    return {
        "sha256_fingerprint": sha256_display,
        "sha256": sha256_fp,
        "issuer": _format_name(cert.issuer),
        "subject": _format_name(cert.subject),
        "serial_number": str(cert.serial_number),
        "not_valid_before": str(not_before) if not_before else None,
        "not_valid_after": str(not_after) if not_after else None,
        "expired": expired,
        "not_yet_valid": not_yet_valid,
        "hash_algorithm": hash_algo,
        "weak_hash_algorithm": weak_algo,
        "signature_algorithm": str(getattr(cert, "signature_algo", "?")),
        "self_signed": self_signed,
        "key_algorithm": key_algo,
        "key_bits": key_bits,
        "known_signer_name": known_name,
        "known_signer_org": known_org,
        "known_signer_type": known_type,
    }


def verify_apk_signature(apk_path: str) -> dict:
    from androguard.core.apk import APK

    a = APK(apk_path)

    result: dict = {
        "is_signed": False,
        "schemes": {
            "v1": a.is_signed_v1(),
            "v2": a.is_signed_v2(),
            "v3": a.is_signed_v3(),
            "v31": a.is_signed_v31() if hasattr(a, "is_signed_v31") else False,
        },
        "has_duplicate_signature_ids": a.has_duplicate_apk_signature_ids() if hasattr(a, "has_duplicate_apk_signature_ids") else False,
        "certificates": [],
        "flags": [],
        "apksigner_verify": None,
    }

    result["is_signed"] = a.is_signed()

    certs = a.get_certificates() or []
    for cert in certs:
        info = _parse_cert_info(cert)
        result["certificates"].append(info)

    if not result["is_signed"]:
        result["flags"].append("unsigned")
    else:
        if result["has_duplicate_signature_ids"]:
            result["flags"].append("tampered_duplicate_ids")
        if not result["schemes"].get("v2") and not result["schemes"].get("v3"):
            result["flags"].append("no_v2_v3_signing")

        for info in result["certificates"]:
            if info.get("expired"):
                result["flags"].append("expired_certificate")
            if info.get("not_yet_valid"):
                result["flags"].append("certificate_not_yet_valid")
            if info.get("weak_hash_algorithm"):
                result["flags"].append("weak_hash_algorithm")
            if info.get("self_signed") in ("yes", "maybe") and not info.get("known_signer_name"):
                result["flags"].append("self_signed")

            if not info.get("known_signer_name") and info.get("self_signed") not in ("yes", "maybe"):
                result["flags"].append("unknown_signer")
            elif info.get("known_signer_type") == "debug":
                result["flags"].append("debug_signer")

    result["apksigner_verify"] = _run_apksigner_verify(apk_path)

    return result


def _run_apksigner_verify(apk_path: str) -> dict | None:
    apksigner = _find_apksigner()
    if not apksigner:
        return None

    try:
        r = subprocess.run(
            [apksigner, "verify", "--verbose", apk_path],
            capture_output=True, text=True, timeout=30,
        )
        lines = r.stdout.strip().split("\n") if r.stdout else []
        structured = {
            "exit_code": r.returncode,
            "valid": r.returncode == 0,
            "stdout": r.stdout.strip(),
            "stderr": r.stderr.strip(),
            "schemes_verified": [],
        }
        for line in lines:
            line = line.strip()
            if "v1" in line.lower() and ("verified" in line.lower() or "present" in line.lower()):
                structured["schemes_verified"].append("v1")
            if "v2" in line.lower() and ("verified" in line.lower() or "present" in line.lower()):
                structured["schemes_verified"].append("v2")
            if "v3" in line.lower() and ("verified" in line.lower() or "present" in line.lower()):
                structured["schemes_verified"].append("v3")
        return structured
    except Exception as e:
        logger.debug("apksigner verify failed: %s", e)
        return {"error": str(e)}


def _find_apksigner() -> str | None:
    apksigner = shutil.which("apksigner")
    if apksigner:
        return apksigner

    sdk = os.environ.get("ANDROID_HOME") or os.environ.get("ANDROID_SDK_ROOT") or ""
    if sdk:
        bt = os.path.join(sdk, "build-tools")
        if os.path.isdir(bt):
            versions = sorted(os.listdir(bt), reverse=True)
            for v in versions:
                candidate = os.path.join(bt, v, "apksigner")
                if os.path.isfile(candidate):
                    return candidate
    return None
