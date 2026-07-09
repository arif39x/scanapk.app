import logging
import os
import shutil
import subprocess
import tempfile
import zipfile

logger = logging.getLogger(__name__)

_BUNDLETOOL_PATHS = [
    "/usr/local/lib/bundletool.jar",
    "/opt/bundletool/bundletool.jar",
    os.path.expanduser("~/.android/bundletool.jar"),
]


def is_aab(path: str) -> bool:
    return path.lower().endswith(".aab")


def _find_bundletool() -> str | None:
    for p in _BUNDLETOOL_PATHS:
        if os.path.isfile(p):
            return p
    bundled = os.path.join(
        os.path.dirname(__file__), "..", "data", "bundletool", "bundletool.jar"
    )
    if os.path.isfile(bundled):
        return bundled
    return None


def _extract_from_aab(aab_path: str, out_apk: str) -> list[str]:
    """Extract DEX, manifest, and native libs from an AAB and write a
    standard APK ZIP to *out_apk*.  Returns a list of warning messages."""
    warnings: list[str] = []
    with zipfile.ZipFile(aab_path, "r") as src:
        all_names = src.namelist()

        dex_blobs: list[tuple[str, bytes]] = []
        manifest_blob: bytes | None = None
        native_blobs: list[tuple[str, bytes]] = []

        for name in all_names:
            if name.startswith("base/dex/") and name.endswith(".dex"):
                dex_blobs.append((name, src.read(name)))
            elif name == "base/manifest/AndroidManifest.xml":
                manifest_blob = src.read(name)
            elif "/native/" in name and name.endswith(".so"):
                native_blobs.append((name, src.read(name)))

        if not dex_blobs:
            warnings.append("No DEX files found in AAB")
        if manifest_blob is None:
            warnings.append("No AndroidManifest.xml found in AAB")

        with zipfile.ZipFile(out_apk, "w", zipfile.ZIP_DEFLATED) as out:
            dex_blobs.sort(key=lambda x: x[0])
            for i, (_, data) in enumerate(dex_blobs):
                arcname = "classes.dex" if i == 0 else f"classes{i+1}.dex"
                out.writestr(arcname, data)

            if manifest_blob is not None:
                out.writestr("AndroidManifest.xml", manifest_blob)

            for orig_path, data in native_blobs:
                parts = orig_path.split("/")
                try:
                    idx = parts.index("native")
                    rel = "/".join(parts[idx + 1:])
                    out.writestr(f"lib/{rel}", data)
                except ValueError:
                    out.writestr(orig_path, data)

    return warnings


def convert_aab(aab_path: str, output_dir: str | None = None) -> str:
    """Convert a .aab file to a standard .apk (single merged file).

    Tries ``bundletool build-apks --mode=universal`` first; falls back
    to direct ZIP extraction.
    """
    bundletool = _find_bundletool()
    apk_path: str | None = None

    if bundletool:
        tmp = tempfile.mkdtemp(prefix="scanapk_aab_")
        try:
            apks_zip = os.path.join(tmp, "output.apks")
            cmd = [
                "java", "-jar", bundletool,
                "build-apks",
                f"--bundle={aab_path}",
                f"--output={apks_zip}",
                "--mode=universal",
                "--overwrite",
            ]
            logger.info("Running bundletool: %s", " ".join(cmd))
            subprocess.run(cmd, check=True, capture_output=True, timeout=120)

            if output_dir:
                os.makedirs(output_dir, exist_ok=True)
                apk_path = os.path.join(output_dir, os.path.basename(aab_path).replace(".aab", ".apk"))
            else:
                apk_path = os.path.join(tmp, "converted.apk")

            with zipfile.ZipFile(apks_zip, "r") as apks_z:
                for name in apks_z.namelist():
                    if name.endswith(".apk"):
                        with open(apk_path, "wb") as f:
                            f.write(apks_z.read(name))
                        break

            if apk_path and os.path.isfile(apk_path):
                logger.info("bundletool created %s", apk_path)
                return apk_path
        except Exception as e:
            logger.warning("bundletool conversion failed, falling back to direct extraction: %s", e)

    # Fallback: direct AAB extraction
    if output_dir:
        os.makedirs(output_dir, exist_ok=True)
        out = os.path.join(output_dir, os.path.basename(aab_path).replace(".aab", ".apk"))
    else:
        fd, out = tempfile.mkstemp(suffix=".apk", prefix="scanapk_aab_")
        os.close(fd)

    warnings = _extract_from_aab(aab_path, out)
    for w in warnings:
        logger.warning(w)

    return out
