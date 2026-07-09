import logging
import os
import tempfile
import zipfile

logger = logging.getLogger(__name__)


def merge_apks(apk_paths: list[str], output_path: str) -> str:
    """Merge multiple split APKs into a single APK at *output_path*.

    DEX files are merged across all APKs; native libs are deduplicated
    (earlier APKs win).  The manifest from the first APK is used.
    """
    seen_dex: set[str] = set()
    seen_libs: set[str] = set()
    manifest_blob: bytes | None = None
    first = True

    with zipfile.ZipFile(output_path, "w", zipfile.ZIP_DEFLATED) as out:
        for apk in apk_paths:
            if not os.path.isfile(apk):
                logger.warning("Skipping non-existent APK: %s", apk)
                continue
            with zipfile.ZipFile(apk, "r") as z:
                for name in z.namelist():
                    # DEX files
                    if name.startswith("classes") and name.endswith(".dex"):
                        if name not in seen_dex:
                            seen_dex.add(name)
                            out.writestr(name, z.read(name))
                    # Manifest (first APK only)
                    elif name == "AndroidManifest.xml" and first:
                        manifest_blob = z.read(name)
                        out.writestr(name, manifest_blob)
                    # Native libs (first occurrence wins)
                    elif name.startswith("lib/") and name.endswith(".so"):
                        if name not in seen_libs:
                            seen_libs.add(name)
                            out.writestr(name, z.read(name))
                    # Everything else from the first APK
                    elif first and not name.startswith("META-INF"):
                        if name not in ("AndroidManifest.xml",):
                            out.writestr(name, z.read(name))
                first = False

        if manifest_blob is None:
            for apk in apk_paths:
                if os.path.isfile(apk):
                    with zipfile.ZipFile(apk, "r") as z:
                        if "AndroidManifest.xml" in z.namelist():
                            out.writestr("AndroidManifest.xml", z.read("AndroidManifest.xml"))
                            break

    return output_path


def merge_apks_temp(apk_paths: list[str]) -> str:
    """Merge split APKs into a temporary file and return its path."""
    fd, path = tempfile.mkstemp(suffix=".apk", prefix="scanapk_merged_")
    os.close(fd)
    return merge_apks(apk_paths, path)
