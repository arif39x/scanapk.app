import logging
import math
import re
from collections import Counter

logger = logging.getLogger(__name__)

try:
    import lief
except ImportError:
    lief = None

try:
    from capstone import Cs, CS_ARCH_ARM, CS_ARCH_ARM64, CS_ARCH_X86
    from capstone import CS_MODE_ARM, CS_MODE_THUMB, CS_MODE_64, CS_MODE_32
except ImportError:
    Cs = None

_SUSPICIOUS_SYMBOLS: dict[str, str] = {
    "ptrace": "anti_debug",
    "dlopen": "dynamic_loading",
    "dlsym": "dynamic_loading",
    "dlclose": "dynamic_loading",
    "dlerror": "dynamic_loading",
    "socket": "network",
    "connect": "network",
    "sendto": "network",
    "recvfrom": "network",
    "inet_pton": "network",
    "fork": "process_control",
    "execve": "process_control",
    "kill": "process_control",
    "__system_property_get": "anti_vm",
    "popen": "shell_exec",
    "system": "shell_exec",
    "mmap": "memory_manipulation",
    "mprotect": "memory_manipulation",
    "memfd_create": "memory_manipulation",
}

_SUSPICIOUS_STRINGS: list[re.Pattern] = [
    re.compile(r"/proc/self/maps"),
    re.compile(r"/proc/self/status"),
    re.compile(r"/system/bin/su"),
    re.compile(r"/data/local/tmp"),
    re.compile(r"frida", re.IGNORECASE),
    re.compile(r"xposed", re.IGNORECASE),
    re.compile(r"magisk", re.IGNORECASE),
    re.compile(r"substrate", re.IGNORECASE),
]


def _shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counter = Counter(data)
    length = len(data)
    return -sum(
        (count / length) * math.log2(count / length) for count in counter.values()
    )


def _get_arch_info(binary) -> tuple[str, tuple | None]:
    try:
        header = binary.header
        machine = header.machine_type
    except AttributeError:
        return "unknown", None

    if machine == lief.ELF.ARCH.AARCH64:
        return "ARM64", (CS_ARCH_ARM64, CS_MODE_ARM)
    if machine == lief.ELF.ARCH.ARM:
        return "ARM", (CS_ARCH_ARM, CS_MODE_ARM)
    if machine == lief.ELF.ARCH.X86_64:
        return "x86_64", (CS_ARCH_X86, CS_MODE_64)
    if machine == lief.ELF.ARCH.I386:
        return "x86", (CS_ARCH_X86, CS_MODE_32)
    return f"machine_{machine}", None


def _analyze_sections(binary, lib_name: str) -> dict:
    sections_info: list[dict] = []
    high_entropy: list[dict] = []

    for section in binary.sections:
        name = section.name
        size = section.size
        if size == 0:
            continue
        raw = section.content
        entropy = _shannon_entropy(bytes(raw))
        flags: list[str] = []
        try:
            if section.has(lief.ELF.SECTION_FLAGS.EXECINSTR):
                flags.append("EXEC")
            if section.has(lief.ELF.SECTION_FLAGS.WRITE):
                flags.append("WRITE")
            if section.has(lief.ELF.SECTION_FLAGS.ALLOC):
                flags.append("ALLOC")
        except Exception:
            pass

        sections_info.append({
            "name": name,
            "virtual_address": hex(section.virtual_address),
            "size": size,
            "entropy": round(entropy, 4),
            "flags": flags,
        })

        if entropy > 7.0 and size > 512:
            high_entropy.append({
                "library": lib_name,
                "section": name,
                "size": size,
                "entropy": round(entropy, 4),
                "finding": f"High-entropy section ({name}) — possible packed/encrypted payload",
            })

    return {"sections": sections_info, "high_entropy": high_entropy}


def _analyze_symbols(binary, lib_name: str) -> dict:
    imports: list[dict] = []
    exports: list[dict] = []
    suspicious_symbols: list[dict] = []

    seen_sym: set[str] = set()

    for sym in binary.dynamic_symbols:
        name = sym.name or ""
        if not name or name in seen_sym:
            continue
        seen_sym.add(name)

        entry = {
            "name": name,
            "address": hex(sym.value) if sym.value else "0x0",
        }

        if sym.exported:
            entry["type"] = "export"
            exports.append(entry)
        elif sym.imported:
            entry["type"] = "import"
            imports.append(entry)
        else:
            continue

        for pattern, category in _SUSPICIOUS_SYMBOLS.items():
            if pattern in name.lower():
                suspicious_symbols.append({
                    "library": lib_name,
                    "symbol": name,
                    "category": category,
                    "type": "export" if sym.exported else "import",
                })
                break

    return {
        "imports": imports[:80],
        "exports": exports[:80],
        "suspicious_symbols": suspicious_symbols,
    }


def _scan_strings(binary, lib_name: str) -> list[dict]:
    findings: list[dict] = []
    try:
        raw = bytearray()
        for section in binary.sections:
            raw.extend(section.content)

        strings: list[str] = []
        current: list[int] = []
        for byte_val in raw:
            if 32 <= byte_val <= 126:
                current.append(byte_val)
            else:
                if len(current) >= 4:
                    strings.append(bytes(current).decode("ascii"))
                current = []
        if len(current) >= 4:
            strings.append(bytes(current).decode("ascii"))

        for pattern in _SUSPICIOUS_STRINGS:
            for s in strings:
                if pattern.search(s):
                    findings.append({
                        "library": lib_name,
                        "string": s[:100],
                        "pattern": pattern.pattern,
                    })
                    break
    except Exception as e:
        logger.debug("Error scanning strings in %s: %s", lib_name, e)

    return findings


def _disassemble_jni_functions(
    binary, lib_name: str, arch_info: tuple | None,
) -> list[dict]:
    if Cs is None:
        return [{"error": "Capstone not installed", "library": lib_name}]

    if arch_info is None or arch_info[0] is None:
        return []

    arch, default_mode = arch_info

    text_section = None
    for section in binary.sections:
        if section.name == ".text":
            text_section = section
            break

    if text_section is None:
        return []

    text_base = text_section.virtual_address
    text_data = bytes(text_section.content)

    results: list[dict] = []

    for sym in binary.dynamic_symbols:
        if not sym.exported:
            continue
        name = sym.name or ""
        if not name.startswith("Java_"):
            continue

        addr = sym.value
        if addr < text_base or addr >= text_base + len(text_data):
            continue

        offset = addr - text_base
        code = text_data[offset:offset + 64]

        # Try ARM mode first; if Thumb function (LSB set), use Thumb
        mode = default_mode
        if arch == CS_ARCH_ARM and (addr & 1):
            mode = CS_MODE_THUMB

        try:
            md = Cs(arch, mode)
            md.detail = False
            md.skipdata = True
            insns = list(md.disasm(code, addr))
            disasm = [
                {"address": hex(i.address), "mnemonic": i.mnemonic, "op_str": i.op_str}
                for i in insns[:20]
            ]
            results.append({
                "library": lib_name,
                "function": name,
                "address": hex(addr),
                "instructions_count": len(insns),
                "instructions_preview": disasm,
            })
        except Exception as e:
            logger.debug("Disassembly failed for %s in %s: %s", name, lib_name, e)

    return results


def analyze_native(apk) -> dict:
    result: dict = {
        "libraries": [],
        "total_libs": 0,
        "high_entropy_sections": [],
        "suspicious_findings": [],
        "jni_functions": [],
    }

    if lief is None:
        logger.warning("LIEF not installed — skipping native ELF analysis")
        so_files = [f for f in apk.get_files() if f.endswith(".so")]
        result["total_libs"] = len(so_files)
        for f in so_files:
            result["libraries"].append({
                "path": f, "name": f.split("/")[-1], "error": "LIEF not available",
            })
        return result

    so_files = [f for f in apk.get_files() if f.endswith(".so")]
    result["total_libs"] = len(so_files)

    for so_path in so_files:
        lib_name = so_path.split("/")[-1]
        lib_info: dict = {
            "path": so_path,
            "name": lib_name,
        }

        try:
            raw_bytes = apk.zip.read(so_path)
        except Exception:
            logger.debug("Could not read %s from APK", so_path)
            result["libraries"].append(lib_info)
            continue

        try:
            binary = lief.ELF.parse(list(raw_bytes))
        except Exception as e:
            lib_info["error"] = f"LIEF parse failed: {e}"
            logger.debug("LIEF parse failed for %s: %s", lib_name, e)
            result["libraries"].append(lib_info)
            continue

        if binary is None:
            lib_info["error"] = "LIEF returned None"
            result["libraries"].append(lib_info)
            continue

        try:
            lib_info["entry_point"] = hex(binary.entrypoint)
        except Exception:
            pass

        arch_name, arch_info = "unknown", None
        try:
            arch_name, arch_info = _get_arch_info(binary)
            lib_info["arch"] = arch_name
        except Exception as e:
            logger.debug("Arch detection failed for %s: %s", lib_name, e)

        try:
            sec_result = _analyze_sections(binary, lib_name)
            lib_info["sections"] = sec_result["sections"]
            result["high_entropy_sections"].extend(sec_result["high_entropy"])
        except Exception as e:
            logger.debug("Section analysis failed for %s: %s", lib_name, e)

        try:
            sym_result = _analyze_symbols(binary, lib_name)
            lib_info["import_count"] = len(sym_result["imports"])
            lib_info["export_count"] = len(sym_result["exports"])
            result["suspicious_findings"].extend(sym_result["suspicious_symbols"])
        except Exception as e:
            logger.debug("Symbol analysis failed for %s: %s", lib_name, e)

        try:
            string_findings = _scan_strings(binary, lib_name)
            result["suspicious_findings"].extend(string_findings)
        except Exception as e:
            logger.debug("String scan failed for %s: %s", lib_name, e)

        try:
            jni_results = _disassemble_jni_functions(binary, lib_name, arch_info)
            result["jni_functions"].extend(jni_results)
        except Exception as e:
            logger.debug("JNI disassembly failed for %s: %s", lib_name, e)

        result["libraries"].append(lib_info)

    return result
