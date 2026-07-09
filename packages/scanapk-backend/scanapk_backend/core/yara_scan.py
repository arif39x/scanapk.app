import logging
from pathlib import Path

logger = logging.getLogger(__name__)

YARA_DIR = Path(__file__).resolve().parent.parent / "data" / "yara"

_rules_cache = None


def load_rules():
    global _rules_cache
    if _rules_cache is not None:
        return _rules_cache

    try:
        import yara
    except ImportError:
        logger.warning("yara-python not installed — YARA scanning disabled")
        _rules_cache = []
        return _rules_cache

    rule_files = sorted(YARA_DIR.glob("*.yar"))
    if not rule_files:
        _rules_cache = []
        return _rules_cache

    rules = []
    for rf in rule_files:
        try:
            compiled = yara.compile(filepath=str(rf))
            rules.append((rf.name, compiled))
        except Exception as e:
            logger.warning("Failed to compile YARA rules from %s: %s", rf.name, e)

    _rules_cache = rules
    logger.info("Loaded %d YARA rule files (%d rules total)",
                len(rule_files), sum(len(r[1]) for r in rules))
    return rules


def _freeze_match(m):
    items = []
    try:
        for offset, identifier, data in m.strings:
            if isinstance(data, bytes):
                try:
                    decoded = data.decode("utf-8", errors="replace")
                except Exception:
                    decoded = data.hex()[:40]
            else:
                decoded = str(data)[:80]
            items.append({
                "identifier": identifier,
                "offset": offset,
                "matched": decoded,
            })
    except Exception:
        pass
    return {
        "rule": m.rule,
        "tags": list(m.tags),
        "meta": dict(m.meta),
        "matches": items[:30],
    }


def scan_bytes(data: bytes, source_label: str = "") -> list[dict]:
    matches = []
    rules = load_rules()
    if not rules:
        return matches

    for rule_file_name, compiled in rules:
        try:
            result = compiled.match(data=data)
            for m in result:
                entry = _freeze_match(m)
                entry["source"] = source_label
                entry["rule_file"] = rule_file_name
                matches.append(entry)
        except Exception as e:
            logger.debug("YARA scan error in %s: %s", rule_file_name, e)

    return matches


def scan_apk_artifacts(apk_path: str) -> list[dict]:
    all_matches: list[dict] = []

    try:
        from androguard.core.apk import APK
        a = APK(apk_path)
    except Exception as e:
        logger.warning("Failed to open APK for YARA scan: %s", e)
        return all_matches

    # 1) Scan DEX bytecode
    try:
        dex_data = bytearray()
        for raw_dex in a.get_all_dex():
            dex_data.extend(raw_dex)
        if dex_data:
            all_matches.extend(scan_bytes(bytes(dex_data), source_label="dex"))
    except Exception as e:
        logger.debug("YARA DEX scan failed: %s", e)

    # 2) Scan decoded manifest XML
    try:
        from androguard.core.bytecodes.axml import AXMLPrinter
        raw_axml = a.get_android_manifest_axml()
        if raw_axml:
            axml = AXMLPrinter(raw_axml)
            manifest_obj = axml.get_xml_obj()
            if manifest_obj is not None:
                xml_text = str(manifest_obj)
                all_matches.extend(scan_bytes(
                    xml_text.encode("utf-8", errors="replace"),
                    source_label="manifest",
                ))
    except Exception as e:
        logger.debug("YARA manifest scan failed: %s", e)

    # 3) Scan extracted native .so files
    try:
        so_files = [f for f in a.get_files() if f.endswith(".so")]
        for so_path in so_files:
            try:
                so_data = a.get_file(so_path)
                if so_data:
                    all_matches.extend(
                        scan_bytes(so_data, source_label=f"so:{so_path}")
                    )
            except Exception as e:
                logger.debug("YARA .so scan failed for %s: %s", so_path, e)
    except Exception as e:
        logger.debug("YARA native lib enumeration failed: %s", e)

    return all_matches
