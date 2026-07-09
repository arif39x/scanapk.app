import json
import re
import logging

try:
    from loguru import logger as loguru_logger
    loguru_logger.disable("androguard")
except ImportError:
    pass

from dataclasses import dataclass
from androguard.core.apk import APK
from androguard.core.dex import DEX
from androguard.core.analysis.analysis import Analysis

logger = logging.getLogger(__name__)

_URL_PATTERN = re.compile(r"https?://[A-Za-z0-9\-._~:/?#\[\]@!$&'()*+,;=%]{8,}")
_IP_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}(?::\d{2,5})?\b")


@dataclass
class StaticData:
    apk: APK
    dexes: list[DEX]
    analysis: Analysis
    all_strings: list[str]
    urls: list[str]
    ips: list[str]


_apk_cache: dict[str, StaticData] = {}


def _build_analysis(apk_path: str) -> StaticData:
    a = APK(apk_path)
    dexes: list[DEX] = []
    analysis = Analysis()
    all_strings: list[str] = []

    for raw_dex in a.get_all_dex():
        try:
            dex = DEX(raw_dex)
            dexes.append(dex)
            analysis.add(dex)
            all_strings.extend(dex.get_strings())
        except Exception as e:
            logger.warning("Skipping bad DEX in %s: %s", apk_path, e)

    analysis.create_xref()

    seen_urls: set[str] = set()
    seen_ips: set[str] = set()
    for s in all_strings:
        for u in _URL_PATTERN.findall(s):
            seen_urls.add(u)
        for ip in _IP_PATTERN.findall(s):
            seen_ips.add(ip)

    data = StaticData(
        apk=a,
        dexes=dexes,
        analysis=analysis,
        all_strings=all_strings,
        urls=sorted(seen_urls),
        ips=sorted(seen_ips),
    )
    _apk_cache[apk_path] = data
    return data


def get_static(apk_path: str) -> StaticData:
    if apk_path not in _apk_cache:
        return _build_analysis(apk_path)
    return _apk_cache[apk_path]


def load_apk(apk_path: str) -> APK:
    return get_static(apk_path).apk


def load_dex(apk_path: str) -> list[DEX]:
    return get_static(apk_path).dexes


def load_analysis(apk_path: str) -> Analysis:
    return get_static(apk_path).analysis


def as_json(result) -> str:
    return json.dumps(result, indent=2)
