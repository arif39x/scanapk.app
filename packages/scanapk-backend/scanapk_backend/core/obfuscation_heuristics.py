import logging
import math
from collections import deque

logger = logging.getLogger(__name__)

_REFLECTION_APIS = {
    "Ljava/lang/Class;->forName",
    "Ljava/lang/reflect/Method;->invoke",
    "Ljava/lang/reflect/Field;->getDeclaredField",
    "Ljava/lang/reflect/Field;->getDeclaredFields",
    "Ljava/lang/reflect/Field;->setAccessible",
    "Ljava/lang/reflect/AccessibleObject;->setAccessible",
    "Ljava/lang/reflect/Array;->newInstance",
    "Ljava/lang/reflect/Proxy;->newProxyInstance",
}

_DYNAMIC_LOADING_APIS = {
    "Ldalvik/system/DexClassLoader;-><init>",
    "Ldalvik/system/PathClassLoader;-><init>",
    "Ldalvik/system/DexFile;->loadDex",
    "Ldalvik/system/InMemoryDexClassLoader;-><init>",
    "Ljava/lang/ClassLoader;->loadClass",
}

_STRING_ENCRYPTION_APIS = {
    "Landroid/util/Base64;->decode",
    "Landroid/util/Base64;->encodeToString",
    "Ljava/util/Base64;->getDecoder",
    "Ljava/util/Base64;->getEncoder",
    "Ljava/util/Base64$Decoder;->decode",
}

_XOR_PATTERNS = {
    "xor",
    "decrypt",
    "decryption_key",
}


def _count_xref_calls(analysis, api_set: set) -> int:
    count = 0
    found: set[str] = set()
    for method_sig in api_set:
        try:
            cls, meth = method_sig.rsplit(";->", 1)
            for ma in analysis.find_methods(
                classname=cls, methodname=meth, no_external=False
            ):
                callers = ma.get_xref_from()
                if callers:
                    found.add(method_sig)
                    count += len(callers)
        except Exception:
            continue
    return count


def _count_xref_methods(analysis, api_set: set) -> int:
    """Count distinct calling methods (not total call sites)."""
    callers_seen: set[str] = set()
    for method_sig in api_set:
        try:
            cls, meth = method_sig.rsplit(";->", 1)
            for ma in analysis.find_methods(
                classname=cls, methodname=meth, no_external=False
            ):
                for ca, meth_ma, _ in ma.get_xref_from():
                    try:
                        k = f"{ca.name}->{meth_ma.name}"
                        callers_seen.add(k)
                    except Exception:
                        pass
        except Exception:
            continue
    return len(callers_seen)


def _compute_shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    size = len(data)
    entropy = 0.0
    for c in freq:
        if c:
            p = c / size
            entropy -= p * math.log2(p)
    return round(entropy, 4)


def compute_heuristics(
    analysis,
    all_strings: list[str],
    dex_raw: bytes,
    call_graph: dict,
) -> dict:
    results: dict = {}

    # 1) Reflection ratio
    total_methods = call_graph.get("node_count", 0)
    reflection_callers = _count_xref_methods(analysis, _REFLECTION_APIS)
    reflection_ratio = round(reflection_callers / total_methods, 4) if total_methods > 0 else 0.0
    results["reflection_callers"] = reflection_callers
    results["reflection_ratio"] = reflection_ratio

    # 2) String encryption indicators
    enc_apicallers = _count_xref_methods(analysis, _STRING_ENCRYPTION_APIS)
    xor_count = sum(1 for s in all_strings if any(p in s.lower() for p in _XOR_PATTERNS))
    has_cipher_key_combo = False
    try:
        cipher_methods = set()
        for ma in analysis.find_methods(
            classname=r"Ljavax/crypto/Cipher", methodname=r".*", no_external=False
        ):
            for ca, _, _ in ma.get_xref_from():
                cipher_methods.add(f"{ca.name}->{ca.name}")
        key_methods = set()
        for ma in analysis.find_methods(
            classname=r"Ljavax/crypto/spec/SecretKeySpec", methodname=r".*",
            no_external=False
        ):
            for ca, _, _ in ma.get_xref_from():
                key_methods.add(f"{ca.name}->{ca.name}")
        has_cipher_key_combo = bool(cipher_methods & key_methods)
    except Exception:
        pass

    enc_weight = enc_apicallers + (3 if has_cipher_key_combo else 0) + min(xor_count, 5)
    results["encryption_api_callers"] = enc_apicallers
    results["xor_string_hits"] = xor_count
    results["has_cipher_key_combo"] = has_cipher_key_combo
    results["string_encryption_weight"] = min(enc_weight, 15)

    # 3) Dynamic loading
    dynamic_callers = _count_xref_methods(analysis, _DYNAMIC_LOADING_APIS)
    results["dynamic_loading_callers"] = dynamic_callers

    # 4) DEX entropy
    dex_entropy = _compute_shannon_entropy(dex_raw)
    results["dex_entropy"] = dex_entropy

    # 5) Dead code ratio
    dead_ratio = call_graph.get("dead_code_ratio", 0.0)
    dead_count = call_graph.get("dead_code_count", 0)
    results["dead_code_ratio"] = dead_ratio
    results["dead_code_count"] = dead_count

    return results
