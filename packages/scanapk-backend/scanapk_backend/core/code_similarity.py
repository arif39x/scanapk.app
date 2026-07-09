"""Code similarity: imphash, ssdeep-style fuzzy hash, TLSH-style hash."""

from __future__ import annotations

import hashlib
from typing import Optional

_B64CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"


# ---------------------------------------------------------------------------
# imphash
# ---------------------------------------------------------------------------

def compute_imphash(analysis, package: str = "") -> Optional[str]:
    """Compute an imphash from Androguard Analysis.

    Extracts all external method references (class->method) called by code
    within the DEX, normalises them, sorts, and SHA-256 hashes the result.
    If *package* is given, references to classes in that package are excluded
    (i.e. only "imported" / framework calls are kept).
    """
    imports: set[str] = set()
    skip_prefixes: list[str] = []
    if package:
        pkg_path = "L" + package.replace(".", "/")
        skip_prefixes.append(pkg_path)

    for method in analysis.get_methods():
        for _ca, callee, _offset in method.get_xref_to():
            cname: str = callee.get_class_name()
            mname: str = callee.name
            descr: str = callee.get_descriptor()
            if not cname or not mname:
                continue
            if any(cname.startswith(sp) for sp in skip_prefixes):
                continue
            sig = f"{cname}->{mname}{descr}"
            imports.add(sig)

    if not imports:
        return None

    normalised = sorted(imports)
    raw = ",".join(normalised)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# ssdeep-style fuzzy hash (context-triggered piecewise hash)
# ---------------------------------------------------------------------------

def _b64(val: int) -> str:
    return _B64CHARS[val & 63]


def compute_ssdeep(data: bytes) -> str:
    """Compute a ssdeep-style fuzzy hash of *data*.

    Returns a string ``"blocksize:signature"`` or ``""`` for empty input.
    """
    if not data:
        return ""

    # Pick a starting block size so we get roughly 32-64 chunks
    bs = 64
    while bs * 64 < len(data):
        bs *= 2
    bs = max(bs, 64)

    a, b = 1, 0
    sig: list[str] = []
    chunk_start = 0
    h = hashlib.sha256()

    for i, byte in enumerate(data):
        a = (a + byte) & 0xFFFF
        b = (b + a) & 0xFFFF

        if i > 0 and b % bs == (bs - 1):
            chunk = data[chunk_start : i + 1]
            h.update(chunk)
            sig.append(_b64(h.digest()[0]))
            h = hashlib.sha256()
            chunk_start = i + 1

    if chunk_start < len(data):
        h.update(data[chunk_start:])
        sig.append(_b64(h.digest()[0]))

    signature = "".join(sig)
    return f"{bs}:{signature}"


def _parse_ssdeep(h: str) -> tuple[int, str]:
    try:
        bs_str, sig = h.split(":", 1)
        return int(bs_str), sig
    except (ValueError, AttributeError):
        return 0, ""


def compare_ssdeep(h1: str, h2: str) -> int:
    """Compare two ssdeep-style hashes and return a similarity score 0-100."""
    bs1, sig1 = _parse_ssdeep(h1)
    bs2, sig2 = _parse_ssdeep(h2)
    if not sig1 or not sig2:
        return 0

    # Block sizes must be equal or adjacent (factor of 2)
    if bs1 != bs2:
        if bs1 > bs2 * 2 or bs2 > bs1 * 2:
            return 0

    max_len = max(len(sig1), len(sig2))
    if max_len == 0:
        return 0

    # Weighted edit-distance-like measure: count matching chars at same pos
    # and also check for shifted matches (insertions/deletions)
    matches = 0
    # Direct position matches
    for a, b in zip(sig1, sig2):
        if a == b:
            matches += 1

    # Cross-correlation: check if shorter sig appears as substring in longer
    short, long_ = (sig1, sig2) if len(sig1) <= len(sig2) else (sig2, sig1)
    if len(short) >= 3 and short in long_:
        matches += min(len(short), 5)  # bonus for substring match

    score = int((matches / max_len) * 100)
    return min(score, 100)


# ---------------------------------------------------------------------------
# TLSH-style locality-sensitive hash  (simplified)
# ---------------------------------------------------------------------------

def _tlsh_quarter_buckets(data: bytes) -> bytearray:
    """Compute 32 bucket-values (0-3) from byte frequencies in *data*."""
    freq = [0] * 256
    for byte in data:
        freq[byte] += 1

    sorted_f = sorted(freq)
    n = len(sorted_f)
    if n < 4:
        return bytearray(32)
    q1 = sorted_f[n // 4]
    q2 = sorted_f[n // 2]
    q3 = sorted_f[3 * n // 4]
    if q1 == q2 == q3:
        q3 = max(q2 + 1, 255)

    buckets = bytearray(32)
    for i, f in enumerate(freq):
        bidx = i // 8
        if f > q3:
            val = 3
        elif f > q2:
            val = 2
        elif f > q1:
            val = 1
        else:
            val = 0
        shift = (i % 8) * 2
        mask = (3 << shift) & 0xFF
        buckets[bidx] = (buckets[bidx] & ~mask) | ((val << shift) & mask)
    return buckets


def compute_tlsh(data: bytes) -> str:
    """Compute a position-aware TLSH-style locality-sensitive hash.

    Splits the data into 4 quarters, computes bucket histograms per quarter,
    and concatenates them for a more discriminating fingerprint.

    Returns a hex string or ``""`` for empty / very short input.
    """
    if not data or len(data) < 50:
        return ""

    # 4 quarters for positional sensitivity
    quarters = 4
    seg_len = len(data) // quarters
    all_buckets = bytearray()
    for qi in range(quarters):
        start = qi * seg_len
        end = start + seg_len if qi < quarters - 1 else len(data)
        all_buckets.extend(_tlsh_quarter_buckets(data[start:end]))

    body = bytes(all_buckets).hex()

    # Checksum: XOR of first 256 bytes
    checksum_val = 0
    for byte in data[:256]:
        checksum_val ^= byte

    # Length
    len_val = min(len(data), 0xFFFF)

    return f"T{len_val:04x}{checksum_val:02x}{body}"


def _tlsh_diff_bits(b1: int, b2: int) -> int:
    """Count bits that differ between two integers (max 8)."""
    return (b1 ^ b2).bit_count()


def compare_tlsh(h1: str, h2: str) -> int:
    """Compare two TLSH-style hashes and return a similarity score 0-100.

    100 = identical, 0 = completely different.
    """
    if h1 == h2:
        return 100
    if not h1 or not h2 or len(h1) < 10 or len(h1) != len(h2):
        return 0
    if h1[0] != "T" or h2[0] != "T":
        return 0

    try:
        body1 = bytes.fromhex(h1[7:])
        body2 = bytes.fromhex(h2[7:])
    except (ValueError, IndexError):
        return 0

    if len(body1) != len(body2):
        return 0

    total_bits = len(body1) * 8
    diff = sum(_tlsh_diff_bits(a, b) for a, b in zip(body1, body2))
    if total_bits == 0:
        return 0
    score = int((1 - diff / total_bits) * 100)
    return max(0, min(score, 100))


# ---------------------------------------------------------------------------
# Combined similarity
# ---------------------------------------------------------------------------

def compute_all_hashes(dex_raw: bytes, analysis, package: str = "") -> dict:
    """Compute imphash, ssdeep, and TLSH in one call.

    Returns a dict with keys ``imphash``, ``ssdeep``, ``tlsh`` (all
    strings, possibly empty).
    """
    return {
        "imphash": compute_imphash(analysis, package) or "",
        "ssdeep": compute_ssdeep(dex_raw),
        "tlsh": compute_tlsh(dex_raw),
    }


def best_similarity(
    scan_hashes: dict,
    known_hashes: list[dict],
    weights: Optional[dict] = None,
) -> list[dict]:
    """Compare *scan_hashes* against a list of known hash records.

    Each record in *known_hashes* should have keys ``imphash``, ``ssdeep``,
    ``tlsh``, ``package``, ``label``.

    Returns a list of matches sorted by combined score descending.
    """
    if weights is None:
        weights = {"imphash": 0.5, "ssdeep": 0.25, "tlsh": 0.25}

    results: list[dict] = []
    for kh in known_hashes:
        scores: dict[str, float] = {}
        # imphash: exact match or nothing
        if scan_hashes.get("imphash") and kh.get("imphash"):
            scores["imphash"] = 100.0 if scan_hashes["imphash"] == kh["imphash"] else 0.0
        else:
            scores["imphash"] = 0.0

        # ssdeep: fuzzy compare
        if scan_hashes.get("ssdeep") and kh.get("ssdeep"):
            scores["ssdeep"] = float(compare_ssdeep(scan_hashes["ssdeep"], kh["ssdeep"]))
        else:
            scores["ssdeep"] = 0.0

        # tlsh: fuzzy compare
        if scan_hashes.get("tlsh") and kh.get("tlsh"):
            scores["tlsh"] = float(compare_tlsh(scan_hashes["tlsh"], kh["tlsh"]))
        else:
            scores["tlsh"] = 0.0

        combined = sum(scores[k] * weights[k] for k in weights)
        if combined >= 50:
            results.append({
                "known_package": kh.get("package", "?"),
                "known_label": kh.get("label", ""),
                "combined_score": round(combined, 1),
                "imphash_match": scores.get("imphash", 0) == 100,
                "ssdeep_score": round(scores.get("ssdeep", 0)),
                "tlsh_score": round(scores.get("tlsh", 0)),
            })

    results.sort(key=lambda r: r["combined_score"], reverse=True)
    return results[:10]
