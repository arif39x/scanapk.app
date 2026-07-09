"""SQLite database for storing and querying known APK hashes."""

from __future__ import annotations

import json
import os
import sqlite3
import time
from typing import Any
from scanapk_backend.core.code_similarity import best_similarity

DB_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "data")
DB_PATH = os.path.join(DB_DIR, "known_hashes.db")


def _ensure_dir() -> None:
    os.makedirs(DB_DIR, exist_ok=True)


def _conn() -> sqlite3.Connection:
    _ensure_dir()
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_db() -> None:
    """Create tables if they don't exist."""
    conn = _conn()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS known_hashes (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            package     TEXT NOT NULL,
            app_name    TEXT DEFAULT '',
            imphash     TEXT DEFAULT '',
            ssdeep      TEXT DEFAULT '',
            tlsh        TEXT DEFAULT '',
            label       TEXT DEFAULT 'unknown',
            source      TEXT DEFAULT '',
            first_seen  INTEGER NOT NULL,
            last_seen   INTEGER NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_known_imphash ON known_hashes(imphash);
        CREATE INDEX IF NOT EXISTS idx_known_package ON known_hashes(package);

        CREATE TABLE IF NOT EXISTS scan_log (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            package     TEXT NOT NULL,
            app_name    TEXT DEFAULT '',
            imphash     TEXT DEFAULT '',
            ssdeep      TEXT DEFAULT '',
            tlsh        TEXT DEFAULT '',
            similarity  TEXT DEFAULT '[]',
            scanned_at  INTEGER NOT NULL
        );
    """)
    conn.commit()
    conn.close()
    print(f"  Hash DB ready: {DB_PATH}")


# ---------------------------------------------------------------------------
# Known-hash CRUD
# ---------------------------------------------------------------------------

def store_known_hash(
    package: str,
    app_name: str = "",
    imphash: str = "",
    ssdeep: str = "",
    tlsh: str = "",
    label: str = "unknown",
    source: str = "",
) -> int:
    """Insert or update a known-malware hash record.

    If a record with the same **imphash** already exists its ``last_seen``
    is updated; otherwise a new row is inserted.
    Returns the row id.
    """
    now = int(time.time())
    conn = _conn()
    if imphash:
        existing = conn.execute(
            "SELECT id FROM known_hashes WHERE imphash = ?", (imphash,)
        ).fetchone()
        if existing:
            conn.execute(
                "UPDATE known_hashes SET last_seen=?, package=?, app_name=?, "
                "ssdeep=?, tlsh=?, label=?, source=? WHERE id=?",
                (now, package, app_name, ssdeep, tlsh, label, source, existing["id"]),
            )
            row_id = existing["id"]
        else:
            cur = conn.execute(
                "INSERT INTO known_hashes (package, app_name, imphash, ssdeep, "
                "tlsh, label, source, first_seen, last_seen) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (package, app_name, imphash, ssdeep, tlsh, label, source, now, now),
            )
            row_id = cur.lastrowid
    else:
        # No imphash — always insert
        cur = conn.execute(
            "INSERT INTO known_hashes (package, app_name, imphash, ssdeep, "
            "tlsh, label, source, first_seen, last_seen) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (package, app_name, imphash, ssdeep, tlsh, label, source, now, now),
        )
        row_id = cur.lastrowid
    conn.commit()
    conn.close()
    return row_id


def search_similar(scan_hashes: dict) -> list[dict]:
    """Compare *scan_hashes* against all known hashes.

    Returns matching records with combined score >= 50,
    sorted descending.
    """
    conn = _conn()
    rows = conn.execute("SELECT * FROM known_hashes").fetchall()
    conn.close()

    known = [dict(r) for r in rows]
    return best_similarity(scan_hashes, known)


def get_known_count() -> int:
    """Return the number of known-hash records."""
    conn = _conn()
    count = conn.execute("SELECT COUNT(*) FROM known_hashes").fetchone()[0]
    conn.close()
    return count


# ---------------------------------------------------------------------------
# Scan-log helpers
# ---------------------------------------------------------------------------

def log_scan(
    package: str,
    app_name: str,
    hashes: dict,
    matches: list[dict],
) -> int:
    """Log a scan result (hashes + similarity matches) to the DB."""
    conn = _conn()
    cur = conn.execute(
        "INSERT INTO scan_log (package, app_name, imphash, ssdeep, tlsh, "
        "similarity, scanned_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (
            package,
            app_name,
            hashes.get("imphash", ""),
            hashes.get("ssdeep", ""),
            hashes.get("tlsh", ""),
            json.dumps(matches),
            int(time.time()),
        ),
    )
    conn.commit()
    conn.close()
    return cur.lastrowid


# ---------------------------------------------------------------------------
# JSON import / export
# ---------------------------------------------------------------------------

def import_json(path: str) -> int:
    """Import known hashes from a JSON file.

    Expected format::

        [{"package": "...", "imphash": "...", "ssdeep": "...",
          "tlsh": "...", "label": "malware", "source": "..."}, ...]
    """
    with open(path) as f:
        records = json.load(f)
    count = 0
    for rec in records:
        store_known_hash(
            package=rec.get("package", "unknown"),
            app_name=rec.get("app_name", ""),
            imphash=rec.get("imphash", ""),
            ssdeep=rec.get("ssdeep", ""),
            tlsh=rec.get("tlsh", ""),
            label=rec.get("label", "unknown"),
            source=rec.get("source", ""),
        )
        count += 1
    return count


def export_json(path: str) -> int:
    """Export all known hashes to a JSON file."""
    conn = _conn()
    rows = conn.execute("SELECT * FROM known_hashes").fetchall()
    conn.close()
    records = [dict(r) for r in rows]
    with open(path, "w") as f:
        json.dump(records, f, indent=2)
    return len(records)
