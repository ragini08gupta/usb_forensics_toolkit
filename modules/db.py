import sqlite3
from datetime import datetime, timezone

SCHEMA = """
CREATE TABLE IF NOT EXISTS cases(
    id INTEGER PRIMARY KEY, name TEXT, examiner TEXT, created TEXT);
CREATE TABLE IF NOT EXISTS evidence(
    id INTEGER PRIMARY KEY, case_id INTEGER, source_path TEXT,
    sha256_before TEXT, sha256_after TEXT, md5 TEXT,
    acquired_at TEXT, examiner TEXT, tool TEXT);
CREATE TABLE IF NOT EXISTS files(
    id INTEGER PRIMARY KEY, case_id INTEGER, path TEXT, name TEXT, size INTEGER,
    created TEXT, modified TEXT, accessed TEXT,
    deleted INTEGER, recovered_path TEXT, hidden INTEGER,
    suspicious INTEGER, reasons TEXT);
CREATE TABLE IF NOT EXISTS usb_events(
    id INTEGER PRIMARY KEY, case_id INTEGER, vid TEXT, pid TEXT, serial TEXT,
    manufacturer TEXT, product TEXT, connected TEXT, disconnected TEXT);
CREATE TABLE IF NOT EXISTS events(
    id INTEGER PRIMARY KEY, case_id INTEGER, ts TEXT, source TEXT,
    kind TEXT, description TEXT);
CREATE TABLE IF NOT EXISTS alerts(
    id INTEGER PRIMARY KEY, case_id INTEGER, severity TEXT,
    verdict TEXT, details TEXT);
CREATE TABLE IF NOT EXISTS custody_log(
    id INTEGER PRIMARY KEY, case_id INTEGER, evidence_id INTEGER,
    ts TEXT, examiner TEXT, action TEXT, details TEXT);
"""

# Columns added to the original evidence table by writeblock.py (Vijay).
# Original meaning kept:  sha256_before = SHA-256 of the source before acquisition,
#                         sha256_after  = SHA-256 of the acquired copy,
#                         md5           = MD5 of the source before acquisition.
EVIDENCE_EXTRA_COLUMNS = {
    "dest_path": "TEXT",           # where the acquired copy was written
    "size_bytes": "INTEGER",       # bytes copied
    "md5_after": "TEXT",           # MD5 of the acquired copy
    "sha256_source_after": "TEXT", # source re-hashed after acquisition (proves it is unchanged)
    "verified": "INTEGER",         # 1 = all hashes matched, 0 = not verified
    "status": "TEXT",              # VERIFIED / MISMATCH / FAILED
    "protection": "TEXT",          # which safeguards were actually applied
}


def _add_missing_columns(conn):
    """Older case.db files were created before the new columns existed."""
    existing = {r["name"] for r in conn.execute("PRAGMA table_info(evidence)")}
    for col, typ in EVIDENCE_EXTRA_COLUMNS.items():
        if col not in existing:
            conn.execute(f"ALTER TABLE evidence ADD COLUMN {col} {typ}")
    conn.commit()


def get_conn(path="case.db"):
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.executescript(SCHEMA)
    _add_missing_columns(conn)
    return conn

def new_case(conn, name, examiner):
    cur = conn.execute(
        "INSERT INTO cases(name,examiner,created) VALUES(?,?,?)",
        (name, examiner, datetime.now(timezone.utc).isoformat()))
    conn.commit()
    return cur.lastrowid
