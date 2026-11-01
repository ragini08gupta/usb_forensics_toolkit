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
CREATE TABLE IF NOT EXISTS volume(
    id INTEGER PRIMARY KEY, case_id INTEGER, fs_type TEXT, oem_name TEXT,
    volume_serial TEXT, label TEXT, bytes_per_sector INTEGER,
    cluster_size INTEGER, total_bytes INTEGER, source TEXT);
CREATE TABLE IF NOT EXISTS reports(
    id INTEGER PRIMARY KEY, case_id INTEGER, path TEXT, sha256 TEXT,
    created TEXT, examiner TEXT);
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

# Phase 4/5 additions. Older case.db files are migrated in place.
EXTRA_COLUMNS = {
    "evidence": EVIDENCE_EXTRA_COLUMNS,
    "files": {
        "inode": "INTEGER",
        "sha256": "TEXT",            # hash of the file content (live or recovered)
        "md5": "TEXT",
        "session_id": "INTEGER",     # usb_events.id the file was written during (created time)
        "copy_indicator": "TEXT",    # e.g. "created after modified: copied onto the volume"
    },
    "usb_events": {
        "port": "TEXT",
        "bcd_device": "TEXT",
        "bcd_usb": "TEXT",
        "interfaces": "TEXT",        # comma list: mass_storage, hid_keyboard, ...
        "serial_index": "INTEGER",   # iSerialNumber string index (0 = device has no serial)
        "block_device": "TEXT",      # e.g. sdb
        "capacity_bytes": "INTEGER",
        "sources": "TEXT",           # kernel_log, usbmon, sysfs
        "score": "INTEGER",          # impersonation risk score
        "verdict": "TEXT",           # GENUINE / UNVERIFIED / SUSPICIOUS / LIKELY_SPOOFED
        "reasons": "TEXT",
        "profile": "TEXT",           # matched known-good profile name
        "after_hours": "INTEGER",
        "is_evidence_device": "INTEGER",
        "disconnect_note": "TEXT",   # inferred / still connected at end of log
    },
    "alerts": {
        "category": "TEXT",          # impersonation / policy / file / integrity
        "ref": "TEXT",               # what the alert is about (session id, path, ...)
        "ts": "TEXT",
    },
}


def _add_missing_columns(conn):
    """Older case.db files were created before the new columns existed."""
    for table, cols in EXTRA_COLUMNS.items():
        existing = {r["name"] for r in conn.execute(f"PRAGMA table_info({table})")}
        for col, typ in cols.items():
            if col not in existing:
                conn.execute(f"ALTER TABLE {table} ADD COLUMN {col} {typ}")
    conn.commit()


def get_conn(path="case.db", check_same_thread=True):
    conn = sqlite3.connect(path, check_same_thread=check_same_thread)
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


def add_alert(conn, case_id, severity, category, verdict, details, ref=None, ts=None):
    conn.execute(
        "INSERT INTO alerts(case_id,severity,category,verdict,details,ref,ts) "
        "VALUES(?,?,?,?,?,?,?)", (case_id, severity, category, verdict, details, ref, ts))
    conn.commit()
