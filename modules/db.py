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
"""

def get_conn(path="case.db"):
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.executescript(SCHEMA)
    return conn

def new_case(conn, name, examiner):
    cur = conn.execute(
        "INSERT INTO cases(name,examiner,created) VALUES(?,?,?)",
        (name, examiner, datetime.now(timezone.utc).isoformat()))
    conn.commit()
    return cur.lastrowid
