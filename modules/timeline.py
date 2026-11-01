"""
timeline.py - timeline reconstruction and file/session correlation (Ragini).

Time base: FAT stores LOCAL time without a zone and syslog has no zone
either, so both are shown as the suspect machine's local wall-clock time
(the "+00:00" pytsk3 adds is dropped). Custody events are the examiner's
UTC clock and are labelled as such.
"""
import csv
from datetime import datetime

from modules import db


def _t(s):
    return s[:19] if s else None


def _dt(s):
    return datetime.fromisoformat(s[:19]) if s else None


def correlate_files(conn, case_id):
    """Link each file to the USB session during which it was written.

    On FAT the created time is set when the file is written to the volume,
    so a created time inside a connection window means the file arrived
    during that session. Only sessions of storage devices are considered.
    Returns a list of (file_row, session_row) pairs."""
    sessions = conn.execute(
        "SELECT * FROM usb_events WHERE case_id=? AND interfaces LIKE '%mass_storage%' "
        "AND connected IS NOT NULL ORDER BY connected", (case_id,)).fetchall()
    # prefer the device identified as the imaged one, if any
    evid = [s for s in sessions if s["is_evidence_device"]]
    candidates = evid or sessions
    links = []
    for f in conn.execute("SELECT * FROM files WHERE case_id=?", (case_id,)).fetchall():
        c = _dt(f["created"])
        hit = None
        # several windows can contain the time when a session has no logged end
        # ("still connected at end of log"); the one that started LAST is the
        # one the file can belong to, so an open session never swallows later ones
        for s in candidates:
            start, end = _dt(s["connected"]), _dt(s["disconnected"])
            if c and start <= c and (end is None or c <= end):
                if hit is None or start > _dt(hit["connected"]):
                    hit = s
        conn.execute("UPDATE files SET session_id=? WHERE id=?",
                     (hit["id"] if hit else None, f["id"]))
        if hit:
            links.append((f, hit))
    conn.commit()
    return links


def file_alerts(conn, case_id):
    """Alerts for confidential/suspicious files written during after-hours sessions."""
    rows = conn.execute(
        "SELECT f.*, u.connected AS s_conn, u.after_hours AS s_after, u.serial AS s_serial "
        "FROM files f JOIN usb_events u ON u.id=f.session_id "
        "WHERE f.case_id=? AND f.suspicious=1 ORDER BY f.created", (case_id,)).fetchall()
    for f in rows:
        sev = "HIGH" if f["s_after"] else "MEDIUM"
        db.add_alert(conn, case_id, sev, "file", "FLAGGED_COPY",
                     f'{f["path"]} written to device serial {f["s_serial"]} at {_t(f["created"])}'
                     f'{" (after hours)" if f["s_after"] else ""}'
                     f'{"; later deleted" if f["deleted"] else ""}: {f["reasons"]}',
                     ref=f["path"], ts=_t(f["created"]))


def build_events(conn, case_id, include_custody=True):
    """Turn files, USB sessions and custody actions into timeline events."""
    conn.execute("DELETE FROM events WHERE case_id=?", (case_id,))
    sess = {s["id"]: s for s in conn.execute("SELECT * FROM usb_events WHERE case_id=?", (case_id,))}
    rows = []

    for f in conn.execute("SELECT * FROM files WHERE case_id=?", (case_id,)):
        tag = ""
        if f["session_id"] in sess:
            s = sess[f["session_id"]]
            tag = f' -> written during USB session #{s["id"]} ({s["product"] or s["vid"]})'
        flags = " [SUSPICIOUS]" if f["suspicious"] else ""
        if f["created"]:
            rows.append((_t(f["created"]), "filesystem", "FILE_CREATED", f["path"] + flags + tag))
        if f["modified"]:
            note = " (content timestamp, carried over from the source)" if f["copy_indicator"] else ""
            rows.append((_t(f["modified"]), "filesystem", "FILE_MODIFIED", f["path"] + note))
        if f["accessed"]:
            rows.append((_t(f["accessed"]), "filesystem", "FILE_ACCESSED",
                         f["path"] + " (FAT stores access date only)"))
        if f["deleted"] and f["modified"]:
            # FAT stores no deletion time, so mtime is only an approximation
            rows.append((_t(f["modified"]), "filesystem", "FILE_DELETED_ENTRY",
                         f["path"] + " (deletion time unknown, mtime used)"))

    for d in sess.values():
        desc = f'#{d["id"]} {d["vid"]}:{d["pid"]} {d["manufacturer"] or ""} {d["product"] or ""} ' \
               f'serial={d["serial"]}'
        if d["verdict"]:
            desc += f' [{d["verdict"]}]'
        if d["after_hours"]:
            desc += " [AFTER HOURS]"
        if d["connected"]:
            rows.append((_t(d["connected"]), "usb_log", "USB_CONNECT", desc))
        if d["disconnected"]:
            note = f' ({d["disconnect_note"]})' if d["disconnect_note"] else ""
            rows.append((_t(d["disconnected"]), "usb_log", "USB_DISCONNECT", desc + note))

    if include_custody:
        for c in conn.execute("SELECT * FROM custody_log WHERE case_id=?", (case_id,)):
            rows.append((_t(c["ts"]), "custody(UTC)", c["action"],
                         f'{c["examiner"]}: {c["details"] or ""}'))   # full text, never cut

    conn.executemany(
        "INSERT INTO events(case_id,ts,source,kind,description) VALUES(?,?,?,?,?)",
        [(case_id,) + r for r in rows])
    conn.commit()


def get_timeline(conn, case_id, include_custody=True):
    q = "SELECT ts, source, kind, description FROM events WHERE case_id=?"
    if not include_custody:
        q += " AND source NOT LIKE 'custody%'"
    return conn.execute(q + " ORDER BY ts, id", (case_id,)).fetchall()


def print_timeline(rows):
    print(f'{"TIME":<21}{"SOURCE":<14}{"EVENT":<22}DETAIL')
    for r in rows:
        print(f'{r["ts"][:19]:<21}{r["source"]:<14}{r["kind"]:<22}{r["description"]}')


def export_csv(rows, path):
    with open(path, "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["timestamp", "source", "event", "description"])
        for r in rows:
            w.writerow([r["ts"], r["source"], r["kind"], r["description"]])
