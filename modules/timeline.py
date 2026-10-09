import csv


def build_events(conn, case_id):
    """Turn files and USB sessions into timeline events and store them."""
    conn.execute("DELETE FROM events WHERE case_id=?", (case_id,))
    rows = []

    for f in conn.execute("SELECT * FROM files WHERE case_id=?", (case_id,)):
        for label, col in (("CREATED", "created"), ("MODIFIED", "modified"),
                           ("ACCESSED", "accessed")):
            if f[col]:
                rows.append((f[col], "filesystem", f"FILE_{label}", f["path"]))
        if f["deleted"] and f["modified"]:
            # FAT stores no deletion time, so mtime is only an approximation
            rows.append((f["modified"], "filesystem", "FILE_DELETED_ENTRY",
                         f["path"] + " (deletion time unknown, mtime used)"))

    for d in conn.execute("SELECT * FROM usb_events WHERE case_id=?", (case_id,)):
        desc = f'{d["vid"]}:{d["pid"]} {d["manufacturer"] or ""} {d["product"] or ""} serial={d["serial"]}'
        if d["connected"]:
            rows.append((d["connected"], "usb_log", "USB_CONNECT", desc))
        if d["disconnected"]:
            rows.append((d["disconnected"], "usb_log", "USB_DISCONNECT", desc))

    conn.executemany(
        "INSERT INTO events(case_id,ts,source,kind,description) VALUES(?,?,?,?,?)",
        [(case_id,) + r for r in rows])
    conn.commit()


def get_timeline(conn, case_id):
    return conn.execute(
        "SELECT ts, source, kind, description FROM events "
        "WHERE case_id=? ORDER BY ts", (case_id,)).fetchall()


def print_timeline(rows):
    print(f'{"TIME":<27}{"SOURCE":<12}{"EVENT":<20}DETAIL')
    for r in rows:
        print(f'{r["ts"][:19]:<27}{r["source"]:<12}{r["kind"]:<20}{r["description"]}')


def export_csv(rows, path):
    with open(path, "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["timestamp", "source", "event", "description"])
        for r in rows:
            w.writerow([r["ts"], r["source"], r["kind"], r["description"]])
