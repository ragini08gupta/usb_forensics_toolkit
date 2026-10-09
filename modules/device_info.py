import re
from datetime import datetime

TS = r"(?P<ts>\w{3}\s+\d+\s[\d:]{8})"
RE_FOUND = re.compile(TS + r".*usb (?P<port>[\d.-]+): New USB device found, "
                           r"idVendor=(?P<vid>\w+), idProduct=(?P<pid>\w+)")
RE_PROD = re.compile(r"usb (?P<port>[\d.-]+): Product: (?P<v>.+)")
RE_MANU = re.compile(r"usb (?P<port>[\d.-]+): Manufacturer: (?P<v>.+)")
RE_SER = re.compile(r"usb (?P<port>[\d.-]+): SerialNumber: (?P<v>.+)")
RE_DISC = re.compile(TS + r".*usb (?P<port>[\d.-]+): USB disconnect")


def parse_ts(s, year):
    # syslog has no year, so the caller supplies it
    return datetime.strptime(f"{year} {' '.join(s.split())}",
                             "%Y %b %d %H:%M:%S").isoformat()


def parse_log(path, year=2026):
    devices, open_by_port = [], {}
    with open(path) as fh:
        for line in fh:
            if m := RE_FOUND.search(line):
                d = {"vid": m["vid"], "pid": m["pid"], "serial": None,
                     "manufacturer": None, "product": None,
                     "connected": parse_ts(m["ts"], year), "disconnected": None}
                devices.append(d)
                open_by_port[m["port"]] = d
            elif m := RE_PROD.search(line):
                if m["port"] in open_by_port:
                    open_by_port[m["port"]]["product"] = m["v"].strip()
            elif m := RE_MANU.search(line):
                if m["port"] in open_by_port:
                    open_by_port[m["port"]]["manufacturer"] = m["v"].strip()
            elif m := RE_SER.search(line):
                if m["port"] in open_by_port:
                    open_by_port[m["port"]]["serial"] = m["v"].strip()
            elif m := RE_DISC.search(line):
                d = open_by_port.pop(m["port"], None)
                if d:
                    d["disconnected"] = parse_ts(m["ts"], year)
    return devices


def save_usb_events(conn, case_id, devices):
    for d in devices:
        conn.execute(
            "INSERT INTO usb_events(case_id,vid,pid,serial,manufacturer,product,"
            "connected,disconnected) VALUES(?,?,?,?,?,?,?,?)",
            (case_id, d["vid"], d["pid"], d["serial"], d["manufacturer"],
             d["product"], d["connected"], d["disconnected"]))
    conn.commit()
