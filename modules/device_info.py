"""
device_info.py - USB device identification and connection history (Ragini).

Sources:
  * parse_log(path)        Linux kernel log (journalctl -k -o short-iso / dmesg -T / syslog).
                           One dict per connection SESSION: VID/PID, bcdDevice,
                           strings, serial, interfaces the kernel bound
                           (usb-storage, HID keyboard/mouse), block device,
                           capacity, connect/disconnect times.
  * sysfs_identify(dev)    For a LIVE block device (/dev/sdb), walk sysfs up to
                           the USB parent and read the same fields (udev view).
"""
import os
import re
from datetime import datetime

# --- timestamps -----------------------------------------------------------
# Supported line formats (all kernel messages, e.g. journalctl -k / syslog / dmesg -T):
#   2026-10-08T22:50:02+0530 host kernel: usb 1-2: ...   (journalctl -k -o short-iso; has year)
#   [Thu Oct  8 22:50:02 2026] usb 1-2: ...               (dmesg -T; has year)
#   Oct  8 22:50:02 host kernel: [12000.0] usb 1-2: ...   (classic syslog; NO year -> log_year)
# Times are kept as the machine's local wall-clock time (zone-less), the same
# base FAT uses; an ISO offset, when present, is remembered in LAST_PARSE.
RE_ISO = re.compile(r"^(?P<iso>\d{4}-\d\d-\d\d[T ]\d\d:\d\d:\d\d)(?:[.,]\d+)?"
                    r"(?P<off>Z|[+-]\d\d:?\d\d)?\s")
RE_DMESG_T = re.compile(r"^\[(?:\w{3}\s+)?(?P<mon>\w{3})\s+(?P<d>\d+)\s(?P<t>\d\d:\d\d:\d\d)\s"
                        r"(?P<y>\d{4})\]")
RE_SYSLOG = re.compile(r"^(?P<mon>\w{3})\s+(?P<d>\d+)\s(?P<t>\d\d:\d\d:\d\d)\s")
RE_RAW_DMESG = re.compile(r"^\[\s*\d+\.\d+\]")

PORT = r"(?P<port>\d+-[\d.]+)"
RE_FOUND = re.compile(r"usb " + PORT + r": New USB device found, "
                      r"idVendor=(?P<vid>\w+), idProduct=(?P<pid>\w+)"
                      r"(?:, bcdDevice=\s*(?P<bcd>[\d.]+))?")
RE_STRINGS = re.compile(r"usb " + PORT + r": New USB device strings: Mfr=(?P<m>\d+), "
                        r"Product=(?P<p>\d+), SerialNumber=(?P<s>\d+)")
RE_PROD = re.compile(r"usb " + PORT + r": Product: (?P<v>.+)")
RE_MANU = re.compile(r"usb " + PORT + r": Manufacturer: (?P<v>.+)")
RE_SER = re.compile(r"usb " + PORT + r": SerialNumber: (?P<v>.+)")
RE_DISC = re.compile(r"usb " + PORT + r": USB disconnect")
RE_STORAGE = re.compile(r"usb-storage " + PORT + r":[\d.]+: USB Mass Storage device detected")
RE_SCSI_HOST = re.compile(r"scsi host(?P<host>\d+): usb-storage " + PORT + r":")
RE_SD_SIZE = re.compile(r"sd (?P<host>\d+):\d+:\d+:\d+: \[(?P<dev>sd\w+)\] "
                        r"(?P<blocks>\d+) (?P<bs>\d+)-byte logical blocks")
RE_INPUT = re.compile(r"input: .* as /devices/.*/" + PORT + r":[\d.]+/"
                      r"[0-9A-Fa-f]{4}:(?P<vid>[0-9A-Fa-f]{4}):(?P<pid>[0-9A-Fa-f]{4})")
RE_HID = re.compile(r"hid-generic [0-9A-Fa-f]{4}:(?P<vid>[0-9A-Fa-f]{4}):(?P<pid>[0-9A-Fa-f]{4})"
                    r"\.\w+: .*USB HID v[\d.]+ (?P<kind>Keyboard|Mouse|Device)")

LAST_PARSE = {}


def parse_ts(s, year):
    """Classic syslog time ('Oct  8 22:50:02') + a year supplied by the caller."""
    return datetime.strptime(f"{year} {' '.join(s.split())}",
                             "%Y %b %d %H:%M:%S").isoformat()


def line_ts(line, year):
    """(local ISO time, utc offset or None) for a log line, or None if it has no wall clock.
    Raises ValueError for an impossible date (e.g. Feb 29 in a non-leap year)."""
    if m := RE_ISO.match(line):
        return datetime.fromisoformat(m["iso"].replace(" ", "T")).isoformat(), m["off"]
    if m := RE_DMESG_T.match(line):
        return parse_ts(f'{m["mon"]} {m["d"]} {m["t"]}', m["y"]), None
    if m := RE_SYSLOG.match(line):
        return parse_ts(f'{m["mon"]} {m["d"]} {m["t"]}', year), None
    return None


def _new_session(m, ts):
    return {"vid": m["vid"].lower(), "pid": m["pid"].lower(), "port": m["port"],
            "bcd_device": m["bcd"], "serial": None, "serial_index": None,
            "manufacturer": None, "product": None,
            "connected": ts, "disconnected": None, "disconnect_note": None,
            "interfaces": [], "block_device": None, "capacity_bytes": None,
            "sources": ["kernel_log"]}


def _add_iface(d, name):
    if d is not None and name not in d["interfaces"]:
        d["interfaces"].append(name)


def parse_log(path, year=None):
    """Return one dict per USB connection session. Details in LAST_PARSE:
    warnings, utc_offset (if the log carried one), log_end (last timestamp)."""
    year = year or datetime.now().year
    devices, open_by_port, host_port, input_port = [], {}, {}, {}
    warn, offsets, last_ts, raw_dmesg = [], set(), None, 0
    with open(path, errors="replace") as fh:
        for n, line in enumerate(fh, 1):
            try:
                stamp = line_ts(line, year)
            except ValueError as e:
                warn.append(f"line {n}: bad date ({e}); line skipped")
                continue
            if stamp:
                ts, off = stamp
                last_ts = ts
                if off:
                    offsets.add(off)
            else:
                ts = None
                raw_dmesg += bool(RE_RAW_DMESG.match(line))
            if m := RE_FOUND.search(line):
                if ts is None:
                    warn.append(f"line {n}: device found without a wall-clock time; skipped")
                    continue
                if old := open_by_port.get(m["port"]):
                    # a new device on a port that never logged a disconnect:
                    # the old one must have gone by now
                    old["disconnected"] = ts
                    old["disconnect_note"] = "inferred: next device on the same port"
                d = _new_session(m, ts)
                devices.append(d)
                open_by_port[m["port"]] = d
            elif m := RE_STRINGS.search(line):
                if d := open_by_port.get(m["port"]):
                    d["serial_index"] = int(m["s"])
            elif m := RE_PROD.search(line):
                if m["port"] in open_by_port:
                    open_by_port[m["port"]]["product"] = m["v"].strip()
            elif m := RE_MANU.search(line):
                if m["port"] in open_by_port:
                    open_by_port[m["port"]]["manufacturer"] = m["v"].strip()
            elif m := RE_SER.search(line):
                if m["port"] in open_by_port:
                    open_by_port[m["port"]]["serial"] = m["v"].strip()
            elif m := RE_STORAGE.search(line):
                _add_iface(open_by_port.get(m["port"]), "mass_storage")
            elif m := RE_SCSI_HOST.search(line):
                host_port[m["host"]] = m["port"]
            elif m := RE_SD_SIZE.search(line):
                if d := open_by_port.get(host_port.get(m["host"])):
                    d["block_device"] = m["dev"]
                    d["capacity_bytes"] = int(m["blocks"]) * int(m["bs"])
            elif m := RE_INPUT.search(line):
                input_port[(m["vid"].lower(), m["pid"].lower())] = m["port"]
            elif m := RE_HID.search(line):
                kind = {"Keyboard": "hid_keyboard", "Mouse": "hid_mouse"}.get(m["kind"], "hid")
                key = (m["vid"].lower(), m["pid"].lower())
                port = input_port.pop(key, None)
                d = open_by_port.get(port) if port else None
                if d is not None and (d["vid"], d["pid"]) == key:
                    _add_iface(d, kind)          # the exact device, by its port
                else:                            # no 'input:' line: fall back to VID:PID
                    for d in open_by_port.values():
                        if (d["vid"], d["pid"]) == key:
                            _add_iface(d, kind)
            elif m := RE_DISC.search(line):
                d = open_by_port.pop(m["port"], None)
                if d:
                    d["disconnected"] = ts or last_ts
                    if ts is None:
                        d["disconnect_note"] = "approximate: disconnect line had no time"
    for d in open_by_port.values():
        d["disconnect_note"] = "still connected at end of log"
    if raw_dmesg and not devices:
        warn.append(f"{raw_dmesg} lines are raw dmesg ([seconds since boot]) with no wall "
                    "clock; export with 'journalctl -k -o short-iso' or 'dmesg -T'")
    LAST_PARSE.clear()
    LAST_PARSE.update(warnings=warn, log_end=last_ts,
                      utc_offset=offsets.pop() if len(offsets) == 1 else None)
    return devices


def save_usb_events(conn, case_id, devices):
    """Insert sessions; stores the new row id back into each dict as d['id']."""
    for d in devices:
        cur = conn.execute(
            "INSERT INTO usb_events(case_id,vid,pid,serial,manufacturer,product,"
            "connected,disconnected,port,bcd_device,bcd_usb,interfaces,serial_index,"
            "block_device,capacity_bytes,sources,disconnect_note) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (case_id, d["vid"], d["pid"], d.get("serial"), d.get("manufacturer"),
             d.get("product"), d.get("connected"), d.get("disconnected"), d.get("port"),
             d.get("bcd_device"), d.get("bcd_usb"), ",".join(d.get("interfaces") or []),
             d.get("serial_index"), d.get("block_device"), d.get("capacity_bytes"),
             ",".join(d.get("sources") or []), d.get("disconnect_note")))
        d["id"] = cur.lastrowid
    conn.commit()


# --------------------------------------------------------------------------
# Live device identification through sysfs (what udev / USBView read)
# --------------------------------------------------------------------------
IFACE_CLASS = {"08": "mass_storage", "03": "hid", "02": "cdc", "0a": "cdc_data",
               "01": "audio", "0e": "video", "e0": "wireless", "ff": "vendor"}


def _read(path):
    try:
        with open(path) as fh:
            return fh.read().strip()
    except OSError:
        return None


def iface_name(cls, proto):
    cls = (cls or "").lower()
    if cls == "03":
        return {"01": "hid_keyboard", "02": "hid_mouse"}.get((proto or "").lower(), "hid")
    return IFACE_CLASS.get(cls, f"class_{cls}")


def sysfs_usb_device(usb_dir):
    """Read one USB device directory (/sys/bus/usb/devices/1-1)."""
    r = lambda n: _read(os.path.join(usb_dir, n))     # noqa: E731
    bcd = r("bcdDevice")
    d = {"vid": (r("idVendor") or "").lower(), "pid": (r("idProduct") or "").lower(),
         "port": os.path.basename(usb_dir), "manufacturer": r("manufacturer"),
         "product": r("product"), "serial": r("serial"),
         "bcd_device": f"{int(bcd[:2])}.{bcd[2:]}" if bcd and len(bcd) == 4 else bcd,
         "bcd_usb": r("version"), "interfaces": [], "sources": ["sysfs"],
         "connected": None, "disconnected": None, "block_device": None,
         "capacity_bytes": None}
    d["serial_index"] = 1 if d["serial"] else 0
    for name in sorted(os.listdir(usb_dir)):
        sub = os.path.join(usb_dir, name)
        if ":" in name and os.path.isdir(sub):
            _add_iface(d, iface_name(_read(os.path.join(sub, "bInterfaceClass")),
                                     _read(os.path.join(sub, "bInterfaceProtocol"))))
    return d


def sysfs_identify(block_path, sys_root="/sys"):
    """USB identity of a live block device such as /dev/sdb, or None."""
    name = os.path.basename(os.path.realpath(block_path))
    node = os.path.realpath(os.path.join(sys_root, "class", "block", name, "device"))
    while node and node != os.path.dirname(node):
        if os.path.exists(os.path.join(node, "idVendor")):
            d = sysfs_usb_device(node)
            d["block_device"] = name
            sectors = _read(os.path.join(sys_root, "class", "block", name, "size"))
            d["capacity_bytes"] = int(sectors) * 512 if sectors and sectors.isdigit() else None
            return d
        node = os.path.dirname(node)
    return None


def enumerate_sysfs(sys_root="/sys"):
    """All USB devices currently attached (hubs and root hubs skipped)."""
    base = os.path.join(sys_root, "bus", "usb", "devices")
    out = []
    if not os.path.isdir(base):
        return out
    for name in sorted(os.listdir(base)):
        path = os.path.join(base, name)
        if ":" in name or name.startswith("usb"):
            continue
        if not os.path.exists(os.path.join(path, "idVendor")):
            continue
        if (_read(os.path.join(path, "bDeviceClass")) or "") == "09":   # hub
            continue
        out.append(sysfs_usb_device(path))
    return out
