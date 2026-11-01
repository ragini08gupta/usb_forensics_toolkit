"""
usb_capture.py - read USB enumeration descriptors from a usbmon packet
capture (Vijay, impersonation evidence).

A capture is made on Linux with:
    sudo modprobe usbmon
    sudo tcpdump -i usbmon1 -w capture.pcap        (or Wireshark on usbmon1)

The pcap link type is LINKTYPE_USB_LINUX_MMAPPED (220) or LINKTYPE_USB_LINUX
(189). Scapy reads the pcap records; this module decodes the usbmon header
and the GET_DESCRIPTOR replies the host received during enumeration:

    device descriptor  -> VID, PID, bcdUSB, bcdDevice, class, bMaxPacketSize0,
                          iManufacturer / iProduct / iSerialNumber indices
    configuration      -> every interface's class / subclass / protocol
    string descriptors -> manufacturer, product, serial text

These are the values the DEVICE claimed about itself; a BadUSB device can lie
in the strings, but it cannot hide the HID interface it needs to type.
"""
import struct
from datetime import datetime, timedelta, timezone

from modules.device_info import iface_name

LINKTYPE_USB_LINUX = 189
LINKTYPE_USB_LINUX_MMAPPED = 220
GET_DESCRIPTOR = 0x06
DT_DEVICE, DT_CONFIG, DT_STRING, DT_INTERFACE = 1, 2, 3, 4


def _records(path):
    """Yield (timestamp_float, bytes, linktype). Scapy if present, else a tiny pcap reader."""
    try:
        from scapy.utils import RawPcapReader
        reader = RawPcapReader(path)
        linktype = getattr(reader, "linktype", LINKTYPE_USB_LINUX_MMAPPED)
        for data, meta in reader:
            ts = meta.sec + meta.usec / 1e6 if hasattr(meta, "sec") else \
                meta.tshigh * 4294967.296 + meta.tslow / 1e6
            yield ts, bytes(data), linktype
        reader.close()
        return
    except ImportError:
        pass
    with open(path, "rb") as fh:
        hdr = fh.read(24)
        magic = hdr[:4]
        end = "<" if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1") else ">"
        nano = magic in (b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d")
        linktype = struct.unpack(end + "I", hdr[20:24])[0]
        while rec := fh.read(16):
            sec, frac, incl, _ = struct.unpack(end + "IIII", rec)
            yield sec + frac / (1e9 if nano else 1e6), fh.read(incl), linktype


def _usbmon(pkt, linktype):
    """Decode the 48/64-byte usbmon header. Returns dict or None."""
    hlen = 64 if linktype == LINKTYPE_USB_LINUX_MMAPPED else 48
    if len(pkt) < hlen:
        return None
    (urb, typ, xfer, ep, dev, bus, flag_setup, _flag_data, ts_s, ts_us,
     status, length, captured) = struct.unpack_from("<QBBBBHbbqiiII", pkt, 0)
    data = pkt[hlen:hlen + captured]
    return {"urb": urb, "type": chr(typ), "xfer": xfer, "ep": ep & 0x7F, "dev": dev,
            "bus": bus, "setup": pkt[40:48] if flag_setup == 0 else None,
            "status": status, "data": data, "ts": ts_s + ts_us / 1e6,
            # snap length cut the packet, or the record itself is shorter than declared
            "truncated": len(data) < captured or captured < length}


def _bcd(v):
    return f"{v >> 8:x}.{v & 0xFF:02x}"


def parse_device_descriptor(b):
    if len(b) < 18 or b[1] != DT_DEVICE:
        return {}
    (_l, _t, bcd_usb, cls, sub, proto, mps, vid, pid, bcd_dev,
     i_man, i_prod, i_ser, _ncfg) = struct.unpack("<BBHBBBBHHHBBBB", b[:18])
    return {"bcd_usb": _bcd(bcd_usb), "device_class": cls, "max_packet0": mps,
            "vid": f"{vid:04x}", "pid": f"{pid:04x}", "bcd_device": _bcd(bcd_dev),
            "i_manufacturer": i_man, "i_product": i_prod, "serial_index": i_ser}


def parse_config_descriptor(b):
    out, i = [], 0
    while i + 2 <= len(b) and b[i] >= 2:
        if b[i + 1] == DT_INTERFACE and i + 9 <= len(b):
            out.append(iface_name(f"{b[i + 5]:02x}", f"{b[i + 7]:02x}"))
        i += b[i]
    return out


def parse_offset(off):
    """'+0530', '+05:30', 'Z' or None -> timedelta (None = UTC)."""
    if not off or off == "Z":
        return timedelta(0)
    sign = -1 if off[0] == "-" else 1
    digits = off[1:].replace(":", "")
    return sign * timedelta(hours=int(digits[:2]), minutes=int(digits[2:4] or 0))


def parse_capture(path, utc_offset=None):
    """Return one dict per enumerated device (keyed by bus/devnum).
    pcap times are UTC epoch seconds; they are converted to the suspect
    machine's local wall-clock time with utc_offset (e.g. '+0530', taken
    from the kernel log) so they line up with log and FAT times.
    Raises ValueError for a file that is not a readable pcap."""
    try:
        return _parse_capture(path, parse_offset(utc_offset))
    except (struct.error, EOFError, OSError) as e:
        raise ValueError(f"unreadable usbmon capture: {e}")
    except Exception as e:                       # scapy raises its own exception types
        if type(e).__module__.startswith("scapy"):
            raise ValueError(f"unreadable usbmon capture: {e}")
        raise


def _parse_capture(path, offset):
    pending, devs = {}, {}
    for ts, pkt, linktype in _records(path):
        u = _usbmon(pkt, linktype)
        if not u or u["xfer"] != 2 or u["ep"] != 0:          # control transfers on EP0 only
            continue
        key = (u["bus"], u["dev"])
        if u["type"] == "S" and u["setup"] is not None:
            req_type, req, wvalue, windex, _ = struct.unpack("<BBHHH", u["setup"])
            if req == GET_DESCRIPTOR and req_type & 0x80:
                pending[u["urb"]] = (wvalue >> 8, wvalue & 0xFF)
            continue
        if u["type"] != "C" or u["urb"] not in pending or u["status"] != 0:
            continue
        dtype, idx = pending.pop(u["urb"])
        d = devs.setdefault(key, {"bus": u["bus"], "devnum": u["dev"], "strings": {},
                                  "interfaces": [], "first_seen": ts, "truncated": False})
        data = u["data"]
        if u["truncated"]:
            d["truncated"] = True
        if dtype == DT_DEVICE:
            if len(data) >= 18:
                d.update(parse_device_descriptor(data))
            else:
                d["truncated"] = True
        elif dtype == DT_CONFIG and len(data) > 9:
            if struct.unpack_from("<H", data, 2)[0] > len(data):
                d["truncated"] = True            # interfaces past the cut are missing
            for name in parse_config_descriptor(data):
                if name not in d["interfaces"]:
                    d["interfaces"].append(name)
        elif dtype == DT_STRING and idx and len(data) >= 2:
            if data[0] > len(data) or data[1] != DT_STRING:
                d["truncated"] = True            # never trust half a serial number
            else:
                d["strings"][idx] = data[2:data[0]].decode("utf-16-le", "replace")
    out = []
    for d in devs.values():
        if "vid" not in d:
            continue
        s = d.pop("strings")
        d["manufacturer"] = s.get(d.get("i_manufacturer"))
        d["product"] = s.get(d.get("i_product"))
        d["serial"] = s.get(d.get("serial_index")) if d.get("serial_index") else None
        # pcap time = UTC epoch -> suspect-local wall clock
        d["seen"] = (datetime.fromtimestamp(d.pop("first_seen"), timezone.utc) + offset) \
            .replace(tzinfo=None).isoformat(timespec="seconds")
        d["sources"] = ["usbmon"]
        out.append(d)
    return out


def merge_into_sessions(sessions, captured, window_s=10):
    """Attach descriptor evidence to the kernel-log session it belongs to
    (same VID:PID, capture time inside the session). Unmatched captured
    devices become sessions of their own. Returns the merged list."""
    def t(s):
        return datetime.fromisoformat(s) if s else None
    merged = list(sessions)
    for c in captured:
        seen = t(c["seen"])
        match = None
        for s in sessions:
            start, end = t(s.get("connected")), t(s.get("disconnected"))
            if (s["vid"], s["pid"]) != (c["vid"], c["pid"]) or not start:
                continue
            if abs((seen - start).total_seconds()) <= window_s or \
                    (end and start <= seen <= end):
                match = s
                break
        if match is None:
            new = {k: c.get(k) for k in ("vid", "pid", "manufacturer", "product", "serial",
                                         "serial_index", "bcd_device", "bcd_usb")}
            new.update(connected=c["seen"], disconnected=None, port=f'bus{c["bus"]}-dev{c["devnum"]}',
                       interfaces=list(c["interfaces"]), block_device=None,
                       capacity_bytes=None, sources=["usbmon"], descriptor=c)
            merged.append(new)
            continue
        match["descriptor"] = c          # impersonation compares its strings with the log's
        match["bcd_usb"] = c.get("bcd_usb")
        match.setdefault("sources", []).append("usbmon")
        for i in c["interfaces"]:
            if i not in match["interfaces"]:
                match["interfaces"].append(i)
    return merged
