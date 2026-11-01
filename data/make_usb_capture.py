"""
make_usb_capture.py - build data/usb_capture.pcap, a usbmon capture of two
enumerations from the Scenario B night (run from data/):

  22:44:10  bus 1 dev 7  claims Kingston DataTraveler 3.0 (0951:1666) but is a
                         USB 1.1 HID boot keyboard with no serial number
  22:50:02  bus 1 dev 8  SanDisk Cruzer Blade (0781:5567), genuine mass storage

Real captures come from `tcpdump -i usbmon1 -w file.pcap`; this file only
exists so the impersonation demo is reproducible without the hardware.
Written as a classic pcap (link type 220) with struct; read back with Scapy.
"""
import struct
from datetime import datetime, timedelta, timezone

LINKTYPE = 220            # LINKTYPE_USB_LINUX_MMAPPED


IST = timezone(timedelta(hours=5, minutes=30))     # the lab PC's clock (log says +0530)


def epoch(s):
    """Local IST wall-clock time -> the real UTC epoch a capture stores."""
    return datetime.fromisoformat(s).replace(tzinfo=IST).timestamp()


def string_desc(text):
    b = text.encode("utf-16-le")
    return bytes([len(b) + 2, 3]) + b


def device_desc(bcd_usb, mps, vid, pid, bcd_dev, i_ser):
    return struct.pack("<BBHBBBBHHHBBBB", 18, 1, bcd_usb, 0, 0, 0, mps,
                       vid, pid, bcd_dev, 1, 2, i_ser, 1)


def config_desc(iface_cls, sub, proto, extra, n_ep):
    iface = struct.pack("<BBBBBBBBB", 9, 4, 0, 0, n_ep, iface_cls, sub, proto, 0)
    body = iface + extra
    return struct.pack("<BBHBBBBB", 9, 2, 9 + len(body), 1, 1, 0, 0x80, 50) + body


HID_KBD_EXTRA = (bytes([9, 0x21, 0x11, 0x01, 0, 1, 0x22, 63, 0])        # HID descriptor
                 + bytes([7, 5, 0x81, 3, 8, 0, 10]))                     # interrupt IN
MSC_EXTRA = bytes([7, 5, 0x81, 2, 0, 2, 0]) + bytes([7, 5, 0x02, 2, 0, 2, 0])


def usbmon(urb, typ, dev, ts, setup=None, data=b"", status=0):
    sec, usec = int(ts), int(round((ts - int(ts)) * 1e6))
    hdr = struct.pack("<QBBBBHbbqiiII", urb, ord(typ), 2, 0x80, dev, 1,
                      0 if setup else ord("-"), 0 if typ == "S" else ord("="),
                      sec, usec, -115 if typ == "S" else status,
                      len(data) if typ == "C" else 64, len(data))
    hdr += setup if setup else b"\x00" * 8
    hdr += struct.pack("<iiII", 0, 0, 0, 0)
    return hdr + data


def enumeration(dev, t0, descs, urb0):
    """descs: list of (dtype, index, reply_bytes) -> list of (ts, packet)."""
    pkts, t, urb = [], t0, urb0
    for dtype, idx, reply in descs:
        setup = struct.pack("<BBHHH", 0x80, 6, (dtype << 8) | idx, 0x0409 if dtype == 3 else 0,
                            255)
        pkts.append((t, usbmon(urb, "S", dev, t, setup=setup)))
        t += 0.0004
        pkts.append((t, usbmon(urb, "C", dev, t, data=reply)))
        t += 0.002
        urb += 1
    return pkts


def build():
    rogue = enumeration(7, epoch("2026-10-08T22:44:10.462"), [
        (1, 0, device_desc(0x0110, 8, 0x0951, 0x1666, 0x0100, 0)),
        (2, 0, config_desc(3, 1, 1, HID_KBD_EXTRA, 1)),
        (3, 1, string_desc("Kingston")),
        (3, 2, string_desc("DataTraveler 3.0")),
    ], 0xFFFF8E0001000000)
    sandisk = enumeration(8, epoch("2026-10-08T22:50:02.001"), [
        (1, 0, device_desc(0x0210, 64, 0x0781, 0x5567, 0x0100, 3)),
        (2, 0, config_desc(8, 6, 0x50, MSC_EXTRA, 2)),
        (3, 1, string_desc("SanDisk")),
        (3, 2, string_desc("Cruzer Blade")),
        (3, 3, string_desc("4C530001230915101234")),
    ], 0xFFFF8E0002000000)
    return rogue + sandisk


def write(path="usb_capture.pcap"):
    pkts = build()
    with open(path, "wb") as fh:
        fh.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, LINKTYPE))
        for ts, p in pkts:
            sec, usec = int(ts), int(round((ts - int(ts)) * 1e6))
            fh.write(struct.pack("<IIII", sec, usec, len(p), len(p)) + p)
    print(f"  {path}: {len(pkts)} usbmon packets")


if __name__ == "__main__":
    write()
