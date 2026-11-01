"""
live_usb.py - enumerate USB devices attached RIGHT NOW and check them for
impersonation (Vijay).

    python -m modules.live_usb                 list devices with verdicts
    python -m modules.live_usb --watch         keep running; report every new device
    python -m modules.live_usb --json          machine-readable output

Linux: reads /sys/bus/usb/devices (the same data udev and lsusb use; no root
needed). Elsewhere, or with --pyusb: uses pyusb (libusb) to read the device
and configuration descriptors directly.
Nothing is written to any device.
"""
import argparse
import json
import sys
import time
from datetime import datetime

from modules import device_info, impersonation


def enumerate_pyusb():
    import usb.core
    import usb.util
    out = []
    for dev in usb.core.find(find_all=True):
        if dev.bDeviceClass == 9:                      # hub
            continue

        def s(idx):
            if not idx:
                return None
            try:
                return usb.util.get_string(dev, idx)
            except (ValueError, usb.core.USBError, NotImplementedError):
                return None
        d = {"vid": f"{dev.idVendor:04x}", "pid": f"{dev.idProduct:04x}",
             "bcd_device": f"{dev.bcdDevice >> 8:x}.{dev.bcdDevice & 0xFF:02x}",
             "bcd_usb": f"{dev.bcdUSB >> 8:x}.{dev.bcdUSB & 0xFF:02x}",
             "manufacturer": s(dev.iManufacturer), "product": s(dev.iProduct),
             "serial": s(dev.iSerialNumber), "serial_index": dev.iSerialNumber,
             "port": f"bus{dev.bus}-{dev.address}", "interfaces": [], "sources": ["pyusb"],
             "connected": datetime.now().isoformat(timespec="seconds"), "disconnected": None,
             "block_device": None, "capacity_bytes": None}
        try:
            for cfg in dev:
                for intf in cfg:
                    name = device_info.iface_name(f"{intf.bInterfaceClass:02x}",
                                                  f"{intf.bInterfaceProtocol:02x}")
                    if name not in d["interfaces"]:
                        d["interfaces"].append(name)
        except usb.core.USBError:
            pass
        out.append(d)
    return out


def enumerate_devices(use_pyusb=False, sys_root="/sys"):
    if not use_pyusb:
        devs = device_info.enumerate_sysfs(sys_root)
        if devs or sys.platform.startswith("linux"):
            now = datetime.now().isoformat(timespec="seconds")
            for d in devs:
                d["connected"] = now
            return devs
    return enumerate_pyusb()


def check(devs, cfg):
    return impersonation.analyse_sessions(devs, cfg)


def line(d):
    mark = "!" if d["verdict"] in ("LIKELY_SPOOFED", "SUSPICIOUS") else " "
    return (f"{mark} {d['port']:<10} {d['vid']}:{d['pid']}  {(d.get('manufacturer') or '?')[:14]:<14} "
            f"{(d.get('product') or '?')[:22]:<22} {','.join(d['interfaces']) or '-':<22} "
            f"{d['verdict']:<15} {d['score']}")


def main(argv=None):
    p = argparse.ArgumentParser(prog="python -m modules.live_usb")
    p.add_argument("--watch", action="store_true", help="poll and report newly attached devices")
    p.add_argument("--interval", type=float, default=1.0)
    p.add_argument("--pyusb", action="store_true", help="use pyusb/libusb instead of sysfs")
    p.add_argument("--json", action="store_true")
    p.add_argument("--profiles", default=impersonation.DEFAULT_PROFILES)
    p.add_argument("--sys-root", default="/sys", help=argparse.SUPPRESS)
    a = p.parse_args(argv)
    cfg = impersonation.load_profiles(a.profiles)
    try:
        devs = check(enumerate_devices(a.pyusb, a.sys_root), cfg)
    except ImportError:
        print("pyusb is not installed (pip install pyusb) and sysfs is not available")
        return 1
    if a.json:
        print(json.dumps(devs, indent=2))
        return 0
    print(f"  {'PORT':<10} {'VID:PID':<10} {'MANUFACTURER':<14} {'PRODUCT':<22} "
          f"{'INTERFACES':<22} {'VERDICT':<15} SCORE")
    if not devs:
        print("  (no USB devices found)")
    for d in devs:
        print(line(d))
        if d["verdict"] in ("LIKELY_SPOOFED", "SUSPICIOUS"):
            for r in d["reasons"]:
                print(f"      {r}")
    if not a.watch:
        return 0
    seen = {(d["port"], d["vid"], d["pid"], d.get("serial")) for d in devs}
    print("\nWatching for new USB devices (Ctrl+C to stop)...")
    try:
        while True:
            time.sleep(a.interval)
            now = enumerate_devices(a.pyusb, a.sys_root)
            keys = {(d["port"], d["vid"], d["pid"], d.get("serial")): d for d in now}
            for k in set(keys) - seen:
                d = check([keys[k]], cfg)[0]
                print(f"[{datetime.now():%H:%M:%S}] NEW " + line(d))
                for r in d["reasons"]:
                    print(f"      {r}")
            for k in seen - set(keys):
                print(f"[{datetime.now():%H:%M:%S}] REMOVED {k[0]} {k[1]}:{k[2]}")
            seen = set(keys)
    except KeyboardInterrupt:
        return 0


if __name__ == "__main__":
    sys.exit(main())
