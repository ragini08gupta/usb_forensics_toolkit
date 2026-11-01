"""
impersonation.py - USB impersonation / rogue-device detection (Vijay).

Each USB connection session (kernel log, optionally enriched with usbmon
descriptors or read live from sysfs) is compared with a database of
known-good device fingerprints (data/known_good.json). Every deviation adds
points; the total gives a verdict:

    GENUINE          score < 25 and the VID:PID matches a known-good profile
    UNVERIFIED       score < 25 but there is no profile for this VID:PID
    SUSPICIOUS       25 <= score < 60
    LIKELY_SPOOFED   score >= 60, or VID:PID is a known attack/HID-injection board

Rules (points):
    known attack board VID:PID ..................................... 100
    storage profile, but the device enumerated a HID keyboard ........ 60
    composite mass storage + keyboard (no profile) ................... 60
    manufacturer string differs from profile ......................... 40
    same serial number seen with a different VID:PID (cloned) ........ 40
      (only on the device that does not fit its profile; the genuine one gets a note)
    usbmon capture strings/serial differ from the kernel log .......... 40
    product string differs from profile .............................. 30
    no serial number although the genuine model always has one ....... 25
    other interface not in the profile ............................... 25
    expected mass-storage interface missing .......................... 20
    serial number has the wrong format for this model ................ 20
    USB version lower than the genuine model (e.g. 1.1 vs 2.0) ....... 15
    no known-good profile for this VID:PID ........................... 15
    bcdDevice (firmware revision) not seen for this model ............ 10
    keyboard present only for a very short time (< 2 min) ............ 10

Limitations: a perfect clone that copies every descriptor (strings, serial,
interfaces) cannot be told apart by descriptors alone; the HID interface a
keystroke injector needs is what usually gives it away.
"""
import json
import os
import re
from datetime import datetime

from modules import db

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_PROFILES = os.path.join(HERE, "data", "known_good.json")

SPOOFED, SUSPICIOUS = 60, 25


def load_profiles(path=DEFAULT_PROFILES):
    with open(path) as fh:
        cfg = json.load(fh)
    cfg.setdefault("profiles", [])
    cfg.setdefault("known_bad", [])
    cfg.setdefault("policy", {})
    return cfg


def _ver(v):
    try:
        major, _, minor = str(v).partition(".")
        return int(major), int((minor or "0")[:2].ljust(2, "0"))
    except ValueError:
        return None


def _dt(s):
    return datetime.fromisoformat(s[:19]) if s else None


def evaluate(d, cfg, all_sessions=()):
    """Return (score, verdict, [reasons], profile_name) for one session dict."""
    vid, pid = (d.get("vid") or "").lower(), (d.get("pid") or "").lower()
    ifaces = list(d.get("interfaces") or [])
    reasons = []

    def add(points, text):
        reasons.append((points, text))

    bad = next((b for b in cfg["known_bad"] if (b["vid"], b["pid"]) == (vid, pid)), None)
    if bad:
        add(100, f"VID:PID {vid}:{pid} is a known attack/HID-injection board: {bad['label']}")

    prof = next((p for p in cfg["profiles"] if (p["vid"], p["pid"]) == (vid, pid)), None)
    if prof:
        man, prod = d.get("manufacturer"), d.get("product")
        if man and prof.get("manufacturer") and man.strip().lower() != prof["manufacturer"].lower():
            add(40, f'manufacturer "{man}" but genuine {vid}:{pid} reports "{prof["manufacturer"]}"')
        if prod and prof.get("product") and prod.strip().lower() != prof["product"].lower():
            add(30, f'product "{prod}" but genuine {vid}:{pid} reports "{prof["product"]}"')
        expected = set(prof.get("interfaces") or [])
        storage_profile = "mass_storage" in expected
        for i in ifaces:
            if i in expected:
                continue
            if i == "hid_keyboard" and storage_profile:
                add(60, "claims to be a storage device but enumerated a HID keyboard interface "
                        "(BadUSB keystroke-injection pattern)")
            else:
                add(25, f"interface '{i}' is not part of the genuine {prof['name']}")
        if storage_profile and ifaces and "mass_storage" not in ifaces:
            add(20, "expected mass-storage interface was never bound by the kernel")
        desc = d.get("descriptor") or {}
        no_serial = d.get("serial_index") == 0 or desc.get("serial_index") == 0
        if prof.get("serial_required") and no_serial:
            add(25, "no serial number (iSerialNumber=0); the genuine model always reports one")
        elif prof.get("serial_required") and not d.get("serial"):
            add(0, "serial number not recorded in the log, so it could not be checked")
        elif d.get("serial") and prof.get("serial_regex") and \
                not re.match(prof["serial_regex"], d["serial"]):
            add(20, f'serial "{d["serial"]}" does not match the format of genuine {prof["name"]}')
        if d.get("bcd_device") and prof.get("bcd_device") and \
                d["bcd_device"] not in prof["bcd_device"]:
            add(10, f'bcdDevice {d["bcd_device"]} not seen for genuine {prof["name"]} '
                    f'({", ".join(prof["bcd_device"])})')
        if d.get("bcd_usb") and prof.get("min_bcd_usb") and _ver(d["bcd_usb"]) and \
                _ver(d["bcd_usb"]) < _ver(prof["min_bcd_usb"]):
            add(15, f'reports USB {d["bcd_usb"]} but genuine {prof["name"]} is USB '
                    f'{prof["min_bcd_usb"]}+ (descriptor bcdUSB)')
    elif not bad:
        add(15, f"no known-good profile for {vid}:{pid}")
        if "mass_storage" in ifaces and "hid_keyboard" in ifaces:
            add(60, "composite device: mass storage AND HID keyboard in one device")

    # descriptors captured on the wire must tell the same story as the kernel log
    desc = d.get("descriptor") or {}
    if desc.get("truncated"):
        add(0, "usbmon capture of this device is truncated; its descriptors were only partly checked")
    for field in ("manufacturer", "product", "serial"):
        a, b = desc.get(field), d.get(field)
        if a and b and a.strip() != b.strip() and not desc.get("truncated"):
            add(40, f'{field} in the usbmon capture ("{a}") differs from the kernel log ("{b}")')

    base = sum(p for p, _ in reasons)
    if d.get("serial"):
        others = {(o.get("vid"), o.get("pid")) for o in all_sessions
                  if o is not d and o.get("serial") == d["serial"]}
        others.discard((vid, pid))
        if others:
            where = ", ".join(f"{v}:{p}" for v, p in sorted(others))
            if base > 0 or not prof or bad:
                add(40, f"serial number also seen on {where} (cloned serial)")
            else:      # this device matches its genuine profile: the OTHER one is the clone
                add(0, f"serial number also used by {where}; that device is the one to suspect")

    if "hid_keyboard" in ifaces and sum(p for p, _ in reasons) > 0:
        start, end = _dt(d.get("connected")), _dt(d.get("disconnected"))
        if start and end and (end - start).total_seconds() < 120:
            add(10, f"keyboard connected for only {int((end - start).total_seconds())} s "
                    "(typical of automated keystroke injection)")

    score = sum(p for p, _ in reasons)
    if bad or score >= SPOOFED:
        verdict = "LIKELY_SPOOFED"
    elif score >= SUSPICIOUS:
        verdict = "SUSPICIOUS"
    elif prof:
        verdict = "GENUINE"
    else:
        verdict = "UNVERIFIED"
    return score, verdict, [f"(+{p}) {t}" for p, t in reasons], prof["name"] if prof else None


def after_hours(ts, policy):
    hours = policy.get("office_hours")
    if not ts or not hours:
        return False
    t = ts[11:16]
    return not (hours[0] <= t < hours[1])


def analyse_sessions(sessions, cfg, evidence_size=None, device_serial=None):
    """Annotate every session dict in place; returns the list."""
    storage = set(cfg["policy"].get("storage_classes", ["mass_storage"]))
    for d in sessions:
        d["score"], d["verdict"], d["reasons"], d["profile"] = evaluate(d, cfg, sessions)
        d["after_hours"] = after_hours(d.get("connected"), cfg["policy"])
        d["is_evidence_device"] = False
    # which device is the one we imaged? serial given by the examiner wins,
    # otherwise the storage device(s) whose reported capacity equals the image size
    for d in sessions:
        if device_serial:
            d["is_evidence_device"] = d.get("serial") == device_serial
        elif evidence_size and d.get("capacity_bytes") == evidence_size and \
                storage & set(d.get("interfaces") or []):
            d["is_evidence_device"] = True
    return sessions


def save(conn, case_id, sessions):
    """Write verdicts to usb_events (rows must have d['id']) and raise alerts."""
    for d in sessions:
        conn.execute(
            "UPDATE usb_events SET score=?, verdict=?, reasons=?, profile=?, after_hours=?, "
            "is_evidence_device=?, bcd_usb=?, interfaces=?, sources=? WHERE id=?",
            (d["score"], d["verdict"], "\n".join(d["reasons"]), d["profile"],
             int(d["after_hours"]), int(d["is_evidence_device"]), d.get("bcd_usb"),
             ",".join(d.get("interfaces") or []), ",".join(d.get("sources") or []), d["id"]))
        label = f'session #{d["id"]} {d["vid"]}:{d["pid"]} {d.get("manufacturer") or ""} ' \
                f'{d.get("product") or ""}'.strip()
        if d["verdict"] in ("LIKELY_SPOOFED", "SUSPICIOUS"):
            db.add_alert(conn, case_id, "HIGH" if d["verdict"] == "LIKELY_SPOOFED" else "MEDIUM",
                         "impersonation", d["verdict"],
                         f'{label} at {d.get("connected")}: score {d["score"]}; '
                         + "; ".join(r.split(") ", 1)[-1] for r in d["reasons"]),
                         ref=str(d["id"]), ts=d.get("connected"))
        if d["after_hours"]:
            db.add_alert(conn, case_id, "MEDIUM", "policy", "AFTER_HOURS",
                         f'{label} connected outside office hours at {d.get("connected")}',
                         ref=str(d["id"]), ts=d.get("connected"))
    conn.commit()


def summary(sessions):
    counts = {}
    for d in sessions:
        counts[d["verdict"]] = counts.get(d["verdict"], 0) + 1
    return counts
