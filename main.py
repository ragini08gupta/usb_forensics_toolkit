"""
USB Forensics Investigation Toolkit - command line.

    python main.py <image|/dev/sdX> [usb_log] [--pcap capture.pcap]
                   [--examiner NAME] [--device-serial SERIAL] [--no-report] [--setro]

Exit codes: 0 ok, 1 bad input, 2 acquisition failed, 3 integrity failed
after analysis, 4 no readable file system, 5 USB log / capture unreadable.
"""
import argparse
import os
import sys

from modules import pipeline

BASE = os.path.dirname(os.path.abspath(__file__))


def main():
    p = argparse.ArgumentParser(
        usage="python main.py <image> [usb_log] [--pcap FILE] [--examiner NAME] "
              "[--device-serial SERIAL] [--profiles FILE] [--no-report] [--setro]")
    p.add_argument("image", help="forensic image file or USB block device (/dev/sdX)")
    p.add_argument("usb_log", nargs="?", default=os.path.join(BASE, "data", "usb.log"),
                   help="kernel log with USB events (default data/usb.log)")
    p.add_argument("--pcap", help="usbmon capture (tcpdump -i usbmon1) with enumeration descriptors")
    p.add_argument("--examiner", default="Ragini",
                   help="name recorded in the case and chain-of-custody log")
    p.add_argument("--device-serial", help="USB serial of the imaged device (else matched by size)")
    p.add_argument("--profiles", help="known-good device profiles (default data/known_good.json)")
    p.add_argument("--db", default="case.db", help="case database (default case.db)")
    p.add_argument("--log-year", type=int,
                   help="year for classic syslog lines that carry none (default: this year)")
    p.add_argument("--tz-offset",
                   help="suspect PC's UTC offset for the pcap, e.g. +0530 (default: from the log)")
    p.add_argument("--no-report", action="store_true", help="skip the PDF report")
    p.add_argument("--setro", action="store_true",
                   help="live block device only, root: set kernel read-only flag before acquisition")
    p.add_argument("--hide-custody", action="store_true",
                   help="leave chain-of-custody actions out of the printed timeline")
    args = p.parse_args()

    try:
        case_id, s = pipeline.run_case(
            args.image, args.usb_log, args.examiner, db_path=args.db, pcap=args.pcap,
            profiles=args.profiles, device_serial=args.device_serial,
            make_report=not args.no_report, set_ro=args.setro, log_year=args.log_year,
            tz_offset=args.tz_offset)
    except pipeline.PipelineError as e:
        if e.code == 1:
            print(e)
        elif e.code == 3:
            print("  Evidence integrity: FAILED")
        sys.exit(e.code)

    print_summary(case_id, s, args.hide_custody, args.db)


def print_summary(case_id, s, hide_custody=False, db_path="case.db"):
    print()
    print("=" * 78)
    print(f"CASE {case_id} SUMMARY")
    print("=" * 78)
    print(f"  Evidence integrity: {'VERIFIED' if s['integrity_ok'] else 'FAILED'}")
    print(f"  Files found: {len(s['files'])}  Deleted: {len(s['deleted'])}  "
          f"Suspicious: {len(s['suspicious'])}")
    print(f"  USB sessions: {len(s['sessions'])}  "
          f"Rogue/suspicious devices: {len(s['rogue'])}")
    for r in s["suspicious"]:
        print(f'  ! {r["path"]}: {r["reasons"]}')

    print("\n  Q1. Was the device genuine?")
    print(f"      {s['device_answer']}")
    for d in s["rogue"]:
        print(f"      ! Rogue device #{d['id']} {d['vid']}:{d['pid']} \"{d['manufacturer']} "
              f"{d['product']}\" at {d['connected']}: {d['verdict']} (score {d['score']})")
    print("\n  Q2/Q3. What was copied onto the evidence device, and when?")
    sess = {x["id"]: x for x in s["sessions"]}
    if not s["files_by_session"]:
        print("      no file could be tied to a logged USB session")
    for sid, files in s["files_by_session"].items():
        x = sess[sid]
        print(f"      Session #{sid} {x['connected'][:19]} -> {(x['disconnected'] or '?')[:19]}"
              f"{'  [AFTER HOURS]' if x['after_hours'] else ''}")
        for f in files:
            tags = [t for t, on in (("SUSPICIOUS", f["suspicious"]), ("DELETED", f["deleted"]),
                                    ("HIDDEN", f["hidden"])) if on]
            print(f"        {f['created'][11:19]}  {f['path']:<20} {' '.join(tags)}")
    if s["alerts"]:
        print(f"\n  Alerts: {len(s['alerts'])}")
        for a in s["alerts"]:
            print(f"    [{a['severity']:<6}] {a['category']:<13} {a['details'][:110]}")
    print()
    from modules import timeline
    rows = [r for r in s["timeline"] if not (hide_custody and r["source"].startswith("custody"))]
    timeline.print_timeline(rows)
    print(f"\nCase {case_id} saved to {db_path}, timeline written to {s['timeline_csv']} "
          f"({s['elapsed']:.2f}s)")
    if s.get("report"):
        print(f"Forensic report: {s['report']}")
    print("Dashboard: python dashboard/app.py  ->  http://127.0.0.1:5000")


if __name__ == "__main__":
    main()
