import argparse
import os
import sys
import time

from modules import db, forensics, device_info, timeline, writeblock

BASE = os.path.dirname(os.path.abspath(__file__))


def main():
    p = argparse.ArgumentParser(
        usage="python main.py <image> [usb_log] [--examiner NAME]")
    p.add_argument("image")
    p.add_argument("usb_log", nargs="?", default=os.path.join(BASE, "data", "usb.log"))
    p.add_argument("--examiner", default="Ragini",
                   help="name recorded in the case and chain-of-custody log")
    args = p.parse_args()
    image, log = args.image, args.usb_log
    if not os.path.isfile(log):
        print(f"USB log not found: {log}")
        sys.exit(1)

    start = time.time()
    conn = db.get_conn("case.db")
    case_id = db.new_case(conn, f"Investigation of {image}", args.examiner)

    # Step 1 (Vijay): acquire a verified copy; the original is never analysed directly.
    print("[1/6] Acquiring evidence (software write-block + SHA-256/MD5)...")
    dest = os.path.join("evidence", f"case_{case_id}", "evidence.img")
    try:
        evidence = writeblock.acquire(image, dest, conn, case_id)
    except writeblock.AcquisitionError as e:
        print(f"  ACQUISITION FAILED: {e}")
        print(f"  Analysis stopped. Failure recorded for case {case_id} in case.db.")
        sys.exit(2)
    ev = conn.execute("SELECT * FROM evidence WHERE id=?",
                      (writeblock.latest_evidence_id(conn, case_id),)).fetchone()
    print(f"  Source  : {ev['source_path']}")
    print(f"  Copy    : {ev['dest_path']}  ({ev['size_bytes']} bytes, read-only)")
    print(f"  SHA-256 : {ev['sha256_before']}")
    print(f"  MD5     : {ev['md5']}")
    print(f"  Status  : {ev['status']} (evidence id {ev['id']})")

    print("[2/6] Analysing file system (on the acquired copy)...")
    try:
        results = forensics.analyze(evidence)
    except OSError as e:
        print(f"  ANALYSIS FAILED: no readable file system in the image ({e})")
        print(f"  The verified copy is kept at {ev['dest_path']}.")
        sys.exit(4)
    forensics.save_files(conn, case_id, results)

    print("[3/6] Parsing USB connection log...")
    devices = device_info.parse_log(log)
    device_info.save_usb_events(conn, case_id, devices)

    print("[4/6] Building timeline...")
    timeline.build_events(conn, case_id)
    rows = timeline.get_timeline(conn, case_id)
    timeline.export_csv(rows, "timeline.csv")

    print("[5/6] Re-verifying acquired copy after analysis...")
    still_ok = writeblock.reverify(conn, ev["id"])

    print("[6/6] Summary")
    deleted = [r for r in results if r["deleted"]]
    sus = [r for r in results if r["suspicious"]]
    print(f"  Evidence integrity: {'VERIFIED' if still_ok else 'FAILED'}")
    print(f"  Files found: {len(results)}  Deleted: {len(deleted)}  Suspicious: {len(sus)}")
    print(f"  USB sessions: {len(devices)}")
    for r in sus:
        print(f'  ! {r["path"]}: {"; ".join(r["reasons"])}')
    print()
    timeline.print_timeline(rows)
    print(f"\nCase {case_id} saved to case.db, timeline.csv written "
          f"({time.time() - start:.2f}s)")
    if not still_ok:
        sys.exit(3)


if __name__ == "__main__":
    main()
