import sys
import time

from modules import db, forensics, device_info, timeline


def main():
    if len(sys.argv) < 2:
        print("usage: python main.py <image> [usb_log]")
        sys.exit(1)
    image = sys.argv[1]
    log = sys.argv[2] if len(sys.argv) > 2 else "data/usb.log"

    start = time.time()
    conn = db.get_conn("case.db")
    case_id = db.new_case(conn, f"Investigation of {image}", "Ragini")

    # TODO (Vijay): writeblock.acquire(image, "evidence.img", conn, case_id)
    # then analyze the acquired copy instead of the original.

    print("[1/4] Analysing file system...")
    results = forensics.analyze(image)
    forensics.save_files(conn, case_id, results)

    print("[2/4] Parsing USB connection log...")
    devices = device_info.parse_log(log)
    device_info.save_usb_events(conn, case_id, devices)

    print("[3/4] Building timeline...")
    timeline.build_events(conn, case_id)
    rows = timeline.get_timeline(conn, case_id)
    timeline.export_csv(rows, "timeline.csv")

    print("[4/4] Summary")
    deleted = [r for r in results if r["deleted"]]
    sus = [r for r in results if r["suspicious"]]
    print(f"  Files found: {len(results)}  Deleted: {len(deleted)}  Suspicious: {len(sus)}")
    print(f"  USB sessions: {len(devices)}")
    for r in sus:
        print(f'  ! {r["path"]}: {"; ".join(r["reasons"])}')
    print()
    timeline.print_timeline(rows)
    print(f"\nCase {case_id} saved to case.db, timeline.csv written "
          f"({time.time() - start:.2f}s)")


if __name__ == "__main__":
    main()
