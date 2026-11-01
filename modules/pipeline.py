"""
pipeline.py - the full investigation, shared by main.py and the dashboard.

    [1/8] Acquire          writeblock.acquire     (verified read-only copy)
    [2/8] Device identity  forensics.volume_info  (+ sysfs if the source is a live USB disk)
    [3/8] File system      forensics.analyze      (on the COPY, never the original)
    [4/8] USB history      device_info.parse_log  (+ usb_capture descriptors if a pcap is given)
    [5/8] Impersonation    impersonation.analyse_sessions
    [6/8] Timeline         timeline.correlate_files / build_events
    [7/8] Re-verify        writeblock.reverify
    [8/8] Report           report.generate (PDF) + summary
"""
import os
import stat
import time

from modules import db, device_info, forensics, impersonation, timeline, usb_capture, writeblock


TOOL_VERSION = "usb_forensics_toolkit 2.0"


class PipelineError(Exception):
    def __init__(self, msg, code, case_id=None):
        super().__init__(msg)
        self.code, self.case_id = code, case_id


def run_case(image, usb_log, examiner, db_path="case.db", workdir=None, pcap=None,
             profiles=None, device_serial=None, make_report=True, set_ro=False,
             log=print, case_name=None, log_year=None, tz_offset=None):
    """Run the whole investigation. Returns (case_id, summary dict).
    Raises PipelineError(code): 1 bad input, 2 acquisition failed, 3 integrity
    failed after analysis, 4 no readable file system, 5 USB log / capture unreadable.
    Evidence, recovered files and reports go next to the database (workdir)."""
    say = writeblock._safe_logger(log)
    if usb_log and not os.path.isfile(usb_log):
        raise PipelineError(f"USB log not found: {usb_log}", 1)
    if pcap and not os.path.isfile(pcap):
        raise PipelineError(f"usbmon capture not found: {pcap}", 1)
    cfg = impersonation.load_profiles(profiles or impersonation.DEFAULT_PROFILES)
    workdir = os.path.abspath(workdir or os.path.dirname(os.path.abspath(db_path)))

    start = time.time()
    conn = db.get_conn(db_path)
    case_id = db.new_case(conn, case_name or f"Investigation of {os.path.basename(image)}", examiner)
    try:
        return case_id, _run(conn, case_id, image, usb_log, examiner, workdir, pcap, cfg,
                             device_serial, make_report, set_ro, say, start, log_year,
                             tz_offset)
    finally:
        conn.close()


def _stop(conn, case_id, examiner, say, step, err, code):
    say(f"  {step} FAILED: {err}")
    writeblock.custody(conn, case_id, examiner, "ANALYSIS_FAILED", f"{step}: {err}")
    raise PipelineError(str(err), code, case_id)


def _run(conn, case_id, image, usb_log, examiner, workdir, pcap, cfg, device_serial,
         make_report, set_ro, say, start, log_year, tz_offset):
    # ---- 1. acquisition (Vijay) -------------------------------------------------
    say("[1/8] Acquiring evidence (software write-block + SHA-256/MD5)...")
    dest = os.path.join(workdir, "evidence", f"case_{case_id}", "evidence.img")
    try:
        evidence = writeblock.acquire(image, dest, conn, case_id, log=say, set_ro=set_ro)
    except writeblock.AcquisitionError as e:
        say(f"  ACQUISITION FAILED: {e}")
        say(f"  Analysis stopped. Failure recorded for case {case_id} in case.db.")
        raise PipelineError(str(e), 2, case_id)
    ev = conn.execute("SELECT * FROM evidence WHERE id=?",
                      (writeblock.latest_evidence_id(conn, case_id),)).fetchone()
    say(f"  Source  : {ev['source_path']}")
    say(f"  Copy    : {ev['dest_path']}  ({ev['size_bytes']} bytes, read-only)")
    say(f"  SHA-256 : {ev['sha256_before']}")
    say(f"  MD5     : {ev['md5']}")
    say(f"  Status  : {ev['status']} (evidence id {ev['id']})")

    # ---- 2. device / volume identification ------------------------------------
    writeblock.custody(conn, case_id, examiner, "ANALYSIS_STARTED",
                       f"{TOOL_VERSION}; pytsk3 on the verified copy {evidence}; "
                       f"usb_log={usb_log and os.path.abspath(usb_log)}; "
                       f"pcap={pcap and os.path.abspath(pcap)}", ev["id"])
    say("[2/8] Identifying device and volume...")
    try:
        import pytsk3
        _, offset = forensics.open_fs(pytsk3.Img_Info(evidence))
    except OSError:
        offset = 0
    vol = forensics.volume_info(evidence, offset)
    forensics.save_volume(conn, case_id, vol)
    say(f"  Volume  : {vol.get('fs_type')}  serial {vol.get('volume_serial', '-')}  "
        f"label '{vol.get('label', '')}'  OEM '{vol.get('oem_name', '')}'  "
        f"{vol['total_bytes']} bytes" + (f"  (partition at byte {offset})" if offset else ""))
    live = None
    if stat.S_ISBLK(os.stat(image).st_mode):
        live = device_info.sysfs_identify(image)
        if live:
            say(f"  Live USB: {live['vid']}:{live['pid']} {live['manufacturer']} "
                f"{live['product']} serial={live['serial']} (sysfs)")

    # ---- 3. file system (Ragini) ------------------------------------------------
    say("[3/8] Analysing file system (on the acquired copy)...")
    try:
        results = forensics.analyze(evidence, os.path.join(workdir, "recovered", f"case_{case_id}"))
    except OSError as e:
        say(f"  ANALYSIS FAILED: no readable file system in the image ({e})")
        say(f"  The verified copy is kept at {ev['dest_path']}.")
        writeblock.custody(conn, case_id, examiner, "ANALYSIS_FAILED",
                           f"no readable file system: {e}", ev["id"])
        raise PipelineError(str(e), 4, case_id)
    forensics.save_files(conn, case_id, results)
    for err in forensics.LAST_RUN.get("errors", []):
        say(f"  ! could not read {err}")
    if not forensics.HIDDEN_CHECK["available"]:
        say("  ! mtools not installed: hidden-attribute check skipped")

    # ---- 4. USB connection history ---------------------------------------------
    say("[4/8] Parsing USB connection history...")
    try:
        sessions = device_info.parse_log(usb_log, year=log_year) if usb_log else []
    except (OSError, UnicodeError) as e:
        _stop(conn, case_id, examiner, say, "USB LOG", e, 5)
    parse = dict(device_info.LAST_PARSE) if usb_log else {}
    for w in parse.get("warnings", []):
        say(f"  ! {w}")
    say(f"  {len(sessions)} session(s) in the kernel log"
        + (f", clock offset {parse['utc_offset']}" if parse.get("utc_offset") else ""))
    if pcap:
        try:
            captured = usb_capture.parse_capture(pcap, tz_offset or parse.get("utc_offset"))
        except ValueError as e:
            _stop(conn, case_id, examiner, say, "USB CAPTURE", e, 5)
        say(f"  usbmon capture: {len(captured)} enumerated device(s) with descriptors")
        sessions = usb_capture.merge_into_sessions(sessions, captured)
    if live:
        sessions.append(live)
    device_info.save_usb_events(conn, case_id, sessions)

    # ---- 5. impersonation (Vijay) ----------------------------------------------
    say("[5/8] Checking devices against known-good fingerprints...")
    impersonation.analyse_sessions(sessions, cfg, evidence_size=ev["size_bytes"],
                                   device_serial=device_serial or (live or {}).get("serial"))
    impersonation.save(conn, case_id, sessions)
    for d in sessions:
        mark = "!" if d["verdict"] in ("LIKELY_SPOOFED", "SUSPICIOUS") else " "
        say(f"  {mark} #{d['id']:<3} {d['vid']}:{d['pid']} {(d.get('manufacturer') or '')[:10]:<10} "
            f"{(d.get('product') or '')[:18]:<18} {d['verdict']:<15} score {d['score']}"
            f"{'  [evidence device]' if d['is_evidence_device'] else ''}")

    # ---- 6. timeline (Ragini) ---------------------------------------------------
    say("[6/8] Correlating files with USB sessions and building timeline...")
    timeline.correlate_files(conn, case_id)
    timeline.file_alerts(conn, case_id)

    # ---- 7. re-verify (Vijay) ---------------------------------------------------
    say("[7/8] Re-verifying acquired copy after analysis...")
    still_ok = writeblock.reverify(conn, ev["id"], log=say)
    if not still_ok:
        db.add_alert(conn, case_id, "HIGH", "integrity", "REVERIFY_FAIL",
                     "acquired copy no longer matches its acquisition hash")

    writeblock.custody(conn, case_id, examiner, "ANALYSIS_COMPLETED",
                       f"files={len(results)} deleted={sum(r['deleted'] for r in results)} "
                       f"flagged={sum(r['suspicious'] for r in results)} sessions={len(sessions)} "
                       f"read_errors={len(forensics.LAST_RUN.get('errors', []))}", ev["id"])
    timeline.build_events(conn, case_id)
    rows = timeline.get_timeline(conn, case_id)
    os.makedirs(os.path.join(workdir, "reports"), exist_ok=True)
    csv_path = os.path.join(workdir, "reports", f"case_{case_id}_timeline.csv")
    timeline.export_csv(rows, csv_path)
    timeline.export_csv(rows, os.path.join(workdir, "timeline.csv"))      # latest case

    # ---- 8. report + summary -----------------------------------------------------
    report_path = None
    if make_report:
        say("[8/8] Generating forensic report (PDF)...")
        from modules import report                       # ReportLab only needed here
        report_path = report.generate(conn, case_id, report.default_path(workdir, case_id),
                                      examiner=ev["examiner"])
        say(f"  Report  : {report_path}")
    else:
        say("[8/8] Summary (report skipped)")

    s = case_summary(conn, case_id)
    s.update(integrity_ok=still_ok, report=report_path, timeline=rows, timeline_csv=csv_path,
             elapsed=time.time() - start)
    if not still_ok:
        raise PipelineError("integrity check failed after analysis", 3, case_id)
    return s


# ------------------------------------------------------------------------------
# Findings: the three questions of the synopsis - what was copied, when, and
# was the device genuine?
# ------------------------------------------------------------------------------
def case_summary(conn, case_id):
    q = lambda sql, *a: conn.execute(sql, (case_id,) + a).fetchall()   # noqa: E731
    files = q("SELECT * FROM files WHERE case_id=? ORDER BY created")
    sessions = q("SELECT * FROM usb_events WHERE case_id=? ORDER BY connected")
    ev = conn.execute("SELECT * FROM evidence WHERE case_id=? ORDER BY id DESC LIMIT 1",
                      (case_id,)).fetchone()
    by_session = {}
    for f in files:
        if f["session_id"]:
            by_session.setdefault(f["session_id"], []).append(f)
    evid = [s for s in sessions if s["is_evidence_device"]]
    evid_verdicts = {s["verdict"] for s in evid}
    if not evid:
        device_answer = "evidence device not matched to a logged USB session"
    elif evid_verdicts <= {"GENUINE"}:
        s0 = evid[0]
        device_answer = (f"GENUINE - {s0['manufacturer']} {s0['product']} serial {s0['serial']} "
                         f"matches its known-good fingerprint in all {len(evid)} session(s)")
    else:
        device_answer = "NOT VERIFIED - evidence device verdicts: " + ", ".join(sorted(evid_verdicts))
    return {
        "case": conn.execute("SELECT * FROM cases WHERE id=?", (case_id,)).fetchone(),
        "evidence": ev,
        "volume": conn.execute("SELECT * FROM volume WHERE case_id=? ORDER BY id DESC",
                               (case_id,)).fetchone(),
        "files": files,
        "deleted": [f for f in files if f["deleted"]],
        "suspicious": [f for f in files if f["suspicious"]],
        "sessions": sessions,
        "files_by_session": by_session,
        "evidence_sessions": evid,
        "rogue": [s for s in sessions if s["verdict"] in ("LIKELY_SPOOFED", "SUSPICIOUS")],
        "alerts": q("SELECT * FROM alerts WHERE case_id=? ORDER BY "
                    "CASE severity WHEN 'HIGH' THEN 0 WHEN 'MEDIUM' THEN 1 ELSE 2 END, ts, id"),
        "custody": q("SELECT * FROM custody_log WHERE case_id=? ORDER BY id"),
        "device_answer": device_answer,
    }
