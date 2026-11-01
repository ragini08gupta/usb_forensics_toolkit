"""
report.py - auto-generated forensic report (PDF, ReportLab).

    python -m modules.report <case_id> [--db case.db] [--out reports/case_N_report.pdf]

Sections: case details, key findings (was the device genuine / what was
copied / when), evidence integrity, chain of custody, device identification
and impersonation verdicts, connection history with a session chart, file
inventory, deleted & recovered files, suspicious files, alerts, timeline,
limitations and examiner sign-off. The report's own SHA-256 is recorded in
the reports table and the chain-of-custody log.
"""
import hashlib
import os
import sys
from datetime import datetime, timezone

from reportlab.graphics.shapes import Drawing, Line, Rect, String
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (CondPageBreak, KeepTogether, PageBreak, Paragraph, SimpleDocTemplate,
                                Spacer, Table, TableStyle)

from modules import writeblock

TITLE = "USB Forensics Investigation Report"
TEAM = ""

INK = colors.HexColor("#1f2933")
MUTED = colors.HexColor("#5f6b7a")
RULE = colors.HexColor("#d5dbe3")
HEAD_BG = colors.HexColor("#eef1f5")
VERDICT_COLORS = {"GENUINE": colors.HexColor("#2f855a"), "UNVERIFIED": colors.HexColor("#718096"),
                  "SUSPICIOUS": colors.HexColor("#b7791f"),
                  "LIKELY_SPOOFED": colors.HexColor("#c53030")}
SEV_COLORS = {"HIGH": colors.HexColor("#c53030"), "MEDIUM": colors.HexColor("#b7791f"),
              "LOW": colors.HexColor("#718096")}

ss = getSampleStyleSheet()
H1 = ParagraphStyle("H1", parent=ss["Heading1"], fontSize=15, spaceBefore=10, spaceAfter=6,
                    textColor=INK)
H2 = ParagraphStyle("H2", parent=ss["Heading2"], fontSize=11.5, spaceBefore=8, spaceAfter=4,
                    textColor=INK)
BODY = ParagraphStyle("B", parent=ss["BodyText"], fontSize=9, leading=12.5, textColor=INK)
SMALL = ParagraphStyle("S", parent=BODY, fontSize=7.6, leading=9.6)
MONO = ParagraphStyle("M", parent=SMALL, fontName="Courier", fontSize=7.2, leading=9)
CELL = ParagraphStyle("C", parent=SMALL)
CENTER = ParagraphStyle("CT", parent=BODY, alignment=TA_CENTER)


def esc(s):
    return (str(s) if s is not None else "-").replace("&", "&amp;").replace("<", "&lt;") \
        .replace(">", "&gt;")


def P(text, style=CELL):
    return Paragraph(text, style)


def table(rows, widths, header=True, zebra=True, extra=()):
    data = [[c if hasattr(c, "wrap") else P(esc(c)) for c in r] for r in rows]
    t = Table(data, colWidths=widths, repeatRows=1 if header else 0)
    st = [("GRID", (0, 0), (-1, -1), 0.4, RULE),
          ("VALIGN", (0, 0), (-1, -1), "TOP"),
          ("LEFTPADDING", (0, 0), (-1, -1), 3), ("RIGHTPADDING", (0, 0), (-1, -1), 3),
          ("TOPPADDING", (0, 0), (-1, -1), 2), ("BOTTOMPADDING", (0, 0), (-1, -1), 2)]
    if header:
        st.append(("BACKGROUND", (0, 0), (-1, 0), HEAD_BG))
    if zebra:
        for i in range(2 if header else 1, len(rows), 2):
            st.append(("BACKGROUND", (0, i), (-1, i), colors.HexColor("#f9fafb")))
    t.setStyle(TableStyle(st + list(extra)))
    return t


def kv(rows, w=(42 * mm, 128 * mm)):
    return table([[P(f"<b>{esc(k)}</b>"), v if hasattr(v, "wrap") else P(esc(v))]
                  for k, v in rows], w, header=False, zebra=False)


def badge(verdict):
    c = VERDICT_COLORS.get(verdict, MUTED)
    return P(f'<font color="{c.hexval()}"><b>{esc(verdict)}</b></font>')


def t19(s):
    return s[:19].replace("T", " ") if s else "-"


# ------------------------------------------------------------------------------
def session_chart(sessions, files, width=170 * mm):
    """Swim-lane chart: one lane per USB session, file-arrival ticks on top."""
    from datetime import datetime as dt
    times = [dt.fromisoformat(s["connected"][:19]) for s in sessions if s["connected"]]
    times += [dt.fromisoformat(s["disconnected"][:19]) for s in sessions if s["disconnected"]]
    if not times:
        return None
    t0 = min(times).replace(minute=0, second=0)
    t1 = max(times).replace(minute=0, second=0)
    span = max(3600.0, (t1 - t0).total_seconds() + 3600)
    label_w, lane_h = 52 * mm, 7 * mm
    plot_w = width - label_w - 4 * mm
    h = lane_h * len(sessions) + 14 * mm
    d = Drawing(width, h)

    def x(ts):
        return label_w + plot_w * ((dt.fromisoformat(ts[:19]) - t0).total_seconds() / span)

    hours = int(span // 3600)
    step = 1 if hours <= 8 else 2
    for k in range(0, hours + 1, step):
        xx = label_w + plot_w * (k * 3600 / span)
        d.add(Line(xx, 8 * mm, xx, h - 2, strokeColor=RULE, strokeWidth=0.4))
        d.add(String(xx, 3 * mm, f"{(t0.hour + k) % 24:02d}:00", fontSize=6.5, fontName="Helvetica",
                     fillColor=MUTED, textAnchor="middle"))
    by_session = {}
    for f in files:
        if f["session_id"]:
            by_session.setdefault(f["session_id"], []).append(f)
    for i, s in enumerate(sessions):
        y = h - (i + 1) * lane_h - 2
        lab = f'#{s["id"]} {(s["manufacturer"] or s["vid"])} {(s["product"] or s["pid"])}'[:34]
        d.add(String(2, y + 2.2 * mm, lab, fontSize=6.8, fontName="Helvetica", fillColor=INK))
        if not s["connected"]:
            continue
        xa = x(s["connected"])
        xb = x(s["disconnected"]) if s["disconnected"] else label_w + plot_w
        c = VERDICT_COLORS.get(s["verdict"], MUTED)
        d.add(Rect(xa, y + 1 * mm, max(3.0, xb - xa), lane_h - 3 * mm, fillColor=c,
                   strokeColor=None, fillOpacity=0.85))
        for f in by_session.get(s["id"], []):
            fx = x(f["created"])
            d.add(Line(fx, y + lane_h - 1.4 * mm, fx, y + lane_h + 0.2 * mm,
                       strokeColor=colors.HexColor("#c53030") if f["suspicious"] else INK,
                       strokeWidth=0.9))
    return d


# ------------------------------------------------------------------------------
def _footer(canvas, doc):
    canvas.saveState()
    canvas.setFont("Helvetica", 7)
    canvas.setFillColor(MUTED)
    canvas.drawString(18 * mm, 10 * mm, f"{TITLE} - case {doc.case_id}")
    canvas.drawRightString(A4[0] - 18 * mm, 10 * mm, f"page {doc.page}")
    canvas.setStrokeColor(RULE)
    canvas.line(18 * mm, 13 * mm, A4[0] - 18 * mm, 13 * mm)
    canvas.restoreState()


def build_story(s, examiner):
    case, ev, vol = s["case"], s["evidence"], s["volume"]
    sess_by_id = {x["id"]: x for x in s["sessions"]}
    story = [Spacer(1, 4 * mm),
             P(f"<font size=8 color='{MUTED.hexval()}'>INFORMATION SECURITY LAB · "
               f"MINI PROJECT</font>", BODY),
             P(f"<font size=20><b>{TITLE}</b></font>", ParagraphStyle("T", parent=BODY,
                                                                     leading=26)),
             P(f"<font color='{MUTED.hexval()}'>{TEAM}</font>", BODY), Spacer(1, 4 * mm)]
    story.append(kv([
        ("Case", f'#{case["id"]} - {case["name"]}'),
        ("Examiner", case["examiner"]),
        ("Case opened (UTC)", t19(case["created"])),
        ("Report generated (UTC)", t19(datetime.now(timezone.utc).isoformat())),
        ("Evidence source", ev["source_path"] if ev else "-"),
        ("Tool", ev["tool"] if ev else "-"),
    ]))

    # ---- key findings ----
    story.append(P("1. Key findings", H1))
    integ = "VERIFIED" if ev and ev["status"] == "VERIFIED" else (ev["status"] if ev else "-")
    rev = [c for c in s["custody"] if c["action"].startswith("REVERIFY")]
    if rev:
        integ += " · re-verified after analysis: " + ("PASS" if rev[-1]["action"] ==
                                                       "REVERIFY_PASS" else "FAIL")
    copied = []
    for sid, fl in s["files_by_session"].items():
        x = sess_by_id[sid]
        names = ", ".join(
            f'{f["name"]}{" (deleted)" if f["deleted"] else ""}'
            for f in fl
        )

        after_hours = (
            ' <font color="#c53030"><b>AFTER HOURS</b></font>'
            if x["after_hours"] else ""
        )

        copied.append(
            f'<b>Session #{sid}</b> {t19(x["connected"])} - '
            f'{t19(x["disconnected"])[11:]}'
            f'{after_hours}: {esc(names)}'
        )

    rogue = [
        f'<font color="#c53030"><b>{esc(x["verdict"])}</b></font> session #{x["id"]} '
        f'{x["vid"]}:{x["pid"]} "{esc(x["manufacturer"])} {esc(x["product"])}" at '
        f'{t19(x["connected"])} (score {x["score"]})'
        for x in s["rogue"]
    ]
    story.append(kv([
        ("Evidence integrity", integ),
        ("Was the evidence device genuine?", s["device_answer"]),
        ("Rogue / spoofed devices", P("<br/>".join(rogue) or "none detected")),
        ("What was copied, and when", P("<br/>".join(copied) or
                                        "no file could be tied to a logged USB session")),
        ("Files", f'{len(s["files"])} found · {len(s["deleted"])} deleted '
                  f'({sum(1 for f in s["deleted"] if f["recovered_path"])} recovered) · '
                  f'{len(s["suspicious"])} flagged'),
        ("Alerts", f'{len(s["alerts"])} ('
                   + ", ".join(f'{sum(1 for a in s["alerts"] if a["severity"] == k)} {k}'
                               for k in ("HIGH", "MEDIUM", "LOW")) + ")"),
    ], w=(48 * mm, 122 * mm)))
    story.append(Spacer(1, 2 * mm))
    story.append(P("Indicators are triage aids for the examiner; they must be interpreted with "
                   "the wider case context and corroborated before conclusions are drawn.", SMALL))

    # ---- integrity ----
    story.append(P("2. Evidence acquisition and integrity", H1))
    if ev:
        story.append(kv([
            ("Status", badge(ev["status"]) if ev["status"] != "VERIFIED" else
             P(f'<font color="#2f855a"><b>VERIFIED</b></font>')),
            ("Acquired (UTC)", t19(ev["acquired_at"])),
            ("Working copy", ev["dest_path"]),
            ("Size", f'{ev["size_bytes"]:,} bytes' if ev["size_bytes"] else "-"),
            ("SHA-256 source (before)", P(esc(ev["sha256_before"]), MONO)),
            ("SHA-256 source (after)", P(esc(ev["sha256_source_after"]), MONO)),
            ("SHA-256 working copy", P(esc(ev["sha256_after"]), MONO)),
            ("MD5 source / copy", P(f'{esc(ev["md5"])}<br/>{esc(ev["md5_after"])}', MONO)),
            ("Write protection", ev["protection"]),
        ]))

    story.append(P("3. Chain of custody", H1))
    story.append(table([["Time (UTC)", "Examiner", "Action", "Details"]] +
                       [[t19(c["ts"]), c["examiner"], c["action"], P(esc(c["details"]), MONO)]
                        for c in s["custody"]],
                       [27 * mm, 17 * mm, 34 * mm, 92 * mm]))

    # ---- devices ----
    story.append(CondPageBreak(90 * mm))
    story.append(P("4. Device identification and impersonation check", H1))
    if vol:
        story.append(P("4.1 Imaged volume (boot sector)", H2))
        story.append(kv([("File system", vol["fs_type"]), ("Volume serial", vol["volume_serial"]),
                         ("Label", vol["label"]), ("OEM name", vol["oem_name"]),
                         ("Sector / cluster", f'{vol["bytes_per_sector"]} / {vol["cluster_size"]} bytes'),
                         ("Size", f'{vol["total_bytes"]:,} bytes')]))
    story.append(P("4.2 USB devices observed", H2))
    rows = [["#", "VID:PID", "Device (claimed)", "Serial", "Interfaces", "Verdict", "Score"]]
    for x in s["sessions"]:
        rows.append([str(x["id"]), f'{x["vid"]}:{x["pid"]}',
                     P(f'{esc(x["manufacturer"])} {esc(x["product"])}'
                       f'{"<br/><i>imaged device</i>" if x["is_evidence_device"] else ""}'),
                     P(esc(x["serial"] or "(none)"), MONO), x["interfaces"] or "-",
                     badge(x["verdict"]), str(x["score"])])
    story.append(table(rows, [8 * mm, 17 * mm, 40 * mm, 36 * mm, 26 * mm, 30 * mm, 13 * mm]))
    for x in s["sessions"]:
        if x["reasons"]:
            story.append(Spacer(1, 2 * mm))
            story.append(KeepTogether([
                P(f'<b>Session #{x["id"]} {x["vid"]}:{x["pid"]} - {esc(x["verdict"])} '
                  f'(score {x["score"]})</b> · sources: {esc(x["sources"])}', SMALL),
                P(esc(x["reasons"]).replace("\n", "<br/>"), SMALL)]))
    story.append(Spacer(1, 2 * mm))
    story.append(P("Scoring compares each device's descriptors (VID/PID, strings, serial, bcdDevice, "
                   "bcdUSB, bound interfaces) with known-good fingerprints. GENUINE &lt; 25 ≤ "
                   "SUSPICIOUS &lt; 60 ≤ LIKELY_SPOOFED. A perfect descriptor clone cannot be "
                   "detected from descriptors alone.", SMALL))

    story.append(P("5. Connection history", H1))
    chart = session_chart(s["sessions"], s["files"])
    if chart:
        story.append(chart)
        story.append(P("Bars: USB sessions coloured by verdict (green genuine, amber suspicious, red "
                       "likely spoofed, grey unverified). Ticks: files written to the imaged device "
                       "(red = flagged). Times are the suspect machine's local time.", SMALL))
    rows = [["#", "Device", "Port / disk", "Connected", "Disconnected", "Notes"]]
    for x in s["sessions"]:
        notes = []
        if x["after_hours"]:
            notes.append("<font color='#c53030'><b>after hours</b></font>")
        if x["capacity_bytes"]:
            notes.append(f'{x["capacity_bytes"] / 1048576:.1f} MiB')
        if x["is_evidence_device"]:
            notes.append("matches image")
        if x["disconnect_note"]:
            notes.append(esc(x["disconnect_note"]))
        rows.append([str(x["id"]), f'{x["vid"]}:{x["pid"]} {x["product"] or ""}',
                     f'{x["port"] or "-"} {x["block_device"] or ""}', t19(x["connected"]),
                     t19(x["disconnected"]), P(", ".join(notes) or "-")])
    story.append(Spacer(1, 2 * mm))
    story.append(table(rows, [8 * mm, 46 * mm, 20 * mm, 30 * mm, 30 * mm, 36 * mm]))

    # ---- files ----
    story.append(CondPageBreak(80 * mm))
    story.append(P("6. File activity", H1))
    rows = [["Path", "Size", "Created", "Modified", "Session", "State"]]
    for f in s["files"]:
        state = [t for t, on in (("deleted", f["deleted"]), ("hidden", f["hidden"]),
                                 ("flagged", f["suspicious"])) if on]
        rows.append([P(f'<b>{esc(f["path"])}</b>'), f'{f["size"]:,}', t19(f["created"]),
                     t19(f["modified"]), f'#{f["session_id"]}' if f["session_id"] else "-",
                     ", ".join(state) or "-"])
    story.append(table(rows, [38 * mm, 14 * mm, 31 * mm, 31 * mm, 14 * mm, 42 * mm]))
    story.append(Spacer(1, 1.5 * mm))
    story.append(P("On FAT, copying a file keeps its original <i>modified</i> time but sets a new "
                   "<i>created</i> time, so created &gt; modified indicates the content was copied onto "
                   "the device rather than authored there. FAT stores the access date only and no "
                   "deletion time.", SMALL))

    story.append(P("6.1 Deleted and recovered files", H2))
    if s["deleted"]:
        story.append(table([["Path", "Recovered to", "SHA-256 of content"]] +
                           [[f["path"], P(esc(f["recovered_path"]), MONO), P(esc(f["sha256"]), MONO)]
                            for f in s["deleted"]], [32 * mm, 58 * mm, 80 * mm]))
    else:
        story.append(P("No deleted entries were found.", BODY))

    story.append(P("6.2 Suspicious files", H2))
    if s["suspicious"]:
        story.append(table([["Path", "Reasons", "SHA-256"]] +
                           [[f["path"], P(esc(f["reasons"])), P(esc(f["sha256"]), MONO)]
                            for f in s["suspicious"]], [32 * mm, 68 * mm, 70 * mm]))
    else:
        story.append(P("No file met the suspicious-file rules.", BODY))

    story.append(P("7. Alerts", H1))
    if s["alerts"]:
        story.append(table([["Severity", "Category", "Verdict", "Details"]] +
                           [[P(f'<font color="{SEV_COLORS.get(a["severity"], MUTED).hexval()}">'
                               f'<b>{a["severity"]}</b></font>'), a["category"], a["verdict"],
                             a["details"]] for a in s["alerts"]],
                           [16 * mm, 22 * mm, 30 * mm, 102 * mm]))
    else:
        story.append(P("No alerts were raised.", BODY))

    # ---- timeline ----
    story.append(PageBreak())
    story.append(P("8. Reconstructed timeline", H1))
    story.append(P("File-system and USB events in the suspect machine's local time; chain-of-custody "
                   "actions in UTC (examiner clock).", SMALL))
    story.append(Spacer(1, 1.5 * mm))
    story.append(table([["Time", "Source", "Event", "Detail"]] +
                       [[t19(r["ts"]), r["source"], r["kind"], P(esc(r["description"]), SMALL)]
                        for r in s["timeline"]],
                       [28 * mm, 20 * mm, 30 * mm, 92 * mm]))

    story.append(P("9. Limitations", H1))
    for t in ("Write-blocking is software-based (O_RDONLY descriptor, verified write probe; optional "
              "kernel read-only flag for live devices). No hardware write-blocker was used. Hashes "
              "detect change, they do not prevent it.",
              "FAT has no deletion timestamp and only an access date; the deletion entries in the "
              "timeline use the modified time as an approximation.",
              "Log and file-system times are local, zone-less wall-clock times. Clock drift on the "
              "suspect machine affects both equally but is not corrected.",
              "Impersonation checks rely on descriptors. A device that clones every descriptor of a "
              "genuine model (including its serial and interfaces) cannot be distinguished this way.",
              "Suspicious-file rules (signature mismatch, entropy, keywords, hidden attribute) can "
              "produce false positives and need manual review."):
        story.append(P("• " + t, BODY))

    story.append(Spacer(1, 10 * mm))
    story.append(table([["Examiner", "Signature", "Date"],
                        [examiner or case["examiner"], "", ""]],
                       [60 * mm, 70 * mm, 40 * mm], zebra=False,
                       extra=[("ROWBACKGROUNDS", (0, 1), (-1, 1), [colors.white]),
                              ("TOPPADDING", (0, 1), (-1, 1), 12),
                              ("BOTTOMPADDING", (0, 1), (-1, 1), 12)]))
    return story


def default_path(workdir, case_id):
    """A new file per generation, so earlier reports (and their recorded
    SHA-256 in the custody log) stay verifiable."""
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    return os.path.join(workdir, "reports", f"case_{case_id}_report_{stamp}.pdf")


def generate(conn, case_id, out_path, examiner=None, summary=None):
    from modules import pipeline, timeline
    s = summary or pipeline.case_summary(conn, case_id)
    s.setdefault("timeline", timeline.get_timeline(conn, case_id))
    os.makedirs(os.path.dirname(os.path.abspath(out_path)), exist_ok=True)
    doc = SimpleDocTemplate(out_path, pagesize=A4, leftMargin=18 * mm, rightMargin=18 * mm,
                            topMargin=16 * mm, bottomMargin=18 * mm, title=TITLE,
                            author=examiner or s["case"]["examiner"],
                            subject=f"Case {case_id}")
    doc.case_id = case_id
    doc.build(build_story(s, examiner), onFirstPage=_footer, onLaterPages=_footer)
    sha, _, _ = writeblock.hash_file(out_path)
    conn.execute("INSERT INTO reports(case_id,path,sha256,created,examiner) VALUES(?,?,?,?,?)",
                 (case_id, os.path.abspath(out_path), sha, writeblock.now(),
                  examiner or s["case"]["examiner"]))
    writeblock.custody(conn, case_id, examiner or s["case"]["examiner"], "REPORT_GENERATED",
                       f"{os.path.abspath(out_path)} sha256={sha}")
    return out_path


def _cli(argv):
    import argparse
    from modules import db
    p = argparse.ArgumentParser(prog="python -m modules.report")
    p.add_argument("case_id", type=int)
    p.add_argument("--db", default="case.db")
    p.add_argument("--out")
    a = p.parse_args(argv)
    if not os.path.exists(a.db):
        print(f"database not found: {a.db}")
        return 1
    conn = db.get_conn(a.db)
    if not conn.execute("SELECT 1 FROM cases WHERE id=?", (a.case_id,)).fetchone():
        print(f"case {a.case_id} not found")
        return 1
    out = a.out or default_path(os.path.dirname(os.path.abspath(a.db)), a.case_id)
    print(generate(conn, a.case_id, out))
    return 0


if __name__ == "__main__":
    sys.exit(_cli(sys.argv[1:]))
