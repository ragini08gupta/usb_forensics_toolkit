"""
Investigation dashboard (Flask).

    python dashboard/app.py [--db case.db] [--port 5000] [--host 127.0.0.1]

Pages
    /                      case list + "new investigation" form
    /case/<id>             dashboard: findings header + tabs
                           Device identification | Connection history | File activity |
                           Timeline reconstruction | Suspicious files | Evidence & custody
    /case/<id>/report.pdf  forensic report (generated on first request, then cached)
    /case/<id>/timeline.csv, /case/<id>/recovered/<file_id>, /api/case/<id>

The dashboard only READS the case database, except when the examiner starts
a new investigation, re-verifies a copy or regenerates the report; each of
those is written to the chain-of-custody log like on the command line.
Binds to 127.0.0.1 by default: evidence should not be served to the network.
"""
import argparse
import csv
import glob
import hmac
import io
import os
import secrets
import sys

from flask import (Flask, abort, flash, jsonify, redirect, render_template, request,
                   send_file, session, url_for)

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from modules import db, pipeline, timeline, writeblock  # noqa: E402

app = Flask(__name__)
app.config.update(DB=os.path.join(os.getcwd(), "case.db"), SECRET_KEY=os.urandom(16),
                  DATA_DIR=os.path.join(ROOT, "data"))


# ---- CSRF: every POST must carry the token from this browser session ----------
def csrf_token():
    if "csrf" not in session:
        session["csrf"] = secrets.token_hex(16)
    return session["csrf"]


app.jinja_env.globals["csrf_token"] = csrf_token


@app.before_request
def check_csrf():
    if request.method == "POST":
        sent = request.form.get("csrf", "")
        if not sent or not hmac.compare_digest(sent, session.get("csrf", "")):
            abort(400, "missing or invalid CSRF token")


def conn():
    return db.get_conn(app.config["DB"])


def workdir():
    return os.path.dirname(os.path.abspath(app.config["DB"]))


def rows_to_dicts(rows):
    return [dict(r) for r in rows]


def choices():
    d = app.config["DATA_DIR"]
    rel = lambda p: os.path.relpath(p, ROOT)            # noqa: E731
    return {"images": [rel(p) for p in sorted(glob.glob(os.path.join(d, "*.img")))],
            "logs": [rel(p) for p in sorted(glob.glob(os.path.join(d, "*.log")))],
            "pcaps": [rel(p) for p in sorted(glob.glob(os.path.join(d, "*.pcap")))]}


def load_case(case_id):
    c = conn()
    if not c.execute("SELECT 1 FROM cases WHERE id=?", (case_id,)).fetchone():
        c.close()
        abort(404)
    return c, pipeline.case_summary(c, case_id)


@app.template_filter("t19")
def t19(s):
    return s[:19].replace("T", " ") if s else "-"


@app.template_filter("mib")
def mib(n):
    return f"{n / 1048576:,.1f} MiB" if n else "-"


@app.template_filter("label")
def label(code):
    """LIKELY_SPOOFED -> Likely spoofed (the raw code stays in the CSS class)."""
    return str(code or "").replace("_", " ").capitalize() or "-"


# ------------------------------------------------------------------------------
@app.route("/")
def index():
    c = conn()
    cases = c.execute("""
        SELECT c.*, e.status, e.source_path,
          (SELECT COUNT(*) FROM files f WHERE f.case_id=c.id) AS n_files,
          (SELECT COUNT(*) FROM files f WHERE f.case_id=c.id AND f.suspicious=1) AS n_sus,
          (SELECT COUNT(*) FROM usb_events u WHERE u.case_id=c.id
             AND u.verdict IN ('LIKELY_SPOOFED','SUSPICIOUS')) AS n_rogue,
          (SELECT COUNT(*) FROM alerts a WHERE a.case_id=c.id AND a.severity='HIGH') AS n_high
        FROM cases c LEFT JOIN evidence e ON e.id =
          (SELECT MAX(id) FROM evidence WHERE case_id=c.id)
        ORDER BY c.id DESC""").fetchall()
    c.close()
    return render_template("index.html", cases=cases, choices=choices())


@app.route("/new", methods=["POST"])
def new_case():
    ch = choices()
    image, log = request.form.get("image"), request.form.get("log")
    pcap = request.form.get("pcap") or None
    examiner = (request.form.get("examiner") or "").strip()[:40] or "Examiner"
    # only files offered in the form may be used (no arbitrary paths from the browser)
    if image not in ch["images"] or log not in ch["logs"] or (pcap and pcap not in ch["pcaps"]):
        flash("Choose an image, log and capture from the lists.", "error")
        return redirect(url_for("index"))
    out = io.StringIO()
    try:
        case_id, _ = pipeline.run_case(
            os.path.join(ROOT, image), os.path.join(ROOT, log), examiner,
            db_path=app.config["DB"], workdir=workdir(),
            pcap=os.path.join(ROOT, pcap) if pcap else None,
            log=lambda *a: print(*a, file=out))
    except pipeline.PipelineError as e:
        flash(f"Investigation stopped (exit {e.code}): {e}", "error")
        return redirect(url_for("case", case_id=e.case_id) if e.case_id else url_for("index"))
    flash(f"Case {case_id} created: evidence acquired, verified and analysed.", "ok")
    return redirect(url_for("case", case_id=case_id))


@app.route("/case/<int:case_id>")
def case(case_id):
    c, s = load_case(case_id)
    tl = timeline.get_timeline(c, case_id)
    reports = c.execute("SELECT * FROM reports WHERE case_id=? ORDER BY id DESC",
                        (case_id,)).fetchall()
    c.close()
    sess = {x["id"]: x for x in s["sessions"]}
    chart = {
        "sessions": [{"id": x["id"], "label": f'#{x["id"]} {x["manufacturer"] or x["vid"]} '
                                              f'{x["product"] or x["pid"]}',
                      "start": x["connected"], "end": x["disconnected"],
                      "verdict": x["verdict"], "after_hours": bool(x["after_hours"]),
                      "evidence": bool(x["is_evidence_device"])} for x in s["sessions"]],
        "files": [{"name": f["name"], "t": f["created"][:19], "session": f["session_id"],
                   "suspicious": bool(f["suspicious"]), "deleted": bool(f["deleted"])}
                  for f in s["files"] if f["session_id"]],
    }
    # `chart` is rendered with |tojson, which escapes < > & so evidence-controlled
    # strings (USB product names, file names) cannot close the <script> tag
    return render_template("case.html", s=s, sess=sess, tl=tl, reports=reports,
                           chart=chart, case_id=case_id)


def _report_is_current(c, case_id):
    """Latest report, unless custody has new entries since it was made
    (e.g. a re-verification): then it no longer reflects the case."""
    rep = c.execute("SELECT id FROM custody_log WHERE case_id=? AND action='REPORT_GENERATED' "
                    "ORDER BY id DESC LIMIT 1", (case_id,)).fetchone()
    last = c.execute("SELECT MAX(id) FROM custody_log WHERE case_id=?", (case_id,)).fetchone()[0]
    row = c.execute("SELECT * FROM reports WHERE case_id=? ORDER BY id DESC LIMIT 1",
                    (case_id,)).fetchone()
    if rep and row and rep["id"] == last and os.path.exists(row["path"]):
        return row["path"]
    return None


def _new_report(c, case_id, examiner):
    from modules import report
    return report.generate(c, case_id, report.default_path(workdir(), case_id), examiner=examiner)


@app.route("/case/<int:case_id>/report.pdf")
def report_pdf(case_id):
    c, s = load_case(case_id)
    path = _report_is_current(c, case_id) or _new_report(c, case_id, s["case"]["examiner"])
    c.close()
    return send_file(os.path.abspath(path), mimetype="application/pdf",
                     download_name=f"case_{case_id}_forensic_report.pdf")


@app.route("/case/<int:case_id>/report", methods=["POST"])
def regenerate_report(case_id):
    c, s = load_case(case_id)
    _new_report(c, case_id, s["case"]["examiner"])
    c.close()
    flash("A new report was generated; its SHA-256 is in the custody log.", "ok")
    return redirect(url_for("case", case_id=case_id) + "#custody")


@app.route("/case/<int:case_id>/timeline.csv")
def timeline_csv(case_id):
    c, _ = load_case(case_id)
    rows = timeline.get_timeline(c, case_id)
    c.close()
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["timestamp", "source", "event", "description"])
    for r in rows:
        w.writerow([r["ts"], r["source"], r["kind"], r["description"]])
    return send_file(io.BytesIO(buf.getvalue().encode()), mimetype="text/csv",
                     as_attachment=True, download_name=f"case_{case_id}_timeline.csv")


@app.route("/case/<int:case_id>/recovered/<int:file_id>")
def recovered(case_id, file_id):
    c = conn()
    f = c.execute("SELECT * FROM files WHERE id=? AND case_id=?", (file_id, case_id)).fetchone()
    c.close()
    if not f or not f["recovered_path"]:
        abort(404)
    path = f["recovered_path"]
    if not os.path.isabs(path):
        path = os.path.join(workdir(), path)
    if not os.path.isfile(path):
        abort(404)
    # always a download, never rendered: recovered content is untrusted
    return send_file(os.path.abspath(path), mimetype="application/octet-stream",
                     as_attachment=True, download_name=f"recovered_{f['name']}")


@app.route("/case/<int:case_id>/verify", methods=["POST"])
def verify(case_id):
    c, s = load_case(case_id)
    ev = writeblock.latest_evidence_id(c, case_id)
    if ev is None:
        flash("No verified evidence in this case.", "error")
    else:
        ok = writeblock.reverify(c, ev, examiner=s["case"]["examiner"], log=None)
        flash("Re-verification PASSED: working copy still matches its acquisition hash." if ok
              else "Re-verification FAILED: the working copy has changed!", "ok" if ok else "error")
        timeline.build_events(c, case_id)
    c.close()
    return redirect(url_for("case", case_id=case_id) + "#custody")


@app.route("/api/case/<int:case_id>")
def api_case(case_id):
    c, s = load_case(case_id)
    tl = timeline.get_timeline(c, case_id)
    c.close()
    out = {k: (rows_to_dicts(v) if isinstance(v, list) else dict(v) if v is not None and
               hasattr(v, "keys") else v) for k, v in s.items() if k != "files_by_session"}
    out["files_by_session"] = {str(k): [f["path"] for f in v]
                               for k, v in s["files_by_session"].items()}
    out["timeline"] = rows_to_dicts(tl)
    return jsonify(out)


def main():
    p = argparse.ArgumentParser(description="USB forensics investigation dashboard")
    p.add_argument("--db", default="case.db")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=5000)
    a = p.parse_args()
    app.config["DB"] = os.path.abspath(a.db)
    print(f"Case database: {app.config['DB']}")
    if a.host not in ("127.0.0.1", "localhost", "::1"):
        print("WARNING: the dashboard serves evidence and has no login; "
              f"binding to {a.host} exposes it to the network.")
    app.run(host=a.host, port=a.port, debug=False)


if __name__ == "__main__":
    main()
