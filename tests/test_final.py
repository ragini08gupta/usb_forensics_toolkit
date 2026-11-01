"""
Tests for the final-phase modules: device identification, usbmon capture
parsing, impersonation detection, file/session correlation, PDF report,
live sysfs enumeration and the Flask dashboard.

    python -m unittest discover -s tests -v

Everything runs on temporary files and copies of the scenario images.
"""
import builtins
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from modules import db, device_info, impersonation, usb_capture, writeblock  # noqa: E402

DATA = os.path.join(ROOT, "data")
SCEN_A, SCEN_B = os.path.join(DATA, "scenario_a.img"), os.path.join(DATA, "scenario_b.img")
LOG_B, LOG_A = os.path.join(DATA, "usb.log"), os.path.join(DATA, "usb_a.log")
PCAP = os.path.join(DATA, "usb_capture.pcap")
CFG = impersonation.load_profiles()

try:
    import pytsk3  # noqa: F401
    HAVE_TSK = True
except ImportError:
    HAVE_TSK = False
try:
    import flask  # noqa: F401
    import reportlab  # noqa: F401
    HAVE_WEB = True
except ImportError:
    HAVE_WEB = False
HAVE_IMAGES = os.path.exists(SCEN_A) and os.path.exists(SCEN_B)


def csrf_from(html):
    import re
    return re.search(rb'name="csrf" value="([0-9a-f]+)"', html).group(1).decode()


def session(**kw):
    d = {"vid": "0781", "pid": "5567", "manufacturer": "SanDisk", "product": "Cruzer Blade",
         "serial": "4C530001230915101234", "serial_index": 3, "bcd_device": "1.00",
         "bcd_usb": "2.10", "interfaces": ["mass_storage"], "connected": "2026-10-08T10:00:00",
         "disconnected": "2026-10-08T10:30:00", "capacity_bytes": None}
    d.update(kw)
    return d


# ------------------------------------------------------------------------------
class TestDeviceLog(unittest.TestCase):
    def test_01_sessions_and_fields(self):
        s = device_info.parse_log(LOG_B)
        self.assertEqual(len(s), 5)
        sandisk = s[1]
        self.assertEqual((sandisk["vid"], sandisk["pid"], sandisk["serial"]),
                         ("0781", "5567", "4C530001230915101234"))
        self.assertEqual(sandisk["interfaces"], ["mass_storage"])
        self.assertEqual((sandisk["block_device"], sandisk["capacity_bytes"]), ("sdb", 64 * 1048576))
        self.assertEqual(sandisk["bcd_device"], "1.00")
        rogue = s[3]
        self.assertEqual(rogue["interfaces"], ["hid_keyboard"])
        self.assertEqual(rogue["serial_index"], 0)
        self.assertIsNone(rogue["serial"])
        self.assertEqual((rogue["connected"], rogue["disconnected"]),
                         ("2026-10-08T22:44:10", "2026-10-08T22:44:58"))
        self.assertIsNone(s[0]["disconnected"])            # keyboard never unplugged

    def test_02_old_style_log_still_parses(self):
        """The prototype's log format (no strings/interfaces lines) must still work."""
        tmp = tempfile.mkdtemp()
        p = os.path.join(tmp, "old.log")
        with open(p, "w") as fh:
            fh.write("Oct  8 10:15:32 lab kernel: [ 1.0] usb 1-1: New USB device found, "
                     "idVendor=0781, idProduct=5567, bcdDevice= 1.00\n"
                     "Oct  8 10:15:32 lab kernel: [ 1.0] usb 1-1: SerialNumber: ABC\n"
                     "Oct  8 10:42:10 lab kernel: [ 2.0] usb 1-1: USB disconnect, device number 5\n")
        s = device_info.parse_log(p, year=2026)
        shutil.rmtree(tmp)
        self.assertEqual(len(s), 1)
        self.assertEqual(s[0]["serial"], "ABC")
        self.assertEqual(s[0]["disconnected"], "2026-10-08T10:42:10")


class TestUsbCapture(unittest.TestCase):
    def check(self, devs):
        by = {(d["vid"], d["pid"]): d for d in devs}
        rogue, good = by[("0951", "1666")], by[("0781", "5567")]
        self.assertEqual(rogue["interfaces"], ["hid_keyboard"])
        self.assertEqual((rogue["bcd_usb"], rogue["serial_index"], rogue["max_packet0"]),
                         ("1.10", 0, 8))
        self.assertEqual(rogue["product"], "DataTraveler 3.0")
        self.assertEqual(good["serial"], "4C530001230915101234")
        self.assertEqual(good["interfaces"], ["mass_storage"])
        self.assertEqual(good["seen"], "2026-10-08T22:50:02")

    def test_03_capture_with_scapy(self):
        self.check(usb_capture.parse_capture(PCAP, "+0530"))

    def test_04_capture_without_scapy(self):
        real = builtins.__import__

        def no_scapy(name, *a, **k):
            if name.startswith("scapy"):
                raise ImportError("hidden for test")
            return real(name, *a, **k)
        with mock.patch("builtins.__import__", no_scapy):
            self.check(usb_capture.parse_capture(PCAP, "+0530"))

    def test_05_merge_into_log_sessions(self):
        merged = usb_capture.merge_into_sessions(device_info.parse_log(LOG_B),
                                                 usb_capture.parse_capture(PCAP, "+0530"))
        self.assertEqual(len(merged), 5)                    # both matched existing sessions
        self.assertEqual(merged[3]["bcd_usb"], "1.10")
        self.assertIn("usbmon", merged[3]["sources"])
        self.assertIn("usbmon", merged[4]["sources"])
        self.assertNotIn("usbmon", merged[1]["sources"])   # morning session was not captured

    def test_06_unmatched_capture_becomes_session(self):
        merged = usb_capture.merge_into_sessions([], usb_capture.parse_capture(PCAP, "+0530"))
        self.assertEqual(len(merged), 2)


class TestImpersonation(unittest.TestCase):
    def verdict(self, d, others=()):
        return impersonation.evaluate(d, CFG, [d, *others])

    def test_07_genuine(self):
        score, v, reasons, prof = self.verdict(session())
        self.assertEqual((score, v, prof), (0, "GENUINE", "SanDisk Cruzer Blade"))

    def test_08_badusb_storage_claim_with_keyboard(self):
        d = session(vid="0951", pid="1666", manufacturer="Kingston", product="DataTraveler 3.0",
                    serial=None, serial_index=0, bcd_usb="1.10", interfaces=["hid_keyboard"],
                    connected="2026-10-08T22:44:10", disconnected="2026-10-08T22:44:58")
        score, v, reasons, _ = self.verdict(d)
        self.assertEqual(v, "LIKELY_SPOOFED")
        self.assertEqual(score, 130)
        self.assertTrue(any("HID keyboard" in r for r in reasons))

    def test_09_known_attack_board(self):
        d = session(vid="16d0", pid="0753", manufacturer=None, product=None,
                    interfaces=["hid_keyboard"])
        self.assertEqual(self.verdict(d)[1], "LIKELY_SPOOFED")

    def test_10_manufacturer_mismatch_is_suspicious(self):
        d = session(manufacturer="SanDlsk")
        score, v, _, _ = self.verdict(d)
        self.assertEqual((score, v), (40, "SUSPICIOUS"))

    def test_11_cloned_serial(self):
        a = session()
        b = session(vid="058f", pid="6387", manufacturer="Generic", product="Mass Storage")
        score, v, reasons, _ = self.verdict(b, [a])
        self.assertTrue(any("cloned serial" in r for r in reasons))
        self.assertIn(v, ("SUSPICIOUS", "LIKELY_SPOOFED"))

    def test_12_unknown_device(self):
        d = session(vid="abcd", pid="1234", manufacturer="Acme", product="Stick")
        self.assertEqual(self.verdict(d)[1], "UNVERIFIED")
        d = session(vid="abcd", pid="1234", interfaces=["mass_storage", "hid_keyboard"])
        self.assertEqual(self.verdict(d)[1], "LIKELY_SPOOFED")

    def test_13_genuine_keyboard_not_flagged(self):
        d = session(vid="046d", pid="c31c", manufacturer="Logitech", product="USB Keyboard",
                    serial=None, serial_index=0, bcd_device="64.02", bcd_usb=None,
                    interfaces=["hid_keyboard"])
        self.assertEqual(self.verdict(d)[1], "GENUINE")

    def test_14_scenario_verdicts_and_evidence_device(self):
        s = usb_capture.merge_into_sessions(device_info.parse_log(LOG_B),
                                            usb_capture.parse_capture(PCAP, "+0530"))
        impersonation.analyse_sessions(s, CFG, evidence_size=64 * 1048576)
        self.assertEqual([d["verdict"] for d in s],
                         ["GENUINE", "GENUINE", "GENUINE", "LIKELY_SPOOFED", "GENUINE"])
        self.assertEqual([d["is_evidence_device"] for d in s], [False, True, False, False, True])
        self.assertEqual([d["after_hours"] for d in s], [False, False, False, True, True])


class TestSysfs(unittest.TestCase):
    """A fake /sys tree: one SanDisk stick (sdb) and one HID-only 'Kingston'."""

    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="sysfs_")
        dev = os.path.join(self.root, "devices", "pci0000:00", "usb1")

        def mk(port, attrs, ifaces):
            d = os.path.join(dev, port)
            os.makedirs(d)
            for k, v in attrs.items():
                with open(os.path.join(d, k), "w") as fh:
                    fh.write(v + "\n")
            for i, (cls, proto) in enumerate(ifaces):
                idir = os.path.join(d, f"{port}:1.{i}")
                os.makedirs(idir)
                for k, v in (("bInterfaceClass", cls), ("bInterfaceProtocol", proto)):
                    with open(os.path.join(idir, k), "w") as fh:
                        fh.write(v + "\n")
            link = os.path.join(self.root, "bus", "usb", "devices", port)
            os.makedirs(os.path.dirname(link), exist_ok=True)
            os.symlink(d, link)
            return d
        stick = mk("1-1", {"idVendor": "0781", "idProduct": "5567", "bcdDevice": "0100",
                           "manufacturer": "SanDisk", "product": "Cruzer Blade",
                           "serial": "4C530001230915101234", "version": " 2.10",
                           "bDeviceClass": "00"}, [("08", "50")])
        mk("1-3", {"idVendor": "0951", "idProduct": "1666", "bcdDevice": "0100",
                   "manufacturer": "Kingston", "product": "DataTraveler 3.0", "version": " 1.10",
                   "bDeviceClass": "00"}, [("03", "01")])
        disk = os.path.join(stick, "1-1:1.0", "host6", "target6:0:0", "6:0:0:0", "block", "sdb")
        os.makedirs(disk)
        os.makedirs(os.path.join(self.root, "class", "block"))
        os.symlink(disk, os.path.join(self.root, "class", "block", "sdb"))
        os.symlink(os.path.dirname(os.path.dirname(disk)), os.path.join(disk, "device"))
        with open(os.path.join(disk, "size"), "w") as fh:
            fh.write("131072\n")

    def tearDown(self):
        shutil.rmtree(self.root)

    def test_15_identify_block_device(self):
        d = device_info.sysfs_identify("/dev/sdb", sys_root=self.root)
        self.assertEqual((d["vid"], d["pid"], d["serial"]), ("0781", "5567", "4C530001230915101234"))
        self.assertEqual((d["block_device"], d["capacity_bytes"]), ("sdb", 64 * 1048576))
        self.assertEqual((d["bcd_device"], d["interfaces"]), ("1.00", ["mass_storage"]))

    def test_16_live_enumeration_flags_rogue(self):
        from modules import live_usb
        devs = live_usb.check(live_usb.enumerate_devices(sys_root=self.root), CFG)
        self.assertEqual({d["port"]: d["verdict"] for d in devs},
                         {"1-1": "GENUINE", "1-3": "LIKELY_SPOOFED"})


@unittest.skipUnless(HAVE_TSK and HAVE_IMAGES, "needs pytsk3 and scenario images")
class TestVolumeAndTimes(unittest.TestCase):
    def test_17_volume_info(self):
        from modules import forensics
        v = forensics.volume_info(SCEN_B)
        self.assertEqual((v["fs_type"], v["volume_serial"], v["label"]), ("FAT32", "4C53-B0B0", "USB_B"))
        self.assertEqual(forensics.volume_info(LOG_B)["fs_type"], "unknown")

    def test_18_story_timestamps_and_copy_indicator(self):
        from modules import forensics
        tmp = tempfile.mkdtemp()
        res = {r["name"]: r for r in forensics.analyze(SCEN_B, tmp)}
        shutil.rmtree(tmp)
        self.assertNotIn("USB_B", " ".join(res))           # volume label is not a file
        self.assertEqual(res["salary.xlsx"]["created"][:19], "2026-10-08T22:51:20")
        self.assertEqual(res["salary.xlsx"]["modified"][:19], "2026-10-05T17:30:12")
        self.assertIsNotNone(res["salary.xlsx"]["copy_indicator"])
        self.assertIsNone(res["secret.txt"]["copy_indicator"])   # authored on the stick
        self.assertEqual(len(res["salary.xlsx"]["sha256"]), 64)

    def test_19_images_are_reproducible(self):
        """Two rebuilds give byte-identical images (fixed volume id + stamped times)."""
        if not shutil.which("mkfs.vfat") or not shutil.which("mcopy"):
            self.skipTest("mtools/dosfstools not installed")
        hashes = []
        for _ in range(2):
            tmp = tempfile.mkdtemp()
            for f in ("make_scenarios.sh", "set_fat_times.py", "times_a.json", "times_b.json"):
                shutil.copy(os.path.join(DATA, f), tmp)
            for d in ("planted", "planted_a"):
                shutil.copytree(os.path.join(DATA, d), os.path.join(tmp, d))
            subprocess.run(["bash", "make_scenarios.sh"], cwd=tmp, check=True, capture_output=True)
            hashes.append([writeblock.hash_file(os.path.join(tmp, n))[0]
                           for n in ("scenario_a.img", "scenario_b.img")])
            shutil.rmtree(tmp)
        self.assertEqual(hashes[0], hashes[1])


@unittest.skipUnless(HAVE_TSK and HAVE_IMAGES and HAVE_WEB, "needs pytsk3, flask, reportlab, images")
class TestPipelineReportDashboard(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from modules import pipeline
        cls.tmp = tempfile.mkdtemp(prefix="final_")
        cls.db = os.path.join(cls.tmp, "case.db")
        cls.case_b, cls.sb = pipeline.run_case(SCEN_B, LOG_B, "Vijay", db_path=cls.db,
                                               workdir=cls.tmp, pcap=PCAP, log=None)
        cls.case_a, cls.sa = pipeline.run_case(SCEN_A, LOG_A, "Ragini", db_path=cls.db,
                                               workdir=cls.tmp, log=None)

    @classmethod
    def tearDownClass(cls):
        for dirpath, _, files in os.walk(cls.tmp):
            for f in files:
                os.chmod(os.path.join(dirpath, f), 0o644)
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def test_20_what_was_copied_and_when(self):
        s = self.sb
        names = {sid: sorted(f["name"] for f in fl) for sid, fl in s["files_by_session"].items()}
        sess = {x["id"]: x for x in s["sessions"]}
        night = [sid for sid in names if sess[sid]["connected"].endswith("22:50:02")][0]
        self.assertEqual(names[night], sorted(["client_list.docx", "salary.xlsx", "passwords.txt",
                                               "report.pdf", "invoice.jpg", "secret.txt"]))
        morning = [sid for sid in names if sess[sid]["connected"].endswith("10:15:32")][0]
        self.assertEqual(names[morning], ["holiday.jpg", "notes.txt"])
        self.assertTrue(s["device_answer"].startswith("GENUINE"))
        self.assertEqual(len(s["rogue"]), 1)
        self.assertTrue(s["integrity_ok"])

    def test_21_alerts(self):
        cats = [(a["severity"], a["category"]) for a in self.sb["alerts"]]
        self.assertEqual(cats.count(("HIGH", "impersonation")), 1)
        self.assertEqual(cats.count(("HIGH", "file")), 6)
        self.assertEqual(cats.count(("MEDIUM", "policy")), 2)

    def test_22_scenario_a_has_no_alerts(self):
        self.assertEqual(self.sa["alerts"], [])
        self.assertEqual(self.sa["rogue"], [])
        self.assertEqual(len(self.sa["files"]), 3)

    def test_23_report_pdf_and_custody(self):
        path = self.sb["report"]
        with open(path, "rb") as fh:
            self.assertEqual(fh.read(5), b"%PDF-")
        conn = db.get_conn(self.db)
        row = conn.execute("SELECT * FROM reports WHERE case_id=?", (self.case_b,)).fetchone()
        self.assertEqual(row["sha256"], writeblock.hash_file(path)[0])
        acts = [r["action"] for r in conn.execute(
            "SELECT action FROM custody_log WHERE case_id=? ORDER BY id", (self.case_b,))]
        self.assertEqual(acts[-1], "REPORT_GENERATED")
        self.assertIn("REVERIFY_PASS", acts)
        conn.close()
        try:
            import pdfplumber
        except ImportError:
            return
        with pdfplumber.open(path) as pdf:
            text = "\n".join(p.extract_text() or "" for p in pdf.pages)
        for needle in ("LIKELY_SPOOFED", "salary.xlsx", "Chain of custody", "AFTER HOURS"):
            self.assertIn(needle, text)

    def test_24_dashboard_pages(self):
        from dashboard import app as dash
        dash.app.config.update(DB=self.db, TESTING=True)
        c = dash.app.test_client()
        self.assertEqual(c.get("/").status_code, 200)
        r = c.get(f"/case/{self.case_b}")
        self.assertEqual(r.status_code, 200)
        for needle in (b"LIKELY_SPOOFED", b"Device identification", b"Connection history",
                       b"File activity", b"Timeline reconstruction", b"Suspicious files"):
            self.assertIn(needle, r.data)
        self.assertEqual(c.get("/case/999").status_code, 404)
        r = c.get(f"/case/{self.case_b}/report.pdf")
        self.assertEqual((r.status_code, r.data[:5]), (200, b"%PDF-"))
        r.close()
        r = c.get(f"/case/{self.case_b}/timeline.csv")
        self.assertIn(b"USB_CONNECT", r.data)
        j = c.get(f"/api/case/{self.case_b}").get_json()
        self.assertEqual(len(j["sessions"]), 5)

    def test_25_dashboard_recovered_download(self):
        from dashboard import app as dash
        dash.app.config.update(DB=self.db, TESTING=True)
        c = dash.app.test_client()
        conn = db.get_conn(self.db)
        f = conn.execute("SELECT id, name FROM files WHERE case_id=? AND name='salary.xlsx'",
                         (self.case_b,)).fetchone()
        live = conn.execute("SELECT id FROM files WHERE case_id=? AND deleted=0",
                            (self.case_b,)).fetchone()
        conn.close()
        r = c.get(f"/case/{self.case_b}/recovered/{f['id']}")
        with open(os.path.join(DATA, "planted", "salary.xlsx"), "rb") as fh:
            self.assertEqual(r.data, fh.read())
        self.assertIn("attachment", r.headers["Content-Disposition"])
        r.close()
        self.assertEqual(c.get(f"/case/{self.case_b}/recovered/{live['id']}").status_code, 404)
        self.assertEqual(c.get(f"/case/{self.case_a}/recovered/{f['id']}").status_code, 404)

    def test_26_dashboard_rejects_arbitrary_paths_and_reverifies(self):
        from dashboard import app as dash
        dash.app.config.update(DB=self.db, TESTING=True)
        c = dash.app.test_client()
        token = csrf_from(c.get("/").data)
        n = sqlite3.connect(self.db).execute("SELECT COUNT(*) FROM cases").fetchone()[0]
        r = c.post("/new", data={"image": "/etc/passwd", "log": "data/usb.log", "examiner": "x",
                                 "csrf": token})
        self.assertEqual(r.status_code, 302)
        self.assertEqual(sqlite3.connect(self.db).execute("SELECT COUNT(*) FROM cases")
                         .fetchone()[0], n)
        r = c.post(f"/case/{self.case_a}/verify", data={"csrf": token}, follow_redirects=True)
        self.assertIn(b"Re-verification PASSED", r.data)

    def test_30_csrf_required(self):
        from dashboard import app as dash
        dash.app.config.update(DB=self.db, TESTING=True)
        c = dash.app.test_client()
        c.get("/")
        self.assertEqual(c.post(f"/case/{self.case_a}/verify").status_code, 400)
        self.assertEqual(c.post(f"/case/{self.case_a}/verify", data={"csrf": "x" * 32})
                         .status_code, 400)
        self.assertEqual(c.post("/new", data={"image": "data/scenario_a.img",
                                              "log": "data/usb_a.log"}).status_code, 400)

    def test_31_report_history_and_stale_report(self):
        from dashboard import app as dash
        dash.app.config.update(DB=self.db, TESTING=True)
        c = dash.app.test_client()
        token = csrf_from(c.get("/").data)
        q = "SELECT path, sha256 FROM reports WHERE case_id=? ORDER BY id"
        before = sqlite3.connect(self.db).execute(q, (self.case_b,)).fetchall()
        c.post(f"/case/{self.case_b}/verify", data={"csrf": token})     # custody changes
        r = c.get(f"/case/{self.case_b}/report.pdf")                      # -> stale -> rebuilt
        r.close()
        after = sqlite3.connect(self.db).execute(q, (self.case_b,)).fetchall()
        self.assertEqual(len(after), len(before) + 1)
        for path, sha in after:                       # every recorded report still verifies
            self.assertEqual(writeblock.hash_file(path)[0], sha)
        r = c.get(f"/case/{self.case_b}/report.pdf")                      # current -> reused
        r.close()
        self.assertEqual(len(sqlite3.connect(self.db).execute(q, (self.case_b,)).fetchall()),
                         len(after))


class TestMisc(unittest.TestCase):
    def test_27_setro_on_regular_file_is_harmless(self):
        tmp = tempfile.mkdtemp()
        p = os.path.join(tmp, "x.img")
        with open(p, "wb") as fh:
            fh.write(b"x" * 10)
        self.assertIn("not a block device", writeblock.enforce_kernel_ro(p))
        shutil.rmtree(tmp)

    def test_28_old_database_is_migrated(self):
        tmp = tempfile.mkdtemp()
        path = os.path.join(tmp, "old.db")
        old = sqlite3.connect(path)
        old.executescript("CREATE TABLE usb_events(id INTEGER PRIMARY KEY, case_id INTEGER, vid TEXT);"
                          "CREATE TABLE files(id INTEGER PRIMARY KEY, case_id INTEGER, path TEXT);"
                          "CREATE TABLE alerts(id INTEGER PRIMARY KEY, case_id INTEGER, severity TEXT);"
                          "INSERT INTO usb_events(case_id, vid) VALUES(1, '0781');")
        old.commit()
        old.close()
        conn = db.get_conn(path)
        for table, cols in db.EXTRA_COLUMNS.items():
            have = {r["name"] for r in conn.execute(f"PRAGMA table_info({table})")}
            self.assertTrue(set(cols) <= have, table)
        self.assertEqual(conn.execute("SELECT vid FROM usb_events").fetchone()[0], "0781")
        conn.close()
        shutil.rmtree(tmp)

    def test_29_profiles_file_is_valid(self):
        with open(impersonation.DEFAULT_PROFILES) as fh:
            cfg = json.load(fh)
        for p in cfg["profiles"]:
            self.assertRegex(p["vid"], r"^[0-9a-f]{4}$")
            self.assertRegex(p["pid"], r"^[0-9a-f]{4}$")
            self.assertTrue(p["interfaces"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
