"""
Regression tests for the final code review (one test per finding).
Each test reproduces the original problem and checks it stays fixed.

    python -m unittest discover -s tests -v
"""
import os
import re
import shutil
import sqlite3
import struct
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from modules import device_info, impersonation, usb_capture  # noqa: E402

DATA = os.path.join(ROOT, "data")
SCEN_B = os.path.join(DATA, "scenario_b.img")
LOG_B = os.path.join(DATA, "usb.log")
PCAP = os.path.join(DATA, "usb_capture.pcap")
MTOOLS = all(shutil.which(t) for t in ("mkfs.vfat", "mcopy", "mmd", "mdeltree"))

try:
    import pytsk3  # noqa: F401
    import flask  # noqa: F401
    HAVE_TSK = True
except ImportError:
    HAVE_TSK = False


def run_main(cwd, *args, tz=None):
    env = dict(os.environ)
    if tz:
        env["TZ"] = tz
    return subprocess.run([sys.executable, os.path.join(ROOT, "main.py"), *args],
                          cwd=cwd, capture_output=True, text=True, env=env)


class Tmp(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="review_")

    def tearDown(self):
        for dirpath, _, files in os.walk(self.tmp):
            for f in files:
                os.chmod(os.path.join(dirpath, f), 0o644)
        shutil.rmtree(self.tmp, ignore_errors=True)

    def write(self, name, text):
        p = os.path.join(self.tmp, name)
        with open(p, "w") as fh:
            fh.write(text)
        return p


@unittest.skipUnless(HAVE_TSK and os.path.exists(SCEN_B), "needs pytsk3 + scenario images")
class TestR1TimezoneIndependence(Tmp):
    def test_ist_machine_gives_same_findings(self):
        """Finding 1: on an IST (or any non-UTC) PC the file times used to shift
        and no file matched its USB session."""
        p = run_main(self.tmp, SCEN_B, LOG_B, "--pcap", PCAP, "--no-report", tz="Asia/Kolkata")
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn("Alerts: 9", p.stdout)
        self.assertIn("22:51:20  /salary.xlsx", p.stdout)
        self.assertIn("Rogue/suspicious devices: 1", p.stdout)


@unittest.skipUnless(HAVE_TSK and MTOOLS, "needs pytsk3 + mtools")
class TestR3DeletedFolders(Tmp):
    def test_files_in_deleted_folder_are_found_and_recovered(self):
        """Finding 3: deleting a whole folder used to hide everything in it."""
        from modules import forensics
        img = os.path.join(self.tmp, "f.img")
        subprocess.run(["dd", "if=/dev/zero", f"of={img}", "bs=1M", "count=34", "status=none"],
                       check=True)
        subprocess.run(["mkfs.vfat", "-F", "32", img], check=True, capture_output=True)
        src = self.write("payroll.txt", "payroll for october\n")
        subprocess.run(["mmd", "-i", img, "::loot"], check=True)
        subprocess.run(["mcopy", "-i", img, src, "::loot/"], check=True)
        subprocess.run(["mdeltree", "-i", img, "::loot"], check=True)
        res = forensics.analyze(img, os.path.join(self.tmp, "rec"))
        self.assertEqual(len(res), 1)
        r = res[0]
        self.assertTrue(r["deleted"])
        self.assertTrue(r["path"].endswith("ayroll.txt"))       # FAT drops the first letter
        with open(r["recovered_path"]) as fh:
            self.assertEqual(fh.read(), "payroll for october\n")


@unittest.skipUnless(HAVE_TSK and MTOOLS, "needs pytsk3 + mtools")
class TestR2R5HostileFileNames(Tmp):
    def test_html_and_path_names_are_safe(self):
        """Findings 2 and 5: names from the evidence must never become markup
        or paths outside the recovery folder."""
        from modules import forensics
        img = os.path.join(self.tmp, "n.img")
        subprocess.run(["dd", "if=/dev/zero", f"of={img}", "bs=1M", "count=34", "status=none"],
                       check=True)
        subprocess.run(["mkfs.vfat", "-F", "32", img], check=True, capture_output=True)
        src = self.write("a.txt", "x\n")
        evil = "..&x';y z.txt"      # FAT forbids < > / \\ in names; these are what is left
        subprocess.run(["mcopy", "-i", img, src, f"::{evil}"], check=True, capture_output=True)
        subprocess.run(["mdel", "-i", img, f"::{evil}"], check=True, capture_output=True)
        res = forensics.analyze(img, os.path.join(self.tmp, "rec"))
        self.assertEqual(len(res), 1)
        out = res[0]["recovered_path"]
        self.assertEqual(os.path.dirname(out), os.path.join(self.tmp, "rec"))
        self.assertRegex(os.path.basename(out), r"^[A-Za-z0-9._-]+$")

    def test_safe_name_caps_length(self):
        from modules import forensics
        n = forensics.safe_name({"inode": 7, "name": "文" * 200 + ".txt"})
        self.assertLess(len(n.encode()), 100)
        t = forensics.safe_name({"inode": 7, "name": "../../etc/passwd"})
        self.assertNotIn("/", t)
        self.assertTrue(t.startswith("7_"))


@unittest.skipUnless(HAVE_TSK and os.path.exists(SCEN_B), "needs pytsk3 + scenario images")
class TestR2DashboardXss(Tmp):
    def test_usb_strings_cannot_break_out_of_script(self):
        """Finding 2: a BadUSB product string like </script><script>... was
        rendered raw inside the chart's <script> block."""
        with open(LOG_B) as fh:
            log = fh.read().replace("Product: DataTraveler 3.0\n",
                                    "Product: </script><script>alert(document.domain)</script>\n", 1)
        logp = self.write("evil.log", log)
        db = os.path.join(self.tmp, "case.db")
        from modules import pipeline
        case_id, _ = pipeline.run_case(SCEN_B, logp, "T", db_path=db, make_report=False, log=None)
        from dashboard import app as dash
        dash.app.config.update(DB=db, TESTING=True)
        html = dash.app.test_client().get(f"/case/{case_id}").data
        self.assertNotIn(b"<script>alert(document.domain)", html)
        self.assertNotIn(b"</script><script>alert", html)


class TestR4OpenSessions(Tmp):
    def test_missing_disconnect_does_not_swallow_later_sessions(self):
        """Finding 4: a session without a disconnect line claimed every later file."""
        with open(LOG_B) as fh:
            lines = [ln for ln in fh if "10:42:10" not in ln]      # drop the 10:42 disconnect
        logp = self.write("nodisc.log", "".join(lines))
        s = device_info.parse_log(logp)
        morning = [d for d in s if d["connected"].endswith("10:15:32")][0]
        self.assertEqual(morning["disconnected"], "2026-10-08T14:03:55")   # next device, same port
        self.assertIn("inferred", morning["disconnect_note"])
        if HAVE_TSK and os.path.exists(SCEN_B):
            p = run_main(self.tmp, SCEN_B, logp, "--no-report")
            self.assertEqual(p.returncode, 0, p.stderr)
            night = p.stdout.split("Session #5")[1]
            self.assertIn("[AFTER HOURS]", night.splitlines()[0])
            self.assertIn("/salary.xlsx", night)


class TestR6LogFormats(Tmp):
    LINES = ("usb 1-1: New USB device found, idVendor=0781, idProduct=5567, bcdDevice= 1.00\n",
             "usb 1-1: SerialNumber: 4C530001230915101234\n",
             "usb 1-1: USB disconnect, device number 5\n")

    def test_dmesg_T_and_iso_carry_their_year(self):
        a = self.write("t.log", "".join(f"[Thu Oct  8 10:15:3{i} 2026] {x}"
                                        for i, x in enumerate(self.LINES)))
        b = self.write("i.log", "".join(f"2025-12-31T23:59:5{i}+0100 pc kernel: {x}"
                                        for i, x in enumerate(self.LINES)))
        self.assertEqual(device_info.parse_log(a)[0]["connected"], "2026-10-08T10:15:30")
        s = device_info.parse_log(b)
        self.assertEqual(s[0]["connected"], "2025-12-31T23:59:50")
        self.assertEqual(device_info.LAST_PARSE["utc_offset"], "+0100")

    def test_feb_29_is_skipped_not_fatal(self):
        p = self.write("f.log", "Feb 29 10:00:00 pc kernel: " + self.LINES[0]
                       + "Oct  8 10:15:32 pc kernel: " + self.LINES[0])
        s = device_info.parse_log(p, year=2026)
        self.assertEqual(len(s), 1)
        self.assertTrue(any("bad date" in w for w in device_info.LAST_PARSE["warnings"]))

    def test_raw_dmesg_warns(self):
        p = self.write("r.log", "".join(f"[ 12.3{i}] {x}" for i, x in enumerate(self.LINES)))
        self.assertEqual(device_info.parse_log(p), [])
        self.assertTrue(any("journalctl" in w for w in device_info.LAST_PARSE["warnings"]))


class TestR8Captures(Tmp):
    def test_truncated_capture_never_yields_half_a_serial(self):
        with open(PCAP, "rb") as fh:
            data = fh.read()
        p = os.path.join(self.tmp, "cut.pcap")
        with open(p, "wb") as fh:
            fh.write(data[:-30])
        good = [d for d in usb_capture.parse_capture(p, "+0530") if d["vid"] == "0781"][0]
        self.assertIsNone(good["serial"])
        self.assertTrue(good["truncated"])

    def test_garbage_capture_is_a_clean_error(self):
        p = os.path.join(self.tmp, "junk.pcap")
        with open(p, "wb") as fh:
            fh.write(b"not a pcap" * 50)
        with self.assertRaises(ValueError):
            usb_capture.parse_capture(p)
        if HAVE_TSK and os.path.exists(SCEN_B):
            r = run_main(self.tmp, SCEN_B, LOG_B, "--pcap", p, "--no-report")
            self.assertEqual(r.returncode, 5)
            self.assertNotIn("Traceback", r.stderr)
            db = sqlite3.connect(os.path.join(self.tmp, "case.db"))
            acts = [a for (a,) in db.execute("SELECT action FROM custody_log")]
            self.assertIn("ANALYSIS_FAILED", acts)

    def test_capture_time_uses_log_offset(self):
        """Finding 7: pcap times are UTC; +0530 maps them onto the IST log."""
        seen = {d["vid"]: d["seen"] for d in usb_capture.parse_capture(PCAP, "+0530")}
        self.assertEqual(seen["0951"], "2026-10-08T22:44:10")
        utc = {d["vid"]: d["seen"] for d in usb_capture.parse_capture(PCAP)}
        self.assertEqual(utc["0951"], "2026-10-08T17:14:10")

    def test_capture_strings_must_match_log(self):
        cfg = impersonation.load_profiles()
        d = {"vid": "0781", "pid": "5567", "manufacturer": "SanDisk", "product": "Cruzer Blade",
             "serial": "4C530001230915101234", "serial_index": 3, "bcd_device": "1.00",
             "interfaces": ["mass_storage"],
             "descriptor": {"manufacturer": "SanDisk", "product": "Cruzer Blade",
                            "serial": "AAAAAAAAAAAAAAAAAAAA"}}
        score, verdict, _, _ = impersonation.evaluate(d, cfg, [d])
        self.assertEqual((score, verdict), (40, "SUSPICIOUS"))


class TestR10R11Scoring(unittest.TestCase):
    cfg = impersonation.load_profiles()

    def test_genuine_device_not_blamed_for_its_clone(self):
        g = {"vid": "0781", "pid": "5567", "manufacturer": "SanDisk", "product": "Cruzer Blade",
             "serial": "4C530001230915101234", "serial_index": 3, "interfaces": ["mass_storage"]}
        c = dict(g, vid="058f", pid="6387", manufacturer="Generic", product="Mass Storage")
        self.assertEqual(impersonation.evaluate(g, self.cfg, [g, c])[1], "GENUINE")
        self.assertEqual(impersonation.evaluate(c, self.cfg, [g, c])[1], "LIKELY_SPOOFED")

    def test_unknown_serial_is_not_scored_as_missing(self):
        g = {"vid": "0781", "pid": "5567", "manufacturer": "SanDisk", "product": "Cruzer Blade",
             "serial": None, "serial_index": None, "interfaces": ["mass_storage"]}
        score, verdict, reasons, _ = impersonation.evaluate(g, self.cfg, [g])
        self.assertEqual((score, verdict), (0, "GENUINE"))
        self.assertFalse(any("iSerialNumber=0" in r for r in reasons))

    def test_keyboard_matched_by_port_not_model(self):
        """Finding 11: two sticks of the same model; only the one that typed is a keyboard."""
        tmp = tempfile.mkdtemp()
        p = os.path.join(tmp, "two.log")
        t = "2026-10-08T22:00:0{}+0530 pc kernel: "
        with open(p, "w") as fh:
            fh.write(t.format(1) + "usb 1-1: New USB device found, idVendor=0951, idProduct=1666, bcdDevice= 1.00\n"
                     + t.format(2) + "usb 1-2: New USB device found, idVendor=0951, idProduct=1666, bcdDevice= 1.00\n"
                     + t.format(3) + "input: X as /devices/pci0000:00/0000:00:14.0/usb1/1-2/1-2:1.0/0003:0951:1666.0001/input/input9\n"
                     + t.format(3) + "hid-generic 0003:0951:1666.0001: input,hidraw0: USB HID v1.11 Keyboard [X] on usb-0000:00:14.0-2/input0\n")
        s = device_info.parse_log(p)
        shutil.rmtree(tmp)
        self.assertEqual([d["interfaces"] for d in s], [[], ["hid_keyboard"]])


@unittest.skipUnless(HAVE_TSK and MTOOLS, "needs pytsk3 + mtools")
class TestR12PartitionedImage(Tmp):
    def test_whole_disk_image_with_mbr(self):
        """Finding 12: a /dev/sdX image has an MBR; the FAT starts at sector 2048."""
        from modules import forensics
        img = os.path.join(self.tmp, "disk.img")
        size = 40 * 1048576
        with open(img, "wb") as fh:
            fh.truncate(size)
        part_start, part_len = 2048, size // 512 - 2048
        subprocess.run(["mkfs.vfat", "-F", "32", "--offset", str(part_start), img,
                        str(part_len * 512 // 1024)], check=True, capture_output=True)
        with open(img, "r+b") as fh:            # one MBR entry, type 0x0C (FAT32 LBA)
            fh.seek(446)
            fh.write(struct.pack("<B3sB3sII", 0, b"\0\0\0", 0x0C, b"\0\0\0", part_start, part_len))
            fh.seek(510)
            fh.write(b"\x55\xaa")
        src = self.write("doc.txt", "hello\n")
        subprocess.run(["mcopy", "-i", f"{img}@@{part_start * 512}", src, "::"], check=True)
        res = forensics.analyze(img, os.path.join(self.tmp, "rec"))
        self.assertEqual([r["name"] for r in res], ["doc.txt"])
        self.assertEqual(forensics.LAST_RUN["offset"], part_start * 512)
        v = forensics.volume_info(img, part_start * 512)
        self.assertEqual(v["fs_type"], "FAT32")


@unittest.skipUnless(HAVE_TSK and os.path.exists(SCEN_B), "needs pytsk3 + scenario images")
class TestR13R14CustodyAndPaths(Tmp):
    def test_analysis_steps_in_custody_and_files_next_to_db(self):
        sub = os.path.join(self.tmp, "cases")
        os.makedirs(sub)
        p = run_main(self.tmp, SCEN_B, LOG_B, "--db", os.path.join(sub, "other.db"), "--no-report")
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertTrue(os.path.exists(os.path.join(sub, "evidence", "case_1", "evidence.img")))
        self.assertTrue(os.path.exists(os.path.join(sub, "reports", "case_1_timeline.csv")))
        self.assertIn("other.db", p.stdout)
        acts = [a for (a,) in sqlite3.connect(os.path.join(sub, "other.db"))
                .execute("SELECT action FROM custody_log ORDER BY id")]
        self.assertLess(acts.index("ACQUISITION_VERIFIED"), acts.index("ANALYSIS_STARTED"))
        self.assertLess(acts.index("ANALYSIS_STARTED"), acts.index("ANALYSIS_COMPLETED"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
