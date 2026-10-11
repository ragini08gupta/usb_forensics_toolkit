"""
Tests for modules/writeblock.py (Vijay) and its integration with
Ragini's forensics module.  Run from the project root:

    python -m unittest discover -s tests -v

All tests use disposable files in a temporary directory or COPIES of the
scenario images. Nothing here ever writes to a real USB device.
"""
import hashlib
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

from modules import db, writeblock  # noqa: E402

DATA = os.path.join(ROOT, "data")
SCEN_A = os.path.join(DATA, "scenario_a.img")
SCEN_B = os.path.join(DATA, "scenario_b.img")

try:
    import pytsk3  # noqa: F401
    from modules import forensics
    HAVE_TSK = True
except ImportError:
    HAVE_TSK = False


def sha256_of(path):
    with open(path, "rb") as fh:
        return hashlib.sha256(fh.read()).hexdigest()


def md5_of(path):
    with open(path, "rb") as fh:
        return hashlib.md5(fh.read()).hexdigest()


class WriteblockTestBase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="wb_test_")
        self.conn = db.get_conn(os.path.join(self.tmp, "case.db"))
        self.case_id = db.new_case(self.conn, "unit test", "Vijay")
        # disposable 3 MiB + 123 bytes "evidence" (not a multiple of the chunk size)
        self.src = os.path.join(self.tmp, "source.img")
        with open(self.src, "wb") as fh:
            fh.write(os.urandom(3 * 1024 * 1024 + 123))
        self.dest = os.path.join(self.tmp, "out", "evidence.img")

    def tearDown(self):
        self.conn.close()
        for dirpath, _, files in os.walk(self.tmp):   # read-only files block rmtree on some OSes
            for f in files:
                os.chmod(os.path.join(dirpath, f), 0o644)
        shutil.rmtree(self.tmp, ignore_errors=True)

    def acquire(self, src=None, dest=None, **kw):
        kw.setdefault("log", None)                      # keep test output quiet
        return writeblock.acquire(src or self.src, dest or self.dest,
                                  self.conn, self.case_id, **kw)

    def evidence_rows(self):
        return self.conn.execute("SELECT * FROM evidence WHERE case_id=? ORDER BY id",
                                 (self.case_id,)).fetchall()

    def custody_actions(self):
        return [r["action"] for r in self.conn.execute(
            "SELECT action FROM custody_log WHERE case_id=? ORDER BY id", (self.case_id,))]


class TestAcquisition(WriteblockTestBase):
    def test_01_successful_acquisition_hashes_match(self):
        out = self.acquire()
        self.assertEqual(out, self.dest)
        self.assertEqual(sha256_of(out), sha256_of(self.src))
        self.assertEqual(md5_of(out), md5_of(self.src))
        row = self.evidence_rows()[-1]
        self.assertEqual(row["status"], "VERIFIED")
        self.assertEqual(row["verified"], 1)
        self.assertEqual(row["sha256_before"], sha256_of(self.src))   # independent hashlib check
        self.assertEqual(row["sha256_after"], row["sha256_before"])
        self.assertEqual(row["sha256_source_after"], row["sha256_before"])
        self.assertEqual(row["md5"], md5_of(self.src))
        self.assertEqual(row["md5_after"], row["md5"])
        self.assertEqual(row["size_bytes"], os.path.getsize(self.src))
        self.assertEqual(row["examiner"], "Vijay")
        self.assertIn("O_RDONLY", row["protection"])
        self.assertIn("not used / not verified", row["protection"])

    def test_02_original_evidence_preserved(self):
        before_hash = sha256_of(self.src)
        before_mtime = os.stat(self.src).st_mtime_ns
        self.acquire()
        self.assertEqual(sha256_of(self.src), before_hash)
        self.assertEqual(os.stat(self.src).st_mtime_ns, before_mtime)

    def test_03_copy_is_read_only_and_no_partial_left(self):
        out = self.acquire()
        self.assertEqual(os.stat(out).st_mode & 0o777, 0o444)
        self.assertFalse(os.path.exists(self.dest + ".part"))

    def test_04_chain_of_custody_recorded(self):
        self.acquire()
        self.assertEqual(self.custody_actions(), [
            "ACQUISITION_STARTED", "SOURCE_HASHED", "WRITE_PROTECTION",
            "ACQUISITION_VERIFIED"])
        r = self.conn.execute("SELECT * FROM custody_log WHERE action='ACQUISITION_VERIFIED'"
                              ).fetchone()
        self.assertEqual(r["examiner"], "Vijay")
        self.assertIn(sha256_of(self.src), r["details"])
        self.assertTrue(r["ts"])

    def test_05_hash_mismatch_detected(self):
        real_copy = writeblock._copy

        def corrupting_copy(src_fd, dst_fd, chunk):     # simulate a bad copy
            n = real_copy(src_fd, dst_fd, chunk)
            os.pwrite(dst_fd, b"\x00\xff", 1000)
            return n

        with mock.patch.object(writeblock, "_copy", corrupting_copy):
            with self.assertRaises(writeblock.IntegrityError):
                self.acquire()
        self.assertFalse(os.path.exists(self.dest), "bad copy must not be presented as evidence")
        self.assertTrue(os.path.exists(self.dest + ".MISMATCH"))
        row = self.evidence_rows()[-1]
        self.assertEqual(row["status"], "MISMATCH")
        self.assertEqual(row["verified"], 0)
        self.assertNotEqual(row["sha256_before"], row["sha256_after"])
        self.assertIn("VERIFICATION_FAILED", self.custody_actions())

    def test_06_source_changed_during_acquisition_detected(self):
        real_copy = writeblock._copy

        def copy_then_tamper(src_fd, dst_fd, chunk):
            n = real_copy(src_fd, dst_fd, chunk)
            with open(self.src, "ab") as fh:            # disposable test file only
                fh.write(b"tampered")
            return n

        with mock.patch.object(writeblock, "_copy", copy_then_tamper):
            with self.assertRaises(writeblock.IntegrityError) as cm:
                self.acquire()
        self.assertIn("source unchanged", str(cm.exception))
        self.assertEqual(self.evidence_rows()[-1]["status"], "MISMATCH")

    def test_07_missing_source(self):
        with self.assertRaises(writeblock.AcquisitionError) as cm:
            self.acquire(src=os.path.join(self.tmp, "nope.img"))
        self.assertIn("not found", str(cm.exception))
        self.assertFalse(os.path.exists(self.dest))
        self.assertEqual(self.evidence_rows()[-1]["status"], "FAILED")
        self.assertIn("ACQUISITION_FAILED", self.custody_actions())

    def test_08_invalid_sources(self):
        empty = os.path.join(self.tmp, "empty.img")
        open(empty, "wb").close()
        for bad, msg in ((empty, "empty"), (self.tmp, "not a regular file")):
            with self.subTest(source=bad):
                with self.assertRaises(writeblock.AcquisitionError) as cm:
                    self.acquire(src=bad)
                self.assertIn(msg, str(cm.exception))
        self.assertFalse(os.path.exists(self.dest))

    def test_09_existing_destination_not_overwritten(self):
        os.makedirs(os.path.dirname(self.dest))
        with open(self.dest, "wb") as fh:
            fh.write(b"EARLIER EVIDENCE")
        with self.assertRaises(writeblock.AcquisitionError) as cm:
            self.acquire()
        self.assertIn("refusing to overwrite", str(cm.exception))
        with open(self.dest, "rb") as fh:
            self.assertEqual(fh.read(), b"EARLIER EVIDENCE")

    def test_10_repeated_acquisition(self):
        first = self.acquire()
        second = self.acquire(dest=os.path.join(self.tmp, "out2", "evidence.img"))
        self.assertNotEqual(first, second)
        rows = self.evidence_rows()
        self.assertEqual([r["status"] for r in rows], ["VERIFIED", "VERIFIED"])
        self.assertEqual(rows[0]["sha256_after"], rows[1]["sha256_after"])
        with self.assertRaises(writeblock.AcquisitionError):   # same dest again -> refused
            self.acquire()
        self.assertEqual(sha256_of(first), sha256_of(self.src))

    def test_11_leftover_partial_file_is_not_touched(self):
        os.makedirs(os.path.dirname(self.dest))
        with open(self.dest + ".part", "wb") as fh:
            fh.write(b"old partial")
        with self.assertRaises(writeblock.AcquisitionError):
            self.acquire()
        with open(self.dest + ".part", "rb") as fh:
            self.assertEqual(fh.read(), b"old partial")

    def test_12_io_error_during_copy_cleans_up(self):
        def failing_copy(src_fd, dst_fd, chunk):
            os.write(dst_fd, b"half")
            raise OSError(28, "No space left on device (simulated)")

        with mock.patch.object(writeblock, "_copy", failing_copy):
            with self.assertRaises(writeblock.AcquisitionError) as cm:
                self.acquire()
        self.assertIn("No space left", str(cm.exception))
        self.assertFalse(os.path.exists(self.dest + ".part"))
        self.assertFalse(os.path.exists(self.dest))
        self.assertEqual(self.evidence_rows()[-1]["status"], "FAILED")

    def test_13_unknown_case_rejected(self):
        with self.assertRaises(writeblock.AcquisitionError):
            writeblock.acquire(self.src, self.dest, self.conn, 9999, log=None)

    def test_14_reverify_detects_later_tampering(self):
        out = self.acquire()
        ev = writeblock.latest_evidence_id(self.conn, self.case_id)
        self.assertTrue(writeblock.reverify(self.conn, ev, log=None))
        os.chmod(out, 0o644)
        with open(out, "r+b") as fh:                    # tamper with the disposable copy
            fh.seek(10)
            fh.write(b"X")
        self.assertFalse(writeblock.reverify(self.conn, ev, log=None))
        self.assertEqual(self.custody_actions()[-2:], ["REVERIFY_PASS", "REVERIFY_FAIL"])


    def test_23_broken_output_does_not_change_outcome(self):
        def broken_log(*args):                          # e.g. `python main.py ... | head`
            raise BrokenPipeError(32, "Broken pipe")
        self.acquire(log=broken_log)
        self.assertEqual(self.evidence_rows()[-1]["status"], "VERIFIED")


class TestWriteProtection(WriteblockTestBase):
    def test_15_write_probe_blocks_read_only_descriptor(self):
        fd = os.open(self.src, os.O_RDONLY)
        try:
            self.assertTrue(writeblock.write_probe(fd).startswith("BLOCKED"))
        finally:
            os.close(fd)

    def test_16_write_probe_rejects_writable_descriptor(self):
        fd = os.open(self.src, os.O_RDWR)                # disposable file only
        try:
            with self.assertRaises(writeblock.AcquisitionError):
                writeblock.write_probe(fd)
        finally:
            os.close(fd)
        self.assertEqual(os.path.getsize(self.src), 3 * 1024 * 1024 + 123)

    def test_17_hash_file_matches_hashlib(self):
        sha, md5, size = writeblock.hash_file(self.src, chunk_size=4096)
        self.assertEqual((sha, md5, size),
                         (sha256_of(self.src), md5_of(self.src), os.path.getsize(self.src)))


class TestDatabaseCompatibility(unittest.TestCase):
    def test_18_old_case_db_is_upgraded(self):
        tmp = tempfile.mkdtemp(prefix="wb_db_")
        path = os.path.join(tmp, "old.db")
        old = sqlite3.connect(path)          # evidence table exactly as in the original db.py
        old.execute("CREATE TABLE evidence(id INTEGER PRIMARY KEY, case_id INTEGER, "
                    "source_path TEXT, sha256_before TEXT, sha256_after TEXT, md5 TEXT, "
                    "acquired_at TEXT, examiner TEXT, tool TEXT)")
        old.execute("INSERT INTO evidence(case_id, source_path) VALUES(1, 'old.img')")
        old.commit()
        old.close()
        conn = db.get_conn(path)
        cols = {r["name"] for r in conn.execute("PRAGMA table_info(evidence)")}
        self.assertTrue(set(db.EVIDENCE_EXTRA_COLUMNS) <= cols)
        self.assertEqual(conn.execute("SELECT source_path FROM evidence").fetchone()[0], "old.img")
        conn.close()
        shutil.rmtree(tmp)


@unittest.skipUnless(HAVE_TSK and os.path.exists(SCEN_A) and os.path.exists(SCEN_B),
                     "needs pytsk3 and data/scenario_*.img (run data/make_scenarios.sh)")
class TestIntegrationWithForensics(WriteblockTestBase):
    """The acquired copy must give exactly Ragini's reported results."""

    def analyse_copy(self, image):
        before = sha256_of(image)
        copy = self.acquire(src=image)
        results = forensics.analyze(copy, os.path.join(self.tmp, "recovered"))
        self.assertEqual(sha256_of(image), before, "original image changed")
        self.assertEqual(sha256_of(copy), before, "acquired copy changed by analysis")
        return results

    def test_19_scenario_b_on_acquired_copy(self):
        res = {r["name"]: r for r in self.analyse_copy(SCEN_B)}
        self.assertEqual(len(res), 8)
        expected_flagged = {"salary.xlsx", "passwords.txt", "report.pdf",
                            "invoice.jpg", "secret.txt", "client_list.docx"}
        self.assertEqual({n for n, r in res.items() if r["suspicious"]}, expected_flagged)
        self.assertFalse(res["notes.txt"]["suspicious"])
        self.assertFalse(res["holiday.jpg"]["suspicious"])
        self.assertTrue(res["secret.txt"]["hidden"])
        self.assertTrue(any("exe" in x for x in res["invoice.jpg"]["reasons"]))
        self.assertTrue(any("zip" in x for x in res["report.pdf"]["reasons"]))
        deleted = {n for n, r in res.items() if r["deleted"]}
        self.assertEqual(deleted, {"salary.xlsx", "passwords.txt"})
        for n in deleted:                               # recovered byte-for-byte
            with open(res[n]["recovered_path"], "rb") as a, \
                 open(os.path.join(DATA, "planted", n), "rb") as b:
                self.assertEqual(a.read(), b.read())

    def test_20_scenario_a_clean(self):
        res = self.analyse_copy(SCEN_A)
        self.assertEqual(len(res), 3)
        self.assertEqual([r["name"] for r in res if r["suspicious"]], [])
        self.assertEqual([r["name"] for r in res if r["deleted"]], [])


@unittest.skipUnless(HAVE_TSK and os.path.exists(SCEN_B), "needs pytsk3 and scenario_b.img")
class TestMainPipeline(unittest.TestCase):
    """Run main.py as a user would, in a throw-away working directory."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="wb_main_")
        self.img = os.path.join(self.tmp, "scenario_b_copy.img")
        shutil.copyfile(SCEN_B, self.img)

    def tearDown(self):
        for dirpath, _, files in os.walk(self.tmp):
            for f in files:
                os.chmod(os.path.join(dirpath, f), 0o644)
        shutil.rmtree(self.tmp, ignore_errors=True)

    def run_main(self, image):
        return subprocess.run(
            [sys.executable, os.path.join(ROOT, "main.py"), image,
             os.path.join(DATA, "usb.log"), "--examiner", "Vijay"],
            cwd=self.tmp, capture_output=True, text=True)

    def test_21_main_runs_twice_and_verifies(self):
        before = sha256_of(self.img)
        for case in (1, 2):
            p = self.run_main(self.img)
            self.assertEqual(p.returncode, 0, p.stderr)
            self.assertIn("Status  : VERIFIED", p.stdout)
            self.assertIn("Evidence integrity: VERIFIED", p.stdout)
            self.assertIn("Files found: 8  Deleted: 2  Suspicious: 6", p.stdout)
            self.assertTrue(os.path.exists(
                os.path.join(self.tmp, "evidence", f"case_{case}", "evidence.img")))
        self.assertEqual(sha256_of(self.img), before)

    def test_22_main_stops_on_missing_source(self):
        p = self.run_main(os.path.join(self.tmp, "missing.img"))
        self.assertEqual(p.returncode, 2)
        self.assertIn("ACQUISITION FAILED", p.stdout)
        self.assertNotIn("[2/6]", p.stdout, "analysis must not run without verified evidence")

    def test_24_main_missing_usb_log_clean_error(self):
        p = subprocess.run([sys.executable, os.path.join(ROOT, "main.py"), self.img,
                            os.path.join(self.tmp, "no.log")],
                           cwd=self.tmp, capture_output=True, text=True)
        self.assertEqual(p.returncode, 1)
        self.assertIn("USB log not found", p.stdout)
        self.assertNotIn("Traceback", p.stderr)

    def test_25_main_non_disk_image_clean_error(self):
        junk = os.path.join(self.tmp, "not_an_image.img")
        with open(junk, "wb") as fh:
            fh.write(b"this is not a file system" * 100)
        p = self.run_main(junk)
        self.assertEqual(p.returncode, 4)
        self.assertIn("Status  : VERIFIED", p.stdout)      # acquisition itself is fine
        self.assertIn("ANALYSIS FAILED", p.stdout)
        self.assertNotIn("Traceback", p.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)
