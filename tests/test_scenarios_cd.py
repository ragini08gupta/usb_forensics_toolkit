"""Scenario C (genuine device, suspicious files) and Scenario D (spoofed device,
harmless files). Each isolates one detection mechanism. Skipped if the images
are missing (build them with: cd data && bash make_scenarios_cd.sh)."""
import os
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from modules import db, pipeline  # noqa: E402

DATA = os.path.join(ROOT, "data")


def run(image, log):
    tmp = tempfile.mkdtemp()
    cid, s = pipeline.run_case(os.path.join(DATA, image), os.path.join(DATA, log), "Tester",
                               db_path=os.path.join(tmp, "case.db"), workdir=tmp,
                               make_report=False, log=lambda *a: None)
    return s


@unittest.skipUnless(os.path.exists(os.path.join(DATA, "scenario_c.img")), "scenario_c.img not built")
class ScenarioC(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.s = run("scenario_c.img", "usb_c.log")

    def test_files_and_flags(self):
        self.assertEqual(len(self.s["files"]), 9)
        self.assertEqual(len(self.s["deleted"]), 2)
        self.assertEqual(len(self.s["suspicious"]), 7)

    def test_no_rogue_device(self):
        self.assertEqual(self.s["rogue"], [])
        self.assertTrue(all(x["verdict"] == "GENUINE" for x in self.s["evidence_sessions"]))

    def test_after_hours_alerts(self):
        high = [a for a in self.s["alerts"] if a["severity"] == "HIGH"]
        self.assertEqual(len(high), 7)


@unittest.skipUnless(os.path.exists(os.path.join(DATA, "scenario_d.img")), "scenario_d.img not built")
class ScenarioD(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.s = run("scenario_d.img", "usb_d.log")

    def test_no_suspicious_files(self):
        self.assertEqual(len(self.s["files"]), 4)
        self.assertEqual(len(self.s["suspicious"]), 0)

    def test_evidence_device_is_spoofed(self):
        self.assertEqual([x["verdict"] for x in self.s["evidence_sessions"]], ["LIKELY_SPOOFED"])
        self.assertEqual(len(self.s["rogue"]), 1)

    def test_genuine_keyboard_not_flagged(self):
        kb = [x for x in self.s["sessions"] if x["vid"] == "046d"]
        self.assertEqual(kb[0]["verdict"], "GENUINE")


if __name__ == "__main__":
    unittest.main()
