# USB Forensics Investigation Toolkit

Information Security Lab mini project. Ragini Gupta (240953306) and Vijay (240953312). Guide: Abhishek A K.

Command-line toolkit that investigates suspected USB data theft on a FAT32 disk image:

1. **Acquire** (`modules/writeblock.py`, Vijay): a read-only acquisition with SHA-256/MD5 verification and a chain-of-custody log.
2. **Forensics** (`modules/forensics.py`, Ragini): file listing, MAC times, deleted-file recovery, suspicious-file rules.
3. **Device info** (`modules/device_info.py`, Ragini): USB connection history from a syslog-style log.
4. **Timeline** (`modules/timeline.py`, Ragini): merged events, printed and exported to `timeline.csv`.

Everything is stored in SQLite (`case.db`, schema in `modules/db.py`).
The dashboard, PDF report and impersonation detection belong to later phases and are not built yet.

> **Write-blocking scope.** This toolkit uses *software* write-blocking only: the source is opened `O_RDONLY`, and a write attempt is shown to fail. Hashing **detects** changes but does not prevent them. OS-level read-only state (file permissions, `blockdev --setro`) is reported but not changed. Hardware write-blockers are not used. They are future work.

## Setup (Ubuntu / WSL)

```bash
sudo apt update
sudo apt install -y python3-venv python3-dev build-essential sleuthkit mtools dosfstools sqlite3
cd usb_forensics_toolkit
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

* `sleuthkit` is the library behind `pytsk3`. `mtools` and `dosfstools` build the images and read the FAT hidden attribute. `sqlite3` lets you inspect `case.db`.
* `pip install` should end with `Successfully installed pytsk3-...`. Tested with pytsk3 20260715 on Python 3.10, 3.12 and 3.13.

## Build the test images (Scenario A and B)

```bash
cd data && bash make_scenarios.sh && cd ..
```

Prints `Scenario images rebuilt.` and creates `data/scenario_a.img` and `data/scenario_b.img` (64 MiB FAT32 each).
**The image hashes change every time you rebuild**, because file timestamps change. Compare hashes within one run, never against old logs.

## Run the tests

```bash
python -m unittest discover -s tests -v
```

Expected output: 25 tests, each ending `ok`, then `OK`. The tests only use temporary files and copies of the scenario images.

## Progress-evaluation demo (Scenario B, Phases 2 + 3)

```bash
rm -rf case.db evidence recovered timeline.csv        # start a fresh case database (case id 1)
python main.py data/scenario_b.img --examiner Vijay
```

Expected output:
* `[1/6]` shows the write probe `BLOCKED (EBADF ...)`, four `[PASS]` hash checks and `Status  : VERIFIED`.
* `[2/6]`–`[4/6]` run Ragini's analysis on `evidence/case_1/evidence.img`.
* `[5/6]` shows `[PASS] acquired copy still matches acquisition hash`.
* The summary shows `Files found: 8  Deleted: 2  Suspicious: 6`, the six `!` lines, then the timeline.

The usage line is `python main.py <image> [usb_log] [--examiner NAME]`. The log defaults to `data/usb.log`, and the examiner defaults to `Ragini`.

## Verify the acquisition hashes

```bash
sha256sum data/scenario_b.img evidence/case_1/evidence.img   # two identical hashes
md5sum    data/scenario_b.img evidence/case_1/evidence.img   # two identical hashes
ls -l evidence/case_1/                                        # -r--r--r--  (read-only copy)
python -m modules.writeblock verify 1                         # re-hashes the copy, compares with case.db
python -m modules.writeblock custody 1                        # chain-of-custody log for case 1
sqlite3 -header -column case.db "SELECT id, case_id, status, verified, sha256_before, sha256_after, examiner FROM evidence;"
```

Use the case number that `main.py` printed (`Case N saved to case.db`).

## Scenario A (clean, no false positives)

```bash
python main.py data/scenario_a.img --examiner Vijay
```

Expected output: `Status  : VERIFIED`, then `Files found: 3  Deleted: 0  Suspicious: 0`.

## Show that hash mismatches are detected

```bash
python tests/demo_mismatch.py
```

This runs on a temporary copy of the image. It first corrupts one byte during the copy, which gives `[FAIL]` hash lines and `status=MISMATCH`. It then tampers with a good copy after acquisition, which makes re-verification report `[FAIL]`.

## Optional extra OS layer (normal user, not root)

```bash
chmod a-w data/scenario_b.img                 # original becomes read-only
echo tamper >> data/scenario_b.img            # -> Permission denied
python main.py data/scenario_b.img --examiner Vijay   # "OS read-only status: file permissions are read-only"
chmod u+w data/scenario_b.img                 # undo (needed before make_scenarios.sh)
```

Root ignores permission bits. The tool reports this when run as root.

## Save demo logs

```bash
mkdir -p mylogs
python main.py data/scenario_b.img --examiner Vijay 2>&1 | tee mylogs/scenario_b.log
python -m unittest discover -s tests -v 2>&1 | tee mylogs/tests.log
```

Logs captured while building this version are in `tests/logs/`. Renderings of them are in `tests/screenshots/07_vijay_*.png` to `13_vijay_*.png`.

## Folder layout

```
main.py                  CLI pipeline (acquire -> analyse copy -> log -> timeline -> re-verify)
modules/db.py            SQLite schema (cases, evidence, files, usb_events, events, alerts, custody_log)
modules/writeblock.py    acquisition, write-block probe, hashing, verification, custody (Vijay)
modules/forensics.py     file system analysis (Ragini)
modules/device_info.py   USB log parsing (Ragini)
modules/timeline.py      timeline + CSV (Ragini)
data/                    planted files, make_scenarios.sh, usb.log
docs/                    architecture, DB schema, flowcharts, Vijay's evaluation notes
tests/                   unit/integration tests, mismatch demo, logs, screenshots
evidence/                acquired copies (created at run time, git-ignored)
```
