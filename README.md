# USB Forensics Investigation Toolkit

Information Security Lab mini project. Ragini Gupta (240953306) and Vijay (240953312). Guide: Abhishek A K.

The toolkit investigates suspected data theft over USB. You give it a USB device or its forensic image, plus the host's USB history. It then:

1. **Acquires** a verified read-only copy, using software write-blocking, SHA-256/MD5 and a chain-of-custody log.
2. **Identifies** the device and volume: VID/PID, serial, interfaces, disk capacity, FAT volume serial and label.
3. **Analyses** the file system: MAC times, file hashes, deleted-file recovery, suspicious-file rules, and copy indicators.
4. **Rebuilds** the USB connection history from kernel logs, optionally adding usbmon descriptor captures (Scapy).
5. **Detects impersonation**: each device is compared with known-good fingerprints, which catches BadUSB HID injectors, spoofed strings and cloned serials.
6. **Correlates** files with sessions. It shows which file was written to the stick, during which session, and whether this happened after hours.
7. **Presents** the findings in a Flask investigation dashboard and an auto-generated PDF report (ReportLab).

The tool answers the three questions from the synopsis: *what was copied, when, and was the device genuine?*

```
python main.py data/scenario_b.img data/usb.log --pcap data/usb_capture.pcap --examiner Vijay
...
  Q1. Was the device genuine?
      GENUINE - SanDisk Cruzer Blade serial 4C530001230915101234 matches its known-good fingerprint in all 2 session(s)
      ! Rogue device #4 0951:1666 "Kingston DataTraveler 3.0" at 2026-10-08T22:44:10: LIKELY_SPOOFED (score 130)

  Q2/Q3. What was copied onto the evidence device, and when?
      Session #5 2026-10-08T22:50:02 -> 2026-10-08T23:10:10  [AFTER HOURS]
        22:51:14  /client_list.docx    SUSPICIOUS
        22:51:20  /salary.xlsx         SUSPICIOUS DELETED
        ...
```

> **Running the demo?** Follow `RUN_GUIDE.md` (setup, checks, the 10-minute professor demo, troubleshooting). `docs/USB_Forensics_What_Changed.docx` explains every feature and what changed since the prototype.

## How the synopsis objectives map to the code

| Synopsis | Implemented in | What it does |
|---|---|---|
| **Obj 1** device information (VID/PID, serial, connection times) | `modules/device_info.py` | Parses kernel-log sessions: strings, iSerialNumber index, bound interfaces (usb-storage / HID keyboard / mouse), `sdX` disk and capacity. Uses `sysfs_identify()` for a live `/dev/sdX`. |
| **Obj 1** file metadata, deleted and suspicious files | `modules/forensics.py` | pytsk3 walk that includes deleted entries; MAC times; SHA-256/MD5 per file; recovery; magic-byte, entropy, keyword and hidden-attribute rules; *copied-onto-volume* indicator (FAT created > modified); boot-sector volume identity. |
| **Obj 1** USB activity timeline | `modules/timeline.py` | Links each file to the USB session it was written in. Merges file-system, USB-log and custody events. Raises alerts for flagged files copied after hours. Exports to CSV. |
| **Obj 2** write-blocking + MD5/SHA-256 chain of custody | `modules/writeblock.py` | `O_RDONLY` with a verified write probe; optional `blockdev --setro` for live devices (`--setro`); before, after and copy hashes; re-verification; custody log. |
| **Obj 3** impersonation detection (descriptor anomalies vs known-good profiles) | `modules/impersonation.py`, `modules/usb_capture.py`, `modules/live_usb.py`, `data/known_good.json` | Rule scoring with GENUINE / UNVERIFIED / SUSPICIOUS / LIKELY_SPOOFED verdicts. Descriptors come from usbmon pcaps (Scapy), sysfs (udev view) or pyusb. Includes a live watch mode. |
| **Obj 3** interactive investigation dashboard | `dashboard/app.py` | Flask app. Finding cards, then tabs for **Device identification · Connection history · File activity · Timeline reconstruction · Suspicious files** and **Evidence & custody**. |
| **Obj 3** auto-generated forensic report | `modules/report.py` | ReportLab PDF with findings, integrity, custody, devices and verdicts, a session chart, files, recovered files, alerts, timeline, limitations and sign-off. The report's own SHA-256 is written to the custody log. |
| SQLite case store | `modules/db.py` | Tables: `cases, evidence, custody_log, volume, files, usb_events, alerts, events, reports`. Older `case.db` files are migrated in place. |

See `docs/pipeline_flowchart.png`, `docs/impersonation_flowchart.png`, `docs/writeblock_flowchart.png` and `docs/architecture.png`.

> **Write-blocking scope.** The toolkit uses *software* write-blocking: the source is opened `O_RDONLY`, and a write attempt is shown to fail. For live block devices, `--setro` (run as root) also sets the kernel read-only flag before acquisition. Hashing **detects** changes but does not prevent them. Hardware write-blockers are not used.

## Setup (Ubuntu / WSL)

```bash
sudo apt update
sudo apt install -y python3-venv python3-dev build-essential sleuthkit mtools dosfstools sqlite3
cd usb_forensics_toolkit
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

`pytsk3` needs `sleuthkit`. `mtools` and `dosfstools` build the images and read the FAT hidden attribute. `scapy` and `pyusb` are optional: without Scapy, a built-in pcap reader is used, and pyusb is only needed for live enumeration on non-Linux systems.

## Build the test data

```bash
cd data
bash make_scenarios.sh        # scenario_a.img + scenario_b.img (64 MiB FAT32)
python3 make_usb_capture.py   # usb_capture.pcap (usbmon capture of the night's enumerations)
cd ..
```

The images are now **reproducible**. The volume IDs are fixed (`mkfs.vfat --invariant -i`), and `set_fat_times.py` writes the story timestamps from `times_a.json` and `times_b.json` into the FAT directory entries, so every rebuild gives the same SHA-256.

### Scenario B story (employee suspected of copying confidential files)

| Time (8 Oct) | Event | Expected finding |
|---|---|---|
| 09:02 | Logitech keyboard (real HID) | GENUINE: keyboards are not flagged just for being keyboards |
| 10:15–10:42 | SanDisk Cruzer Blade `4C53…1234` (the imaged stick) | notes.txt and holiday.jpg written; normal |
| 14:03–14:30 | Genuine Kingston DataTraveler | GENUINE, nothing on the image |
| **22:44:10–22:44:58** | Device claiming *Kingston DataTraveler 3.0* (0951:1666): USB 1.1, no serial, **only a HID keyboard interface** | **LIKELY_SPOOFED (130)**: BadUSB keystroke injector, after hours |
| **22:50–23:10** | Same SanDisk stick again | **After hours.** 6 flagged files written; 2 later deleted (recovered); report.pdf is really a ZIP; invoice.jpg is an EXE whose content timestamp (22:44:36) falls inside the rogue keyboard session |

Scenario A uses another SanDisk stick in office hours with 3 clean files. It must produce **0 alerts**.

## Run the tests

```bash
python -m unittest discover -s tests -v
```

Expected output: **74 tests**, each ending `ok`, then `OK`. The tests are in three files:

* `tests/test_writeblock.py`: the 25 prototype tests.
* `tests/test_final.py`: 31 tests for the final modules.
* `tests/test_review_fixes.py`: 18 regression tests, one for each finding of the final code review (listed in `tests/ground_truth.md`).

The suite passes whatever time zone the PC uses (`TZ=Asia/Kolkata python -m unittest discover -s tests`).

## Final demo

```bash
rm -rf case.db evidence recovered reports timeline.csv
python main.py data/scenario_b.img data/usb.log --pcap data/usb_capture.pcap --examiner Vijay   # case 1
python main.py data/scenario_a.img data/usb_a.log --examiner Ragini                             # case 2 (clean)
python dashboard/app.py                                                                        # http://127.0.0.1:5000
```

Expected output for case 1:

* `[1/8]` shows `BLOCKED (EBADF ...)`, four `[PASS]` lines and `Status  : VERIFIED`.
* `[5/8]` lists five devices, with `! #4 0951:1666 ... LIKELY_SPOOFED score 130`.
* The summary shows `Files found: 8  Deleted: 2  Suspicious: 6`, `Rogue/suspicious devices: 1`, and 9 alerts (7 HIGH, 2 MEDIUM).
* The report is written to `reports/case_1_report_<UTC timestamp>.pdf`. Each regeneration makes a new file, so every SHA-256 in the custody log can still be checked. A copy is in `docs/sample_report_scenario_b.pdf`.
* The timeline goes to `reports/case_1_timeline.csv`, and `timeline.csv` always holds the latest case.

Case 2 should show `Files found: 3  Deleted: 0  Suspicious: 0` and no alerts.

Useful flags:

* `--no-report`: skip the PDF report.
* `--hide-custody`: leave custody actions out of the printed timeline.
* `--device-serial SERIAL`: say which USB session is the imaged device. Without it, the device is matched by capacity.
* `--profiles FILE`: use a different known-good device list.
* `--db FILE`: use a different case database. Evidence, recovered files and reports are stored next to it.
* `--log-year YEAR`: set the year for classic syslog lines, which carry none.
* `--tz-offset +0530`: set the suspect PC's UTC offset for the pcap. By default it is read from the log.

Exit codes: `0` ok, `1` bad input, `2` acquisition failed, `3` integrity failed after analysis, `4` no readable file system, `5` USB log or capture unreadable. Every failure after acquisition is recorded in the custody log as `ANALYSIS_FAILED`.

**Time base.** FAT and kernel logs both store the suspect PC's local wall-clock time. The tool keeps that time base, so results are identical whichever time zone the analysis PC uses. pcap times are UTC; they are converted with the log's offset (`+0530` in the demo).

### Dashboard

`python dashboard/app.py [--db case.db] [--port 5000]` binds to 127.0.0.1 only.

* POST actions need a CSRF token, and evidence-controlled text (USB strings, file names) is always escaped.
* The **case list** offers a "New investigation" form that only accepts the images, logs and pcaps in `data/`.
* Each case opens with **finding cards** for integrity, rogue devices, files and alerts, followed by the two answers: *was the device genuine?* and *what was copied, when?*
* The tabs are: **Device identification** (volume and device cards with score breakdowns), **Connection history** (SVG session chart with file-write ticks and after-hours shading), **File activity** (filters), **Timeline reconstruction** (source filters and search), **Suspicious files** (reasons, hashes, recovered-file download, all alerts), and **Evidence & custody** (hashes, custody log, *Re-verify now*, report history).
* Downloads: PDF report and timeline CSV.

Screenshots are in `tests/screenshots/14_*.png` to `21_*.png`.

### Report only

```bash
python -m modules.report 1                  # writes a new reports/case_1_report_<timestamp>.pdf and logs its SHA-256
```

### Integrity and custody (as before)

```bash
sha256sum data/scenario_b.img evidence/case_1/evidence.img
python -m modules.writeblock verify 1
python -m modules.writeblock custody 1
python tests/demo_mismatch.py               # 1-byte corruption and post-acquisition tampering are both detected
```

## Using it on a real USB stick (Linux)

```bash
lsblk                                               # find the stick, e.g. /dev/sdb (do NOT mount it)
sudo modprobe usbmon
sudo tcpdump -i usbmon1 -w case.pcap &              # optional: start BEFORE plugging in, to capture descriptors
#   ... plug the stick in, wait a few seconds, then stop tcpdump ...
sudo journalctl -k -o short-iso --since today > host_usb.log   # has the year + UTC offset (or: sudo dmesg -T)
sudo python main.py /dev/sdb host_usb.log --pcap case.pcap --setro --examiner Vijay
# a whole-disk device has a partition table; the first readable FAT partition is analysed
```

With a block device as the source, the tool reads its USB identity from sysfs, sets the kernel read-only flag (`--setro`), and acquires the whole device.

Live rogue-device check:

```bash
python -m modules.live_usb            # every attached USB device with its verdict
python -m modules.live_usb --watch    # reports each newly plugged device as it appears
```

Add your organisation's approved device models to `data/known_good.json`.

## Folder layout

```
main.py                     CLI (8 steps, exit codes 0/1/2/3/4)
modules/pipeline.py         the investigation pipeline + case summary (shared by CLI and dashboard)
modules/writeblock.py       acquisition, write-block probe, --setro, hashing, verification, custody (Vijay)
modules/forensics.py        file system analysis, hashes, copy indicator, volume identity (Ragini)
modules/device_info.py      USB kernel-log sessions, sysfs identification (Ragini)
modules/timeline.py         timeline, file/session correlation, CSV (Ragini)
modules/impersonation.py    known-good fingerprint scoring and verdicts (Vijay)
modules/usb_capture.py      usbmon pcap descriptor decoding with Scapy (Vijay)
modules/live_usb.py         live sysfs/pyusb enumeration and watch mode (Vijay)
modules/report.py           ReportLab PDF report
modules/db.py               SQLite schema + migration
dashboard/                  Flask app, templates, CSS (no external CDN; works offline)
data/                       planted files, make_scenarios.sh, set_fat_times.py, times_*.json,
                            usb.log, usb_a.log, make_usb_capture.py, usb_capture.pcap, known_good.json
docs/                       architecture, flowcharts, DB schema, evaluation notes, sample report
tests/                      unit/integration tests, mismatch demo, logs, screenshots
evidence/ recovered/ reports/   created at run time (git-ignored)
```

## Limitations

* Write-blocking is done in software and is verified by a probe, but it is not a hardware blocker. The toolkit targets Linux; live-device mode and `--setro` are Linux-only.
* FAT/FAT32 volumes and partition images are supported. Whole-disk images (MBR/GPT) are opened at their first readable partition. NTFS and exFAT are not tested.
* FAT stores no deletion time and only an access *date*. Deletion events use the modified time as an approximation.
* Log times and FAT times are local wall-clock times without a time zone. Clock drift on the suspect machine is not corrected.
* A device that clones *every* descriptor of a genuine model, including serial and interfaces, cannot be detected from descriptors. A keystroke injector still has to expose a HID interface, which is what gives it away.
* Suspicious-file rules are triage aids and can give false positives.
