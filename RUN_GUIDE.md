# How to run the project

**Project:** USB Forensics Investigation Toolkit, final version

This guide assumes the same setup you used for the prototype: Ubuntu or WSL (Ubuntu on Windows) with Python 3.10 or newer.

---

## Part A: One-time setup

### A1. Put the new project in its own folder

Keep your old prototype folder as it is; don't unzip on top of it. The new version uses a new folder.

If you use **WSL**, copy the zip into your Linux home folder rather than working on `C:\`. On the Windows drive, the "read-only" protection behaves differently and everything runs slower.

```bash
cd ~
cp /mnt/c/Users/<your-windows-username>/Downloads/IS_project_final.zip .    # WSL only; adjust the path
unzip IS_project_final.zip -d final_project
cd final_project/usb_forensics_toolkit
```

On native Ubuntu, just unzip it anywhere in your home folder and `cd` into `usb_forensics_toolkit`.

### A2. System packages

These are the same as for the prototype. Running the command again is harmless.

```bash
sudo apt update
sudo apt install -y python3-venv python3-dev build-essential sleuthkit mtools dosfstools sqlite3
```

### A3. A fresh Python environment

The final version needs three more Python packages than the prototype: **Flask** (dashboard), **ReportLab** (PDF report) and **Scapy** (USB packet capture). Make a new environment inside the new folder:

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

The last line should end with `Successfully installed ... flask ... pytsk3 ... reportlab ... scapy ...`.

> **Remember:** every time you open a new terminal, go into the project folder and run `source venv/bin/activate` first. Your prompt will start with `(venv)`.

### A4. Check that everything is installed

```bash
python -c "import pytsk3, flask, reportlab, scapy; print('all good')"
```

It should print `all good`. If not, see **Part E: Troubleshooting**.

---

## Part B: Check that it works (do this the day before the demo)

### B1. Run all the tests

```bash
python -m unittest discover -s tests
```

**Expected:** after about 20 seconds you get `Ran 74 tests` and then `OK`. If you get `OK`, everything is working on your machine.

### B2. Check the evidence images are the right ones

```bash
sha256sum data/scenario_b.img data/scenario_a.img
```

**Expected:**

```
849bba6ebffdd19392c53d18d9232ccd2daa09b6dab45470f30a0ed43120669b  data/scenario_b.img
7d4ff48aa80a96453d36c4dff61edb9779e716dfe043ab0a94a873b3a2ec5700  data/scenario_a.img
```

These hashes are always the same, even if you rebuild the images with `cd data && bash make_scenarios.sh && cd ..`. That makes a nice point to show the professor: our test evidence is reproducible.

### B3. Do one full dry run

Follow Part C once, start to finish, so nothing surprises you on the day.

---

## Part C: The demo for the professor (about 10 minutes)

### Before the professor arrives

Open **two terminals**. In both, go to the project folder and activate the environment:

```bash
cd ~/final_project/usb_forensics_toolkit
source venv/bin/activate
```

In **terminal 1**, start from a clean case database. This deletes only old demo output, never the evidence images.

```bash
rm -rf case.db evidence recovered reports timeline.csv
```

Make the terminal font big enough for the professor to read.

---

### Step 1: Explain the scenario (30 seconds)

> "An employee is suspected of copying confidential files to a pen drive at night. We have a forensic image of the pen drive and the computer's USB log. Our toolkit answers three questions: **was the pen drive genuine, what was copied onto it, and when**, without ever changing the evidence."

### Step 2: Show the tests pass (30 seconds)

In terminal 1:

```bash
python -m unittest discover -s tests
```

Point at **`Ran 74 tests ... OK`**.

> "74 automated tests. 18 of them reproduce bugs we found in our own final code review, so they can't come back."

### Step 3: Run the main investigation (2 to 3 minutes)

```bash
python main.py data/scenario_b.img data/usb.log --pcap data/usb_capture.pcap --examiner Ragini --hide-custody
```

Walk down the output and point at these lines:

| Where in the output | What to say |
|---|---|
| `[1/8]` … `BLOCKED (EBADF ...)` | "We open the evidence read-only and prove a write attempt is refused." |
| `[1/8]` four `[PASS]` lines, `Status : VERIFIED` | "SHA-256 and MD5 of the original before and after, and of our copy, all match. We only ever analyse the copy." |
| `[5/8]` `! #4 0951:1666 Kingston ... LIKELY_SPOOFED score 130` | "This device claimed to be a Kingston pen drive, but it registered as a **keyboard**, had no serial number, used an older USB version, and was plugged in for only 48 seconds at 22:44. That's a BadUSB keystroke-injection attack." |
| `[5/8]` the Logitech keyboard is `GENUINE score 0` | "A real keyboard is not flagged; only a device lying about what it is." |
| `[7/8]` `[PASS] acquired copy still matches` | "Our analysis didn't change the evidence." |
| `Q1. Was the device genuine?` | "The SanDisk pen drive itself matches its genuine fingerprint." |
| `Q2/Q3` Session #5, `[AFTER HOURS]` | "Six confidential files were copied onto it between 22:51 and 22:56, after office hours. Salary and passwords were deleted later, and we recovered both." |
| `Alerts: 9` | "Seven HIGH alerts and two MEDIUM ones." |

Note: the line `OS read-only status: file is writable by this user` is normal. It only reports the file permissions; the actual protection is the read-only descriptor shown in the line above it.

### Step 4: Show it doesn't raise false alarms (30 seconds)

```bash
python main.py data/scenario_a.img data/usb_a.log --examiner Ragini --hide-custody
```

Point at **`Files found: 3  Deleted: 0  Suspicious: 0`** and the absence of alerts.

> "A clean pen drive used in office hours gives zero alerts."

### Step 5: The dashboard (3 minutes)

In **terminal 2**:

```bash
python dashboard/app.py
```

Then open **http://127.0.0.1:5000** in your browser. On WSL, Chrome or Edge on Windows works directly. Click through in this order:

1. **Cases page.** Case 1 shows 1 rogue device and high alerts; case 2 is clean. Click **case 1**.
2. **Top of the page.** Show the four cards and the two answers: *"Was the evidence device genuine?"* and *"What was copied onto it, and when?"*
3. **Device identification tab.** Open the **red card #4** and read the score breakdown aloud: +60 keyboard on a storage device, +25 no serial, and so on.
4. **Connection history tab.** Show the chart: the red sliver at 22:44 (the fake keyboard), then the SanDisk session with file ticks, inside the shaded after-hours area.
5. **File activity tab.** Click **"Copied onto device"**.
   > "On FAT, a copied file keeps its old *modified* time but gets a new *created* time. Created later than modified means it was copied here."
6. **Suspicious files tab.**
   > "invoice.jpg is really a Windows program, and report.pdf is really a ZIP."

   Click **download** next to salary.xlsx to show the recovered deleted file.
7. **Evidence & custody tab.** Show the matching hashes and the custody log, then click **"Re-verify working copy now"**. The result is a green PASSED message.

### Step 6: The PDF report (1 minute)

Click **"Forensic report (PDF)"** at the top right of the dashboard. Show:

- Page 1, **Key findings**: the three answers in one table.
- **Chain of custody**: every action with its time and hash.
- **Connection history**: the session chart.

> "The report's own SHA-256 is written into the custody log, and every regeneration is a new file, so nobody can quietly edit a report."

### Step 7: Prove tampering is detected (1 minute)

Stop the dashboard with Ctrl+C in terminal 2, or just use terminal 1:

```bash
python tests/demo_mismatch.py
```

Point at the **`[FAIL]`** lines and **`MISMATCH`** / **`REVERIFY_FAIL`**.

> "If even one byte changes during copying or afterwards, we detect it. This runs on a throw-away copy, so the real evidence is never touched."

### Step 8: Close by mapping back to the synopsis (30 seconds)

> - "**Objective 1**: device info, file metadata, deleted and suspicious files, and the timeline. That was steps 2 to 4 and 6."
> - "**Objective 2**: write-blocking with MD5/SHA-256 and the chain of custody. That was steps 1 and 7."
> - "**Objective 3**: detecting spoofed USB devices, plus the dashboard and the auto-generated report. That was steps 5 and 8."

---

## Part D: Questions the professor may ask

**"Is this real write-blocking?"**
It's software write-blocking: the evidence is opened read-only and we prove a write fails. For a real pen drive there's also `--setro`, which makes Linux lock the whole device read-only (needs `sudo`). Hashing *detects* changes but can't prevent them. A hardware write-blocker would be stronger, and we say so in our limitations.

**"How do you know when a file was copied?"**
FAT gives a copied file a new *created* time. If that time falls inside a USB connection window from the log, the file was written during that session.

**"How do you detect a fake device?"**
We compare it with known genuine models in `data/known_good.json`. Every mismatch adds points: below 25 is genuine, 25 to 59 is suspicious, and 60 or more is likely spoofed. The fake Kingston scores 130.

**"Could a perfect clone fool it?"**
Yes, if it copies every detail including the serial number. But a keystroke-injection device has to show up as a keyboard, and that's what we catch.

**"Can it run on a real pen drive?"**
Yes, on Linux, and the steps are in the README under *"Using it on a real USB stick"*. Be honest that we've tested this part with a simulated device, not real hardware.

**"Where is the code for each part?"**

| Part | File |
|---|---|
| Safe copy and hashing | `modules/writeblock.py` |
| Files and recovery | `modules/forensics.py` |
| USB log | `modules/device_info.py` |
| Packet capture | `modules/usb_capture.py` |
| Fake-device detection | `modules/impersonation.py` |
| Timeline | `modules/timeline.py` |
| Report | `modules/report.py` |
| Dashboard | `dashboard/app.py` |
| All steps joined together | `modules/pipeline.py` |

---

## Part E: Troubleshooting

| Problem | Fix |
|---|---|
| `ModuleNotFoundError: No module named 'pytsk3'` (or flask, reportlab) | You forgot `source venv/bin/activate`, or you're in the old prototype folder. Check that your prompt shows `(venv)` and that you're in `final_project/usb_forensics_toolkit`. |
| `pip install` fails while building pytsk3 | Run the `sudo apt install` line from A2 again (it needs `python3-dev`, `build-essential` and `sleuthkit`), then `pip install -r requirements.txt` again. |
| `ACQUISITION FAILED: destination already exists` | Old demo output is still there. Run `rm -rf case.db evidence recovered reports timeline.csv` and try again. |
| Dashboard says `Address already in use` | Port 5000 is busy. Run `python dashboard/app.py --port 5001` and open http://127.0.0.1:5001. |
| Browser on Windows can't open the dashboard (WSL) | Make sure the dashboard is still running in terminal 2. Try http://localhost:5000. |
| `Bad Request: missing or invalid CSRF token` after restarting the dashboard | Refresh the page (F5) and click again. |
| `mtools not installed: hidden-attribute check skipped` | Run `sudo apt install mtools`. Without it, secret.txt won't be flagged as hidden. |
| Need to open the PDF from WSL | Download it from the dashboard, or run `explorer.exe reports` to open the folder in Windows. |
| Tests fail | Make sure `data/scenario_b.img` has the hash from B2. If not, rebuild with `cd data && bash make_scenarios.sh && python3 make_usb_capture.py && cd ..`. |

---

## Quick command card

```bash
cd ~/final_project/usb_forensics_toolkit && source venv/bin/activate     # every new terminal

python -m unittest discover -s tests                                      # 74 tests, OK
rm -rf case.db evidence recovered reports timeline.csv                    # clean start
python main.py data/scenario_b.img data/usb.log --pcap data/usb_capture.pcap --examiner Ragini --hide-custody
python main.py data/scenario_a.img data/usb_a.log --examiner Ragini --hide-custody
python dashboard/app.py                                                   # http://127.0.0.1:5000
python tests/demo_mismatch.py                                             # tamper detection
python -m modules.writeblock custody 1                                    # custody log, case 1
python -m modules.writeblock verify 1                                     # re-check case 1's copy
```
