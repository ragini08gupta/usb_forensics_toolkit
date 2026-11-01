# Scenario B ground truth

| File | Planted as | Expected | Observed |
|---|---|---|---|
| salary.xlsx | deleted + keyword | deleted, recovered, keyword | PASS |
| passwords.txt | deleted + keyword | deleted, recovered, keyword | PASS |
| report.pdf | ZIP disguised as PDF | magic mismatch | PASS |
| invoice.jpg | EXE disguised as JPG | magic mismatch | PASS |
| secret.txt | hidden attribute | hidden flag | PASS |
| client_list.docx | keyword in name | keyword flag | PASS |
| notes.txt, holiday.jpg | clean | no flags | PASS |

Detection: 6/6 true positives, 0 false positives. Recovery: 2/2.

# Phase 3: acquisition and hash integrity (Vijay)

Run on 2026-10-11 as a normal user with freshly built images (`tests/logs/`).

| Check | Scenario B | Scenario A |
|---|---|---|
| Write probe on source descriptor | BLOCKED (EBADF) | BLOCKED (EBADF) |
| SHA-256 source == acquired copy | PASS | PASS |
| MD5 source == acquired copy | PASS | PASS |
| Source SHA-256 unchanged after acquisition | PASS | PASS |
| Copy re-verified after analysis | PASS | PASS |
| Analysis results on acquired copy | 8 files, 2 deleted (2/2 recovered), 6/6 flagged, 0 FP | 3 files, 0 flagged |
| Total time (acquire + analyse + timeline) | 0.77 s | 0.78 s |

Intentional mismatch (1 byte corrupted in a disposable copy): detected, status MISMATCH.
Tampering after acquisition: detected by re-verification (REVERIFY_FAIL).

# Final phase: impersonation, correlation, report and dashboard

Run on freshly built, reproducible images (`tests/logs/08_*` to `12_*`).

### USB devices (Scenario B, `usb.log` + `usb_capture.pcap`)

| # | Device | Planted as | Expected verdict | Observed |
|---|---|---|---|---|
| 1 | 046d:c31c Logitech keyboard | genuine HID keyboard | GENUINE | PASS (0) |
| 2 | 0781:5567 SanDisk (morning) | imaged stick | GENUINE, evidence device | PASS (0) |
| 3 | 0951:1666 Kingston (afternoon) | genuine | GENUINE | PASS (0) |
| 4 | 0951:1666 "Kingston" 22:44 | HID keyboard only, USB 1.1, no serial, 48 s | LIKELY_SPOOFED | PASS (130) |
| 5 | 0781:5567 SanDisk 22:50 | imaged stick, after hours | GENUINE, evidence device, after hours | PASS (0) |

### File-to-session correlation

| File | Written at | Expected session | Observed |
|---|---|---|---|
| notes.txt, holiday.jpg | 10:16, 10:17 | #2 (morning) | PASS |
| client_list.docx, salary.xlsx, passwords.txt, report.pdf, invoice.jpg, secret.txt | 22:51–22:56 | #5 (after hours) | PASS |
| secret.txt | created 22:56:31, modified 22:56:30 | authored on the stick (no copy indicator) | PASS |

Alerts: 1 HIGH impersonation, 6 HIGH flagged-copy, 2 MEDIUM after-hours, so 9 in total. Scenario A: 0 alerts, 0 rogue devices (no false positives).
Unit and integration tests: 54/54 pass.

# Final code review (independent reviewer): findings and fixes

| # | Severity | Finding | Fix | Regression test |
|---|---|---|---|---|
| 1 | High | File times shifted with the analysis PC's time zone; on an IST PC no file matched a session | Process pinned to UTC before pytsk3, times kept as suspect-local wall clock | `TestR1TimezoneIndependence` (runs `main.py` with `TZ=Asia/Kolkata`) |
| 2 | High | XSS: USB product strings or file names could close the chart `<script>` | `|tojson` escaping | `TestR2DashboardXss` |
| 3 | High | Files inside a deleted folder were never listed | Walk deleted folders and `$OrphanFiles`, guarding against loops | `TestR3DeletedFolders` |
| 4 | High | A session with no disconnect line claimed every later file | Inferred disconnect when the port is reused; latest-starting session wins | `TestR4OpenSessions` |
| 5 | Medium | Long or odd evidence file names aborted the whole analysis | Sanitised, length-capped recovery names; errors handled per file | `TestR2R5HostileFileNames` |
| 6 | Medium | A garbage pcap, a Feb 29 line or a raw dmesg log crashed or gave nothing silently | Exit code 5 + custody `ANALYSIS_FAILED`; bad lines skipped with warnings; ISO and `dmesg -T` years | `TestR6LogFormats`, `TestR8Captures` |
| 7 | Medium | pcap times are UTC but were compared with local log times | Converted with the log's UTC offset (`--tz-offset`) | `test_capture_time_uses_log_offset` |
| 8 | Medium | A truncated capture gave half a serial number; capture strings were ignored | Truncation detected; capture strings must match the log (+40) | `test_truncated_capture...`, `test_capture_strings_must_match_log` |
| 9 | Medium | No CSRF protection; GET had side effects; report history overwritten; stale report | CSRF tokens; POST to regenerate; timestamped reports; rebuilt after custody changes | `test_30_csrf_required`, `test_31_report_history_and_stale_report` |
| 10 | Low | A genuine device was penalised when a clone copied its serial; an unknown serial was scored as missing | Clone penalty goes only to the misfit device; an unknown serial is a note (+0) | `TestR10R11Scoring` |
| 11 | Low | A HID keyboard was attached to every device of the same model | Matched by port from the `input:` line | `test_keyboard_matched_by_port_not_model` |
| 12 | Low | Whole-disk (MBR) images failed | Partition table read; first readable FAT partition analysed | `TestR12PartitionedImage` |
| 13 | Low | `--setro` ran after the first read; analysis steps were missing from the custody log | `--setro` moved to before hashing; `ANALYSIS_STARTED/COMPLETED/FAILED` added | `TestR13R14CustodyAndPaths` |
| 14 | Low | Evidence folders were relative to the current directory, not the database | Everything is stored next to `--db`; per-case timeline CSV | `TestR13R14CustodyAndPaths` |

Tests: 74/74 pass, in UTC and in Asia/Kolkata.
