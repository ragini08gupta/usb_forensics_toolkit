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
