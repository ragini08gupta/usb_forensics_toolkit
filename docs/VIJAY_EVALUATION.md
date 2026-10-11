# Progress Evaluation: Vijay (240953312)
## Module: USB Write-Blocking and Evidence Integrity (`modules/writeblock.py`)

The sections below follow the five criteria on the progress-evaluation sheet (10 marks): problem understanding and objectives (1), design/methodology (2), implementation progress (4), testing/initial results (2), and presentation and viva (1).

---

## 1. Problem understanding: my module in my own words

In a USB data-theft investigation, the evidence (the USB drive or its image) must not change, and we must be able to *prove* that it did not change. Otherwise the findings are not defensible.

My module covers **Objective 2** of the synopsis: *"implement a USB write-blocking mechanism that prevents any modification to the original evidence during acquisition, and verify data integrity throughout the investigation using cryptographic hashing (MD5/SHA-256) for a defensible chain of custody."*

What it does:

1. **Acquires** a bit-for-bit copy of the evidence image (`evidence/case_N/evidence.img`), so that analysis never runs on the original.
2. **Protects the original in software.** The source is opened only with `os.O_RDONLY`. Before copying, the tool attempts a write on that descriptor and shows that the operating system refuses it (`EBADF`).
3. **Hashes** the source before acquisition (SHA-256 + MD5), hashes the copy after acquisition, and re-hashes the source afterwards. All three must match.
4. **Records** everything in the case database: an `evidence` row and a step-by-step `custody_log` (who, when, action, hashes, tool).
5. **Re-verifies** the copy after Ragini's analysis, to show that the analysis did not change it.
6. **Fails safely.** It never overwrites existing evidence, never leaves half-written copies, and never reports success when a check fails.

**What it does not do:** it is a *software* write-blocker. Hashing does not stop modification; it detects it. OS read-only state is reported, not enforced. No hardware write-blocker is used. The roadmap lists that as future work.

---

## 2. Architecture and pipeline (my part)

See `docs/architecture.png`. My boxes are **Acquire (writeblock.py)** and, later, **Impersonation**.

Pipeline as implemented in `main.py`:

```
[1/6] Acquire        writeblock.acquire(image, evidence/case_N/evidence.img, conn, case_id)   <- Vijay
[2/6] Forensics      forensics.analyze(<acquired copy>) + save_files                         <- Ragini
[3/6] Device info    device_info.parse_log(usb.log) + save_usb_events                         <- Ragini
[4/6] Timeline       timeline.build_events / get_timeline / export_csv                        <- Ragini
[5/6] Re-verify      writeblock.reverify(conn, evidence_id)                                   <- Vijay
[6/6] Summary        integrity status + Ragini's findings + timeline
```

If acquisition fails, `main.py` prints `ACQUISITION FAILED`, records the failure and exits with code 2. **The original image is never analysed as a fallback.**

### Flowchart

`docs/writeblock_flowchart.png` (source: `docs/writeblock_flowchart.dot`).

Validate inputs → hash source → open `O_RDONLY` + write probe → copy in 1 MiB chunks to `.part` → hash copy and re-hash source → all match?
* **Yes:** finalise `evidence.img` (read-only 0444) → record VERIFIED → return the path to `forensics.analyze` → re-verify after analysis.
* **No:** record MISMATCH, keep the bad copy as `.MISMATCH`, stop.

### Database (additions only; Ragini's tables unchanged)

The original `evidence` table is kept, with the same column meanings:

| Column | Meaning |
|---|---|
| `sha256_before` | SHA-256 of the source before acquisition |
| `sha256_after` | SHA-256 of the acquired copy |
| `md5` | MD5 of the source before acquisition |
| `acquired_at`, `examiner`, `tool`, `source_path` | as in the original schema |

New columns, added automatically to old `case.db` files by `db._add_missing_columns`:

`dest_path`, `size_bytes`, `md5_after`, `sha256_source_after`, `verified` (1/0), `status` (VERIFIED / MISMATCH / FAILED), `protection` (which safeguards were actually applied).

New table `custody_log(id, case_id, evidence_id, ts, examiner, action, details)`. Actions are:
`ACQUISITION_STARTED`, `SOURCE_HASHED`, `WRITE_PROTECTION`, `ACQUISITION_VERIFIED` / `VERIFICATION_FAILED` / `ACQUISITION_FAILED`, `REVERIFY_PASS` / `REVERIFY_FAIL`.

---

## 3. How my module connects to Ragini's module

* **Interface:** `writeblock.acquire(source, dest, conn, case_id)` returns the path of the verified copy. `main.py` passes that path to Ragini's `forensics.analyze()` instead of the original image. Her function signature is unchanged.
* **Shared database:** both modules use the same `conn` and `case_id` from `db.new_case()`. My rows go into `evidence` and `custody_log`; hers go into `files`, `usb_events` and `events`.
* **The examiner name** for custody comes from the existing `cases.examiner` column (set with `--examiner`).
* **Read-only copy:** Ragini's code only reads the image. `pytsk3.Img_Info` opens it for reading, and `mattrib` opens it with `O_RDONLY` (checked with `strace`). So the read-only copy (permissions 0444) works with her code unchanged.
* **Proof of compatibility:** her Scenario B results (6/6 detections, 2/2 recoveries, 0 false positives on A) are the same on the acquired copy (tests 19–21).

---

## 4. Files created or modified

| File | Change |
|---|---|
| `modules/writeblock.py` | **New.** Acquisition, write probe, OS status report, hashing, verification, custody log, re-verify, small CLI (`verify`, `custody`). |
| `main.py` | **Modified.** Step 1 acquires via `writeblock`; analysis runs on the acquired copy; step 5 re-verifies; added the `--examiner` option; stops (exit 2) if acquisition fails; prints clear messages instead of tracebacks for a missing USB log or an image without a file system; the default log path works from any folder. Ragini's steps and output are unchanged. |
| `modules/db.py` | **Modified (additive).** New `evidence` columns, `custody_log` table, automatic upgrade of older `case.db` files. |
| `tests/test_writeblock.py` | **New.** 25 unit and integration tests. |
| `tests/demo_mismatch.py` | **New.** Live demo of mismatch and tampering detection on a disposable copy. |
| `tests/logs/*.log` | **New.** Captured output of the runs below. |
| `tests/screenshots/07_vijay_*` … `13_vijay_*` | **New.** Images rendered from those logs (not screenshots of the evaluation laptop). |
| `tests/ground_truth.md` | **Appended.** Phase 3 results section. |
| `docs/writeblock_flowchart.png`, `.dot` | **New.** Flowchart. |
| `docs/VIJAY_EVALUATION.md` | **New.** This document. |
| `README.md`, `requirements.txt` | **New.** Commands and dependencies. |
| `.gitignore` | Added `evidence/`. |
| `CONTRIBUTIONS.md` | Added Vijay's entry. |

Unchanged: `modules/forensics.py`, `modules/device_info.py`, `modules/timeline.py`, `data/`.

---

## 5. Testing: tests actually run and their real outcomes

Environment: Linux, Python 3.13 (suite also passed on 3.10 and 3.12), pytsk3 20260715, run as a **normal (non-root) user**, with fresh images built by `make_scenarios.sh`. Logs are in `tests/logs/`. The same suite also passed when run as root.

### Automated (`python -m unittest discover -s tests -v`): 25/25 passed (`01_unit_tests.log`)

| # | Test | What it checks | Result |
|---|---|---|---|
| 1 | Successful acquisition | The copy's SHA-256 and MD5 equal the source's (checked independently with `hashlib`); the DB row is VERIFIED with all hash columns filled | PASS |
| 2 | Original preserved | The source's SHA-256 and mtime are unchanged after acquisition | PASS |
| 3 | Copy read-only | The copy has mode 0444; no `.part` file is left | PASS |
| 4 | Chain of custody | The custody actions are in the correct order, with examiner, timestamp and hash | PASS |
| 5 | Intentional hash mismatch | A corrupted copy raises `IntegrityError`, the status is MISMATCH, no `evidence.img` is produced, and it is kept as `.MISMATCH` | PASS |
| 6 | Source changed during acquisition | Detected by the "source unchanged" check → MISMATCH | PASS |
| 7 | Missing source | `AcquisitionError`, FAILED row and custody entry, no copy | PASS |
| 8 | Invalid source (empty file, directory) | Rejected with a clear message | PASS |
| 9 | Destination already exists | Refused; the existing file is left untouched | PASS |
| 10 | Repeated acquisition | Two destinations are both VERIFIED with identical hashes; reusing the same destination is refused | PASS |
| 11 | Leftover `.part` file | Refused; the leftover file is not deleted | PASS |
| 12 | I/O error during copy (simulated disk full) | FAILED; the partial file is removed | PASS |
| 13 | Unknown case id | Rejected | PASS |
| 14 | Tampering after acquisition | `reverify` gives PASS, then FAIL after one byte is changed | PASS |
| 15 | Write probe on an `O_RDONLY` descriptor | Write refused (BLOCKED) | PASS |
| 16 | Write probe on a writable descriptor | The tool raises an error (it would never report a writable source as blocked) | PASS |
| 17 | Chunked hash function | Equals `hashlib` over the whole file | PASS |
| 18 | Old `case.db` upgrade | New columns are added and existing rows are kept | PASS |
| 19 | Scenario B on the acquired copy | 8 files; the exact 6 expected files flagged; `notes.txt` and `holiday.jpg` clean; 2/2 deleted files recovered byte-identical; original and copy hashes unchanged after analysis | PASS |
| 20 | Scenario A on the acquired copy | 3 files, 0 suspicious, 0 deleted | PASS |
| 21 | `main.py` run twice | Exit 0, VERIFIED, `8/2/6` summary, `case_1` and `case_2` copies created, input unchanged | PASS |
| 22 | `main.py` with a missing source | Exit 2, `ACQUISITION FAILED`, analysis not started | PASS |
| 23 | Broken output (e.g. piped to `head`) | The acquisition result stays VERIFIED | PASS |
| 24 | `main.py` with a missing USB log | Clear message `USB log not found`, exit 1, no Python traceback | PASS |
| 25 | `main.py` with a file that is not a disk image | Acquisition VERIFIED, then a clear `ANALYSIS FAILED` message, exit 4, no traceback | PASS |

The suite was also checked to make sure it really catches bugs. Three deliberate code changes were each detected:
* Skipping the hash comparison: 2 failures.
* Allowing overwrite: 1 failure.
* Opening the source read-write: 12 failures/errors.

### Command-line runs

| Run | Log | Real outcome |
|---|---|---|
| Baseline (Ragini's original code, before my changes) on B and A | (console) | B: 8 files, 2 deleted, 6 suspicious; recovered files byte-identical to planted ones. A: 3 files, 0 suspicious |
| Scenario B demo | `02_scenario_b_demo.log` | Write probe BLOCKED (EBADF); 4/4 hash checks PASS; VERIFIED; `Files found: 8  Deleted: 2  Suspicious: 6`; re-verify PASS; 0.77 s |
| Hash verification | `03_hash_verification.log` | `sha256sum`/`md5sum` of the original and copy identical; copy is `-r--r--r--`; `writeblock verify` PASS |
| Chain of custody | `04_chain_of_custody.log` | 6 entries for case 1 |
| Scenario A | `05_scenario_a_clean.log` | VERIFIED; `Files found: 3  Deleted: 0  Suspicious: 0`; 0.78 s |
| Error handling | `06_error_handling.log` | Missing source → exit 2, FAILED row; write to the copy → `Permission denied`; with `chmod a-w`, write to the original → `Permission denied`, and the tool reports "permissions are read-only"; hashes unchanged |
| Mismatch demo | `07_mismatch_detection.log` | Corrupted copy → 2 × `[FAIL]`, MISMATCH; tampered copy → `REVERIFY_FAIL` |

Ragini's reported baseline is confirmed in this environment: **6/6 planted items detected, 2/2 deleted files recovered, 0 false positives on Scenario A.** It is also unchanged when the analysis runs on the acquired copy.

**Bug found and fixed during testing.** Piping `main.py` into `head` closed the output early. A failed `print` then made the acquisition be recorded as FAILED. Logging is now isolated, so it can never change the evidence result (test 23).

**Not tested:**
* A real block device with `blockdev --setro`. The code only reads the kernel flag from `/sys/class/block/<dev>/ro`; it was never run on a device here.
* Windows without WSL.
* Hardware write-blockers.

---

## 6. Viva guide

**Why do hashes prove evidence integrity?**
A cryptographic hash is a fixed-size fingerprint of the data. Changing even one bit gives a completely different value (the avalanche effect), and it is computationally infeasible to find different data with the same SHA-256. If the hash taken at acquisition equals the hash computed later, the data is the same. Hashes **detect** changes; they do not **prevent** them.

**SHA-256 vs MD5. Why both?**
* SHA-256 gives a 256-bit digest (64 hex characters), with no known practical collisions. It is the defensible value.
* MD5 gives a 128-bit digest (32 hex characters). It is fast, but practical collisions have been demonstrated, so it is not trustworthy on its own.
* We record both because the synopsis specifies MD5/SHA-256, and many forensic tools still report MD5. We treat SHA-256 as the primary value, and both must match.

**What is write-blocking? Software vs hardware?**
A write-blocker stops any writes from reaching the evidence.
* A **hardware** blocker sits physically between the drive and the computer and refuses write commands, whatever the OS does.
* A **software** blocker depends on the OS or the program behaving correctly.
* Our tool is software only: it opens the source `O_RDONLY` and proves that a write on that descriptor fails. It cannot stop *another* program, or an OS auto-mount, from writing. That is why we report OS status separately and say hardware blockers are future work.

**What is the "write probe"? Isn't it dangerous?**
It calls `os.write(fd, b"")`: a write of zero bytes on the read-only descriptor. The kernel rejects it with `EBADF` (bad file descriptor: not open for writing). A zero-byte write cannot change data even if it were allowed, so the probe is safe on real evidence.

**What OS-level controls exist?**
* For an image file: read-only permissions (`chmod a-w`), or mounting with `mount -o ro,loop`.
* For a real device: `blockdev --setro /dev/sdX` sets the kernel read-only flag.
* Root bypasses permission bits, and the tool reports this.

**What does acquisition mean here?**
Making a bit-for-bit copy (an image) of the evidence and analysing only the copy. We copy in 1 MiB chunks (so memory use stays low for large drives), call `fsync`, and then hash the copy *read back from disk*, not from memory.

**Why re-hash the source after copying?**
To prove the original was not changed during acquisition. Test 6 shows this check catching a change.

**How is overwriting prevented?**
* Destinations are refused if they already exist.
* The copy is written to `evidence.img.part` with `O_EXCL` (create-new-only).
* The finished copy is moved into place with `os.link`, which also refuses to overwrite.
* Each case gets its own folder: `evidence/case_N/`.

**What happens on failure?**
* Missing or invalid input, an I/O error or a mismatch never reports success.
* A FAILED or MISMATCH row and a custody entry are written.
* Partial copies are deleted. A mismatched copy is kept only as `.MISMATCH`, for inspection.
* `main.py` stops before analysis.

**What is chain of custody?**
A record of who handled the evidence, when, what they did, and its hash at each step. That record shows the evidence presented later is the same as what was collected. Our `custody_log` holds timestamp, examiner, action and details for every step, including the re-verification after analysis.

**What are the limitations?**
* Software write-block only.
* Disk images rather than live USB drives.
* The tool cannot stop other processes from writing.
* `blockdev` was not exercised on a real device.
* Root bypasses permission bits.
* MD5 is weak (SHA-256 is primary).

**What is EBADF / O_RDONLY / O_EXCL / fsync?**
* `O_RDONLY`: open for reading only.
* `EBADF`: the error returned when writing to a descriptor that is not open for writing.
* `O_EXCL`: fail if the file already exists.
* `fsync`: force the written data to disk.

---

## 7. Demo checklist and suggested order (about 5 minutes for my part)

**Before the evaluation**
- [ ] `source venv/bin/activate`
- [ ] `cd data && bash make_scenarios.sh && cd ..`
- [ ] `python -m unittest discover -s tests -v` shows `OK`
- [ ] `rm -rf case.db evidence recovered timeline.csv`, so the demo is case 1
- [ ] Terminal font large enough to read; `docs/writeblock_flowchart.png` open

**Order**
1. Problem in one sentence; show the flowchart (30 s).
2. `sha256sum data/scenario_b.img`: note the hash of the original.
3. `python main.py data/scenario_b.img --examiner Vijay`. Point out:
   - the write probe BLOCKED;
   - the "Hardware blocker: not used";
   - the four `[PASS]` lines and VERIFIED;
   - `[2/6]` analysing the *copy*;
   - `[5/6]` re-verify PASS.

   Then hand over to Ragini for the findings and timeline.
4. `sha256sum data/scenario_b.img evidence/case_1/evidence.img`: identical, and the same as step 2.
5. `ls -l evidence/case_1/` (read-only), then `echo tamper >> evidence/case_1/evidence.img` → Permission denied (as a normal user).
6. `python -m modules.writeblock custody 1`: the chain of custody.
7. `python tests/demo_mismatch.py`: mismatch and tampering detected.
8. `python main.py data/scenario_a.img --examiner Vijay`: clean, 0 suspicious.
9. If asked: `python main.py data/missing.img` → ACQUISITION FAILED, exit code 2.

Take your own screenshots on the evaluation laptop during the rehearsal. The images in `tests/screenshots/07_vijay_*` were rendered from logs captured in the build environment.

---

## 8. Remaining work (later phases, not started)

* `impersonation.py` (Phase 4, Vijay): `known_good.json`, rule scoring, Genuine / Suspicious / Likely spoofed verdicts.
* Custody/acquisition events in the timeline (optional, Phase 4).
* Flask dashboard and ReportLab PDF report, which should include the hashes and custody log (Phase 5).
