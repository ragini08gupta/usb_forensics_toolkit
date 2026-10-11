"""
writeblock.py - evidence acquisition, software write-blocking and hash
verification (Vijay).

What this module actually does (and does NOT do):

  * SOFTWARE safeguard: the source is only ever opened with os.O_RDONLY.
    Before copying, a zero-byte write is attempted on that descriptor; the
    kernel must refuse it (EBADF). A zero-byte write cannot change any data,
    so this probe is safe even on real evidence.
  * OS-level status is REPORTED, not changed: whether the file permissions
    (or a block device's kernel read-only flag) would stop a write.
    Running as root bypasses permission bits, and this is reported too.
  * HARDWARE write-blocking is NOT used and NOT verified by this tool.
  * Hashing does not prevent modification - it DETECTS it. SHA-256 and MD5
    are calculated for the source before acquisition, for the copy after
    acquisition, and for the source again afterwards. All must agree.
  * Every step is written to the custody_log table (who, when, what, hash).

Public interface used by main.py:
    writeblock.acquire(source, dest, conn, case_id)  ->  path of verified copy
    writeblock.reverify(conn, evidence_id)           ->  True / False
"""

import errno
import hashlib
import os
import stat
import sys
from datetime import datetime, timezone

CHUNK_SIZE = 1024 * 1024          # copy and hash 1 MiB at a time
TOOL = "usb_forensics_toolkit writeblock.py v1.0 (software write-block)"
HARDWARE_NOTE = "hardware write-blocker: not used / not verified"


class AcquisitionError(Exception):
    """Acquisition could not be completed (bad input, I/O error, ...)."""


class IntegrityError(AcquisitionError):
    """The copy was made but the hashes do not match."""


def now():
    return datetime.now(timezone.utc).isoformat()


def _safe_logger(log):
    """Printing progress must never change the evidence outcome (e.g. a closed pipe)."""
    def say(*args):
        if log:
            try:
                log(*args)
            except (OSError, ValueError):
                pass
    return say


# --------------------------------------------------------------------------
# Hashing
# --------------------------------------------------------------------------
def hash_file(path, chunk_size=CHUNK_SIZE):
    """Return (sha256_hex, md5_hex, size) reading the file read-only in chunks."""
    sha, md5, size = hashlib.sha256(), hashlib.md5(), 0
    fd = os.open(path, os.O_RDONLY)
    try:
        while True:
            block = os.read(fd, chunk_size)
            if not block:
                break
            sha.update(block)
            md5.update(block)
            size += len(block)
    finally:
        os.close(fd)
    return sha.hexdigest(), md5.hexdigest(), size


# --------------------------------------------------------------------------
# Write protection checks
# --------------------------------------------------------------------------
def write_probe(fd):
    """Prove the descriptor is read-only: a zero-byte write must be refused."""
    try:
        os.write(fd, b"")
    except OSError as e:
        if e.errno == errno.EBADF:
            return "BLOCKED (EBADF: descriptor opened O_RDONLY)"
        return f"BLOCKED ({errno.errorcode.get(e.errno, e.errno)})"
    raise AcquisitionError("write probe succeeded - source descriptor is NOT read-only")


def os_protection_status(path):
    """Describe OS-level read-only state of the source. Reports only; changes nothing."""
    st = os.stat(path)
    if stat.S_ISBLK(st.st_mode):
        name = os.path.basename(os.path.realpath(path))
        try:
            with open(f"/sys/class/block/{name}/ro") as fh:
                ro = fh.read().strip() == "1"
            return ("block device kernel read-only flag ON (blockdev --setro)" if ro
                    else "block device kernel read-only flag OFF (run: sudo blockdev --setro)")
        except OSError:
            return "block device: kernel read-only flag could not be read"
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        return "running as root: file permissions do NOT stop writes"
    if os.access(path, os.W_OK):
        return "file is writable by this user (permissions are not read-only)"
    return "file permissions are read-only for this user"


# --------------------------------------------------------------------------
# Database helpers (existing evidence table + custody_log)
# --------------------------------------------------------------------------
def custody(conn, case_id, examiner, action, details, evidence_id=None):
    conn.execute(
        "INSERT INTO custody_log(case_id,evidence_id,ts,examiner,action,details) "
        "VALUES(?,?,?,?,?,?)", (case_id, evidence_id, now(), examiner, action, details))
    conn.commit()


def _examiner_for(conn, case_id):
    row = conn.execute("SELECT examiner FROM cases WHERE id=?", (case_id,)).fetchone()
    if row is None:
        raise AcquisitionError(f"case {case_id} does not exist in the database")
    return row["examiner"] or "unknown"


def _save_evidence(conn, case_id, examiner, rec):
    cur = conn.execute(
        "INSERT INTO evidence(case_id,source_path,sha256_before,sha256_after,md5,"
        "acquired_at,examiner,tool,dest_path,size_bytes,md5_after,"
        "sha256_source_after,verified,status,protection) "
        "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (case_id, rec["source"], rec.get("sha256_before"), rec.get("sha256_after"),
         rec.get("md5_before"), now(), examiner, TOOL, rec.get("dest"),
         rec.get("size"), rec.get("md5_after"), rec.get("sha256_source_after"),
         int(rec.get("verified", False)), rec["status"], rec.get("protection")))
    conn.commit()
    return cur.lastrowid


# --------------------------------------------------------------------------
# Acquisition
# --------------------------------------------------------------------------
def _check_inputs(source, dest):
    if not os.path.exists(source):
        raise AcquisitionError(f"source not found: {source}")
    st = os.stat(source)
    if not (stat.S_ISREG(st.st_mode) or stat.S_ISBLK(st.st_mode)):
        raise AcquisitionError(f"source is not a regular file or block device: {source}")
    if stat.S_ISREG(st.st_mode) and st.st_size == 0:
        raise AcquisitionError(f"source is empty (0 bytes): {source}")
    if not os.access(source, os.R_OK):
        raise AcquisitionError(f"source is not readable: {source}")
    if os.path.exists(dest):
        raise AcquisitionError(f"destination already exists, refusing to overwrite: {dest}")
    if os.path.abspath(source) == os.path.abspath(dest):
        raise AcquisitionError("source and destination are the same path")


def _copy(src_fd, dst_fd, chunk_size):
    """Copy every byte from src_fd to dst_fd. Returns the number of bytes copied."""
    total = 0
    while True:
        block = os.read(src_fd, chunk_size)
        if not block:
            break
        view = memoryview(block)
        while view:                       # os.write may write fewer bytes
            n = os.write(dst_fd, view)
            view = view[n:]
        total += len(block)
    os.fsync(dst_fd)                      # make sure the data is on disk before hashing
    return total


def _place_final(part, final):
    """Move part -> final without ever overwriting an existing file."""
    try:
        os.link(part, final)              # fails with FileExistsError if final exists
        os.unlink(part)
    except FileExistsError:
        raise AcquisitionError(f"destination appeared during acquisition: {final}")
    except OSError:                       # filesystem without hard links
        if os.path.exists(final):
            raise AcquisitionError(f"destination already exists: {final}")
        os.rename(part, final)


def acquire(source, dest, conn, case_id, examiner=None,
            chunk_size=CHUNK_SIZE, log=print):
    """
    Acquire a forensic copy of `source` into `dest` and verify it.

    Returns the path of the verified copy. Raises AcquisitionError (or its
    subclass IntegrityError for a hash mismatch); failures are still
    recorded in the evidence and custody_log tables - never reported as success.
    """
    say = _safe_logger(log)
    examiner = examiner or _examiner_for(conn, case_id)
    rec = {"source": os.path.abspath(source), "dest": os.path.abspath(dest),
           "status": "FAILED", "verified": False}
    custody(conn, case_id, examiner, "ACQUISITION_STARTED",
            f"source={rec['source']} dest={rec['dest']} tool={TOOL}")
    part = dest + ".part"
    created_part = False
    try:
        _check_inputs(source, dest)
        if os.path.exists(part):
            raise AcquisitionError(f"leftover partial file exists, remove it first: {part}")
        os.makedirs(os.path.dirname(os.path.abspath(dest)), exist_ok=True)

        # 1. hash the source BEFORE touching anything
        say("  Hashing source before acquisition...")
        rec["sha256_before"], rec["md5_before"], src_size = hash_file(source, chunk_size)
        custody(conn, case_id, examiner, "SOURCE_HASHED",
                f"sha256={rec['sha256_before']} md5={rec['md5_before']} size={src_size}")

        # 2. open source read-only and prove a write is refused
        src_fd = os.open(source, os.O_RDONLY)
        try:
            probe = write_probe(src_fd)
            os_status = os_protection_status(source)
            rec["protection"] = (f"software: O_RDONLY, write probe {probe}; "
                                 f"OS: {os_status}; {HARDWARE_NOTE}")
            say(f"  Software write-block : source opened O_RDONLY, write attempt {probe}")
            say(f"  OS read-only status  : {os_status}")
            say("  Hardware blocker     : not used / not verified")
            custody(conn, case_id, examiner, "WRITE_PROTECTION", rec["protection"])

            # 3. copy in chunks to a new .part file (O_EXCL: never overwrite)
            say(f"  Copying {src_size} bytes in {chunk_size // 1024} KiB chunks...")
            dst_fd = os.open(part, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            created_part = True
            try:
                rec["size"] = _copy(src_fd, dst_fd, chunk_size)
            finally:
                os.close(dst_fd)
        finally:
            os.close(src_fd)

        # 4. hash the copy (read back from disk) and re-hash the source
        say("  Hashing acquired copy and re-hashing source...")
        rec["sha256_after"], rec["md5_after"], copy_size = hash_file(part, chunk_size)
        rec["sha256_source_after"], _, _ = hash_file(source, chunk_size)

        checks = {
            "SHA-256 source == copy": rec["sha256_before"] == rec["sha256_after"],
            "MD5     source == copy": rec["md5_before"] == rec["md5_after"],
            "size    source == copy": src_size == copy_size == rec["size"],
            "source unchanged (SHA-256 before == after)":
                rec["sha256_before"] == rec["sha256_source_after"],
        }
        rec["verified"] = all(checks.values())
        for name, ok in checks.items():
            say(f"    [{'PASS' if ok else 'FAIL'}] {name}")

        if not rec["verified"]:
            failed = [n for n, ok in checks.items() if not ok]
            bad = dest + ".MISMATCH"
            if os.path.exists(bad):
                bad = f"{dest}.MISMATCH.{datetime.now().strftime('%Y%m%d%H%M%S')}"
            os.rename(part, bad)          # keep the bad copy for inspection, never as evidence
            os.chmod(bad, 0o444)
            rec["dest"], rec["status"] = os.path.abspath(bad), "MISMATCH"
            ev = _save_evidence(conn, case_id, examiner, rec)
            custody(conn, case_id, examiner, "VERIFICATION_FAILED",
                    f"failed checks: {', '.join(failed)}; copy kept at {bad}", ev)
            raise IntegrityError(f"hash verification failed: {', '.join(failed)}")

        # 5. success: move into place and make the working copy read-only
        _place_final(part, dest)
        os.chmod(dest, 0o444)
        rec["status"] = "VERIFIED"
        ev = _save_evidence(conn, case_id, examiner, rec)
        custody(conn, case_id, examiner, "ACQUISITION_VERIFIED",
                f"copy={rec['dest']} sha256={rec['sha256_after']} md5={rec['md5_after']} "
                f"(copy set to read-only 0444)", ev)
        return dest

    except IntegrityError:
        raise
    except Exception as e:
        if created_part and os.path.exists(part):
            os.remove(part)               # never leave a half-written copy behind
        ev = _save_evidence(conn, case_id, examiner, rec)
        custody(conn, case_id, examiner, "ACQUISITION_FAILED", f"{type(e).__name__}: {e}", ev)
        if isinstance(e, AcquisitionError):
            raise
        raise AcquisitionError(f"{type(e).__name__}: {e}") from e


# --------------------------------------------------------------------------
# Re-verification (e.g. after analysis, or later in the investigation)
# --------------------------------------------------------------------------
def reverify(conn, evidence_id, examiner=None, log=print):
    """Re-hash the acquired copy and compare with the stored hashes."""
    say = _safe_logger(log)
    row = conn.execute("SELECT * FROM evidence WHERE id=?", (evidence_id,)).fetchone()
    if row is None:
        raise AcquisitionError(f"evidence {evidence_id} not found")
    examiner = examiner or row["examiner"]
    path = row["dest_path"]
    if not path or not os.path.exists(path):
        ok, detail = False, f"acquired copy missing: {path}"
    else:
        sha, md5, _ = hash_file(path)
        ok = sha == row["sha256_after"] and md5 == row["md5_after"]
        detail = f"sha256={sha} md5={md5} stored_sha256={row['sha256_after']}"
    say(f"  [{'PASS' if ok else 'FAIL'}] acquired copy still matches acquisition hash")
    custody(conn, row["case_id"], examiner, "REVERIFY_PASS" if ok else "REVERIFY_FAIL",
            detail, evidence_id)
    return ok


def latest_evidence_id(conn, case_id):
    row = conn.execute("SELECT id FROM evidence WHERE case_id=? AND status='VERIFIED' "
                       "ORDER BY id DESC LIMIT 1", (case_id,)).fetchone()
    return row["id"] if row else None


# --------------------------------------------------------------------------
# Small CLI:  python -m modules.writeblock verify|custody <case_id> [--db case.db]
# --------------------------------------------------------------------------
def _cli(argv):
    import argparse
    from modules import db
    p = argparse.ArgumentParser(prog="python -m modules.writeblock")
    p.add_argument("command", choices=["verify", "custody"])
    p.add_argument("case_id", type=int)
    p.add_argument("--db", default="case.db")
    a = p.parse_args(argv)
    if not os.path.exists(a.db):
        print(f"database not found: {a.db}")
        return 1
    conn = db.get_conn(a.db)
    if a.command == "verify":
        ev = latest_evidence_id(conn, a.case_id)
        if ev is None:
            print(f"no verified evidence for case {a.case_id}")
            return 1
        r = conn.execute("SELECT * FROM evidence WHERE id=?", (ev,)).fetchone()
        print(f"Evidence {ev}: {r['dest_path']}\n  stored SHA-256 {r['sha256_after']}")
        return 0 if reverify(conn, ev) else 2
    for r in conn.execute("SELECT * FROM custody_log WHERE case_id=? ORDER BY id",
                          (a.case_id,)):
        print(f"{r['ts'][:19]}  {r['examiner']:<8} {r['action']:<22} {r['details']}")
    return 0


if __name__ == "__main__":
    sys.exit(_cli(sys.argv[1:]))
