"""
Live demo: show that writeblock.py DETECTS a bad copy and later tampering.

    python tests/demo_mismatch.py [image]      (default: data/scenario_b.img)

Works only on a disposable COPY of the image in a temporary folder with a
temporary database. The original image and case.db are never touched.
"""
import os
import shutil
import sys
import tempfile
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from modules import db, writeblock  # noqa: E402

image = sys.argv[1] if len(sys.argv) > 1 else os.path.join(ROOT, "data", "scenario_b.img")
if not os.path.exists(image):
    sys.exit(f"image not found: {image} (run: cd data && bash make_scenarios.sh)")

tmp = tempfile.mkdtemp(prefix="mismatch_demo_")
src = os.path.join(tmp, "disposable_copy.img")
shutil.copyfile(image, src)
conn = db.get_conn(os.path.join(tmp, "demo.db"))
case_id = db.new_case(conn, "mismatch demo", "Vijay")

print("=== Demo 1: the copy is corrupted during acquisition (1 byte flipped) ===")
real_copy = writeblock._copy


def corrupting_copy(src_fd, dst_fd, chunk):
    n = real_copy(src_fd, dst_fd, chunk)
    os.pwrite(dst_fd, b"\xff", 4096)          # simulate a faulty copy
    return n


with mock.patch.object(writeblock, "_copy", corrupting_copy):
    try:
        writeblock.acquire(src, os.path.join(tmp, "bad", "evidence.img"), conn, case_id)
        print("UNEXPECTED: corrupted copy was accepted")
    except writeblock.IntegrityError as e:
        print(f"  -> IntegrityError raised: {e}")
r = conn.execute("SELECT status, verified, sha256_before, sha256_after FROM evidence "
                 "ORDER BY id DESC LIMIT 1").fetchone()
print(f"  DB row: status={r['status']} verified={r['verified']}")
print(f"  source SHA-256: {r['sha256_before']}")
print(f"  copy   SHA-256: {r['sha256_after']}")

print("\n=== Demo 2: a good copy is tampered with AFTER acquisition ===")
good = writeblock.acquire(src, os.path.join(tmp, "good", "evidence.img"), conn, case_id)
ev = writeblock.latest_evidence_id(conn, case_id)
writeblock.reverify(conn, ev)
os.chmod(good, 0o644)
with open(good, "r+b") as fh:
    fh.seek(8192)
    fh.write(b"X")
print("  (one byte of the disposable copy changed)")
writeblock.reverify(conn, ev)

print("\nChain-of-custody entries for this demo:")
for row in conn.execute("SELECT action FROM custody_log ORDER BY id"):
    print("  " + row["action"])
conn.close()
for d, _, files in os.walk(tmp):
    for f in files:
        os.chmod(os.path.join(d, f), 0o644)
shutil.rmtree(tmp)
print("\nTemporary files removed. Original image untouched.")
