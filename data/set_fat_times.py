"""
set_fat_times.py - stamp the scenario story timestamps into a FAT32 image.

    python3 set_fat_times.py <image.img> <times.json>

mtools stamps every file with the time the image was built, which makes the
timeline meaningless for the demo. This script walks the FAT32 root
directory (live AND deleted 0xE5 entries, long-file-name aware) and rewrites
the created / modified / accessed fields from a JSON map:

    {"salary.xlsx": {"created": "2026-10-08 22:51:20",
                     "modified": "2026-10-05 17:30:12",
                     "accessed": "2026-10-08"}}

FAT stores local time with 2-second resolution (creation time also has a
10 ms field). Only used to BUILD test images, never on evidence.
"""
import json
import struct
import sys
from datetime import datetime

ATTR_LFN = 0x0F


def fat_date(dt):
    return ((dt.year - 1980) << 9) | (dt.month << 5) | dt.day


def fat_time(dt):
    return (dt.hour << 11) | (dt.minute << 5) | (dt.second // 2)


def parse(s):
    return datetime.fromisoformat(s)


def cluster_chain(fh, bpb, first):
    c = first
    while 2 <= c < 0x0FFFFFF8:
        yield c
        fh.seek(bpb["fat_off"] + c * 4)
        c = struct.unpack("<I", fh.read(4))[0] & 0x0FFFFFFF


def lfn_chars(e):
    raw = e[1:11] + e[14:26] + e[28:32]
    s = raw.decode("utf-16-le", errors="ignore")
    return s.split("\x00")[0].replace("￿", "")


def stamp(image, times):
    done = set()
    with open(image, "r+b") as fh:
        bs = fh.read(512)
        bps, spc = struct.unpack_from("<H", bs, 11)[0], bs[13]
        reserved, nfats = struct.unpack_from("<H", bs, 14)[0], bs[16]
        fatsz, root = struct.unpack_from("<I", bs, 36)[0], struct.unpack_from("<I", bs, 44)[0]
        bpb = {"fat_off": reserved * bps,
               "data_off": (reserved + nfats * fatsz) * bps,
               "clus": spc * bps}
        lfn_parts = []
        for c in cluster_chain(fh, bpb, root):
            base = bpb["data_off"] + (c - 2) * bpb["clus"]
            fh.seek(base)
            block = bytearray(fh.read(bpb["clus"]))
            for off in range(0, len(block), 32):
                e = block[off:off + 32]
                if e[0] == 0x00:
                    break
                if e[11] == ATTR_LFN:
                    lfn_parts.insert(0, lfn_chars(e))    # entries are stored last-part-first
                    continue
                if lfn_parts:
                    name = "".join(lfn_parts)
                else:
                    stem = e[1:8].decode("ascii", "replace").strip()
                    ext = e[8:11].decode("ascii", "replace").strip()
                    first = "?" if e[0] == 0xE5 else chr(e[0])
                    name = (first + stem + ("." + ext if ext else "")).lower()
                lfn_parts = []
                t = times.get(name)
                if not t:
                    continue
                cr, mo, ac = parse(t["created"]), parse(t["modified"]), parse(t["accessed"])
                # 13: create 10ms, 14: create time, 16: create date, 18: access date
                # (20: high cluster word - left alone), 22: write time, 24: write date
                struct.pack_into("<BHHH", block, off + 13,
                                 (cr.second % 2) * 100, fat_time(cr), fat_date(cr), fat_date(ac))
                struct.pack_into("<HH", block, off + 22, fat_time(mo), fat_date(mo))
                done.add(name)
            fh.seek(base)
            fh.write(block)
    missing = set(times) - done
    if missing:
        sys.exit(f"entries not found in {image}: {', '.join(sorted(missing))}")
    return done


if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    with open(sys.argv[2]) as fh:
        stamped = stamp(sys.argv[1], json.load(fh))
    print(f"  {sys.argv[1]}: stamped {len(stamped)} entries")
