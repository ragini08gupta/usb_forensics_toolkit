"""
forensics.py - file system analysis of the ACQUIRED COPY (Ragini).

Time base: FAT stores the suspect machine's local wall-clock time with no
zone. The Sleuth Kit turns those fields into epoch seconds with the
analysis machine's time zone, so the same image would give different times
on an IST and a UTC laptop. To keep results identical everywhere, the
process time zone is pinned to UTC before pytsk3 is used; the times then
come back exactly as written on the stick ("suspect local time").
"""
import hashlib
import math
import os
import re
import struct
import subprocess
import time
from collections import Counter
from datetime import datetime, timezone

os.environ["TZ"] = "UTC"            # see module docstring
if hasattr(time, "tzset"):
    time.tzset()

import pytsk3  # noqa: E402

KEYWORDS = ["confidential", "salary", "password", "secret", "client", "payroll"]

# (magic bytes, label, extensions that legitimately use this type)
SIGNATURES = [
    (b"MZ", "exe", {".exe", ".dll", ".sys"}),
    (b"%PDF", "pdf", {".pdf"}),
    (b"PK", "zip/office", {".zip", ".docx", ".xlsx", ".pptx", ".jar", ".apk"}),
    (b"\xff\xd8\xff", "jpeg", {".jpg", ".jpeg"}),
    (b"\x89PNG", "png", {".png"}),
]


def iso(ts):
    """Suspect-local wall-clock time as a zone-less ISO string (see docstring)."""
    if not ts:
        return None
    return datetime.fromtimestamp(ts, timezone.utc).replace(tzinfo=None).isoformat()


DIR_TYPES = (pytsk3.TSK_FS_META_TYPE_DIR, pytsk3.TSK_FS_META_TYPE_VIRT_DIR)


def walk(fs, path="/", inode=None, parent_deleted=False, seen=None):
    """Yield (info_dict, entry) for every file/dir, including deleted ones,
    files inside DELETED folders and TSK's $OrphanFiles. Each directory inode
    is visited once, so corrupt or looping directory chains cannot hang it."""
    seen = set() if seen is None else seen
    try:
        directory = fs.open_dir(inode=inode) if inode is not None else fs.open_dir(path)
    except (IOError, OSError):
        return                                  # unreadable (e.g. overwritten) deleted folder
    for entry in directory:
        name = entry.info.name.name.decode("utf-8", errors="replace")
        meta = entry.info.meta
        if name in (".", "..") or meta is None:
            continue
        if name.endswith("(Volume Label Entry)"):   # FAT label, reported by volume_info()
            continue
        if meta.type not in (pytsk3.TSK_FS_META_TYPE_REG,) + DIR_TYPES:
            continue
        is_dir = meta.type in DIR_TYPES
        deleted = parent_deleted or bool(entry.info.name.flags & pytsk3.TSK_FS_NAME_FLAG_UNALLOC)
        orphan = name == "$OrphanFiles"
        full = path.rstrip("/") + "/" + name
        info = {
            "path": full, "name": name, "size": meta.size, "inode": meta.addr,
            "created": iso(meta.crtime), "modified": iso(meta.mtime),
            "accessed": iso(meta.atime), "deleted": deleted or orphan, "is_dir": is_dir,
        }
        yield info, entry
        if is_dir and meta.addr not in seen:
            seen.add(meta.addr)
            yield from walk(fs, full, inode=meta.addr, parent_deleted=deleted or orphan,
                            seen=seen)


def read_content(entry, size, limit=None):
    n = size if limit is None else min(size, limit)
    return entry.read_random(0, n) if n > 0 else b""


def safe_name(info):
    """File name for a recovered copy. Names come from the evidence and are
    untrusted: only [A-Za-z0-9._-] are kept, the length is capped, and the
    inode prefix makes it unique. The original name stays in the database."""
    base = re.sub(r"[^A-Za-z0-9._-]", "_", info["name"]).lstrip(".")[:80] or "file"
    return f'{info["inode"]}_{base}'


def recover(entry, info, outdir="recovered", chunk=1024 * 1024):
    """Write a deleted file's content to outdir, 1 MiB at a time (no size limit in RAM)."""
    os.makedirs(outdir, exist_ok=True)
    out = os.path.join(outdir, safe_name(info))
    if os.path.realpath(os.path.dirname(out)) != os.path.realpath(outdir):
        raise ValueError(f"unsafe recovery path for {info['name']!r}")
    with open(out, "wb") as fh:
        off, size = 0, info["size"]
        while off < size:
            block = entry.read_random(off, min(chunk, size - off))
            if not block:
                break
            fh.write(block)
            off += len(block)
    return out


def entropy(data):
    if not data:
        return 0.0
    counts = Counter(data)
    n = len(data)
    return -sum(c / n * math.log2(c / n) for c in counts.values())


def check_suspicious(info, data, hidden=False):
    reasons = []
    ext = os.path.splitext(info["name"])[1].lower()
    for magic, label, exts in SIGNATURES:
        if data.startswith(magic) and ext not in exts:
            reasons.append(f"extension {ext or '(none)'} does not match {label} content")
    if hidden:
        reasons.append("hidden attribute set")
    if len(data) >= 1024 and entropy(data) > 7.5:
        reasons.append("high entropy (encrypted/compressed)")
    low = info["name"].lower()
    if any(k in low for k in KEYWORDS):
        reasons.append("suspicious keyword in filename")
    elif any(k.encode() in data[:4096].lower() for k in KEYWORDS):
        reasons.append("suspicious keyword in content")
    return reasons


HIDDEN_CHECK = {"available": True}


def hidden_files(image_path, offset=0):
    """Ask mtools for FAT attributes; return set of paths with the H flag.
    mattrib only lists attributes (it opens the image O_RDONLY; the copy is
    re-hashed afterwards anyway). If mtools is missing, HIDDEN_CHECK says so."""
    target = f"{image_path}@@{offset}" if offset else image_path
    try:
        out = subprocess.run(["mattrib", "-/", "-i", target, "::"],
                             capture_output=True, text=True,
                             env={**os.environ, "MTOOLS_SKIP_CHECK": "1"}).stdout
        HIDDEN_CHECK["available"] = True
    except FileNotFoundError:
        HIDDEN_CHECK["available"] = False
        return set()
    hidden = set()
    for line in out.splitlines():
        if "::" in line:
            attrs, path = line.split("::", 1)
            if "H" in attrs.upper():
                hidden.add("/" + path.strip().lstrip("/"))
    return hidden


def copy_indicator(info):
    """On FAT, copying a file onto the stick keeps the original modified time but
    sets a NEW created time. created > modified therefore means the content is
    older than its arrival on this volume, i.e. it was copied here, not authored here."""
    c, m = info.get("created"), info.get("modified")
    if not (c and m):
        return None
    gap = (datetime.fromisoformat(c[:19]) - datetime.fromisoformat(m[:19])).total_seconds()
    if gap > 2:                          # FAT modified time has 2-second resolution
        return "created after last modification: content was copied onto this volume"
    return None


def file_hashes(entry, size, chunk=1024 * 1024):
    sha, md5, off = hashlib.sha256(), hashlib.md5(), 0
    while off < size:
        block = entry.read_random(off, min(chunk, size - off))
        if not block:
            break
        sha.update(block)
        md5.update(block)
        off += len(block)
    return sha.hexdigest(), md5.hexdigest()


def open_fs(img):
    """File system at offset 0 (a partition/volume image), else the first
    readable partition of a whole-disk image (MBR/GPT). Returns (fs, offset)."""
    try:
        return pytsk3.FS_Info(img), 0
    except (IOError, OSError):
        pass
    try:
        vol = pytsk3.Volume_Info(img)
    except (IOError, OSError):
        raise OSError("no file system or partition table found")
    bsize = vol.info.block_size
    for part in vol:
        if part.len < 16 or not (part.flags & pytsk3.TSK_VS_PART_FLAG_ALLOC):
            continue
        try:
            return pytsk3.FS_Info(img, offset=part.start * bsize), part.start * bsize
        except (IOError, OSError):
            continue
    raise OSError("partition table found, but no readable file system in any partition")


LAST_RUN = {}


def analyze(image_path, recover_dir="recovered"):
    img = pytsk3.Img_Info(image_path)
    fs, offset = open_fs(img)
    LAST_RUN.update(offset=offset, errors=[])
    hidden = hidden_files(image_path, offset)
    results, seen_files = [], set()
    for info, entry in walk(fs):
        if info["is_dir"]:
            continue
        key = (info["inode"], info["name"])
        if key in seen_files:              # same entry reached twice (e.g. via $OrphanFiles)
            continue
        seen_files.add(key)
        info["hidden"] = info["path"] in hidden
        try:
            data = read_content(entry, info["size"], limit=1_000_000)
            info["recovered_path"] = recover(entry, info, recover_dir) if info["deleted"] else None
            info["sha256"], info["md5"] = file_hashes(entry, info["size"])
        except (IOError, OSError, ValueError) as e:   # one bad entry must not stop the case
            data, info["recovered_path"], info["sha256"], info["md5"] = b"", None, None, None
            LAST_RUN["errors"].append(f"{info['path']}: {e}")
        info["reasons"] = check_suspicious(info, data, info["hidden"])
        info["suspicious"] = bool(info["reasons"])
        info["copy_indicator"] = copy_indicator(info)
        results.append(info)
    return results


def volume_info(image_path, offset=0):
    """Identify the volume from its FAT boot sector (read-only).
    Returns a dict, or {"fs_type": "unknown"} for non-FAT images."""
    with open(image_path, "rb") as fh:
        fh.seek(offset)
        bs = fh.read(512)
        size = os.fstat(fh.fileno()).st_size
    info = {"fs_type": "unknown", "total_bytes": size, "offset": offset}
    if len(bs) < 512 or bs[510:512] != b"\x55\xaa":
        return info
    bps, spc = struct.unpack_from("<H", bs, 11)[0], bs[13]
    info.update(oem_name=bs[3:11].decode("ascii", "replace").strip(),
                bytes_per_sector=bps, cluster_size=bps * spc)
    if bs[82:90].startswith(b"FAT32"):
        serial, label, fstype = struct.unpack_from("<I", bs, 67)[0], bs[71:82], "FAT32"
    elif bs[54:62].startswith(b"FAT"):
        serial, label = struct.unpack_from("<I", bs, 39)[0], bs[43:54]
        fstype = bs[54:62].decode("ascii", "replace").strip()
    else:
        return info
    info.update(fs_type=fstype,
                volume_serial=f"{serial >> 16:04X}-{serial & 0xFFFF:04X}",
                label=label.decode("ascii", "replace").strip())
    return info


def save_volume(conn, case_id, info, source="boot sector"):
    conn.execute(
        "INSERT INTO volume(case_id,fs_type,oem_name,volume_serial,label,bytes_per_sector,"
        "cluster_size,total_bytes,source) VALUES(?,?,?,?,?,?,?,?,?)",
        (case_id, info.get("fs_type"), info.get("oem_name"), info.get("volume_serial"),
         info.get("label"), info.get("bytes_per_sector"), info.get("cluster_size"),
         info.get("total_bytes"), source))
    conn.commit()


def save_files(conn, case_id, results):
    for r in results:
        conn.execute(
            "INSERT INTO files(case_id,path,name,size,created,modified,accessed,"
            "deleted,recovered_path,hidden,suspicious,reasons,inode,sha256,md5,copy_indicator) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (case_id, r["path"], r["name"], r["size"], r["created"], r["modified"],
             r["accessed"], int(r["deleted"]), r["recovered_path"], int(r["hidden"]),
             int(r["suspicious"]), "; ".join(r["reasons"]), r.get("inode"),
             r.get("sha256"), r.get("md5"), r.get("copy_indicator")))
    conn.commit()
