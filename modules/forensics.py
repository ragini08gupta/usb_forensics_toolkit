import math
import os
import subprocess
from collections import Counter
from datetime import datetime, timezone

import pytsk3

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
    return datetime.fromtimestamp(ts, timezone.utc).isoformat() if ts else None


def walk(fs, path="/"):
    """Yield (info_dict, entry) for every file/dir, including deleted ones."""
    for entry in fs.open_dir(path):
        name = entry.info.name.name.decode("utf-8", errors="replace")
        meta = entry.info.meta
        if name in (".", "..") or meta is None:
            continue
        if meta.type not in (pytsk3.TSK_FS_META_TYPE_REG, pytsk3.TSK_FS_META_TYPE_DIR):
            continue
        is_dir = meta.type == pytsk3.TSK_FS_META_TYPE_DIR
        deleted = bool(entry.info.name.flags & pytsk3.TSK_FS_NAME_FLAG_UNALLOC)
        full = path.rstrip("/") + "/" + name
        info = {
            "path": full, "name": name, "size": meta.size, "inode": meta.addr,
            "created": iso(meta.crtime), "modified": iso(meta.mtime),
            "accessed": iso(meta.atime), "deleted": deleted, "is_dir": is_dir,
        }
        yield info, entry
        if is_dir and not deleted:
            yield from walk(fs, full)


def read_content(entry, size, limit=None):
    n = size if limit is None else min(size, limit)
    return entry.read_random(0, n) if n > 0 else b""


def recover(entry, info, outdir="recovered"):
    os.makedirs(outdir, exist_ok=True)
    data = read_content(entry, info["size"])
    safe = f'{info["inode"]}_{info["name"]}'.replace("/", "_")
    out = os.path.join(outdir, safe)
    with open(out, "wb") as fh:
        fh.write(data)
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


def hidden_files(image_path):
    """Ask mtools for FAT attributes; return set of paths with the H flag."""
    try:
        out = subprocess.run(["mattrib", "-/", "-i", image_path, "::"],
                             capture_output=True, text=True).stdout
    except FileNotFoundError:
        return set()
    hidden = set()
    for line in out.splitlines():
        if "::" in line:
            attrs, path = line.split("::", 1)
            if "H" in attrs.upper():
                hidden.add("/" + path.strip().lstrip("/"))
    return hidden


def analyze(image_path, recover_dir="recovered"):
    img = pytsk3.Img_Info(image_path)
    fs = pytsk3.FS_Info(img)
    hidden = hidden_files(image_path)
    results = []
    for info, entry in walk(fs):
        if info["is_dir"]:
            continue
        data = read_content(entry, info["size"], limit=1_000_000)
        info["hidden"] = info["path"] in hidden
        info["recovered_path"] = recover(entry, info, recover_dir) if info["deleted"] else None
        info["reasons"] = check_suspicious(info, data, info["hidden"])
        info["suspicious"] = bool(info["reasons"])
        results.append(info)
    return results


def save_files(conn, case_id, results):
    for r in results:
        conn.execute(
            "INSERT INTO files(case_id,path,name,size,created,modified,accessed,"
            "deleted,recovered_path,hidden,suspicious,reasons) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
            (case_id, r["path"], r["name"], r["size"], r["created"], r["modified"],
             r["accessed"], int(r["deleted"]), r["recovered_path"], int(r["hidden"]),
             int(r["suspicious"]), "; ".join(r["reasons"])))
    conn.commit()
