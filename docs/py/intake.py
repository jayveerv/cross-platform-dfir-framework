"""Evidence intake: accept log files with ANY name and put them in the layout the framework reads.

The investigator no longer has to rename files or type folder paths. Give this module files
(single logs, .zip archives, .gz files or whole folders) and it looks INSIDE each file to decide
what it is:

  Windows   binary .evtx (file signature "ElfFile") or a wevtutil / Event Viewer XML export
  Linux     syslog-style auth log (sshd, sudo, su, useradd, PAM ... lines)
  AWS       CloudTrail JSON ("Records" list, plain list, JSON Lines, glued objects)
  Host      artefacts written by the live host collector (host/*.json)
  Cloud     AWS account-state artefacts written by cloudstate.py (cloud/*.json)
  Config    case_config.json

The result is a staging folder (windows_security.xml / *.evtx, auth.log, cloudtrail.json, host/, cloud/,
case_config.json) that pipeline.run_case() reads unchanged. The original files are never modified:
everything is copied, and the SHA-256 of each original is reported so it can be written in the case notes.

  python intake.py FILE_OR_FOLDER ... --out STAGING_DIR      (command-line use)
"""
import gzip
import hashlib
import json
import os
import re
import shutil
import sys
import zipfile

HOST_FILES = {"connections.json", "processes.json", "system.json", "accounts.json", "persistence.json", "files.json",
              "manifest.json"}
CLOUD_FILES = {"identity.json", "trails.json", "iam_account.json", "iam_users.json", "iam_roles.json",
               "s3_buckets.json", "security_groups.json"}
SKIP_NAMES = {"ground_truth.json", "desktop.ini", "thumbs.db", ".ds_store"}

MAX_ZIP_TOTAL = 2 * 1024 ** 3        # refuse archives that expand to more than 2 GB (zip bombs)
SNIFF_BYTES = 256 * 1024

_SYSLOG = re.compile(r"^(?:[A-Z][a-z]{2}\s+\d{1,2}\s+\d\d:\d\d:\d\d|\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\S*)\s+\S+\s+"
                     r"(sshd|sudo|su|useradd|usermod|groupadd|passwd|login|CRON|cron|systemd-logind|gdm-password|"
                     r"pam_unix|polkitd|unix_chkpwd|chpasswd|vsftpd|dropbear)\b", re.M)

LABELS = {
    "windows": "Windows event log",
    "linux": "Linux auth log",
    "aws": "AWS CloudTrail",
    "host": "Live host artefact",
    "cloud": "AWS account state",
    "config": "Case configuration",
    "unknown": "Not recognised",
}


def _sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _head(path, n=SNIFF_BYTES):
    with open(path, "rb") as f:
        return f.read(n)


def detect(path, rel=None):
    """Return (kind, reason) for one file. kind is a key of LABELS."""
    name = os.path.basename(path).lower()
    parts = [p.lower() for p in re.split(r"[\\/]+", rel or "") if p]
    head = _head(path)
    if head.startswith(b"ElfFile\x00"):
        return "windows", "binary EVTX signature"
    if name == "case_config.json":
        return "config", "case configuration file"
    text = head.decode("utf-8-sig", errors="replace")
    stripped = text.lstrip()
    if "<Event" in text and ("<EventID" in text or "<System>" in text):
        return "windows", "Windows event XML"
    if stripped[:1] in "{[":
        if '"eventName"' in text and ('"eventSource"' in text or '"eventTime"' in text):
            return "aws", "CloudTrail records (eventName / eventTime)"
        if name in CLOUD_FILES and ("cloud" in parts[:-1] or name not in HOST_FILES):
            return "cloud", "account-state file " + name
        if name in HOST_FILES:
            return "host", "host artefact " + name
        if "cloud" in parts[:-1] and name.endswith(".json"):
            return "cloud", "file inside a cloud/ folder"
        if "host" in parts[:-1] and name.endswith(".json"):
            return "host", "file inside a host/ folder"
    hits = len(_SYSLOG.findall(text))
    if hits:
        return "linux", f"{hits} auth-log lines found" + (f" in the first {len(head) // 1024} KB" if len(head) >= SNIFF_BYTES else "")
    return "unknown", "no Windows / Linux / AWS signature found"


def _expand(src, rel, work, out):
    """Yield (path, relative name) for every real file behind src (folders walked, .zip and .gz unpacked)."""
    if os.path.isdir(src):
        for root, _dirs, files in os.walk(src):
            for f in sorted(files):
                p = os.path.join(root, f)
                yield from _expand(p, os.path.join(rel, os.path.relpath(p, src)), work, out)
        return
    low = src.lower()
    if low.endswith(".zip") and zipfile.is_zipfile(src):
        dest = os.path.join(work, f"zip{len(os.listdir(work))}")
        os.makedirs(dest, exist_ok=True)
        with zipfile.ZipFile(src) as z:
            total = sum(i.file_size for i in z.infolist())
            if total > MAX_ZIP_TOTAL:
                out.append(dict(name=rel, kind="unknown", label=LABELS["unknown"], reason="archive too large to unpack",
                                size=os.path.getsize(src), sha256=_sha256(src), used=False))
                return
            root_abs = os.path.abspath(dest)
            for info in z.infolist():
                target = os.path.abspath(os.path.join(root_abs, info.filename))
                if not target.startswith(root_abs + os.sep):
                    continue                     # path traversal inside the archive ("../x"): ignored
                if info.is_dir():
                    continue
                os.makedirs(os.path.dirname(target), exist_ok=True)
                with z.open(info) as s, open(target, "wb") as d:
                    shutil.copyfileobj(s, d)
        for root, _dirs, files in os.walk(dest):
            for f in sorted(files):
                p = os.path.join(root, f)
                yield from _expand(p, rel + "!/" + os.path.relpath(p, dest).replace(os.sep, "/"), work, out)
        return
    if low.endswith(".gz"):
        dest = os.path.join(work, f"gz{len(os.listdir(work))}_" + os.path.basename(src)[:-3])
        try:
            with gzip.open(src, "rb") as s, open(dest, "wb") as d:
                shutil.copyfileobj(s, d)
            yield dest, rel[:-3]
            return
        except OSError:
            pass
    yield src, rel


def _windows_events(path):
    with open(path, encoding="utf-8-sig", errors="replace") as f:
        text = f.read()
    return re.findall(r"<Event[ >].*?</Event>", text, re.S)


def _cloudtrail_records(path):
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from normalize import _lenient_records
    with open(path, encoding="utf-8-sig", errors="replace") as f:
        text = f.read()
    try:
        doc = json.loads(text)
        return doc.get("Records", [doc]) if isinstance(doc, dict) else list(doc)
    except ValueError:
        return [r for r in _lenient_records(text) if r is not None]


def stage(sources, staging_dir):
    """sources: list of paths or (path, display_name). Returns the list of per-file results for the UI / console."""
    if os.path.isdir(staging_dir):
        shutil.rmtree(staging_dir)
    os.makedirs(staging_dir)
    work = os.path.join(staging_dir, "_unpacked")
    os.makedirs(work)
    results, found = [], []
    for s in sources:
        path, shown = (s if isinstance(s, (tuple, list)) else (s, os.path.basename(os.path.normpath(s))))
        for p, rel in _expand(path, shown, work, results):
            base = os.path.basename(p)
            if base.lower() in SKIP_NAMES or base.startswith("."):
                continue
            kind, reason = detect(p, rel)
            results.append(dict(name=rel, kind=kind, label=LABELS[kind], reason=reason, size=os.path.getsize(p),
                                sha256=_sha256(p), used=kind != "unknown"))
            found.append((kind, p, rel, results[-1]))

    win_xml, evtx_n, linux, aws = [], 0, [], []
    for kind, p, rel, r in found:
        if kind == "windows":
            if _head(p, 8).startswith(b"ElfFile"):
                evtx_n += 1
                stem = re.sub(r"[^A-Za-z0-9_.-]", "_", os.path.splitext(os.path.basename(p))[0])[:60]
                shutil.copy2(p, os.path.join(staging_dir, f"{evtx_n:02d}_{stem}.evtx"))
            else:
                ev = _windows_events(p)
                r["records"] = len(ev)
                win_xml += ev
        elif kind == "linux":
            with open(p, encoding="utf-8", errors="replace") as f:
                lines = [l.rstrip("\n") for l in f if l.strip()]
            r["records"] = len(lines)
            linux += lines
        elif kind == "aws":
            recs = _cloudtrail_records(p)
            r["records"] = len(recs)
            aws += recs
        elif kind in ("host", "cloud"):
            d = os.path.join(staging_dir, kind)
            os.makedirs(d, exist_ok=True)
            shutil.copy2(p, os.path.join(d, os.path.basename(p)))
        elif kind == "config":
            shutil.copy2(p, os.path.join(staging_dir, "case_config.json"))
    if win_xml:
        with open(os.path.join(staging_dir, "windows_security.xml"), "w", encoding="utf-8") as f:
            f.write("<Events>\n" + "\n".join(win_xml) + "\n</Events>\n")
    if linux:
        with open(os.path.join(staging_dir, "auth.log"), "w", encoding="utf-8") as f:
            f.write("\n".join(linux) + "\n")
    if aws:
        seen, uniq = set(), []
        for rec in aws:                      # the same event exported twice is analysed once
            k = rec.get("eventID") if isinstance(rec, dict) else None
            if k and k in seen:
                continue
            seen.add(k)
            uniq.append(rec)
        with open(os.path.join(staging_dir, "cloudtrail.json"), "w", encoding="utf-8") as f:
            json.dump({"Records": uniq}, f)
    shutil.rmtree(work, ignore_errors=True)
    return results


def summary(results):
    used = [r for r in results if r["used"]]
    kinds = sorted({r["kind"] for r in used if r["kind"] != "config"})
    return dict(files=len(results), used=len(used), ignored=len(results) - len(used),
                platforms=[LABELS[k] for k in kinds])


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser(description="Stage log files with any name for the DFIR framework")
    ap.add_argument("paths", nargs="+")
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    for r in stage(a.paths, a.out):
        print(f"  {'OK ' if r['used'] else '-- '} {r['label']:<22} {r['name']}  ({r['reason']})")
    print("Staged in", os.path.abspath(a.out))
