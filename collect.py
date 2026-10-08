"""Evidence Acquisition layer.

Copies source logs into the case's evidence/ folder, checks the SHA-256 of the source
before and after the copy, and records every file in the chain-of-custody ledger.
Sources supported: Windows Security log (XML export), Linux auth.log, AWS CloudTrail JSON.
"""
import json
import os
import shutil
import subprocess
import sys
import time
from datetime import datetime, timedelta, timezone

from custody import sha256_file

SOURCES = {
    "windows": "windows_security.xml",
    "linux": "auth.log",
    "aws": "cloudtrail.json",
}


def acquire(input_dir, case_dir, ledger):
    """Returns (list of acquired file records, list of messages)."""
    ev_dir = os.path.join(case_dir, "evidence")
    os.makedirs(ev_dir, exist_ok=True)
    acquired, msgs = [], []
    evtx = sorted(f for f in os.listdir(input_dir) if f.lower().endswith(".evtx")) if os.path.isdir(input_dir) else []
    todo = [(s, f) for s, f in SOURCES.items()]
    if evtx:      # binary Windows event logs (.evtx) are accepted in addition to the XML export
        todo = [t for t in todo if t[0] != "windows" or os.path.exists(os.path.join(input_dir, t[1]))] + [("windows", f) for f in evtx]
    have_any = any(os.path.exists(os.path.join(input_dir, f)) for _, f in todo) or os.path.isdir(os.path.join(input_dir, "host")) or os.path.isdir(os.path.join(input_dir, "cloud"))
    for source, fname in todo:
        src = os.path.join(input_dir, fname)
        if not os.path.exists(src):
            if not have_any:      # only complain when there is nothing at all to analyse
                msgs.append(f"{source}: {fname} not found in {input_dir} - skipped")
            continue
        before = sha256_file(src)
        dst = os.path.join(ev_dir, fname)
        shutil.copy2(src, dst)
        after = sha256_file(dst)
        ok = before == after
        entry = ledger.record("acquire", dst, stage="Acquisition", details={
            "source": source, "source_path": os.path.abspath(src), "size_bytes": os.path.getsize(dst),
            "source_sha256": before, "copy_verified": ok})
        acquired.append({"source": source, "file": fname, "sha256": after, "size": os.path.getsize(dst),
                         "copy_verified": ok, "seq": entry["seq"]})
        if not ok:
            msgs.append(f"{source}: HASH MISMATCH after copy!")
    for sub in ("host", "cloud"):
        hd = os.path.join(input_dir, sub)
        if not os.path.isdir(hd):
            continue
        os.makedirs(os.path.join(ev_dir, sub), exist_ok=True)
        for fname in sorted(os.listdir(hd)):
            if not fname.endswith(".json"):
                continue
            src = os.path.join(hd, fname)
            before = sha256_file(src)
            dst = os.path.join(ev_dir, sub, fname)
            shutil.copy2(src, dst)
            after = sha256_file(dst)
            ok = before == after
            entry = ledger.record("acquire", dst, stage="Acquisition", details={
                "source": sub, "source_path": os.path.abspath(src), "size_bytes": os.path.getsize(dst),
                "source_sha256": before, "copy_verified": ok})
            acquired.append({"source": sub, "file": f"{sub}/{fname}", "sha256": after, "size": os.path.getsize(dst),
                             "copy_verified": ok, "seq": entry["seq"]})
            if not ok:
                msgs.append(f"{sub}: {fname} HASH MISMATCH after copy!")
    return acquired, msgs


def collect_live_windows(out_dir, count=5000, fmt="xml"):
    """Export the local Windows Security log with wevtutil (needs Administrator).
    fmt='xml'  -> windows_security.xml (last `count` events)
    fmt='evtx' -> Security.evtx (complete log, binary; needs the python-evtx package to be analysed)"""
    if sys.platform != "win32":
        raise RuntimeError("Live Windows collection works only on Windows.")
    os.makedirs(out_dir, exist_ok=True)
    if fmt == "evtx":
        out = os.path.join(out_dir, "Security.evtx")
        if os.path.exists(out):
            os.remove(out)          # wevtutil epl refuses to overwrite
        r = subprocess.run(["wevtutil", "epl", "Security", out], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    else:
        out = os.path.join(out_dir, "windows_security.xml")
        with open(out, "w", encoding="utf-8") as f:
            r = subprocess.run(["wevtutil", "qe", "Security", f"/c:{count}", "/rd:false", "/f:xml"],
                               stdout=f, stderr=subprocess.PIPE, text=True)
    if r.returncode != 0:
        raise RuntimeError("wevtutil failed. Run Command Prompt as Administrator. " + (r.stderr or "").strip())
    return out


def collect_live_aws(out_dir, days=7, region=None, profile=None, client=None, pause=0.6, max_retries=6):
    """Pull management events from AWS CloudTrail (LookupEvents API, last <=90 days) and write cloudtrail.json.

    Needs boto3 and AWS credentials that allow cloudtrail:LookupEvents (for example a read-only IAM user, or
    'aws configure'). LookupEvents is limited to 2 requests/second per account, so calls are paced and throttling
    errors are retried. `client` can be injected for tests.
    """
    if client is None:
        try:
            import boto3
        except ImportError:
            raise RuntimeError("Live AWS collection needs boto3:  pip install boto3")
        session = boto3.Session(profile_name=profile, region_name=region) if profile else boto3.Session(region_name=region)
        client = session.client("cloudtrail")
    end = datetime.now(timezone.utc)
    start = end - timedelta(days=days)
    records, token, calls = [], None, 0
    while True:
        kw = dict(StartTime=start, EndTime=end, MaxResults=50)
        if token:
            kw["NextToken"] = token
        for attempt in range(max_retries):
            try:
                resp = client.lookup_events(**kw)
                break
            except Exception as e:                       # botocore ClientError: throttling is retried, anything else is fatal
                code = getattr(e, "response", {}).get("Error", {}).get("Code", "")
                if code in ("ThrottlingException", "Throttling", "RequestLimitExceeded") and attempt < max_retries - 1:
                    time.sleep(min(2 ** attempt, 20))
                    continue
                raise RuntimeError(f"CloudTrail LookupEvents failed: {code or type(e).__name__}: {e}")
        calls += 1
        for ev in resp.get("Events", []):
            raw = ev.get("CloudTrailEvent")
            try:
                records.append(json.loads(raw))
            except (TypeError, ValueError):
                pass                                     # event without a parsable body is skipped
        token = resp.get("NextToken")
        if not token:
            break
        time.sleep(pause)
    records.sort(key=lambda r: r.get("eventTime", ""))
    os.makedirs(out_dir, exist_ok=True)
    out = os.path.join(out_dir, "cloudtrail.json")
    with open(out, "w", encoding="utf-8") as f:
        json.dump({"Records": records}, f)
    return out, len(records), calls


def collect_linux_local(out_dir, path="/var/log/auth.log"):
    """Copy a local auth log (needs read permission; on Linux run with sudo)."""
    if not os.path.exists(path):
        raise RuntimeError(f"{path} not found. Debian/Ubuntu: /var/log/auth.log, RHEL/CentOS: /var/log/secure")
    os.makedirs(out_dir, exist_ok=True)
    out = os.path.join(out_dir, "auth.log")
    shutil.copy2(path, out)
    return out


def collect_linux_ssh(host, user, out_dir, key=None, path="/var/log/auth.log", use_sudo=True, port=22, runner=None):
    """Fetch a remote auth log through the ssh client (built into Windows 10/11 and Linux).
    Key-based login is required (BatchMode: it never asks for a password). `runner` can be injected for tests."""
    cmd = ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=15", "-p", str(port)]
    if key:
        cmd += ["-i", key]
    cmd += [f"{user}@{host}", ("sudo " if use_sudo else "") + f"cat {path}"]
    r = (runner or subprocess.run)(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if r.returncode != 0:
        err = (r.stderr or b"").decode("utf-8", "replace").strip()
        raise RuntimeError(f"ssh failed ({r.returncode}): {err or 'no error text'}")
    os.makedirs(out_dir, exist_ok=True)
    out = os.path.join(out_dir, "auth.log")
    with open(out, "wb") as f:
        f.write(r.stdout)
    return out
