"""Chain-of-Custody layer.

Every action on evidence (acquire, normalize, correlate, report) is written to an
append-only ledger. Each entry stores the SHA-256 of the file it touched and the
hash of the previous entry, so changing a file, editing an entry or deleting an
entry breaks the chain and is detected by verify().
"""
import getpass
import hashlib
import hmac
import json
import os
import platform
from datetime import datetime, timezone

GENESIS = "0" * 64


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def load_key(key=None, key_file=None):
    """HMAC key from an argument, a key file, or the DFIR_CUSTODY_KEY environment variable (None = plain hash chain)."""
    if key_file:
        with open(key_file, "rb") as f:
            key = f.read().strip()
    key = key or os.environ.get("DFIR_CUSTODY_KEY")
    if isinstance(key, str):
        key = key.encode("utf-8")
    return key or None


def _mac(key, entry_hash):
    return hmac.new(key, entry_hash.encode("ascii"), hashlib.sha256).hexdigest()


def _entry_hash(entry):
    body = {k: v for k, v in entry.items() if k not in ("entry_hash", "hmac")}
    return hashlib.sha256(json.dumps(body, sort_keys=True).encode()).hexdigest()


class CustodyLedger:
    def __init__(self, path, actor=None, key=None):
        self.path = path
        self.key = load_key(key)
        try:
            user = getpass.getuser()
        except Exception:
            user = "investigator"
        self.actor = actor or f"{user}@{platform.node() or 'host'}"
        self.entries = []
        if os.path.exists(path):
            with open(path, encoding="utf-8") as f:
                self.entries = [json.loads(l) for l in f if l.strip()]

    def record(self, action, target, details=None, stage=None):
        """Record an action on a file (target is a path)."""
        entry = {
            "seq": len(self.entries) + 1,
            "time_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
            "actor": self.actor,
            "stage": stage or action,
            "action": action,
            "target": os.path.basename(target),
            "target_path": os.path.relpath(target, os.path.dirname(self.path)).replace("\\", "/"),
            "sha256": sha256_file(target),
            "details": details or {},
            "prev_hash": self.entries[-1]["entry_hash"] if self.entries else GENESIS,
        }
        entry["entry_hash"] = _entry_hash(entry)
        if self.key:
            entry["hmac"] = _mac(self.key, entry["entry_hash"])   # cannot be recomputed by someone who only has the files
        self.entries.append(entry)
        with open(self.path, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")
        return entry

    def verify(self, anchor=None, key=None):
        """Re-check the whole chain and the current hash of every recorded file.

        anchor: optional head hash noted down earlier; detects entries removed from the end.
        key: HMAC key (defaults to the ledger's own key / DFIR_CUSTODY_KEY); makes a rewritten chain detectable.
        Returns (ok, checks) where checks is a list of dicts for the report.
        """
        checks = []
        entries = []
        with open(self.path, encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    entries.append(json.loads(line))
        key = load_key(key) or self.key
        chain_ok = True
        prev = GENESIS
        for i, e in enumerate(entries):
            problems = []
            if e.get("seq") != i + 1:
                problems.append(f"sequence gap (expected {i + 1}, found {e.get('seq')})")
            if e.get("prev_hash") != prev:
                problems.append("link to previous entry broken")
            if _entry_hash(e) != e.get("entry_hash"):
                problems.append("entry content altered")
            if key:
                if not e.get("hmac"):
                    problems.append("HMAC missing")
                elif not hmac.compare_digest(e["hmac"], _mac(key, e.get("entry_hash", ""))):
                    problems.append("HMAC invalid (entry not written by the key holder)")
            if problems:
                chain_ok = False
            checks.append({"type": "ledger", "item": f"entry {e.get('seq')} ({e.get('action')} {e.get('target')})",
                           "ok": not problems, "note": "; ".join(problems) or "intact"})
            prev = e.get("entry_hash")
        if not key and entries and any(x.get("hmac") for x in entries):
            checks.append({"type": "hmac", "item": "HMAC signatures", "ok": True,
                           "note": "present but NOT verified (no key supplied): a rewritten chain would not be detected"})
        if anchor:
            head_ok = bool(entries) and entries[-1].get("entry_hash") == anchor
            chain_ok &= head_ok
            checks.append({"type": "anchor", "item": "ledger head vs noted anchor hash", "ok": head_ok,
                           "note": "matches" if head_ok else "differs (entries removed, added or altered after the anchor was noted)"})
        # latest recorded hash of each file must match the file on disk now
        latest = {}
        for e in entries:
            latest[e["target_path"]] = e
        base = os.path.dirname(self.path)
        files_ok = True
        for rel, e in sorted(latest.items()):
            p = os.path.join(base, rel)
            if not os.path.exists(p):
                ok, note = False, "file missing"
            else:
                now = sha256_file(p)
                ok = now == e["sha256"]
                note = "hash matches ledger" if ok else f"hash changed ({e['sha256'][:12]}... -> {now[:12]}...)"
            files_ok &= ok
            checks.append({"type": "file", "item": rel, "ok": ok, "note": note})
        return chain_ok and files_ok, checks
