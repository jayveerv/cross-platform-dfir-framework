"""Case operations shared by the web console (webapp.py, Flask) and the in-browser console (docs/, Pyodide).

Everything here is plain Python on top of the framework (intake -> pipeline -> custody); no web framework.
"""
import io
import ipaddress
import json
import os
import re
import shutil
import tempfile
import zipfile
from datetime import datetime, timezone

import config
import correlate
import intake
import pipeline
from custody import CustodyLedger, load_key

STAGES = ["intake", "acquisition", "normalization", "correlation", "custody", "reporting", "done"]
SCENARIOS = {
    "S1": "Full attack from one IP: RDP brute force on Windows -> SSH brute force on Linux -> stolen AWS key, CloudTrail stopped, S3 data theft",
    "S2": "Linux break-in, then AWS abuse from a DIFFERENT IP (linked only through the stolen credential file -> access key)",
    "S3": "Two unrelated attacks at the same time (Windows HR PC, and Linux db01 -> AWS) that must stay separate",
    "S4": "Normal activity only, no attack (false-positive check)",
    "S5": "Hard cases: attacker reuses a logged-in user's account, plus an insider from an internal IP",
}
CASE_FILES = ("report.html", "timeline.csv", "incidents.json", "normalized_events.json", "custody_ledger.jsonl",
              "custody_head.txt", "intake_manifest.json")


class NotFound(Exception):
    pass


def safe_case(name):
    name = re.sub(r"[^A-Za-z0-9_.-]+", "-", (name or "").strip()).strip("-.")[:60]
    return name or "CASE-" + datetime.now().strftime("%Y%m%d-%H%M%S")


def case_dir(cases, name):
    if not re.fullmatch(r"[A-Za-z0-9_.-]+", name or "") or name.startswith("."):
        raise NotFound(name)
    d = os.path.join(cases, name)
    if not os.path.isdir(d):
        raise NotFound(name)
    return d


def stage_message(stage, info):
    return {"acquisition": "Acquisition: copying evidence into the case folder, SHA-256 before and after copy",
            "normalization": f"Normalization: parsing {info.get('files', 0)} evidence file(s) into one schema (UTC)",
            "correlation": f"Correlation: {info.get('events', 0)} events through {len(correlate.FLAGS)} MITRE ATT&CK rules + entity graph",
            "custody": f"Chain of custody: {info.get('alerts', 0)} alerts, {info.get('incidents', 0)} incident(s); "
                       "writing outputs and re-verifying the hash chain",
            "reporting": "Reporting: custody " + ("VERIFIED" if info.get("custody_ok") else "FAILED") +
                         ", writing the forensic HTML report",
            "done": "Finished"}.get(stage, stage)


def cfg_from_form(f, base=None):
    cfg = dict(config.DEFAULT_CASE)
    if base:
        cfg.update(base)
    f = f or {}
    if f.get("investigator"):
        cfg["investigator"] = str(f["investigator"]).strip()[:80]
    if f.get("tz") and re.fullmatch(r"[+-]\d\d:\d\d", str(f["tz"]).strip()):
        cfg["linux_timezone_offset"] = str(f["tz"]).strip()
    if f.get("year") and str(f["year"]).isdigit():
        cfg["linux_log_year"] = int(f["year"])
    good = []
    for r in re.split(r"[\s,]+", f.get("internal_ranges") or ""):
        try:
            if r.strip():
                ipaddress.ip_network(r.strip(), strict=False)
                good.append(r.strip())
        except ValueError:
            pass
    if good:
        cfg["internal_ranges"] = sorted(set(cfg.get("internal_ranges", []) + good))
    inv = {}
    for line in (f.get("credentials") or "").splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            if k.strip() and v.strip():
                inv[k.strip()] = v.strip()
    if inv:
        cfg["credential_inventory"] = dict(cfg.get("credential_inventory", {}), **inv)
    return cfg


def analyse(sources, staging, cases, case, form=None, key=None, log=print, stage=lambda s: None, on_files=lambda f: None):
    """intake -> pipeline for one case. log(msg) gets human-readable progress, stage(name) the current stage."""
    try:
        stage("intake")
        log("Looking inside every file to recognise Windows / Linux / AWS evidence ...")
        files = intake.stage(sources, staging)
        s = intake.summary(files)
        for r in files:
            log(f"{'recognised' if r['used'] else 'ignored'}: {r['name']} -> {r['label']} ({r['reason']})")
        log(f"{s['used']} of {s['files']} files recognised: {', '.join(s['platforms']) or 'none'}")
        on_files(files)
        if not s["used"]:
            raise RuntimeError("None of the files looks like Windows, Linux or AWS evidence. Supported: .evtx / Event Viewer XML, "
                               "Linux auth.log or secure, CloudTrail JSON, .zip / .gz of these.")
        p_cfg = os.path.join(staging, "case_config.json")
        cfg = cfg_from_form(form, config.load_case_config(p_cfg) if os.path.exists(p_cfg) else None)
        cfg["case_id"] = case

        def progress(st, info):
            stage(st)
            log(stage_message(st, info))

        ctx = pipeline.run_case(staging, os.path.join(cases, case), cfg, key=key if key is not None else load_key(),
                                intake=files, progress=progress)
        log(f"{len(ctx['events'])} events, {ctx['corr']['alert_events']} alerts, {len(ctx['corr']['incidents'])} incident(s), "
            f"custody {'VERIFIED' if ctx['custody_ok'] else 'FAILED'}")
        return files, ctx
    finally:
        shutil.rmtree(staging, ignore_errors=True)


# ------------------------------------------------------------------ reading cases back from disk
def _load(p, default=None):
    try:
        with open(p, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return default


def _ledger(d):
    p = os.path.join(d, "custody_ledger.jsonl")
    if not os.path.exists(p):
        return []
    with open(p, encoding="utf-8") as f:
        return [json.loads(l) for l in f if l.strip()]


def case_brief(cases, name):
    d = os.path.join(cases, name)
    inc = _load(os.path.join(d, "incidents.json"), {}) or {}
    led = _ledger(d)
    sev = [i.get("severity") for i in inc.get("incidents", [])]
    return dict(name=name, created=led[0]["time_utc"][:19].replace("T", " ") + " UTC" if led else "",
                incidents=len(inc.get("incidents", [])), alerts=inc.get("alert_events", 0),
                severity="High" if "High" in sev else ("Medium" if sev else "None"),
                platforms=sorted({p for i in inc.get("incidents", []) for p in i.get("platforms", [])}),
                report=os.path.exists(os.path.join(d, "report.html")),
                mtime=os.path.getmtime(os.path.join(d, "custody_ledger.jsonl")) if led else os.path.getmtime(d))


def list_cases(cases):
    if not os.path.isdir(cases):
        return []
    out = [case_brief(cases, n) for n in os.listdir(cases)
           if os.path.isdir(os.path.join(cases, n)) and os.path.exists(os.path.join(cases, n, "incidents.json"))]
    return sorted(out, key=lambda c: -c["mtime"])


def case_detail(cases, name):
    d = case_dir(cases, name)
    inc = _load(os.path.join(d, "incidents.json"), {}) or {}
    events = _load(os.path.join(d, "normalized_events.json"), []) or []
    led = _ledger(d)
    ok, checks = CustodyLedger(os.path.join(d, "custody_ledger.jsonl"), key=load_key()).verify() if led else (False, [])
    p_head = os.path.join(d, "custody_head.txt")
    anchor = open(p_head).read().strip() if os.path.exists(p_head) else None
    per_source = {}
    for e in events:
        per_source[e["source"]] = per_source.get(e["source"], 0) + 1
    alerts = [e for e in events if e.get("flags")]
    by_id = {e["event_id"]: e for e in events}
    fired = inc.get("rules_fired", {})
    return dict(
        name=name, brief=case_brief(cases, name), per_source=per_source, total_events=len(events), alert_events=len(alerts),
        incidents=inc.get("incidents", []), unlinked=[by_id[i] for i in inc.get("unlinked_alerts", []) if i in by_id][:200],
        rules={k: dict(technique=v[0], name=v[1], severity=v[2], count=fired.get(k, 0)) for k, v in correlate.FLAGS.items() if fired.get(k)},
        techniques=sorted({t for e in alerts for t in e.get("techniques", [])}),
        intake=_load(os.path.join(d, "intake_manifest.json"), []) or [],
        evidence=[dict(file=e["target_path"], sha256=e["sha256"], size=(e.get("details") or {}).get("size_bytes"),
                       source=(e.get("details") or {}).get("source"), verified=(e.get("details") or {}).get("copy_verified"))
                  for e in led if e["action"] == "acquire"],
        custody=dict(ok=ok, checks=checks, anchor=anchor, hmac=any(e.get("hmac") for e in led),
                     entries=[dict({k: e.get(k) for k in ("seq", "time_utc", "actor", "stage", "action", "target", "sha256",
                                                           "prev_hash", "entry_hash")}, hmac=bool(e.get("hmac"))) for e in led]),
        incident_events={i["id"]: [by_id[x] for x in i.get("event_ids", []) if x in by_id][:400] for i in inc.get("incidents", [])},
        config=_load(os.path.join(d, "evidence", "case_config.json")), report=os.path.exists(os.path.join(d, "report.html")))


def case_events(cases, name, q="", source="", alerts_only=False, limit=500):
    d = case_dir(cases, name)
    q = (q or "").lower().strip()
    out = []
    for e in _load(os.path.join(d, "normalized_events.json"), []) or []:
        if source and e["source"] != source:
            continue
        if alerts_only and not e.get("flags"):
            continue
        if q:
            hay = " ".join(str(e.get(k) or "") for k in ("event_id", "time_utc", "host", "event_type", "user", "src_ip", "target",
                                                         "detail", "raw", "key_id", "incident"))
            hay += " " + " ".join(e.get("flags") or []) + " " + " ".join(e.get("techniques") or [])
            if q not in hay.lower():
                continue
        out.append({k: e.get(k) for k in ("event_id", "time_utc", "source", "host", "event_type", "user", "src_ip", "target",
                                          "detail", "raw", "severity", "flags", "techniques", "incident", "source_file", "line_ref")})
    limit = max(1, min(int(limit or 500), 5000))
    return dict(total=len(out), events=out[:limit])


def verify(cases, name, anchor=None):
    d = case_dir(cases, name)
    ok, checks = CustodyLedger(os.path.join(d, "custody_ledger.jsonl"), key=load_key()).verify(anchor=anchor or None)
    return dict(ok=ok, checks=checks, at=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"))


def tamper(cases, name, what="evidence"):
    """Tamper test on a COPY of the case: the real case is never touched."""
    d = case_dir(cases, name)
    tmp = tempfile.mkdtemp(prefix="dfir_tamper_")
    try:
        c = os.path.join(tmp, name)
        shutil.copytree(d, c)
        led_path = os.path.join(c, "custody_ledger.jsonl")
        before_ok, _ = CustodyLedger(led_path, key=load_key()).verify()
        lines = open(led_path, encoding="utf-8").read().splitlines()
        if what == "ledger":
            i = 1 if len(lines) > 1 else 0
            e = json.loads(lines[i])
            old = e.get("actor")
            e["actor"] = "attacker@evil"
            lines[i] = json.dumps(e)
            open(led_path, "w", encoding="utf-8").write("\n".join(lines) + "\n")
            action = f"Ledger entry {e['seq']}: actor changed from '{old}' to 'attacker@evil'"
        elif what == "delete" and len(lines) > 1:
            gone = json.loads(lines[1])
            del lines[1]
            open(led_path, "w", encoding="utf-8").write("\n".join(lines) + "\n")
            action = f"Ledger entry {gone['seq']} ({gone['action']} {gone['target']}) deleted"
        else:
            ev = os.path.join(c, "evidence")
            files = sorted(f for f in os.listdir(ev) if os.path.isfile(os.path.join(ev, f)) and f != "case_config.json")
            if not files:
                raise ValueError("no evidence file to alter")
            p = os.path.join(ev, files[0])
            data = bytearray(open(p, "rb").read())
            i = len(data) // 2
            old_b = data[i]
            data[i] = (old_b + 1) % 256
            open(p, "wb").write(bytes(data))
            action = f"evidence/{files[0]}: one byte at offset {i} changed (0x{old_b:02x} -> 0x{data[i]:02x})"
        after_ok, checks = CustodyLedger(led_path, key=load_key()).verify()
        real_ok, _ = CustodyLedger(os.path.join(d, "custody_ledger.jsonl"), key=load_key()).verify()
        return dict(action=action, before_ok=before_ok, after_ok=after_ok, detected=before_ok and not after_ok,
                    failed=[k for k in checks if not k["ok"]], original_still_ok=real_ok)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def case_zip(cases, name):
    d = case_dir(cases, name)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for root, _dirs, files in os.walk(d):
            for fn in files:
                p = os.path.join(root, fn)
                z.write(p, os.path.join(name, os.path.relpath(p, d)))
    return buf.getvalue()
