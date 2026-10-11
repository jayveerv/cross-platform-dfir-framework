"""CP-DFIR Web Console - the framework as a local web application.

    python main.py web            (or double-click start_web.bat)

Opens http://127.0.0.1:8765 in the browser. From there the investigator can
  * drag & drop log files with ANY name (.evtx, .xml, auth logs, CloudTrail JSON, .zip, .gz, whole folders)
  * run a built-in attack scenario, analyse the INPUT folder, or triage this computer
  * watch the pipeline run stage by stage (acquire -> normalize -> correlate -> custody -> report)
  * see incidents, the attack kill chain, linked entities, MITRE techniques and all events
  * re-verify the chain of custody and run a tamper test on a copy of the case
  * open the full forensic HTML report, download the timeline CSV or the whole case as a .zip
Every past case in cases/ is listed and can be reopened.

The server listens on 127.0.0.1 only (this computer); nothing is sent to the Internet.
"""
import io
import json
import os
import re
import shutil
import socket
import sys
import tempfile
import threading
import time
import traceback
import uuid
import webbrowser
import zipfile
from datetime import datetime, timezone

ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)

from flask import Flask, abort, jsonify, request, send_file, send_from_directory  # noqa: E402

import config  # noqa: E402
import correlate  # noqa: E402
import intake  # noqa: E402
import pipeline  # noqa: E402
from custody import CustodyLedger, load_key, sha256_file  # noqa: E402

CASES = os.path.join(ROOT, "cases")
UPLOADS = os.path.join(ROOT, "uploads")
INBOX = os.path.join(ROOT, "INPUT")
WEB = os.path.join(ROOT, "web")
SCENARIOS = {
    "S1": "Full attack from one IP: RDP brute force on Windows -> SSH brute force on Linux -> stolen AWS key, CloudTrail stopped, S3 data theft",
    "S2": "Linux break-in, then AWS abuse from a DIFFERENT IP (linked only through the stolen credential file -> access key)",
    "S3": "Two unrelated attacks at the same time (Windows HR PC, and Linux db01 -> AWS) that must stay separate",
    "S4": "Normal activity only, no attack (false-positive check)",
    "S5": "Hard cases: attacker reuses a logged-in user's account, plus an insider from an internal IP",
}
STAGES = ["intake", "acquisition", "normalization", "correlation", "custody", "reporting", "done"]

app = Flask(__name__, static_folder=None)
app.config["MAX_CONTENT_LENGTH"] = 2 * 1024 ** 3
JOBS = {}
LOCK = threading.Lock()


# ------------------------------------------------------------------ helpers
def _safe_case(name):
    name = re.sub(r"[^A-Za-z0-9_.-]+", "-", (name or "").strip()).strip("-.")[:60]
    return name or "CASE-" + datetime.now().strftime("%Y%m%d-%H%M%S")


def _case_dir(name):
    if not re.fullmatch(r"[A-Za-z0-9_.-]+", name or "") or name.startswith("."):
        abort(404)
    d = os.path.join(CASES, name)
    if not os.path.isdir(d):
        abort(404)
    return d


def _job(jid, **kw):
    with LOCK:
        j = JOBS[jid]
        log = kw.pop("log", None)
        if log:
            j["log"].append(dict(t=time.strftime("%H:%M:%S"), msg=log))
        j.update(kw)


def _new_job(kind, case):
    jid = uuid.uuid4().hex[:12]
    with LOCK:
        JOBS[jid] = dict(id=jid, kind=kind, case=case, state="running", stage="intake", stages_done=[], log=[], files=[],
                         error=None, started=time.time(), finished=None)
    return jid


def _cfg_from_form(f, base=None):
    cfg = dict(config.DEFAULT_CASE)
    if base:
        cfg.update(base)
    if f.get("investigator"):
        cfg["investigator"] = f["investigator"].strip()[:80]
    if f.get("tz") and re.fullmatch(r"[+-]\d\d:\d\d", f["tz"].strip()):
        cfg["linux_timezone_offset"] = f["tz"].strip()
    if f.get("year") and str(f["year"]).isdigit():
        cfg["linux_log_year"] = int(f["year"])
    ranges = [r.strip() for r in re.split(r"[\s,]+", f.get("internal_ranges") or "") if r.strip()]
    if ranges:
        import ipaddress
        good = []
        for r in ranges:
            try:
                ipaddress.ip_network(r, strict=False)
                good.append(r)
            except ValueError:
                pass
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


def _run(jid, sources, case, form, prepare=None):
    """Background job: (optional collection) -> intake -> pipeline."""
    case_dir = os.path.join(CASES, case)
    staging = os.path.join(UPLOADS, jid, "_staged")
    try:
        if prepare:
            sources = prepare(jid) or sources
        _job(jid, stage="intake", log="Looking inside every file to recognise Windows / Linux / AWS evidence ...")
        files = intake.stage(sources, staging)
        s = intake.summary(files)
        for r in files:
            _job(jid, log=f"{'recognised' if r['used'] else 'ignored'}: {r['name']} -> {r['label']} ({r['reason']})")
        _job(jid, files=files, stages_done=["intake"],
             log=f"{s['used']} of {s['files']} files recognised: {', '.join(s['platforms']) or 'none'}")
        if not s["used"]:
            raise RuntimeError("None of the files looks like Windows, Linux or AWS evidence. "
                               "Supported: .evtx / Event Viewer XML, Linux auth.log or secure, CloudTrail JSON, .zip / .gz of these.")
        base = config.load_case_config(os.path.join(staging, "case_config.json")) \
            if os.path.exists(os.path.join(staging, "case_config.json")) else None
        cfg = _cfg_from_form(form, base)
        cfg["case_id"] = case

        def progress(stage, info):
            msg = {"acquisition": "Acquisition: copying evidence into the case folder, SHA-256 before and after copy",
                   "normalization": f"Normalization: parsing {info.get('files', 0)} evidence file(s) into one schema (UTC)",
                   "correlation": f"Correlation: {info.get('events', 0)} events through 57 MITRE ATT&CK rules + entity graph",
                   "custody": f"Chain of custody: {info.get('alerts', 0)} alerts, {info.get('incidents', 0)} incident(s); "
                              "writing outputs and re-verifying the hash chain",
                   "reporting": "Reporting: custody " + ("VERIFIED" if info.get("custody_ok") else "FAILED") +
                                ", writing the forensic HTML report",
                   "done": "Finished"}.get(stage, stage)
            with LOCK:
                j = JOBS[jid]
                if j["stage"] not in j["stages_done"]:
                    j["stages_done"].append(j["stage"])
            _job(jid, stage=stage, log=msg)
            time.sleep(0.25)          # lets the browser show each stage; the measured stage times are unaffected

        ctx = pipeline.run_case(staging, case_dir, cfg, key=load_key(), intake=files, progress=progress)
        _job(jid, state="done", stage="done", stages_done=STAGES, finished=time.time(),
             log=f"{len(ctx['events'])} events, {ctx['corr']['alert_events']} alerts, {len(ctx['corr']['incidents'])} incident(s), "
                 f"custody {'VERIFIED' if ctx['custody_ok'] else 'FAILED'}")
    except Exception as e:      # shown in the browser instead of a crash
        traceback.print_exc()
        _job(jid, state="error", error=str(e), finished=time.time(), log="ERROR: " + str(e))
    finally:
        shutil.rmtree(staging, ignore_errors=True)


def _start(kind, case, sources, form, prepare=None):
    jid = _new_job(kind, case)
    threading.Thread(target=_run, args=(jid, sources, case, form, prepare), daemon=True).start()
    return jid


# ------------------------------------------------------------------ case summary (read back from disk)
def _load(p, default=None):
    try:
        with open(p, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return default


def _ledger(case_dir):
    p = os.path.join(case_dir, "custody_ledger.jsonl")
    out = []
    if os.path.exists(p):
        with open(p, encoding="utf-8") as f:
            out = [json.loads(l) for l in f if l.strip()]
    return out


def case_brief(name):
    d = os.path.join(CASES, name)
    inc = _load(os.path.join(d, "incidents.json"), {}) or {}
    led = _ledger(d)
    sev = [i.get("severity") for i in inc.get("incidents", [])]
    plats = sorted({p for i in inc.get("incidents", []) for p in i.get("platforms", [])})
    return dict(name=name, created=led[0]["time_utc"][:19].replace("T", " ") + " UTC" if led else "",
                incidents=len(inc.get("incidents", [])), alerts=inc.get("alert_events", 0),
                severity="High" if "High" in sev else ("Medium" if sev else "None"), platforms=plats,
                report=os.path.exists(os.path.join(d, "report.html")),
                mtime=os.path.getmtime(os.path.join(d, "custody_ledger.jsonl")) if led else os.path.getmtime(d))


def case_detail(name):
    d = _case_dir(name)
    inc = _load(os.path.join(d, "incidents.json"), {}) or {}
    events = _load(os.path.join(d, "normalized_events.json"), []) or []
    led = _ledger(d)
    ok, checks = CustodyLedger(os.path.join(d, "custody_ledger.jsonl"), key=load_key()).verify() if led else (False, [])
    anchor = (open(os.path.join(d, "custody_head.txt")).read().strip()
              if os.path.exists(os.path.join(d, "custody_head.txt")) else None)
    per_source = {}
    for e in events:
        per_source[e["source"]] = per_source.get(e["source"], 0) + 1
    alerts = [e for e in events if e.get("flags")]
    by_id = {e["event_id"]: e for e in events}
    evidence = [dict(file=e["target_path"], sha256=e["sha256"], size=(e.get("details") or {}).get("size_bytes"),
                     source=(e.get("details") or {}).get("source"), verified=(e.get("details") or {}).get("copy_verified"))
                for e in led if e["action"] == "acquire"]
    rules = {k: dict(technique=v[0], name=v[1], severity=v[2], count=inc.get("rules_fired", {}).get(k, 0))
             for k, v in correlate.FLAGS.items() if inc.get("rules_fired", {}).get(k)}
    cfg = _load(os.path.join(d, "evidence", "case_config.json"))
    return dict(
        name=name, brief=case_brief(name), per_source=per_source, total_events=len(events), alert_events=len(alerts),
        incidents=inc.get("incidents", []), unlinked=[by_id[i] for i in inc.get("unlinked_alerts", []) if i in by_id][:200],
        rules=rules, techniques=sorted({t for e in alerts for t in e.get("techniques", [])}),
        intake=_load(os.path.join(d, "intake_manifest.json"), []) or [], evidence=evidence,
        custody=dict(ok=ok, checks=checks, entries=[{k: e.get(k) for k in ("seq", "time_utc", "actor", "stage", "action", "target",
                                                                            "sha256", "prev_hash", "entry_hash")} | {"hmac": bool(e.get("hmac"))}
                                                    for e in led], anchor=anchor, hmac=any(e.get("hmac") for e in led)),
        incident_events={i["id"]: [by_id[x] for x in i.get("event_ids", []) if x in by_id][:400] for i in inc.get("incidents", [])},
        config=cfg, report=os.path.exists(os.path.join(d, "report.html")))


# ------------------------------------------------------------------ routes: pages and files
@app.get("/")
def index():
    return send_from_directory(WEB, "console.html")


@app.get("/web/<path:f>")
def web_static(f):
    return send_from_directory(WEB, f)


@app.get("/dashboard")
def dashboard():
    p = os.path.join(ROOT, "results", "dashboard.html")
    if not os.path.exists(p):
        return ("The evaluation dashboard has not been built yet. Run option 2 (full evaluation) once, "
                "or click 'Run evaluation' in the console.", 404)
    return send_file(p)


@app.get("/cases/<name>/<path:f>")
def case_file(name, f):
    d = _case_dir(name)
    if f not in ("report.html", "timeline.csv", "incidents.json", "normalized_events.json", "custody_ledger.jsonl",
                 "custody_head.txt", "intake_manifest.json"):
        abort(404)
    return send_from_directory(d, f, as_attachment=f.endswith((".csv", ".jsonl", ".json")))


@app.get("/api/cases/<name>/download")
def case_zip(name):
    d = _case_dir(name)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for root, _dirs, files in os.walk(d):
            for fn in files:
                p = os.path.join(root, fn)
                z.write(p, os.path.join(name, os.path.relpath(p, d)))
    buf.seek(0)
    return send_file(buf, mimetype="application/zip", as_attachment=True, download_name=f"{name}.zip")


# ------------------------------------------------------------------ routes: API
@app.get("/api/info")
def info():
    inbox = sorted(f for f in os.listdir(INBOX) if not f.startswith(".") and f.lower() != "readme.txt") if os.path.isdir(INBOX) else []
    try:
        import ctypes
        admin = bool(ctypes.windll.shell32.IsUserAnAdmin()) if os.name == "nt" else os.geteuid() == 0
    except Exception:
        admin = False
    return jsonify(host=socket.gethostname(), os=sys.platform, admin=admin, scenarios=SCENARIOS, inbox=inbox,
                   inbox_path=INBOX, dashboard=os.path.exists(os.path.join(ROOT, "results", "dashboard.html")),
                   rules=len(correlate.FLAGS), techniques=len({v[0] for v in correlate.FLAGS.values()}),
                   hmac=bool(load_key()), investigator=config.DEFAULT_CASE["investigator"])


@app.get("/api/cases")
def cases():
    if not os.path.isdir(CASES):
        return jsonify([])
    out = [case_brief(n) for n in os.listdir(CASES)
           if os.path.isdir(os.path.join(CASES, n)) and os.path.exists(os.path.join(CASES, n, "incidents.json"))]
    return jsonify(sorted(out, key=lambda c: -c["mtime"]))


@app.get("/api/cases/<name>")
def case(name):
    return jsonify(case_detail(name))


@app.get("/api/cases/<name>/events")
def case_events(name):
    d = _case_dir(name)
    events = _load(os.path.join(d, "normalized_events.json"), []) or []
    q = (request.args.get("q") or "").lower().strip()
    src = request.args.get("source") or ""
    only = request.args.get("alerts") == "1"
    out = []
    for e in events:
        if src and e["source"] != src:
            continue
        if only and not e.get("flags"):
            continue
        if q and q not in " ".join(str(e.get(k) or "") for k in ("event_id", "time_utc", "host", "event_type", "user", "src_ip",
                                                                  "target", "detail", "raw", "key_id", "incident")).lower() \
                and q not in " ".join(e.get("flags") or []).lower() and q not in " ".join(e.get("techniques") or []).lower():
            continue
        out.append({k: e.get(k) for k in ("event_id", "time_utc", "source", "host", "event_type", "user", "src_ip", "target",
                                          "detail", "raw", "severity", "flags", "techniques", "incident", "source_file", "line_ref")})
    limit = min(int(request.args.get("limit") or 500), 5000)
    return jsonify(total=len(out), events=out[:limit])


@app.post("/api/cases/<name>/verify")
def verify(name):
    d = _case_dir(name)
    anchor = (request.get_json(silent=True) or {}).get("anchor") or None
    ok, checks = CustodyLedger(os.path.join(d, "custody_ledger.jsonl"), key=load_key()).verify(anchor=anchor)
    return jsonify(ok=ok, checks=checks, at=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"))


@app.post("/api/cases/<name>/tamper")
def tamper(name):
    """Tamper test on a COPY of the case: the real case is never touched."""
    d = _case_dir(name)
    what = (request.get_json(silent=True) or {}).get("what", "evidence")
    tmp = tempfile.mkdtemp(prefix="dfir_tamper_")
    try:
        c = os.path.join(tmp, name)
        shutil.copytree(d, c)
        led_path = os.path.join(c, "custody_ledger.jsonl")
        before_ok, _ = CustodyLedger(led_path, key=load_key()).verify()
        if what == "ledger":
            lines = open(led_path, encoding="utf-8").read().splitlines()
            e = json.loads(lines[1] if len(lines) > 1 else lines[0])
            old = e.get("actor")
            e["actor"] = "attacker@evil"
            lines[1 if len(lines) > 1 else 0] = json.dumps(e)
            open(led_path, "w", encoding="utf-8").write("\n".join(lines) + "\n")
            action = f"Ledger entry {e['seq']}: actor changed from '{old}' to 'attacker@evil'"
        elif what == "delete":
            lines = open(led_path, encoding="utf-8").read().splitlines()
            gone = json.loads(lines[1])
            del lines[1]
            open(led_path, "w", encoding="utf-8").write("\n".join(lines) + "\n")
            action = f"Ledger entry {gone['seq']} ({gone['action']} {gone['target']}) deleted"
        else:
            ev = os.path.join(c, "evidence")
            files = sorted(f for f in os.listdir(ev) if os.path.isfile(os.path.join(ev, f)) and f != "case_config.json")
            if not files:
                return jsonify(error="no evidence file to alter"), 400
            p = os.path.join(ev, files[0])
            data = bytearray(open(p, "rb").read())
            i = len(data) // 2
            old_b = data[i]
            data[i] = (old_b + 1) % 256
            open(p, "wb").write(bytes(data))
            action = f"evidence/{files[0]}: one byte at offset {i} changed (0x{old_b:02x} -> 0x{data[i]:02x})"
        after_ok, checks = CustodyLedger(led_path, key=load_key()).verify()
        real_ok, _ = CustodyLedger(os.path.join(d, "custody_ledger.jsonl"), key=load_key()).verify()
        return jsonify(action=action, before_ok=before_ok, after_ok=after_ok, detected=before_ok and not after_ok,
                       failed=[c for c in checks if not c["ok"]], original_still_ok=real_ok)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


@app.post("/api/analyze")
def analyze():
    files = request.files.getlist("files")
    if not files:
        return jsonify(error="No files received"), 400
    case = _safe_case(request.form.get("case_name"))
    jid_dir = os.path.join(UPLOADS, uuid.uuid4().hex[:12])
    os.makedirs(jid_dir, exist_ok=True)
    rels = request.form.getlist("paths")
    sources = []
    for n, fs in enumerate(files):
        rel = rels[n] if n < len(rels) and rels[n] else (fs.filename or f"file{n}")
        parts = [re.sub(r"[^A-Za-z0-9_.() -]", "_", p) for p in re.split(r"[\\/]+", rel) if p not in ("", ".", "..")]
        if not parts:
            parts = [f"file{n}"]
        dest = os.path.join(jid_dir, "files", *parts)
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        fs.save(dest)
    top = os.path.join(jid_dir, "files")
    for entry in sorted(os.listdir(top)):
        sources.append((os.path.join(top, entry), entry))
    return jsonify(job=_start("upload", case, sources, request.form.to_dict()), case=case)


@app.post("/api/sample")
def sample():
    import generate_data
    body = request.get_json(silent=True) or {}
    sc = body.get("scenario", "S1")
    if sc not in SCENARIOS:
        return jsonify(error="unknown scenario"), 400
    case = _safe_case(body.get("case_name") or f"SAMPLE-{sc}")
    src = os.path.join(ROOT, "sample_logs", sc)
    generate_data.build(sc, src)
    sources = [(os.path.join(src, f), f) for f in sorted(os.listdir(src))]
    return jsonify(job=_start("sample", case, sources, body), case=case)


@app.post("/api/inbox")
def inbox():
    if not os.path.isdir(INBOX) or not [f for f in os.listdir(INBOX) if f.lower() != "readme.txt" and not f.startswith(".")]:
        return jsonify(error=f"The INPUT folder is empty. Put log files into {INBOX} and try again."), 400
    body = request.get_json(silent=True) or {}
    case = _safe_case(body.get("case_name") or "INPUT-" + datetime.now().strftime("%Y%m%d-%H%M%S"))
    sources = [(os.path.join(INBOX, f), f) for f in sorted(os.listdir(INBOX)) if f.lower() != "readme.txt" and not f.startswith(".")]
    return jsonify(job=_start("inbox", case, sources, body), case=case)


@app.post("/api/triage")
def triage():
    body = request.get_json(silent=True) or {}
    host = re.sub(r"[^A-Za-z0-9_-]", "_", socket.gethostname()) or "host"
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    case = _safe_case(body.get("case_name") or f"TRIAGE-{host}-{stamp}")
    out = os.path.join(ROOT, "live_triage", f"{host}_{stamp}")

    def prepare(jid):
        import hostcollect
        from hostcollect import _local_offset
        _job(jid, stage="intake", log=f"Collecting live evidence from this computer ({host}): processes, network connections, "
                                      "accounts, persistence, recent files, logs ... (can take a minute)")
        os.makedirs(out, exist_ok=True)
        man = hostcollect.collect_host(out, days=int(body.get("days") or 7),
                                       log=lambda m: _job(jid, log="collector:" + str(m).rstrip()))
        _job(jid, log=f"{len(man.get('artifacts', []))} artefacts collected in {man.get('duration_s')} s")
        for v in man.get("limited", {}).values():
            _job(jid, log="LIMIT: " + str(v))
        body.setdefault("tz", _local_offset())
        body.setdefault("year", str(datetime.now().year))
        return [(os.path.join(out, f), f) for f in sorted(os.listdir(out))]

    return jsonify(job=_start("triage", case, [], body, prepare=prepare), case=case)


@app.post("/api/evaluate")
def evaluate_run():
    def work(jid):
        try:
            import evaluate
            import make_dashboard
            _job(jid, stage="correlation", log="Running the full evaluation (S1-S5, tamper tests, cloud checks, scalability up to 100,000 records) - about 1-2 minutes ...")
            buf = io.StringIO()
            old = sys.stdout
            sys.stdout = buf
            try:
                evaluate.run_all(ROOT, quick=False)
            finally:
                sys.stdout = old
            for line in buf.getvalue().splitlines():
                if line.strip():
                    _job(jid, log=line.rstrip())
            make_dashboard.build(ROOT)
            _job(jid, state="done", stage="done", stages_done=STAGES, finished=time.time(), log="Dashboard rebuilt")
        except Exception as e:
            traceback.print_exc()
            _job(jid, state="error", error=str(e), finished=time.time(), log="ERROR: " + str(e))
    jid = _new_job("evaluate", None)
    threading.Thread(target=work, args=(jid,), daemon=True).start()
    return jsonify(job=jid)


@app.get("/api/jobs/<jid>")
def job(jid):
    with LOCK:
        j = JOBS.get(jid)
        if not j:
            abort(404)
        return jsonify(dict(j, elapsed=round((j["finished"] or time.time()) - j["started"], 1)))


def _free_port(port):
    for p in range(port, port + 20):
        with socket.socket() as s:
            try:
                s.bind(("127.0.0.1", p))
                return p
            except OSError:
                continue
    return port


def serve(port=8765, open_browser=True):
    os.makedirs(CASES, exist_ok=True)
    os.makedirs(INBOX, exist_ok=True)
    port = _free_port(port)
    url = f"http://127.0.0.1:{port}/"
    print("=" * 62)
    print("  CP-DFIR Web Console is running")
    print(f"  Open in the browser:  {url}")
    print("  Keep this window open while you use the console. Close it (or Ctrl+C) to stop.")
    print("=" * 62)
    if open_browser:
        threading.Timer(1.2, lambda: webbrowser.open(url)).start()
    import logging
    logging.getLogger("werkzeug").setLevel(logging.WARNING)
    app.run(host="127.0.0.1", port=port, debug=False, threaded=True)


if __name__ == "__main__":
    serve()
