"""CP-DFIR Web Console - the framework as a local web application.

    python main.py web            (or double-click start_web.bat)

Opens http://127.0.0.1:8765 in the browser. From there the investigator can
  * drag & drop log files with ANY name (.evtx, .xml, auth logs, CloudTrail JSON, .zip, .gz, whole folders)
  * run a built-in attack scenario, analyse the INPUT folder, or triage this computer
  * watch the pipeline run stage by stage (intake -> acquire -> normalize -> correlate -> custody -> report)
  * see incidents, the attack kill chain, linked entities, MITRE techniques and all events
  * re-verify the chain of custody and run a tamper test on a copy of the case
  * open the full forensic HTML report, download the timeline CSV or the whole case as a .zip
Every past case in cases/ is listed and can be reopened.

The same console also runs without any server on GitHub Pages (docs/), where the framework's Python code runs
inside the browser (Pyodide). Both use casestore.py.

The server listens on 127.0.0.1 only (this computer); nothing is sent to the Internet.
"""
import io
import os
import re
import socket
import sys
import threading
import time
import traceback
import uuid
import webbrowser
from datetime import datetime, timezone

ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)

from flask import Flask, abort, jsonify, request, send_file, send_from_directory  # noqa: E402

import casestore  # noqa: E402
import config  # noqa: E402
import correlate  # noqa: E402
from casestore import SCENARIOS, STAGES  # noqa: E402,F401
from custody import load_key  # noqa: E402

CASES = os.path.join(ROOT, "cases")
UPLOADS = os.path.join(ROOT, "uploads")
INBOX = os.path.join(ROOT, "INPUT")
WEB = os.path.join(ROOT, "web")

app = Flask(__name__, static_folder=None)
app.config["MAX_CONTENT_LENGTH"] = 2 * 1024 ** 3
JOBS = {}
LOCK = threading.Lock()


def _case_dir(name):
    try:
        return casestore.case_dir(CASES, name)
    except casestore.NotFound:
        abort(404)


# ------------------------------------------------------------------ background jobs
def _job(jid, **kw):
    with LOCK:
        j = JOBS[jid]
        log = kw.pop("log", None)
        if log:
            j["log"].append(dict(t=time.strftime("%H:%M:%S"), msg=log))
        st = kw.get("stage")
        if st and st != j["stage"] and j["stage"] not in j["stages_done"]:
            j["stages_done"].append(j["stage"])
        j.update(kw)


def _new_job(kind, case):
    jid = uuid.uuid4().hex[:12]
    with LOCK:
        JOBS[jid] = dict(id=jid, kind=kind, case=case, state="running", stage="intake", stages_done=[], log=[], files=[],
                         error=None, started=time.time(), finished=None)
    return jid


def _run(jid, sources, case, form, prepare=None):
    try:
        if prepare:
            sources = prepare(jid) or sources

        def stage(s):
            _job(jid, stage=s)
            if s not in ("intake", "done"):
                time.sleep(0.25)       # lets the browser show each stage; the measured stage times are unaffected

        files, ctx = casestore.analyse(sources, os.path.join(UPLOADS, jid, "_staged"), CASES, case, form, key=load_key(),
                                       log=lambda m: _job(jid, log=m), stage=stage,
                                       on_files=lambda f: _job(jid, files=f))
        _job(jid, files=files, state="done", stage="done", stages_done=list(STAGES), finished=time.time())
    except Exception as e:      # shown in the browser instead of a crash
        traceback.print_exc()
        _job(jid, state="error", error=str(e), finished=time.time(), log="ERROR: " + str(e))


def _start(kind, case, sources, form, prepare=None):
    jid = _new_job(kind, case)
    threading.Thread(target=_run, args=(jid, sources, case, form, prepare), daemon=True).start()
    return jid


# ------------------------------------------------------------------ pages and files
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
    if f not in casestore.CASE_FILES:
        abort(404)
    return send_from_directory(d, f, as_attachment=f.endswith((".csv", ".jsonl", ".json")))


@app.get("/api/cases/<name>/download")
def case_zip(name):
    _case_dir(name)
    return send_file(io.BytesIO(casestore.case_zip(CASES, name)), mimetype="application/zip", as_attachment=True,
                     download_name=f"{name}.zip")


# ------------------------------------------------------------------ API
@app.get("/api/info")
def info():
    inbox = sorted(f for f in os.listdir(INBOX) if not f.startswith(".") and f.lower() != "readme.txt") if os.path.isdir(INBOX) else []
    try:
        import ctypes
        admin = bool(ctypes.windll.shell32.IsUserAnAdmin()) if os.name == "nt" else os.geteuid() == 0
    except Exception:
        admin = False
    return jsonify(mode="local", host=socket.gethostname(), os=sys.platform, admin=admin, scenarios=SCENARIOS, inbox=inbox,
                   inbox_path=INBOX, dashboard=os.path.exists(os.path.join(ROOT, "results", "dashboard.html")),
                   rules=len(correlate.FLAGS), techniques=len({v[0] for v in correlate.FLAGS.values()}),
                   hmac=bool(load_key()), investigator=config.DEFAULT_CASE["investigator"])


@app.get("/api/cases")
def cases():
    return jsonify(casestore.list_cases(CASES))


@app.get("/api/cases/<name>")
def case(name):
    _case_dir(name)
    return jsonify(casestore.case_detail(CASES, name))


@app.get("/api/cases/<name>/events")
def case_events(name):
    _case_dir(name)
    return jsonify(casestore.case_events(CASES, name, request.args.get("q"), request.args.get("source"),
                                         request.args.get("alerts") == "1", request.args.get("limit") or 500))


@app.post("/api/cases/<name>/verify")
def verify(name):
    _case_dir(name)
    return jsonify(casestore.verify(CASES, name, (request.get_json(silent=True) or {}).get("anchor")))


@app.post("/api/cases/<name>/tamper")
def tamper(name):
    _case_dir(name)
    try:
        return jsonify(casestore.tamper(CASES, name, (request.get_json(silent=True) or {}).get("what", "evidence")))
    except ValueError as e:
        return jsonify(error=str(e)), 400


@app.post("/api/analyze")
def analyze():
    files = request.files.getlist("files")
    if not files:
        return jsonify(error="No files received"), 400
    case = casestore.safe_case(request.form.get("case_name"))
    top = os.path.join(UPLOADS, uuid.uuid4().hex[:12], "files")
    rels = request.form.getlist("paths")
    for n, fs in enumerate(files):
        rel = rels[n] if n < len(rels) and rels[n] else (fs.filename or f"file{n}")
        parts = [re.sub(r"[^A-Za-z0-9_.() -]", "_", p) for p in re.split(r"[\\/]+", rel) if p not in ("", ".", "..")] or [f"file{n}"]
        dest = os.path.join(top, *parts)
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        fs.save(dest)
    sources = [(os.path.join(top, e), e) for e in sorted(os.listdir(top))]
    return jsonify(job=_start("upload", case, sources, request.form.to_dict()), case=case)


@app.post("/api/sample")
def sample():
    import generate_data
    body = request.get_json(silent=True) or {}
    sc = body.get("scenario", "S1")
    if sc not in SCENARIOS:
        return jsonify(error="unknown scenario"), 400
    case = casestore.safe_case(body.get("case_name") or f"SAMPLE-{sc}")
    src = os.path.join(ROOT, "sample_logs", sc)
    generate_data.build(sc, src)
    return jsonify(job=_start("sample", case, [(os.path.join(src, f), f) for f in sorted(os.listdir(src))], body), case=case)


@app.post("/api/inbox")
def inbox():
    names = [f for f in os.listdir(INBOX) if f.lower() != "readme.txt" and not f.startswith(".")] if os.path.isdir(INBOX) else []
    if not names:
        return jsonify(error=f"The INPUT folder is empty. Put log files into {INBOX} and try again."), 400
    body = request.get_json(silent=True) or {}
    case = casestore.safe_case(body.get("case_name") or "INPUT-" + datetime.now().strftime("%Y%m%d-%H%M%S"))
    return jsonify(job=_start("inbox", case, [(os.path.join(INBOX, f), f) for f in sorted(names)], body), case=case)


@app.post("/api/triage")
def triage():
    body = request.get_json(silent=True) or {}
    host = re.sub(r"[^A-Za-z0-9_-]", "_", socket.gethostname()) or "host"
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    case = casestore.safe_case(body.get("case_name") or f"TRIAGE-{host}-{stamp}")
    out = os.path.join(ROOT, "live_triage", f"{host}_{stamp}")

    def prepare(jid):
        import hostcollect
        from hostcollect import _local_offset
        _job(jid, log=f"Collecting live evidence from this computer ({host}): processes, network connections, "
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
            _job(jid, stage="correlation", log="Running the full evaluation (S1-S5, tamper tests, cloud checks, "
                                               "scalability up to 100,000 records) - about 1-2 minutes ...")
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
            _job(jid, state="done", stage="done", stages_done=list(STAGES), finished=time.time(), log="Dashboard rebuilt")
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
