"""Cross-Platform DFIR Framework - command line entry point.

  python main.py demo                      simulated attack (Windows + Linux + AWS), report opens in the browser
  python main.py evaluate [--quick]        all simulated scenarios, tampering tests, cloud checks, scalability -> results/
  python main.py real-eval                 validation on REAL public data (downloads ~44 MB the first time) -> results/
  python main.py tamper-demo               show tampering being detected (for the viva)
  python main.py web                       WEB CONSOLE: upload logs with any name in the browser, live analysis, cases
  python main.py inbox [--input DIR]       analyse every file put into the INPUT folder (any file names, .zip/.gz ok)
  python main.py analyze --input DIR       analyse your own evidence (windows_security.xml or *.evtx, auth.log, cloudtrail.json,
                                           host/ and cloud/ folders, optional case_config.json)
  python main.py triage                    collect live evidence from THIS computer, analyse it and open the report
  python main.py collect-host --out DIR    only collect live host evidence (no analysis)
  python main.py collect-live --out DIR    export this Windows computer's Security log (run as Administrator)
  python main.py collect-aws --out DIR     pull CloudTrail events and the account state from AWS (needs AWS credentials)
  python main.py collect-linux --out DIR   copy a Linux auth log, locally or over SSH (--host)
  python main.py verify --case DIR         re-verify the chain of custody of a finished case
  python main.py selftest                  run the unit tests
"""
import argparse
import os
import shutil
import socket
import sys
import time
import webbrowser
from datetime import datetime, timezone

try:  # keep the Windows console from failing on non-ASCII characters
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

ROOT = os.path.dirname(os.path.abspath(__file__))
os.chdir(ROOT)
sys.path.insert(0, ROOT)

try:
    import networkx  # noqa: F401
except ImportError:
    print("The 'networkx' package is missing. Install the requirements once with:  pip install -r requirements.txt")
    sys.exit(1)

import collect
import config
import generate_data
import pipeline
from custody import CustodyLedger, load_key


def _open(path, no_open):
    print(f"\nReport: {os.path.abspath(path)}")
    if not no_open:
        try:
            webbrowser.open("file:///" + os.path.abspath(path).replace("\\", "/"))
        except Exception:
            pass


def _key(a):
    return load_key(key_file=getattr(a, "custody_key_file", None))


def _summary(ctx):
    print(f"  Sources processed : {', '.join(ctx['stats']) or 'none'}")
    print(f"  Events normalized : {len(ctx['events'])}")
    print(f"  Events flagged    : {ctx['corr']['alert_events']}")
    print(f"  Incidents found   : {len(ctx['corr']['incidents'])}")
    for inc in ctx["corr"]["incidents"]:
        print(f"    {inc['id']} [{inc['severity']}] {inc['start']} -> {inc['end']}  platforms: {', '.join(inc['platforms'])}"
              f"  events: {inc['event_count']}")
    if ctx["corr"]["unlinked_alerts"]:
        print(f"  Alerts not linked to an incident: {len(ctx['corr']['unlinked_alerts'])} (listed in the report)")
    print(f"  Chain of custody  : {'VERIFIED' if ctx['custody_ok'] else 'FAILED'}{' (HMAC-signed)' if ctx.get('hmac_used') else ''}")
    print(f"  Ledger anchor hash: {ctx['final_head_hash']}")
    print("    (note this hash down OUTSIDE the case folder: it detects deleted ledger entries later)")
    print("  Stage times (s)   : " + ", ".join(f"{k} {v:.3f}" for k, v in ctx["timings"].items()))


# ------------------------------------------------------------------ simulated data
def cmd_demo(a):
    print("Generating simulated logs (Windows + Linux + AWS) for scenario S1 ...")
    generate_data.build("S1", "sample_logs/S1")
    print("Running pipeline: acquire -> normalize -> correlate -> verify -> report ...")
    ctx = pipeline.run_case("sample_logs/S1", "cases/DEMO", key=_key(a))
    _summary(ctx)
    _open(ctx["report_path"], a.no_open)


def cmd_evaluate(a):
    import evaluate
    print("Running evaluation. The full run tests up to 100,000 records and takes about a minute.\n")
    evaluate.run_all(ROOT, quick=a.quick)
    try:
        import make_dashboard
        make_dashboard.build(ROOT)
        print("\nDashboard: results/dashboard.html")
    except Exception as e:                      # the dashboard is a viewer; the evaluation itself is already written
        print("Dashboard not built:", e)
    _open(os.path.join("results", "evaluation_report.html"), a.no_open)
    print("\nAlso written: results/evaluation.json, results/metrics_summary.csv, results/scalability.csv")


def cmd_real(a):
    import realdata
    print("Validation on REAL public data. First run downloads about 44 MB from GitHub (needs internet).\n")
    d = realdata.run(ROOT)
    w = d["windows"]
    core = [x for x in w["labelled"] if not x["hard"]]
    hard = [x for x in w["labelled"] if x["hard"]]
    print(f"\nWindows: {w['samples']} samples, {w['records']:,} records, {w['errors']} parse errors; "
          f"labelled samples detected {sum(x['hit'] for x in core)}/{len(core)}, hard cases {sum(x['hit'] for x in hard)}/{len(hard)}")
    for f, r in d["linux"].items():
        print(f"Linux {f}: {r['normalized']} events, brute-force IPs framework {r['framework_bf_ips']} vs independent {r['independent_bf_ips']}")
    print(f"AWS: {sum(r['hit'] for r in d['aws'])}/{len(d['aws'])} real attack samples detected")
    _open(os.path.join("results", "real_data_report.html"), a.no_open)


def cmd_tamper(a):
    from evaluate import EVAL_KEY, _forge_chain
    generate_data.build("S1", "sample_logs/S1")
    ctx = pipeline.run_case("sample_logs/S1", "cases/DEMO", make_report=False, key=EVAL_KEY)
    anchor = ctx["final_head_hash"]
    lp = os.path.join("cases", "DEMO", "custody_ledger.jsonl")
    led = CustodyLedger(lp)
    ok, _ = led.verify(anchor, EVAL_KEY)
    print(f"1. Untouched case                          -> {'VERIFIED' if ok else 'FAILED'}")
    p = os.path.join("cases", "DEMO", "evidence", "auth.log")
    data = open(p, "rb").read()
    open(p, "wb").write(data.replace(b"Failed password", b"Failed passw0rd", 1))
    ok, checks = led.verify(anchor, EVAL_KEY)
    print(f"2. Changed one word in auth.log            -> {'VERIFIED' if ok else 'TAMPERING DETECTED'}")
    for c in checks:
        if not c["ok"]:
            print(f"     {c['item']}: {c['note']}")
    open(p, "wb").write(data)
    ok, _ = led.verify(anchor, EVAL_KEY)
    print(f"3. File restored                           -> {'VERIFIED' if ok else 'FAILED'}")
    ledger_bytes = open(lp, "rb").read()
    _forge_chain(lp)
    ok, checks = CustodyLedger(lp).verify(None, EVAL_KEY)
    print(f"4. Ledger entry edited + chain recomputed  -> {'VERIFIED' if ok else 'TAMPERING DETECTED'} (HMAC key)")
    ok2, _ = CustodyLedger(lp).verify(None, None)
    print(f"   same forgery, no key and no anchor      -> {'not detected (known limit of a plain hash chain)' if ok2 else 'detected'}")
    open(lp, "wb").write(ledger_bytes)


# ------------------------------------------------------------------ real evidence
def cmd_analyze(a):
    src = os.path.abspath(a.input)
    if not os.path.isdir(src):
        print(f"Folder not found: {src}")
        return 1
    cfg = config.load_case_config(a.config or os.path.join(src, "case_config.json"))
    if not (a.config or os.path.exists(os.path.join(src, "case_config.json"))):
        print("Note: no case_config.json found; using defaults (Linux time zone +05:30, year 2026, no credential inventory).")
    name = a.name or cfg.get("case_id", "CASE")
    ctx = pipeline.run_case(src, os.path.join("cases", name), cfg, key=_key(a))
    _summary(ctx)
    for m in ctx["acquire_msgs"]:
        print("  " + m)
    if not ctx["events"]:
        print("  No supported evidence was found in that folder.")
    _open(ctx["report_path"], a.no_open)


def cmd_inbox(a):
    import intake
    src = os.path.abspath(a.input or "INPUT")
    os.makedirs(src, exist_ok=True)
    names = [f for f in sorted(os.listdir(src)) if f.lower() != "readme.txt" and not f.startswith(".")]
    if not names:
        print(f"The folder is empty: {src}")
        print("Put your log files there (any name: .evtx, .xml, auth.log, CloudTrail .json, or a .zip of them) and run again.")
        return 1
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    name = a.name or f"INPUT-{stamp}"
    staging = os.path.join("uploads", f"inbox_{stamp}")
    print(f"Looking inside {len(names)} item(s) in {src} ...")
    files = intake.stage([(os.path.join(src, f), f) for f in names], staging)
    for r in files:
        print(f"  {'OK ' if r['used'] else '-- '} {r['label']:<22} {r['name']}  ({r['reason']})")
    if not any(r["used"] for r in files):
        print("None of these files is Windows, Linux or AWS evidence.")
        shutil.rmtree(staging, ignore_errors=True)
        return 1
    cfg = config.load_case_config(os.path.join(staging, "case_config.json"))
    cfg["case_id"] = name
    print("Running pipeline: acquire -> normalize -> correlate -> verify -> report ...")
    ctx = pipeline.run_case(staging, os.path.join("cases", name), cfg, key=_key(a), intake=files)
    shutil.rmtree(staging, ignore_errors=True)
    _summary(ctx)
    _open(ctx["report_path"], a.no_open)


def cmd_web(a):
    try:
        import flask  # noqa: F401
    except ImportError:
        print("The web console needs the 'flask' package. Install the requirements once with:  pip install -r requirements.txt")
        return 1
    import webapp
    webapp.serve(port=a.port, open_browser=not a.no_open)


def _collect_host(out, a):
    import hostcollect
    os.makedirs(out, exist_ok=True)
    man = hostcollect.collect_host(out, include_logs=not a.no_logs, days=a.days)
    print(f"  {len(man['artifacts'])} artifacts written to {os.path.abspath(out)} in {man.get('duration_s')} s")
    for v in man.get("limited", {}).values():
        print("  LIMIT:", v)
    for e in man.get("errors", [])[:5]:
        print("  error:", e)
    return man


def cmd_collect_host(a):
    try:
        _collect_host(a.out, a)
    except RuntimeError as e:
        print("Could not collect:", e)
        return 1
    print(f"Now run:  python main.py analyze --input {a.out}")


def cmd_triage(a):
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    host = socket.gethostname().replace(" ", "_") or "host"
    out = a.out or os.path.join("live_triage", f"{host}_{stamp}")
    try:
        _collect_host(out, a)
    except RuntimeError as e:
        print("Could not collect:", e)
        return 1
    cfg = dict(config.DEFAULT_CASE, case_id=f"TRIAGE-{host}-{stamp}")
    from hostcollect import _local_offset
    cfg["linux_timezone_offset"] = _local_offset()
    cfg["linux_log_year"] = datetime.now().year
    print("Analysing ...")
    ctx = pipeline.run_case(out, os.path.join("cases", cfg["case_id"]), cfg, key=_key(a))
    _summary(ctx)
    _open(ctx["report_path"], a.no_open)


def cmd_live(a):
    try:
        out = collect.collect_live_windows(a.out, a.count, a.fmt)
    except Exception as e:
        print("Could not export the Windows Security log:", e)
        return 1
    print("Exported:", out)
    print(f"Now run:  python main.py analyze --input {a.out}")


def cmd_aws(a):
    try:
        out, n, calls = collect.collect_live_aws(a.out, days=a.days, region=a.region, profile=a.profile)
        print(f"CloudTrail: {n} events in {calls} API calls -> {out}")
    except Exception as e:
        print("Could not read CloudTrail:", e)
        if a.no_state:
            return 1
    if not a.no_state:
        try:
            import cloudstate
            man = cloudstate.collect_cloud_state(a.out, region=a.region, profile=a.profile, all_regions=a.all_regions)
            print(f"Account state: {len(man['artifacts'])} files, {len(man['api_operations'])} read-only API operations, {len(man['errors'])} denied/failed calls")
            for v in man["limited"].values():
                print("  LIMIT:", v)
        except Exception as e:
            print("Could not read the account state:", e)
    print(f"Now run:  python main.py analyze --input {a.out}")


def cmd_linux(a):
    try:
        if a.host:
            out = collect.collect_linux_ssh(a.host, a.user, a.out, key=a.key, path=a.path, use_sudo=not a.no_sudo, port=a.port)
        else:
            out = collect.collect_linux_local(a.out, a.path)
    except Exception as e:
        print("Could not copy the auth log:", e)
        return 1
    print("Copied:", out)
    print(f"Now run:  python main.py analyze --input {a.out}")


def cmd_verify(a):
    lp = os.path.join(a.case, "custody_ledger.jsonl")
    if not os.path.exists(lp):
        print("No custody_ledger.jsonl in", a.case)
        return 1
    anchor = a.anchor
    if not anchor and os.path.exists(os.path.join(a.case, "custody_head.txt")):
        anchor = open(os.path.join(a.case, "custody_head.txt")).read().strip()
        print("Using the anchor stored in custody_head.txt (for strong protection, pass the anchor you noted elsewhere with --anchor).")
    ok, checks = CustodyLedger(lp).verify(anchor, _key(a))
    for c in checks:
        print(("OK   " if c["ok"] else "FAIL ") + f"{c['item']}: {c['note']}")
    print("\nRESULT:", "VERIFIED" if ok else "TAMPERING OR ERROR DETECTED")
    return 0 if ok else 2


def cmd_selftest(a):
    import unittest
    import warnings
    warnings.simplefilter("ignore")
    suite = unittest.defaultTestLoader.discover(os.path.join(ROOT, "tests"), pattern="test_*.py")
    t = time.time()
    r = unittest.TextTestRunner(verbosity=1).run(suite)
    skipped = len(r.skipped)
    print(f"\n{r.testsRun} tests, {len(r.failures) + len(r.errors)} failed, {skipped} skipped, {time.time() - t:.1f} s")
    if skipped:
        print("Skipped tests need Linux (real-process tests) or the dev packages:  pip install -r requirements-dev.txt")
    return 0 if r.wasSuccessful() else 1


def main():
    ap = argparse.ArgumentParser(description="Cross-Platform DFIR Framework")
    sub = ap.add_subparsers(dest="cmd", required=True)

    def p_(name, fn, key=False, opener=True):
        p = sub.add_parser(name)
        if opener:
            p.add_argument("--no-open", action="store_true", help="do not open the report in the browser")
        if key:
            p.add_argument("--custody-key-file", help="file with a secret HMAC key for the custody ledger (or set DFIR_CUSTODY_KEY)")
        p.set_defaults(fn=fn)
        return p

    p_("demo", cmd_demo, key=True)
    p = p_("web", cmd_web)
    p.add_argument("--port", type=int, default=8765)
    p = p_("inbox", cmd_inbox, key=True)
    p.add_argument("--input", help="folder to analyse (default: INPUT)")
    p.add_argument("--name", help="case name")
    p_("tamper-demo", cmd_tamper)
    p = p_("evaluate", cmd_evaluate)
    p.add_argument("--quick", action="store_true", help="scalability up to 10,000 records only")
    p_("real-eval", cmd_real)
    p = p_("analyze", cmd_analyze, key=True)
    p.add_argument("--input", required=True)
    p.add_argument("--config")
    p.add_argument("--name")
    for name, fn in (("triage", cmd_triage), ("collect-host", cmd_collect_host)):
        p = p_(name, fn, key=(name == "triage"), opener=(name == "triage"))
        p.add_argument("--out", default=None if name == "triage" else "live_host")
        p.add_argument("--days", type=int, default=7, help="recent-file window in days")
        p.add_argument("--no-logs", action="store_true", help="do not export the system's security logs")
    p = p_("collect-live", cmd_live, opener=False)
    p.add_argument("--out", default="live_logs")
    p.add_argument("--count", type=int, default=5000)
    p.add_argument("--fmt", choices=("xml", "evtx"), default="xml")
    p = p_("collect-aws", cmd_aws, opener=False)
    p.add_argument("--out", default="live_logs")
    p.add_argument("--days", type=int, default=7)
    p.add_argument("--region")
    p.add_argument("--profile")
    p.add_argument("--all-regions", action="store_true", help="read security groups in every region")
    p.add_argument("--no-state", action="store_true", help="CloudTrail events only, skip the account state")
    p = p_("collect-linux", cmd_linux, opener=False)
    p.add_argument("--out", default="live_logs")
    p.add_argument("--host")
    p.add_argument("--user", default="ubuntu")
    p.add_argument("--key")
    p.add_argument("--port", type=int, default=22)
    p.add_argument("--path", default="/var/log/auth.log")
    p.add_argument("--no-sudo", action="store_true")
    p = p_("verify", cmd_verify, key=True, opener=False)
    p.add_argument("--case", required=True)
    p.add_argument("--anchor")
    p_("selftest", cmd_selftest, opener=False)
    a = ap.parse_args()
    sys.exit(a.fn(a) or 0)


if __name__ == "__main__":
    main()
