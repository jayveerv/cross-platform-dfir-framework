"""End-to-end pipeline: acquire -> normalize -> correlate -> verify -> report (every step recorded in the custody ledger)."""
import csv
import json
import os
import shutil
import time

import collect
import config
import correlate
import normalize
from custody import CustodyLedger

CSV_COLS = ["event_id", "time_utc", "source", "host", "event_type", "user", "src_ip", "target", "outcome", "detail",
            "session_id", "key_id", "new_key_id", "severity", "flags", "techniques", "incident", "source_file", "line_ref"]


def _timed(timings, name, fn, *a, **k):
    t = time.perf_counter()
    r = fn(*a, **k)
    timings[name] = time.perf_counter() - t
    return r


def _jsonable(events):
    """Events without the non-JSON parts (nothing to drop today, kept for safety)."""
    return events


def run_case(input_dir, case_dir, cfg=None, make_report=True, clean=True, key=None, intake=None, progress=None):
    """Run the whole framework on one folder of evidence.

    input_dir  folder with windows_security.xml / *.evtx, auth.log, cloudtrail.json, host/ and cloud/ (any subset)
    case_dir   output folder (evidence copy, ledger, timeline, incidents, report)
    cfg        case configuration (default: input_dir/case_config.json, else config.DEFAULT_CASE)
    key        HMAC key for the custody ledger (default: DFIR_CUSTODY_KEY environment variable, else plain hash chain)
    intake     optional list of original files from intake.stage() (name, SHA-256, detected type); written to
               intake_manifest.json and recorded as the first custody entry, so the hashes of the files exactly as
               the investigator supplied them are part of the chain
    progress   optional callback progress(stage, info) used by the web console to show live progress
    """
    say = progress or (lambda *_a, **_k: None)
    if cfg is None:
        cfg = config.load_case_config(os.path.join(input_dir, "case_config.json"))
    else:
        cfg = dict(config.DEFAULT_CASE, **cfg)
    if clean and os.path.isdir(case_dir):
        shutil.rmtree(case_dir)
    os.makedirs(case_dir, exist_ok=True)
    ledger = CustodyLedger(os.path.join(case_dir, "custody_ledger.jsonl"), actor=cfg.get("investigator"), key=key)
    timings = {}
    t_all = time.perf_counter()
    if intake:
        p_in = os.path.join(case_dir, "intake_manifest.json")
        with open(p_in, "w", encoding="utf-8") as f:
            json.dump(intake, f, indent=1)
        ledger.record("intake", p_in, stage="Acquisition",
                      details={"original_files": len(intake), "recognised": sum(1 for r in intake if r.get("used"))})

    say("acquisition", {})
    acquired, msgs = _timed(timings, "acquisition", collect.acquire, input_dir, case_dir, ledger)
    say("normalization", {"files": len(acquired)})
    events, stats = _timed(timings, "normalization", normalize.normalize_case, os.path.join(case_dir, "evidence"), cfg)
    say("correlation", {"events": len(events)})
    corr = _timed(timings, "correlation", correlate.correlate, events, cfg)
    say("custody", {"alerts": corr["alert_events"], "incidents": len(corr["incidents"])})

    def _write_outputs():
        p_json = os.path.join(case_dir, "normalized_events.json")
        with open(p_json, "w", encoding="utf-8") as f:
            json.dump(_jsonable(events), f)
        ledger.record("normalize", p_json, stage="Normalization", details={"events": len(events), "per_source": stats})
        p_csv = os.path.join(case_dir, "timeline.csv")
        with open(p_csv, "w", newline="", encoding="utf-8-sig") as f:
            w = csv.writer(f)
            w.writerow(CSV_COLS)
            for e in events:
                w.writerow([("; ".join(e[c]) if isinstance(e.get(c), list) else ("" if e.get(c) is None else e.get(c))) for c in CSV_COLS])
        p_inc = os.path.join(case_dir, "incidents.json")
        with open(p_inc, "w", encoding="utf-8") as f:
            json.dump(dict(incidents=corr["incidents"], unlinked_alerts=corr["unlinked_alerts"], alert_events=corr["alert_events"],
                           rules_fired=corr["rules_fired"]), f, indent=1)
        ledger.record("correlate", p_inc, stage="Correlation",
                      details={"incidents": len(corr["incidents"]), "alerts": corr["alert_events"]})
        ledger.record("export", p_csv, stage="Correlation", details={"rows": len(events)})

    _timed(timings, "output_and_custody", _write_outputs)
    ok, checks = _timed(timings, "custody_verification", ledger.verify)
    head = ledger.entries[-1]["entry_hash"] if ledger.entries else None
    ctx = dict(cfg=cfg, acquired=acquired, acquire_msgs=msgs, stats=stats, events=events, corr=corr, custody_ok=ok,
               custody_checks=checks, head_hash=head, timings=timings, case_dir=case_dir, ledger=ledger, hmac_used=bool(ledger.key))
    if make_report:
        say("reporting", {"custody_ok": ok})
        import report
        p = os.path.join(case_dir, "report.html")
        _timed(timings, "reporting", report.write_report, ctx, p)
        ledger.record("report", p, stage="Reporting", details={"custody_verified_before_report": ok})
        ctx["report_path"] = p
    timings["total"] = time.perf_counter() - t_all
    ctx["final_head_hash"] = ledger.entries[-1]["entry_hash"]
    with open(os.path.join(case_dir, "custody_head.txt"), "w") as f:
        f.write(ctx["final_head_hash"] + "\n")
    say("done", {})
    return ctx
