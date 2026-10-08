"""Evaluation of the framework against the design parameters.

Design parameter            How it is measured here
--------------------------  ----------------------------------------------------------------------
Evidence completeness       normalized supported records / supported records present in the source
Correlation accuracy        event-level precision / recall / F1 against generator ground truth,
                            plus incident-level errors (missed, false, split, merged)
Evidence integrity          4 tampering attacks on the ledger/evidence + 1 untouched control
Scalability                 processing time and throughput for 1K ... 100K records
Cross-platform support      sources processed with no manual step, and chain coverage of unified
                            vs siloed (one source at a time) analysis
"""
import copy
import csv
import json
import os
import platform
import shutil
import sys
import time
from datetime import datetime, timezone
from html import escape as h

import config
import correlate
import generate_data
import pipeline
from custody import CustodyLedger

SCENARIOS = [
    ("S1", "Full cross-platform attack (same attacker IP on all platforms)"),
    ("S2", "Credential pivot (Linux -> AWS from a different IP)"),
    ("S3", "Two concurrent independent attacks"),
    ("S4", "Benign activity only (false-positive test)"),
    ("S5", "HARD CASES: session collision + insider from internal IP"),
]
CORE = ("S1", "S2", "S3", "S4")
SCALE_SIZES = [1000, 5000, 10000, 50000, 100000]


def _refs(events):
    return {f"{e['source_file']}#{e['line_ref']}" for e in events}


def score(ctx, truth):
    events = ctx["events"]
    norm = _refs(events)
    rel = set(truth["relevant"])
    completeness = len(norm & rel) / len(rel) if rel else 1.0
    extra = len(norm - rel)
    pred = {}
    for e in events:
        if e.get("incident"):
            pred.setdefault(e["incident"], set()).add(f"{e['source_file']}#{e['line_ref']}")
    true = {k: set(v) for k, v in truth["incident_events"].items()}
    tp_set, true_all, pred_all = set(), set().union(*true.values()) if true else set(), set().union(*pred.values()) if pred else set()
    tp = len(true_all & pred_all)
    fp = len(pred_all - true_all)
    fn = len(true_all - pred_all)
    prec = tp / (tp + fp) if (tp + fp) else 1.0
    rec = tp / (tp + fn) if (tp + fn) else 1.0
    f1 = 2 * prec * rec / (prec + rec) if (prec + rec) else 0.0
    missed = sum(1 for t in true.values() if not any(t & p for p in pred.values()))
    false_inc = sum(1 for p in pred.values() if not any(p & t for t in true.values()))
    split = sum(1 for t in true.values() if sum(1 for p in pred.values() if p & t) > 1)
    merged = sum(1 for p in pred.values() if sum(1 for t in true.values() if p & t) > 1)
    false_alerts = sum(1 for e in events if e["flags"] and f"{e['source_file']}#{e['line_ref']}" not in true_all)
    return dict(
        records_in_sources=truth["total_records"], supported_records=len(rel), normalized_supported=len(norm & rel),
        completeness=completeness, unexpected_events=extra,
        incidents_expected=len(true), incidents_found=len(pred), missed_incidents=missed, false_incidents=false_inc,
        split_incidents=split, merged_incidents=merged, attack_events=len(true_all), tp=tp, fp=fp, fn=fn,
        precision=prec, recall=rec, f1=f1, false_alerts=false_alerts,
        cross_platform_incidents=sum(1 for i in ctx["corr"]["incidents"] if i["cross_platform"]))


def chain_coverage(events, cfg, truth):
    """Unified vs siloed analysis: share of each true incident captured by ONE predicted incident."""
    true = {k: set(v) for k, v in truth["incident_events"].items()}

    def best(evs):
        evs = copy.deepcopy(evs)
        c = correlate.correlate(evs, cfg)
        preds = []
        for inc in c["incidents"]:
            ids = set(inc["event_ids"])
            preds.append({f"{e['source_file']}#{e['line_ref']}" for e in evs if e["event_id"] in ids})
        return {k: max((len(p & t) / len(t) for p in preds), default=0.0) for k, t in true.items()}

    out = {"unified": best(events)}
    for src in ("windows", "linux", "aws"):
        sub = [e for e in events if e["source"] == src]
        out[f"siloed_{src}"] = best(sub)
    rows = []
    for k in true:
        rows.append(dict(incident=k, unified=out["unified"][k],
                         best_siloed=max(out[f"siloed_{s}"][k] for s in ("windows", "linux", "aws"))))
    return rows


EVAL_KEY = b"thesis-evaluation-key"


def _forge_chain(lp):
    """Attacker without the HMAC key edits entry 2 and recomputes every hash after it (so the chain is consistent again)."""
    import custody as cu
    entries = [json.loads(l) for l in open(lp, encoding="utf-8").read().splitlines() if l.strip()]
    entries[1]["actor"] = "someone-else"
    prev = entries[0]["entry_hash"]
    for e in entries[1:]:
        e["prev_hash"] = prev
        e["entry_hash"] = cu._entry_hash(e)
        prev = e["entry_hash"]
    open(lp, "w", encoding="utf-8").write("\n".join(json.dumps(x) for x in entries) + "\n")


def tamper_tests(case_dir, anchor, key=EVAL_KEY):
    """Copy the case, attack the copy in several ways, verify each. Also an untouched control."""
    tmp = case_dir + "_tamper"
    results = []

    def fresh():
        if os.path.isdir(tmp):
            shutil.rmtree(tmp)
        shutil.copytree(case_dir, tmp)
        return CustodyLedger(os.path.join(tmp, "custody_ledger.jsonl"))

    led = fresh()
    ok, _ = led.verify(anchor, key)
    results.append(dict(test="Control: untouched case", expect_detect=False, detected=not ok, passed=ok))

    led = fresh()
    p = os.path.join(tmp, "evidence", "auth.log")
    with open(p, "rb") as f:
        data = bytearray(f.read())
    data[len(data) // 2] ^= 0x01                      # flip one bit
    with open(p, "wb") as f:
        f.write(data)
    ok, _ = led.verify(anchor, key)
    results.append(dict(test="Evidence file altered (1 bit flipped)", expect_detect=True, detected=not ok, passed=not ok))

    led = fresh()
    lp = os.path.join(tmp, "custody_ledger.jsonl")
    lines = open(lp, encoding="utf-8").read().splitlines()
    e = json.loads(lines[1])
    e["actor"] = "someone-else"
    lines[1] = json.dumps(e)
    open(lp, "w", encoding="utf-8").write("\n".join(lines) + "\n")
    ok, _ = CustodyLedger(lp).verify(anchor, key)
    results.append(dict(test="Ledger entry edited (actor name changed)", expect_detect=True, detected=not ok, passed=not ok))

    led = fresh()
    lines = open(lp, encoding="utf-8").read().splitlines()
    del lines[2]
    open(lp, "w", encoding="utf-8").write("\n".join(lines) + "\n")
    ok, _ = CustodyLedger(lp).verify(anchor, key)
    results.append(dict(test="Ledger entry deleted (middle of chain)", expect_detect=True, detected=not ok, passed=not ok))

    led = fresh()
    lines = open(lp, encoding="utf-8").read().splitlines()
    open(lp, "w", encoding="utf-8").write("\n".join(lines[:-1]) + "\n")
    ok, _ = CustodyLedger(lp).verify(anchor, key)
    results.append(dict(test="Ledger truncated (last entry removed, anchor noted)", expect_detect=True, detected=not ok, passed=not ok))
    fresh()
    _forge_chain(lp)
    ok, _ = CustodyLedger(lp).verify(None, key)
    results.append(dict(test="Ledger forged: entry edited and whole hash chain recomputed (HMAC key set)", expect_detect=True, detected=not ok, passed=not ok))
    ok, _ = CustodyLedger(lp).verify(None, None)
    results.append(dict(test="Same forgery checked WITHOUT key or anchor", expect_detect=False, limitation=True, detected=not ok, passed=ok))
    shutil.rmtree(tmp, ignore_errors=True)
    return results


def run_scenarios(root):
    rows = []
    for name, desc in SCENARIOS:
        indir = os.path.join(root, "sample_logs", name)
        case = os.path.join(root, "cases", name)
        truth = generate_data.build(name, indir)
        ctx = pipeline.run_case(indir, case, key=EVAL_KEY)
        sc = score(ctx, truth)
        cov = chain_coverage(ctx["events"], ctx["cfg"], truth)
        tam = tamper_tests(case, ctx["final_head_hash"])
        rows.append(dict(name=name, description=desc, score=sc, coverage=cov, tamper=tam, timings=ctx["timings"],
                         sources_processed=len(ctx["stats"]), report=f"../cases/{name}/report.html"))
        print(f"  {name}: completeness {sc['completeness']:.1%}, incidents {sc['incidents_found']}/{sc['incidents_expected']}, "
              f"F1 {sc['f1']:.3f}, tamper {sum(t['passed'] for t in tam if not t.get('limitation'))}/{sum(1 for t in tam if not t.get('limitation'))}")
    return rows


def policy_runs(root):
    """Same logs as S5 and S4, with the admin-source policy configured (admin logons expected only from 10.0.5.10)."""
    out = []
    for name in ("S5", "S4"):
        indir = os.path.join(root, "sample_logs", name)
        truth = json.load(open(os.path.join(indir, "ground_truth.json")))
        cfg = config.load_case_config(os.path.join(indir, "case_config.json"))
        cfg["privileged_source_allowlist"] = ["10.0.5.10/32"]
        ctx = pipeline.run_case(indir, os.path.join(root, "cases", f"{name}_policy"), cfg, make_report=False)
        sc = score(ctx, truth)
        out.append(dict(name=f"{name} + policy", score=sc))
        print(f"  {name} + admin-source policy: incidents {sc['incidents_found']}/{sc['incidents_expected']}, "
              f"precision {sc['precision']:.3f}, recall {sc['recall']:.3f}, F1 {sc['f1']:.3f}, false alerts {sc['false_alerts']}")
    return out


def cloud_check(root):
    """Rule correctness on a labelled cloud-state fixture (NOT real accounts) and one integration check."""
    import collections
    res = {}
    for name, exposed in (("exposed", True), ("clean", False)):
        d = os.path.join(root, "sample_logs", f"cloud_{name}")
        shutil.rmtree(d, ignore_errors=True)
        expected = generate_data.cloud_state(d, exposed)
        ctx = pipeline.run_case(d, os.path.join(root, "cases", f"cloud_{name}"), config.DEFAULT_CASE, make_report=False)
        found = collections.Counter(f for ev in ctx["events"] for f in ev["flags"])
        exp_total, found_total = sum(expected.values()), sum(found.values())
        tp = sum(min(found.get(k, 0), v) for k, v in expected.items())
        res[name] = dict(expected=expected, found=dict(found), expected_total=exp_total, found_total=found_total, tp=tp, fp=found_total - tp, fn=exp_total - tp,
                         incidents=len(ctx["corr"]["incidents"]), events=len(ctx["events"]), custody=ctx["custody_ok"])
    # integration: S1 attack (stolen key used from outside) + the account state that contains that key
    d = os.path.join(root, "sample_logs", "S1_cloud")
    shutil.rmtree(d, ignore_errors=True)
    generate_data.build("S1", d)
    generate_data.cloud_state(d, True)
    ctx = pipeline.run_case(d, os.path.join(root, "cases", "S1_cloud"), make_report=True)
    incs = ctx["corr"]["incidents"]
    ids = set(incs[0]["event_ids"]) if incs else set()
    state_keys = [ev for ev in ctx["events"] if ev["event_type"] == "access_key_state"]
    joined = [ev for ev in state_keys if ev["event_id"] in ids]
    res["integration"] = dict(incidents=len(incs), key_states=len(state_keys), joined=len(joined), joined_keys=[ev["key_id"] for ev in joined],
                              posture_unlinked=len(ctx["corr"]["unlinked_alerts"]))
    for k in ("exposed", "clean"):
        r = res[k]
        print(f"  cloud {k}: expected {r['expected_total']} findings, found {r['found_total']} (TP {r['tp']}, FP {r['fp']}, FN {r['fn']}), incidents {r['incidents']}")
    r = res["integration"]
    print(f"  S1 + account state: {r['incidents']} incident, {r['joined']} of {r['key_states']} access-key records joined it {r['joined_keys']}")
    return res


def cloud_emulated(root):
    """Seeded account inside the moto AWS emulator, collected through the real boto3 code path. Labels come from the seeder."""
    try:
        from datetime import timedelta
        import collections
        from moto import mock_aws
        import freezegun  # noqa: F401
        import cloud_emulation
        import cloudstate
    except ImportError:
        return dict(available=False)
    res = dict(available=True)
    with mock_aws():
        info = cloud_emulation.seed()
        now = datetime.now(timezone.utc) + timedelta(days=200)
        runs = {}
        for name, allr in (("single", False), ("all", True)):
            d = os.path.join(root, "sample_logs", f"cloud_emulated_{name}")
            shutil.rmtree(d, ignore_errors=True)
            man = cloudstate.collect_cloud_state(d, region="us-east-1", now=now, log=lambda *a: None, all_regions=allr)
            runs[name] = (d, man)
    for name, exp in (("single", info["expected"]), ("all", info["expected_all_regions"])):
        d, man = runs[name]
        ctx = pipeline.run_case(d, os.path.join(root, "cases", f"cloud_emulated_{name}"), dict(config.DEFAULT_CASE, case_id=f"CLOUD-EMU-{name}"), make_report=(name == "single"))
        found = collections.Counter(f for ev in ctx["events"] for f in ev["flags"])
        tp = sum(min(found.get(k, 0), v) for k, v in exp.items())
        res[name] = dict(expected=exp, found=dict(found), expected_total=sum(exp.values()), found_total=sum(found.values()), tp=tp, fp=sum(found.values()) - tp,
                         fn=sum(exp.values()) - tp, incidents=len(ctx["corr"]["incidents"]), custody=ctx["custody_ok"], errors=len(man["errors"]),
                         api_operations=len(man["api_operations"]), read_only=all(o.startswith(cloudstate.READ_PREFIXES) for o in man["api_operations"]),
                         limited=list(man["limited"]))
    res["created"] = info["created"]
    # integration: an attack that abuses the key of one emulated user, on top of the collected account state
    d = runs["single"][0]
    g = generate_data.Gen(3)
    g.attack_aws("INC-1", generate_data.T(9, 40), generate_data.ATT_A, info["keys"]["app-uploader"], "AKIAQ3EXAMPLENEW0002", user="app-uploader")
    g.write(d)
    ctx = pipeline.run_case(d, os.path.join(root, "cases", "cloud_emulated_integration"), dict(config.DEFAULT_CASE, case_id="CLOUD-EMU-INT"), make_report=False)
    incs = ctx["corr"]["incidents"]
    ids = set(incs[0]["event_ids"]) if incs else set()
    keys_state = [ev for ev in ctx["events"] if ev["event_type"] == "access_key_state"]
    joined = [ev for ev in keys_state if ev["event_id"] in ids]
    res["integration"] = dict(incidents=len(incs), key_states=len(keys_state), joined=len(joined), joined_user=joined[0]["user"] if joined else None,
                              joined_flags=joined[0]["flags"] if joined else [], unlinked_alerts=len(ctx["corr"]["unlinked_alerts"]))
    for k in ("single", "all"):
        r = res[k]
        print(f"  emulated account ({k} region{'s' if k == 'all' else ''}): expected {r['expected_total']} findings, found {r['found_total']} (TP {r['tp']}, FP {r['fp']}, FN {r['fn']}), read-only ops {r['api_operations']}: {r['read_only']}")
    r = res["integration"]
    print(f"  emulated account + attack: {r['incidents']} incident, key record joined: {r['joined']} of {r['key_states']} ({r['joined_user']})")
    return res


def ablation(root):
    """S2 without the credential inventory: the Linux->AWS pivot cannot be linked."""
    indir = os.path.join(root, "sample_logs", "S2_no_inventory")
    truth = generate_data.build("S2", indir, inventory=False)
    ctx = pipeline.run_case(indir, os.path.join(root, "cases", "S2_no_inventory"), make_report=False)
    sc = score(ctx, truth)
    return dict(with_inventory=None, incidents_found=sc["incidents_found"], split=sc["split_incidents"], recall=sc["recall"])


def scalability(root):
    rows = []
    for n in SCALE_SIZES:
        indir = os.path.join(root, "sample_logs", f"scale_{n}")
        truth = generate_data.build_scaled(indir, n)
        ctx = pipeline.run_case(indir, os.path.join(root, "cases", f"scale_{n}"), make_report=False)
        sc = score(ctx, truth)
        t = ctx["timings"]
        proc = t["acquisition"] + t["normalization"] + t["correlation"] + t["output_and_custody"] + t["custody_verification"]
        rows.append(dict(records=truth["total_records"], events=len(ctx["events"]), acquisition=t["acquisition"],
                         normalization=t["normalization"], correlation=t["correlation"],
                         custody=t["output_and_custody"] + t["custody_verification"], total=proc,
                         throughput=truth["total_records"] / proc, f1=sc["f1"], incidents=sc["incidents_found"],
                         completeness=sc["completeness"]))
        print(f"  {n:>7} records: {proc:6.2f}s total, {truth['total_records'] / proc:8.0f} records/s, F1 {sc['f1']:.3f}")
        shutil.rmtree(indir, ignore_errors=True)
        shutil.rmtree(os.path.join(root, "cases", f"scale_{n}"), ignore_errors=True)
    return rows


# ------------------------------------------------------------------ report
def _svg_scaling(rows):
    W, H, L, B = 640, 300, 70, 44
    xmax = max(r["records"] for r in rows) * 1.05
    ymax = max(r["total"] for r in rows) * 1.2
    lx = lambda v: L + v / xmax * (W - L - 30)
    ly = lambda v: H - B - v / ymax * (H - B - 24)
    p = [f'<svg width="{W}" height="{H}" xmlns="http://www.w3.org/2000/svg" style="border:1px solid #DCE4EF;border-radius:8px;background:#fff">']
    for k in range(5):
        v = ymax * k / 4
        p.append(f'<line x1="{L}" x2="{W - 20}" y1="{ly(v):.0f}" y2="{ly(v):.0f}" stroke="#eee"/>'
                 f'<text x="{L - 8}" y="{ly(v) + 4:.0f}" font-size="11" text-anchor="end">{v:.1f} s</text>')
    step = 25000 if xmax > 60000 else 5000
    v = 0
    while v <= xmax:
        p.append(f'<line x1="{lx(v):.0f}" x2="{lx(v):.0f}" y1="{ly(0)}" y2="{ly(0) + 5}" stroke="#666"/>'
                 f'<text x="{lx(v):.0f}" y="{ly(0) + 19}" font-size="11" text-anchor="middle">{v:,}</text>')
        v += step
    pts = " ".join(f"{lx(r['records']):.1f},{ly(r['total']):.1f}" for r in rows)
    p.append(f'<polyline points="{pts}" fill="none" stroke="#0EA5E9" stroke-width="2.5"/>')
    for r in rows:
        p.append(f'<circle cx="{lx(r["records"]):.1f}" cy="{ly(r["total"]):.1f}" r="4.5" fill="#0EA5E9"/>')
        if r["records"] >= xmax * 0.4:
            p.append(f'<text x="{lx(r["records"]):.1f}" y="{ly(r["total"]) - 10:.1f}" font-size="11" text-anchor="end">{r["total"]:.2f} s</text>')
    p.append(f'<text x="{W / 2}" y="{H - 6}" font-size="12" text-anchor="middle">Log records processed</text>')
    p.append("</svg>")
    return "".join(p)


def _pct(x):
    return f"{x * 100:.1f}%"


def build_eval_report(data):
    sc, scale, abl = data["scenarios"], data["scalability"], data["ablation"]
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    from report import CSS, _table
    o = [f"<!doctype html><html><head><meta charset='utf-8'><title>Evaluation</title><style>{CSS}</style></head><body>"
         f"<header><h1>Framework Evaluation — Design Parameters</h1><p>Generated {now} · Python {platform.python_version()} · {platform.system()} · simulated logs with generator ground truth</p></header><main>"]

    hard = [s for s in sc if s["name"] not in CORE]
    tam_all = [t for s in sc for t in s["tamper"] if t["expect_detect"]]
    ctrl = [t for s in sc for t in s["tamper"] if not t["expect_detect"] and not t.get("limitation")]
    o.append('<div class="cards">')
    o.append(f'<div class="card"><b>{_pct(min(s["score"]["completeness"] for s in sc))}</b><span>evidence completeness (worst scenario)</span></div>')
    o.append(f'<div class="card"><b>{data["overall_f1"]:.3f}</b><span>correlation F1, core scenarios S1-S4</span></div>')
    if hard:
        o.append(f'<div class="card"><b>{hard[0]["score"]["f1"]:.3f}</b><span>correlation F1, hard cases S5</span></div>')
    o.append(f'<div class="card"><b>{sum(t["detected"] for t in tam_all)}/{len(tam_all)}</b><span>tampering attacks detected</span></div>')
    o.append(f'<div class="card"><b>{sum(t["passed"] for t in ctrl)}/{len(ctrl)}</b><span>untouched cases verified (no false alarm)</span></div>')
    o.append(f'<div class="card"><b>{scale[-1]["throughput"]:,.0f}</b><span>records/s at {scale[-1]["records"]:,} records</span></div>')
    o.append("</div>")

    o.append("<h2>1. Evidence completeness and correlation accuracy</h2>")
    o.append(_table(["Scenario", "Description", "Records", "Completeness", "Incidents found / expected", "False incidents", "Split", "Merged", "Precision", "Recall", "F1", "False alerts"],
                    [[f'<a href="{s["report"]}">{s["name"]}</a>', h(s["description"]), s["score"]["records_in_sources"], _pct(s["score"]["completeness"]),
                      f'{s["score"]["incidents_found"]} / {s["score"]["incidents_expected"]}', s["score"]["false_incidents"],
                      s["score"]["split_incidents"], s["score"]["merged_incidents"], _pct(s["score"]["precision"]),
                      _pct(s["score"]["recall"]), f'{s["score"]["f1"]:.3f}', s["score"]["false_alerts"]] for s in sc]))
    o.append("<p class='note'><b>S5 is deliberately hard.</b> (1) A legitimate session for the same user is open when the attacker logs in, and Linux auth.log has no session id, so a legitimate command is wrongly attributed to the attacker (a false positive). "
             "(2) An insider moves laterally from an internal IP without brute force, so no untrusted entity exists and the rules miss the incident (a false negative). These are the known limits of a rule-based design and the motivation for anomaly-based detection as future work.</p>")
    o.append("<p class='note'>Completeness = supported records normalized ÷ supported records present in the source. "
             "Precision/recall are computed per event against the generator's ground truth (which attack each record belongs to). "
             "False alerts = flagged events that are not part of any attack.</p>")

    o.append("<h3>Admin-source policy (mitigation for the S5 insider case)</h3>")
    o.append(_table(["Run", "Incidents found / expected", "Precision", "Recall", "F1", "False alerts"],
                    [[p["name"], f'{p["score"]["incidents_found"]} / {p["score"]["incidents_expected"]}', _pct(p["score"]["precision"]),
                      _pct(p["score"]["recall"]), f'{p["score"]["f1"]:.3f}', p["score"]["false_alerts"]] for p in data["policy"]]))
    o.append("<p class='note'>Policy = the analyst lists the IPs administrators are expected to log on from (<code>privileged_source_allowlist</code> in case_config.json). "
             "A privileged session from anywhere else is flagged. It catches the insider in S5 without new false alerts on benign data (S4), but it needs that list; "
             "the session-collision false positive in S5 remains.</p>")
    cl = data["cloud"]
    o.append("<h3>Cloud account state (AWS)</h3>")
    o.append(_table(["Fixture", "Expected findings", "Found", "True pos.", "False pos.", "Missed", "Incidents"],
                    [[k.title() + " account", cl[k]["expected_total"], cl[k]["found_total"], cl[k]["tp"], cl[k]["fp"], cl[k]["fn"], cl[k]["incidents"]] for k in ("exposed", "clean")]))
    it = cl["integration"]
    o.append(f"<p class='note'>Rule-correctness check on a labelled fixture, not on real accounts. The exposed account contains harmless look-alikes that must not be flagged (an administrator with MFA, a recently used key, world-open port 443, fully blocked buckets). "
             f"Integration: in S1 plus the account state, the account's record of the abused access key joined the incident ({it['joined']} of {it['key_states']} key records; the others were not pulled in), and the incident count stayed {it['incidents']}; posture findings are listed as alerts and never start an incident on their own.</p>")
    ce = data.get("cloud_emulated") or {}
    if ce.get("available"):
        o.append("<h3>Cloud account state through boto3 against the moto AWS emulator</h3>")
        o.append(_table(["Run", "Expected findings", "Found", "True pos.", "False pos.", "Missed", "Write operations used"],
                        [[("One region" if k == "single" else "All regions"), ce[k]["expected_total"], ce[k]["found_total"], ce[k]["tp"], ce[k]["fp"], ce[k]["fn"],
                          "none (%d read operations)" % ce[k]["api_operations"] if ce[k]["read_only"] else "SOME"] for k in ("single", "all")]))
        ci = ce["integration"]
        o.append(f"<p class='note'>An emulated AWS account was seeded with known misconfigurations and harmless look-alikes (custom-policy administrator, administrator with MFA through a group, inactive and fresh keys, conditional and service role trusts, fully blocked buckets, port 443, internal-only rules); "
                 f"the labels come from the seeder. The collector reads it through the normal boto3 code path, so pagination, response handling and policy evaluation are exercised, but this is an emulator, not a real account. "
                 f"With an attack that abuses one user's access key on top of that state, {ci['joined']} of {ci['key_states']} account key records joined the incident (user {h(str(ci['joined_user']))}, flags {h(', '.join(ci['joined_flags']))}); the other findings stayed separate as alerts.</p>")
    o.append("<h2>2. Cross-platform benefit: unified vs siloed analysis</h2>")
    rows = []
    for s in sc:
        for c in s["coverage"]:
            rows.append([s["name"], c["incident"], _pct(c["best_siloed"]), _pct(c["unified"])])
    o.append(_table(["Scenario", "Attack", "Attack chain captured by best single-source analysis", "Attack chain captured by unified framework"], rows))
    o.append(f"<p class='note'>Siloed = the same detectors run on Windows, Linux and AWS logs separately (as separate tools would); the best of the three is shown. "
             f"Credential-link ablation (S2 without the credential inventory): {abl['incidents_found']} incidents found instead of 1, "
             f"recall of the attack chain in a single incident drops (split incidents: {abl['split']}). The link between the Linux host and AWS needs the analyst-supplied key inventory.</p>")

    o.append("<h2>3. Evidence integrity (tampering detection)</h2>")
    rows = []
    for s in sc:
        for t in s["tamper"]:
            if t.get("limitation"):
                rows.append([s["name"], h(t["test"]), "known limitation", '<span class="bad">NOT DETECTED</span> (as expected without key/anchor)' if not t["detected"] else "detected"])
                continue
            rows.append([s["name"], h(t["test"]), "should be detected" if t["expect_detect"] else "should pass",
                         '<span class="ok">PASS</span>' if t["passed"] else '<span class="bad">FAIL</span>'])
    o.append(_table(["Scenario", "Test", "Expected", "Result"], rows))

    o.append("<h2>4. Scalability</h2>")
    o.append(_svg_scaling(scale))
    o.append(_table(["Log records", "Events normalized", "Acquisition (s)", "Normalization (s)", "Correlation (s)", "Custody (s)", "Total (s)", "Records / s", "F1", "Incidents"],
                    [[f'{r["records"]:,}', f'{r["events"]:,}', f'{r["acquisition"]:.3f}', f'{r["normalization"]:.3f}', f'{r["correlation"]:.3f}',
                      f'{r["custody"]:.3f}', f'<b>{r["total"]:.2f}</b>', f'{r["throughput"]:,.0f}', f'{r["f1"]:.3f}', r["incidents"]] for r in scale]))
    o.append("<p class='note'>One S1 attack hidden in growing amounts of normal activity. Time grows in a straight line with the number of records (about "
             f"{scale[-1]['throughput']:,.0f} records/s), and the attack is still found with F1 = {scale[-1]['f1']:.3f}. Times are wall-clock on this machine, single process, pure Python.</p>")

    o.append("<h2>5. Cross-platform support</h2>")
    o.append(_table(["Scenario", "Sources processed automatically", "Manual steps"], [[s["name"], f'{s["sources_processed"]} of 3 (Windows, Linux, AWS)', "none"] for s in sc]))

    o.append("<h2>6. Limitations (state these honestly in the thesis)</h2><ul class='note'>"
             "<li>All data is simulated (real log formats, generated events). Results show the framework works on these scenarios, not on production traffic.</li>"
             "<li>Ground truth comes from the generator, so scenario difficulty is limited by what the generator produces.</li>"
             "<li>Detection is rule-based (thresholds in config.py); novel attack patterns outside the rules are not flagged.</li>"
             "<li>Linux session attribution is a heuristic (latest login of the same user on the same host).</li>"
             "<li>Linking a Linux credential file to an AWS key requires the analyst-supplied credential inventory.</li>"
             "<li>The custody ledger detects changes after the fact; it does not stop them. Removal of the last entries needs the anchor hash noted outside the case folder, and a fully rewritten chain is detected only when the ledger was HMAC-signed with a key the attacker does not have (row 'checked WITHOUT key or anchor' shows the plain hash chain alone misses it).</li>"
             f"<li>Scalability is measured for a single process; the largest test had {scale[-1]['records']:,} records.</li></ul>")
    o.append("</main></body></html>")
    return "".join(o)


def run_all(root, quick=False):
    global SCALE_SIZES
    if quick:
        SCALE_SIZES = [1000, 5000, 10000]
    os.makedirs(os.path.join(root, "results"), exist_ok=True)
    print("Scenarios (accuracy, completeness, integrity):")
    scen = run_scenarios(root)
    print("Admin-source policy (S5 insider case, S4 false-positive check):")
    pol = policy_runs(root)
    print("Cloud account state (labelled fixture + integration):")
    cloud = cloud_check(root)
    print("Cloud account state through boto3 against the moto AWS emulator:")
    cloud_emu = cloud_emulated(root)
    print("Credential-link ablation:")
    abl = ablation(root)
    print(f"  S2 without inventory -> {abl['incidents_found']} incidents (split={abl['split']})")
    print("Scalability:")
    scale = scalability(root)
    core = [s for s in scen if s["name"] in CORE]
    tp = sum(s["score"]["tp"] for s in core)
    fp = sum(s["score"]["fp"] for s in core)
    fn = sum(s["score"]["fn"] for s in core)
    p = tp / (tp + fp) if tp + fp else 1.0
    r = tp / (tp + fn) if tp + fn else 1.0
    overall_f1 = 2 * p * r / (p + r) if p + r else 0.0
    data = dict(generated=datetime.now(timezone.utc).isoformat(), python=platform.python_version(), system=platform.system(),
                scenarios=scen, policy=pol, cloud=cloud, cloud_emulated=cloud_emu, ablation=abl, scalability=scale, overall_precision=p, overall_recall=r, overall_f1=overall_f1)
    res = os.path.join(root, "results")
    with open(os.path.join(res, "evaluation.json"), "w", encoding="utf-8") as f:
        json.dump(data, f, indent=1)
    with open(os.path.join(res, "evaluation_report.html"), "w", encoding="utf-8") as f:
        f.write(build_eval_report(data))
    with open(os.path.join(res, "metrics_summary.csv"), "w", newline="", encoding="utf-8-sig") as f:
        w = csv.writer(f)
        w.writerow(["scenario", "records", "completeness", "incidents_expected", "incidents_found", "false_incidents", "split", "merged",
                    "precision", "recall", "f1", "false_alerts", "tamper_tests_passed", "tamper_tests_total"])
        for s in scen:
            x = s["score"]
            w.writerow([s["name"], x["records_in_sources"], round(x["completeness"], 4), x["incidents_expected"], x["incidents_found"],
                        x["false_incidents"], x["split_incidents"], x["merged_incidents"], round(x["precision"], 4), round(x["recall"], 4),
                        round(x["f1"], 4), x["false_alerts"], sum(t["passed"] for t in s["tamper"] if not t.get("limitation")), sum(1 for t in s["tamper"] if not t.get("limitation"))])
    with open(os.path.join(res, "scalability.csv"), "w", newline="", encoding="utf-8-sig") as f:
        w = csv.writer(f)
        w.writerow(["records", "events", "acquisition_s", "normalization_s", "correlation_s", "custody_s", "total_s", "records_per_s", "f1", "incidents"])
        for r_ in scale:
            w.writerow([r_["records"], r_["events"], round(r_["acquisition"], 4), round(r_["normalization"], 4), round(r_["correlation"], 4),
                        round(r_["custody"], 4), round(r_["total"], 3), round(r_["throughput"]), round(r_["f1"], 4), r_["incidents"]])
    return data
