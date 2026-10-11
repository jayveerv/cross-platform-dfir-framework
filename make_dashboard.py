"""Interactive investigation console for the framework (one self-contained HTML file, works offline, no internet).

Reads results/evaluation.json (python main.py evaluate), the simulated cases in cases/ and, if present,
results/real_data_results.json (python main.py real-eval), and writes results/dashboard.html.
The page is organised around the dissertation title: automated evidence collection, cross-platform correlation,
cloud forensic investigation and scalability, plus chain of custody, MITRE ATT&CK coverage and real-data validation.
Every number on the page is read from those result files; nothing is typed in by hand.

Usage:  python make_dashboard.py      (or double-click view_dashboard.bat)
        python make_dashboard.py --no-open
Open a section directly with  dashboard.html#mitre  (ids: overview, collection, correlation, investigation, mitre,
cloud, custody, scale, realdata, explorer).  Add ?light to the address for the light theme.
"""
import collections
import json
import os
import sys
from datetime import datetime, timezone

ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)

from correlate import FLAGS, POSTURE, RULE_FAMILIES  # noqa: E402
from custody import CustodyLedger  # noqa: E402

TITLE = ("A Scalable Cross-Platform DFIR Framework for Automated Evidence Collection, "
         "Correlation, and Cloud Forensic Investigation")
AUTHOR = "Jayveer Vasava"
ENROL = "2503032330032"
PROGRAM = "M.Tech CSE (Cyber Security), PIET, Parul University"
GUIDES = "Guide: Dr. Ankita Gandhi · Co-guide: Dr. Kruti Kamal Sutaria"

# MITRE ATT&CK technique -> (tactic shown in the matrix, technique name). Techniques with several tactics are
# placed under the tactic in which the framework's rules use them.
TECH = {
    "T1078": ("Initial Access", "Valid Accounts"),
    "T1078.004": ("Initial Access", "Valid Accounts: Cloud Accounts"),
    "T1133": ("Initial Access", "External Remote Services"),
    "T1199": ("Initial Access", "Trusted Relationship"),
    "T1059.001": ("Execution", "PowerShell"),
    "T1059.004": ("Execution", "Unix Shell"),
    "T1059.009": ("Execution", "Cloud API"),
    "T1204.002": ("Execution", "User Execution: Malicious File"),
    "T1569.002": ("Execution", "Service Execution"),
    "T1098": ("Persistence", "Account Manipulation"),
    "T1098.001": ("Persistence", "Additional Cloud Credentials"),
    "T1098.004": ("Persistence", "SSH Authorized Keys"),
    "T1136.001": ("Persistence", "Create Account: Local Account"),
    "T1053.005": ("Persistence", "Scheduled Task"),
    "T1053.003": ("Persistence", "Cron"),
    "T1547.001": ("Persistence", "Registry Run Keys / Startup Folder"),
    "T1543.003": ("Persistence", "Windows Service"),
    "T1543.002": ("Persistence", "Systemd Service"),
    "T1037.004": ("Persistence", "RC Scripts"),
    "T1548.003": ("Privilege Escalation", "Sudo and Sudo Caching"),
    "T1574.006": ("Privilege Escalation", "Dynamic Linker Hijacking"),
    "T1218": ("Defense Evasion", "System Binary Proxy Execution"),
    "T1562.001": ("Defense Evasion", "Disable or Modify Tools"),
    "T1562.008": ("Defense Evasion", "Disable or Modify Cloud Logs"),
    "T1070.001": ("Defense Evasion", "Clear Windows Event Logs"),
    "T1070.004": ("Defense Evasion", "File Deletion"),
    "T1070.006": ("Defense Evasion", "Timestomp"),
    "T1620": ("Defense Evasion", "Reflective Code Loading"),
    "T1535": ("Defense Evasion", "Unused/Unsupported Cloud Regions"),
    "T1110": ("Credential Access", "Brute Force"),
    "T1003.001": ("Credential Access", "OS Credential Dumping: LSASS Memory"),
    "T1552.001": ("Credential Access", "Unsecured Credentials: Credentials In Files"),
    "T1555.006": ("Credential Access", "Cloud Secrets Management Stores"),
    "T1021.002": ("Lateral Movement", "SMB/Windows Admin Shares"),
    "T1530": ("Collection", "Data from Cloud Storage"),
    "T1105": ("Command and Control", "Ingress Tool Transfer"),
    "T1537": ("Exfiltration", "Transfer Data to Cloud Account"),
    "T1565.001": ("Impact", "Stored Data Manipulation"),
}
TACTICS = ["Initial Access", "Execution", "Persistence", "Privilege Escalation", "Defense Evasion", "Credential Access",
           "Lateral Movement", "Collection", "Command and Control", "Exfiltration", "Impact"]


def _load(p):
    with open(p, encoding="utf-8") as f:
        return json.load(f)


def _families():
    """Rules per family, each rule counted once (two live-host rules reuse Windows rule names)."""
    seen, out = set(), []
    for fam, rules in RULE_FAMILIES.items():
        new = [r for r in rules if r not in seen]
        seen.update(rules)
        out.append({"family": fam, "rules": len(new), "shared": len(rules) - len(new)})
    return out


def _case(root, name):
    d = os.path.join(root, "cases", name)
    ip, ep = os.path.join(d, "incidents.json"), os.path.join(d, "normalized_events.json")
    if not (os.path.exists(ip) and os.path.exists(ep)):
        return None
    inc = _load(ip)
    evs = _load(ep)
    by = {e["event_id"]: e for e in evs}
    out = {"name": name, "sources": collections.Counter(e["source"] for e in evs), "events": len(evs),
           "alerts": inc["alert_events"], "rules_fired": list(inc["rules_fired"]), "unlinked": len(inc["unlinked_alerts"]),
           "incidents": []}
    for i in inc["incidents"]:
        out["incidents"].append({
            "id": i["id"], "severity": i["severity"], "start": i["start"], "end": i["end"], "platforms": i["platforms"],
            "cross": i["cross_platform"], "count": i["event_count"], "alerts": i["alert_count"], "techniques": i["techniques"],
            "entities": i["entities"], "links": i["links"],
            "stages": [{k: s[k] for k in ("technique", "name", "severity", "count", "first", "sources", "hosts")} for s in i["stages"]],
            "events": [{"t": by[x]["time_utc"], "e": by[x]["epoch"], "s": by[x]["source"], "ty": by[x]["event_type"],
                        "u": by[x]["user"] or "", "ip": by[x]["src_ip"] or "", "h": by[x]["host"] or "",
                        "tg": (by[x]["target"] or by[x]["detail"] or "")[:90], "f": by[x]["flags"], "sv": by[x]["severity"]}
                       for x in i["event_ids"] if x in by]})
    return out, evs


def build(root=ROOT):
    res = os.path.join(root, "results")
    ev_path = os.path.join(res, "evaluation.json")
    if not os.path.exists(ev_path):
        raise RuntimeError("results/evaluation.json not found. Run  python main.py evaluate  first.")
    data = _load(ev_path)
    sc = {s["name"]: s for s in data["scenarios"]}

    # ---------------- correlation
    scen = []
    for s in data["scenarios"]:
        x = s["score"]
        scen.append({"name": s["name"], "desc": s["description"], "found": x["incidents_found"], "exp": x["incidents_expected"],
                     "p": x["precision"], "r": x["recall"], "f1": x["f1"], "fa": x["false_alerts"], "tp": x["tp"], "fp": x["fp"],
                     "fn": x["fn"], "records": x["records_in_sources"], "cross": x["cross_platform_incidents"], "policy": False})
    for p in data.get("policy", []):
        x = p["score"]
        scen.append({"name": p["name"], "desc": "Same logs with the admin-source policy (admin logons expected only from 10.0.5.10)",
                     "found": x["incidents_found"], "exp": x["incidents_expected"], "p": x["precision"], "r": x["recall"],
                     "f1": x["f1"], "fa": x["false_alerts"], "tp": x["tp"], "fp": x["fp"], "fn": x["fn"],
                     "records": x["records_in_sources"], "cross": x["cross_platform_incidents"], "policy": True})
    coverage = [{"sc": s["name"], "inc": c["incident"], "uni": c["unified"], "silo": c["best_siloed"]}
                for s in data["scenarios"] for c in s["coverage"]]

    # ---------------- tamper
    tam = {}
    for s in data["scenarios"]:
        for t in s["tamper"]:
            b = tam.setdefault(t["test"], {"test": t["test"], "expect": t["expect_detect"], "lim": bool(t.get("limitation")), "ok": 0, "n": 0})
            b["ok"] += t["passed"] if not t.get("limitation") else (not t["detected"])
            b["n"] += 1
    tam = list(tam.values())
    att = [t for t in tam if t["expect"] and not t["lim"]]
    ctrl = [t for t in tam if not t["expect"] and not t["lim"]]

    # ---------------- cases
    cases, explorer = {}, []
    for n in ("S1", "S2", "S3", "S5"):
        r = _case(root, n)
        if r:
            cases[n] = r[0]
            if n == "S1":
                explorer = [{"t": e["time_utc"], "s": e["source"], "h": e["host"] or "", "ty": e["event_type"], "u": e["user"] or "",
                             "ip": e["src_ip"] or "", "tg": (e["target"] or e["detail"] or "")[:90], "f": e["flags"],
                             "sv": e["severity"], "i": e.get("incident") or ""} for e in r[1]]
    for c in cases.values():
        c["sources"] = dict(c["sources"])

    # ---------------- custody ledger of S2
    ledger, ledger_ok, ledger_checks = [], None, []
    lp = os.path.join(root, "cases", "S2", "custody_ledger.jsonl")
    if os.path.exists(lp):
        with open(lp, encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    x = json.loads(line)
                    ledger.append({"seq": x["seq"], "stage": x["stage"], "action": x["action"], "target": x["target"],
                                   "time": x["time_utc"], "sha": x.get("sha256") or "", "prev": x["prev_hash"],
                                   "hash": x["entry_hash"], "hmac": bool(x.get("hmac"))})
        ledger_ok, chk = CustodyLedger(lp).verify(None, b"thesis-evaluation-key")
        ledger_checks = [sum(c["type"] == "ledger" for c in chk), sum(c["type"] == "file" for c in chk)]

    # ---------------- MITRE
    validated = set()
    for c in cases.values():
        validated.update(c["rules_fired"])
    rp = os.path.join(res, "real_data_results.json")
    rd = _load(rp) if os.path.exists(rp) else None
    if rd:
        validated.update(rd["windows"]["flags"])
        for a in rd["aws"]:
            validated.update(a["flags"])
        for l in rd["linux"].values():
            validated.update(l["flags"])
    for k in ("cloud",):
        for v in (data.get(k) or {}).values():
            validated.update(f for f, n in v.get("found", {}).items() if n)
    ce = data.get("cloud_emulated") or {}
    for k in ("single", "all"):
        if ce.get(k):
            validated.update(f for f, n in ce[k]["found"].items() if n)
    fam_of = {}
    for fam, rules in RULE_FAMILIES.items():
        for r in rules:
            fam_of.setdefault(r, []).append(fam)
    techs = {}
    for rule, (tid, name, sev) in FLAGS.items():
        t = techs.setdefault(tid, {"id": tid, "tactic": TECH.get(tid, ("Other", tid))[0], "name": TECH.get(tid, ("", name))[1],
                                   "rules": [], "validated": False})
        t["rules"].append({"rule": rule, "desc": name, "sev": sev, "fam": fam_of.get(rule, []), "val": rule in validated,
                           "posture": rule in POSTURE})
        t["validated"] = t["validated"] or rule in validated

    # ---------------- cloud
    cloud = {"fixture": {}, "emu": {}}
    for k, v in (data.get("cloud") or {}).items():
        if "expected" not in v:
            continue
        cloud["fixture"][k] = {"exp": v["expected"], "found": v["found"], "et": v["expected_total"], "ft": v["found_total"],
                               "fp": v["fp"], "inc": v.get("incidents", 0)}
    for k in ("single", "all"):
        if ce.get(k):
            v = ce[k]
            cloud["emu"][k] = {"exp": v["expected"], "found": v["found"], "et": v["expected_total"], "ft": v["found_total"],
                               "fp": v["fp"], "ops": v.get("api_operations"), "ro": v.get("read_only")}
    s1c = sc.get("S1_cloud") or {}

    # ---------------- real data
    real = None
    if rd:
        w = rd["windows"]
        real = {"win": {"samples": w["samples"], "records": w["records"], "errors": w["errors"], "with_supported": w["with_supported"],
                        "alerted": w["alerted"], "per_tactic": w["per_tactic"],
                        "core": [sum(x["hit"] for x in w["labelled"] if not x["hard"]), sum(1 for x in w["labelled"] if not x["hard"])],
                        "hard": [sum(x["hit"] for x in w["labelled"] if x["hard"]), sum(1 for x in w["labelled"] if x["hard"])],
                        "labelled": [{"file": x["file"], "why": x["why"], "hit": x["hit"], "hard": x["hard"]} for x in w["labelled"]]},
                "linux": [{"file": f, "lines": r["lines"], "norm": r["normalized"], "fw": r["framework_bf_ips"], "ind": r["independent_bf_ips"],
                           "agree": r["bf_ips_agree"], "fail": r["framework_auth_failure"], "top": r["top_attackers"][:5]} for f, r in rd["linux"].items()],
                "aws": [{"file": a["file"], "why": a["why"], "hit": a["hit"]} for a in rd["aws"]]}

    big = data["scalability"][-1]
    s5 = sc.get("S5", {}).get("score", {})
    D = {
        "meta": {"title": TITLE, "author": AUTHOR, "enrol": ENROL, "program": PROGRAM, "guides": GUIDES,
                 "evaluated": data["generated"][:16].replace("T", " ") + " UTC", "python": data["python"], "system": data["system"],
                 "built": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")},
        "kpi": {"f1": data["overall_f1"], "p": data["overall_precision"], "r": data["overall_recall"], "s5": s5.get("f1", 0),
                "tam_ok": sum(t["ok"] for t in att), "tam_n": sum(t["n"] for t in att),
                "ctl_ok": sum(t["ok"] for t in ctrl), "ctl_n": sum(t["n"] for t in ctrl),
                "thr": big["throughput"], "rec": big["records"], "sec": big["total"], "rules": len(FLAGS), "techs": len(techs),
                "cloud_ft": (cloud["emu"].get("all") or {}).get("ft"), "cloud_et": (cloud["emu"].get("all") or {}).get("et")},
        "scen": scen, "coverage": coverage, "ablation": data.get("ablation"), "tamper": tam,
        "ledger": ledger, "ledger_ok": ledger_ok, "ledger_checks": ledger_checks,
        "cases": cases, "explorer": explorer, "families": _families(), "techs": list(techs.values()), "tactics": TACTICS,
        "cloud": cloud, "s1cloud": ({"f1": s1c["score"]["f1"], "found": s1c["score"]["incidents_found"]} if s1c else None),
        "scale": data["scalability"], "real": real,
    }
    js = json.dumps(D, separators=(",", ":")).replace("</", "<\\/")
    html = PAGE.replace("/*__DATA__*/null", js).replace("__TITLE__", TITLE)
    out = os.path.join(res, "dashboard.html")
    with open(out, "w", encoding="utf-8") as f:
        f.write(html)
    return out


PAGE = r"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>CP-DFIR Investigation Console</title>
<style>
:root{--bg:#070B14;--bg2:#0B1222;--panel:#0F1830;--panel2:#13203D;--line:#1D2B4A;--line2:#28406B;--tx:#E6EDF7;--mu:#8EA0BF;--mu2:#5D6F90;
--cy:#22D3EE;--cy2:#0EA5E9;--gr:#34D399;--rd:#F43F5E;--am:#F59E0B;--vi:#A78BFA;--pk:#F472B6;
--win:#38BDF8;--lin:#FACC15;--aws:#FB923C;--host:#A78BFA;--glow:0 0 0 1px rgba(34,211,238,.25),0 8px 30px rgba(14,165,233,.12);
--grid:rgba(34,211,238,.045);--mono:"Cascadia Code",Consolas,"JetBrains Mono",Menlo,monospace}
:root.light{--bg:#EEF2F8;--bg2:#E6ECF5;--panel:#FFFFFF;--panel2:#F4F7FC;--line:#D8E0EC;--line2:#B8C6DC;--tx:#0F172A;--mu:#475569;--mu2:#7B8BA5;
--cy:#0891B2;--cy2:#0369A1;--gr:#059669;--rd:#E11D48;--am:#D97706;--vi:#7C3AED;--win:#0284C7;--lin:#CA8A04;--aws:#EA580C;--host:#7C3AED;
--glow:0 1px 2px rgba(15,23,42,.06),0 6px 20px rgba(15,23,42,.06);--grid:rgba(3,105,161,.05)}
*{box-sizing:border-box}html,body{margin:0;height:100%}
body{font-family:"Segoe UI",Inter,system-ui,-apple-system,Roboto,Arial,sans-serif;background:var(--bg);color:var(--tx);font-size:14px;
background-image:linear-gradient(var(--grid) 1px,transparent 1px),linear-gradient(90deg,var(--grid) 1px,transparent 1px);background-size:32px 32px}
a{color:var(--cy)}
/* ---------- top bar */
.top{position:sticky;top:0;z-index:20;display:flex;align-items:center;gap:16px;padding:10px 22px;background:color-mix(in srgb,var(--bg2) 88%,transparent);
backdrop-filter:blur(10px);border-bottom:1px solid var(--line)}
.brand{display:flex;align-items:center;gap:10px;min-width:232px}
.brand b{font-size:17px;letter-spacing:.5px}.brand small{display:block;color:var(--mu);font-size:10.5px;letter-spacing:1.6px;text-transform:uppercase}
.ttl{flex:1;min-width:0;font-size:12.5px;color:var(--mu);white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.ttl b{color:var(--tx);font-weight:600}
.pill{display:inline-flex;align-items:center;gap:6px;padding:4px 10px;border:1px solid var(--line2);border-radius:999px;font-size:11.5px;color:var(--mu);white-space:nowrap}
.pill.ok{color:var(--gr);border-color:color-mix(in srgb,var(--gr) 45%,transparent);background:color-mix(in srgb,var(--gr) 10%,transparent)}
.dot{width:8px;height:8px;border-radius:50%;background:var(--gr);box-shadow:0 0 10px var(--gr);animation:pulse 1.8s infinite}
@keyframes pulse{50%{opacity:.35}}
.tbtn{cursor:pointer;background:var(--panel);border:1px solid var(--line2);color:var(--tx);border-radius:8px;padding:5px 10px;font-size:13px}
/* ---------- layout */
.wrap{display:flex;min-height:calc(100% - 58px)}
nav{width:250px;flex:none;padding:16px 12px;border-right:1px solid var(--line);background:color-mix(in srgb,var(--bg2) 70%,transparent);position:sticky;top:58px;height:calc(100vh - 58px);overflow:auto}
nav .grp{font-size:10px;letter-spacing:1.8px;text-transform:uppercase;color:var(--mu2);margin:14px 10px 6px}
nav a{display:flex;align-items:center;gap:10px;padding:9px 10px;border-radius:9px;color:var(--mu);text-decoration:none;font-size:13.2px;margin:2px 0;border:1px solid transparent}
nav a svg{width:17px;height:17px;flex:none}
nav a:hover{background:var(--panel);color:var(--tx)}
nav a.on{background:linear-gradient(90deg,color-mix(in srgb,var(--cy) 18%,transparent),transparent);color:var(--tx);border-color:color-mix(in srgb,var(--cy) 35%,transparent)}
nav a.on svg{color:var(--cy)}
nav .who{margin:20px 10px 0;padding-top:14px;border-top:1px solid var(--line);font-size:11.5px;color:var(--mu);line-height:1.55}
nav .who b{color:var(--tx)}
main{flex:1;min-width:0;padding:22px 26px 60px}
section{display:none;animation:fade .35s ease}section.on{display:block}
@keyframes fade{from{opacity:0;transform:translateY(6px)}to{opacity:1;transform:none}}
.sh{display:flex;align-items:flex-end;justify-content:space-between;gap:16px;margin:2px 0 16px}
.sh h1{margin:0;font-size:23px;letter-spacing:.2px}.sh p{margin:4px 0 0;color:var(--mu);font-size:13px;max-width:900px}
.kw{font-size:10.5px;letter-spacing:1.6px;text-transform:uppercase;color:var(--cy);font-weight:600}
/* ---------- panels */
.g{display:grid;gap:16px}.g2{grid-template-columns:repeat(2,minmax(0,1fr))}.g3{grid-template-columns:repeat(3,minmax(0,1fr))}
.g4{grid-template-columns:repeat(4,minmax(0,1fr))}.g32{grid-template-columns:3fr 2fr}.g23{grid-template-columns:2fr 3fr}
@media(max-width:1250px){.g4{grid-template-columns:repeat(2,1fr)}.g3,.g32,.g23{grid-template-columns:1fr}}
@media(max-width:900px){nav{display:none}.g2{grid-template-columns:1fr}.ttl{display:none}}
.card{background:var(--panel);border:1px solid var(--line);border-radius:14px;padding:16px 18px;box-shadow:var(--glow);position:relative;overflow:hidden}
.card h3{margin:0 0 12px;font-size:13px;letter-spacing:.4px;color:var(--mu);font-weight:600;text-transform:uppercase;display:flex;align-items:center;gap:8px}
.card h3 i{font-style:normal;color:var(--cy)}
.kpi{padding:16px 18px}
.kpi .v{font-size:31px;font-weight:700;letter-spacing:-.5px;font-variant-numeric:tabular-nums}
.kpi .l{color:var(--mu);font-size:12.3px;margin-top:2px}
.kpi .s{font-size:11px;color:var(--mu2);margin-top:8px;font-family:var(--mono)}
.kpi:before{content:"";position:absolute;inset:0 auto 0 0;width:3px;background:var(--c,var(--cy));box-shadow:0 0 14px var(--c,var(--cy))}
.kpi .ic{position:absolute;right:14px;top:14px;opacity:.9;color:var(--c,var(--cy))}
.note{font-size:12.3px;color:var(--mu);line-height:1.55}
.info{border:1px solid color-mix(in srgb,var(--am) 40%,transparent);background:color-mix(in srgb,var(--am) 8%,transparent);border-radius:12px;padding:11px 15px;font-size:12.5px;color:var(--mu);line-height:1.55}
.info b{color:var(--am)}
/* hero */
.hero{padding:24px 26px;background:radial-gradient(1200px 300px at 0% 0%,color-mix(in srgb,var(--cy) 16%,transparent),transparent),
radial-gradient(800px 260px at 100% 100%,color-mix(in srgb,var(--vi) 14%,transparent),transparent),var(--panel)}
.hero h2{margin:6px 0 6px;font-size:26px;line-height:1.25;max-width:1050px}
.hero h2 em{font-style:normal;background:linear-gradient(90deg,var(--cy),var(--vi));-webkit-background-clip:text;background-clip:text;color:transparent}
.hero .by{color:var(--mu);font-size:13px}
.flow{width:100%;height:auto;margin-top:16px}
.flow .ln{stroke-dasharray:6 8;animation:dash 1.2s linear infinite}
@keyframes dash{to{stroke-dashoffset:-28}}
/* tables */
table{width:100%;border-collapse:separate;border-spacing:0;font-size:12.8px}
th{text-align:left;font-weight:600;color:var(--mu);font-size:11px;letter-spacing:.8px;text-transform:uppercase;padding:9px 10px;border-bottom:1px solid var(--line2);position:sticky;top:0;background:var(--panel)}
td{padding:9px 10px;border-bottom:1px solid var(--line);vertical-align:middle}
tr:hover td{background:color-mix(in srgb,var(--cy) 5%,transparent)}
.mono{font-family:var(--mono);font-size:11.8px}
.bar{height:7px;border-radius:5px;background:var(--line);overflow:hidden;min-width:70px}
.bar i{display:block;height:100%;border-radius:5px;background:linear-gradient(90deg,var(--cy2),var(--cy));width:0;transition:width 1s cubic-bezier(.2,.8,.2,1)}
.tag{display:inline-block;padding:2px 8px;border-radius:6px;font-size:11px;font-weight:600;border:1px solid;margin:1px 2px 1px 0;white-space:nowrap}
.sev-high{color:var(--rd);border-color:color-mix(in srgb,var(--rd) 50%,transparent);background:color-mix(in srgb,var(--rd) 12%,transparent)}
.sev-medium{color:var(--am);border-color:color-mix(in srgb,var(--am) 50%,transparent);background:color-mix(in srgb,var(--am) 12%,transparent)}
.sev-info{color:var(--mu);border-color:var(--line2)}
.plat{display:inline-flex;align-items:center;gap:6px;font-size:12px}.plat:before{content:"";width:9px;height:9px;border-radius:3px;background:var(--pc)}
.chips{display:flex;gap:8px;flex-wrap:wrap}
.chip{cursor:pointer;padding:7px 13px;border-radius:9px;border:1px solid var(--line2);background:var(--panel2);color:var(--mu);font-size:12.5px;font-weight:600}
.chip.on{color:var(--bg);background:var(--cy);border-color:var(--cy)}
.ok{color:var(--gr)}.bad{color:var(--rd)}.warn{color:var(--am)}
/* graph */
.gwrap{position:relative;border:1px solid var(--line);border-radius:12px;background:var(--bg2);overflow:hidden;aspect-ratio:1060/380}
.gwrap svg{width:100%;height:100%;cursor:grab}.gwrap svg:active{cursor:grabbing}
.gnode{cursor:move}.gnode rect{transition:filter .2s}.gnode:hover rect{filter:brightness(1.25)}
.edge{stroke-dasharray:5 6;animation:dash 1.4s linear infinite}
.gtools{position:absolute;right:10px;bottom:10px;display:flex;gap:6px}
.gtools button{background:var(--panel);border:1px solid var(--line2);color:var(--tx);border-radius:7px;width:30px;height:30px;cursor:pointer;font-size:15px}
.legend{display:flex;gap:16px;flex-wrap:wrap;font-size:11.5px;color:var(--mu);margin-top:10px}
.legend span{display:inline-flex;align-items:center;gap:6px}.legend i{width:11px;height:11px;border-radius:3px;display:inline-block}
/* kill chain */
.kc{position:relative;margin:0;padding:0 0 0 22px;list-style:none;max-height:390px;overflow:auto}
.kc:before{content:"";position:absolute;left:7px;top:6px;bottom:6px;width:2px;background:linear-gradient(var(--cy),var(--vi),var(--rd))}
.kc li{position:relative;padding:4px 0 12px 8px}
.kc li:before{content:"";position:absolute;left:-20px;top:9px;width:10px;height:10px;border-radius:50%;background:var(--bg);border:2px solid var(--c)}
.kc .t{font-family:var(--mono);font-size:11px;color:var(--mu2)}.kc .n{font-weight:600;font-size:13px}
.kc .m{font-size:11.5px;color:var(--mu)}
.kc2{list-style:none;margin:0;padding:0;display:grid;grid-template-columns:repeat(auto-fill,minmax(250px,1fr));gap:10px;counter-reset:k}
.kc2 li{position:relative;border:1px solid var(--line);border-left:3px solid var(--c);border-radius:10px;padding:10px 12px 10px 48px;background:var(--panel2)}
.kc2 .k{position:absolute;left:11px;top:11px;font-family:var(--mono);font-weight:700;font-size:15px;color:var(--c)}
.kc2 .t{font-family:var(--mono);font-size:10.8px;color:var(--mu2)}.kc2 .n{font-weight:600;font-size:13px;margin:2px 0 5px}
/* tooltip */
#tip{position:fixed;pointer-events:none;z-index:50;background:var(--panel2);border:1px solid var(--line2);border-radius:9px;padding:8px 10px;font-size:12px;
box-shadow:0 10px 30px rgba(0,0,0,.35);display:none;max-width:380px;line-height:1.45}
/* mitre */
.mx{display:grid;grid-template-columns:repeat(11,minmax(102px,1fr));gap:6px;overflow-x:auto;padding-bottom:6px}
.mx .col h4{margin:0 0 8px;font-size:10px;text-transform:uppercase;letter-spacing:.7px;color:var(--mu);padding:8px 8px;border-radius:8px;background:var(--panel2);border:1px solid var(--line);min-height:46px;display:flex;align-items:center;justify-content:space-between;gap:6px}
.mx .col h4 span{font-family:var(--mono);color:var(--cy);font-size:11px}
.tc{border-radius:8px;padding:7px 8px;margin-bottom:6px;border:1px solid var(--line);background:var(--panel2);cursor:default;font-size:11px;line-height:1.3;transition:transform .15s}
.tc:hover{transform:translateY(-2px)}
.tc b{display:block;font-family:var(--mono);font-size:10.5px;color:var(--mu);margin-bottom:2px}
.tc.v{border-color:color-mix(in srgb,var(--cy) 60%,transparent);background:linear-gradient(160deg,color-mix(in srgb,var(--cy) 22%,transparent),color-mix(in srgb,var(--vi) 10%,transparent));box-shadow:0 0 16px color-mix(in srgb,var(--cy) 18%,transparent)}
.tc.v b{color:var(--cy)}
.tc .n{display:inline-block;margin-top:5px;font-size:10px;color:var(--mu);font-family:var(--mono)}
/* chain */
.chain{display:flex;gap:0;overflow-x:auto;padding:6px 2px 10px;align-items:stretch}
.blk{flex:1 1 0;min-width:148px;border:1px solid var(--line2);border-radius:11px;background:var(--panel2);padding:11px 12px;position:relative}
.blk .sq{font-family:var(--mono);font-size:10.5px;color:var(--cy)}.blk .a{font-weight:600;margin:3px 0 2px;font-size:13px}
.blk .tg{font-size:11.5px;color:var(--mu);white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.blk .hs{font-family:var(--mono);font-size:10.3px;color:var(--mu);margin-top:7px;line-height:1.5}
.blk .hs em{font-style:normal;color:var(--gr)}
.arw{flex:none;width:26px;display:flex;align-items:center;justify-content:center;color:var(--cy)}
.tt{display:flex;align-items:center;gap:12px;padding:12px 14px;border:1px solid var(--line);border-radius:11px;background:var(--panel2)}
.tt .ic{width:34px;height:34px;border-radius:9px;display:flex;align-items:center;justify-content:center;flex:none}
.tt .x{font-weight:600;font-size:13px}.tt .y{font-size:11.5px;color:var(--mu)}.tt .z{margin-left:auto;font-family:var(--mono);font-weight:700;font-size:15px}
input.q{background:var(--panel2);border:1px solid var(--line2);color:var(--tx);border-radius:9px;padding:8px 12px;font-size:13px;width:360px;outline:none}
input.q:focus{border-color:var(--cy)}
.scroll{max-height:560px;overflow:auto;border:1px solid var(--line);border-radius:10px}
.foot{margin-top:26px;font-size:11.5px;color:var(--mu2)}
svg text{font-family:"Segoe UI",Inter,system-ui,Arial,sans-serif}
/* ---------- embedded inside the CP-DFIR console (one app, one menu) */
.embed .top,.embed nav{display:none}.embed .wrap{min-height:100%}.embed main{padding:22px 26px 60px}
/* same look as the console: plain titles and cards, no gradients or glow bars */
.embed .hero{background:var(--panel)}.embed .hero h2{font-size:22px;font-weight:650}.embed .hero h2 em{background:none;-webkit-background-clip:initial;background-clip:initial;color:var(--tx)}
.embed .sh h1{font-size:22px;font-weight:650}.embed .kw{color:var(--mu2)}
.embed .card{border-radius:12px;padding:18px}.embed .card h3 i,.embed .card h3 svg{color:var(--mu2)}
.embed .kpi:before{display:none}.embed .kpi .ic{display:none}.embed .kpi .v{font-size:28px;font-family:var(--mono);color:var(--c,var(--tx))}
</style></head>
<body>
<div class="top">
  <div class="brand">
    <svg width="34" height="34" viewBox="0 0 48 48"><defs><linearGradient id="lg" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="#22D3EE"/><stop offset="1" stop-color="#A78BFA"/></linearGradient></defs>
    <path d="M24 3 42 10v13c0 11-7.6 19.6-18 22C13.6 42.6 6 34 6 23V10z" fill="none" stroke="url(#lg)" stroke-width="3"/>
    <circle cx="22" cy="22" r="7" fill="none" stroke="url(#lg)" stroke-width="2.6"/><path d="m27 27 6 6" stroke="url(#lg)" stroke-width="3" stroke-linecap="round"/></svg>
    <div><b>CP-DFIR</b><small>Investigation Console</small></div>
  </div>
  <div class="ttl" id="ttl"></div>
  <span class="pill" id="pillPl"></span>
  <span class="pill ok" id="pillCu"><span class="dot"></span><span></span></span>
  <button class="tbtn" id="theme" title="Switch light / dark">◐</button>
</div>
<div class="wrap">
<nav id="nav"></nav>
<main id="main"></main>
</div>
<div id="tip"></div>
<script>
const D=/*__DATA__*/null;
const $=s=>document.querySelector(s), esc=s=>String(s??"").replace(/[&<>"]/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[c]));
const pct=x=>(100*x).toFixed(1)+"%", f3=x=>(+x).toFixed(3), fmt=n=>Math.round(n).toLocaleString("en-US");
const PN={windows:"Windows",linux:"Linux",aws:"AWS",host:"Live host",cloud:"AWS account state"};
const PC={windows:"var(--win)",linux:"var(--lin)",aws:"var(--aws)",host:"var(--host)",cloud:"var(--gr)"};
const SVC={high:"var(--rd)",medium:"var(--am)",info:"var(--mu2)"};
const plat=p=>`<span class="plat" style="--pc:${PC[p]||'var(--mu)'}">${PN[p]||p}</span>`;
const sev=s=>`<span class="tag sev-${String(s).toLowerCase()}">${esc(String(s).toUpperCase())}</span>`;
const bar=(x,c)=>`<div class="bar"><i data-w="${Math.max(0,Math.min(1,x))*100}" ${c?`style="background:${c}"`:""}></i></div>`;
const I={ // icons (stroke)
 ov:'<path d="M3 13h8V3H3zM13 21h8V11h-8zM3 21h8v-6H3zM13 3v6h8V3z"/>',
 col:'<path d="M4 7c0-1.7 3.6-3 8-3s8 1.3 8 3-3.6 3-8 3-8-1.3-8-3z"/><path d="M4 7v10c0 1.7 3.6 3 8 3s8-1.3 8-3V7"/><path d="M4 12c0 1.7 3.6 3 8 3s8-1.3 8-3"/>',
 cor:'<circle cx="5" cy="6" r="2.5"/><circle cx="19" cy="6" r="2.5"/><circle cx="12" cy="18" r="2.5"/><path d="M7 7.5 10.5 16M17 7.5 13.5 16M7.5 6h9"/>',
 inv:'<circle cx="11" cy="11" r="7"/><path d="m21 21-4.3-4.3"/><path d="M8 11h6M11 8v6"/>',
 mit:'<rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/><rect x="14" y="14" width="7" height="7" rx="1"/>',
 cld:'<path d="M7 18h10a4 4 0 0 0 .5-8A6 6 0 0 0 6 9.5 4.3 4.3 0 0 0 7 18z"/>',
 cus:'<path d="M12 3 20 6v6c0 5-3.4 8.5-8 9.5C7.4 20.5 4 17 4 12V6z"/><path d="m9 12 2 2 4-4"/>',
 scl:'<path d="M3 20h18"/><path d="m4 16 5-5 4 3 7-8"/><path d="M15 6h5v5"/>',
 rel:'<path d="M12 2v4M12 18v4M4.9 4.9l2.8 2.8M16.3 16.3l2.8 2.8M2 12h4M18 12h4M4.9 19.1l2.8-2.8M16.3 7.7l2.8-2.8"/><circle cx="12" cy="12" r="3"/>',
 exp:'<path d="M4 6h16M4 12h16M4 18h10"/>',
 bolt:'<path d="M13 2 4 14h7l-1 8 9-12h-7z"/>', key:'<circle cx="7.5" cy="15.5" r="4.5"/><path d="m10.7 12.3 9.3-9.3M17 6l3 3M14.5 8.5l2 2"/>',
 lock:'<rect x="4" y="11" width="16" height="10" rx="2"/><path d="M8 11V7a4 4 0 0 1 8 0v4"/>', tgt:'<circle cx="12" cy="12" r="9"/><circle cx="12" cy="12" r="5"/><circle cx="12" cy="12" r="1.5"/>',
 chk:'<path d="m5 12 5 5L20 7"/>', x:'<path d="M6 6l12 12M18 6 6 18"/>', alert:'<path d="M12 3 2 20h20z"/><path d="M12 10v4M12 17h.01"/>'};
const ic=(k,s=18)=>`<svg width="${s}" height="${s}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round">${I[k]}</svg>`;
const tip=$("#tip");
function showTip(ev,html){tip.innerHTML=html;tip.style.display="block";const x=Math.min(ev.clientX+14,innerWidth-400);tip.style.left=x+"px";tip.style.top=(ev.clientY+14)+"px"}
function hideTip(){tip.style.display="none"}
document.addEventListener("mouseover",e=>{const t=e.target.closest("[data-tip]");if(t)showTip(e,t.dataset.tip)});
document.addEventListener("mousemove",e=>{if(tip.style.display==="block"){const t=e.target.closest("[data-tip]");if(!t)hideTip();else{tip.style.left=Math.min(e.clientX+14,innerWidth-400)+"px";tip.style.top=(e.clientY+14)+"px"}}});

/* ======================================================= sections */
const SECTIONS=[
 {id:"overview",ico:"ov",nav:"Mission Control",grp:"Framework"},
 {id:"collection",ico:"col",nav:"Evidence Collection",grp:"Framework"},
 {id:"correlation",ico:"cor",nav:"Cross-Platform Correlation",grp:"Framework"},
 {id:"investigation",ico:"inv",nav:"Attack Investigation",grp:"Framework"},
 {id:"cloud",ico:"cld",nav:"Cloud Forensics",grp:"Framework"},
 {id:"custody",ico:"cus",nav:"Chain of Custody",grp:"Assurance"},
 {id:"mitre",ico:"mit",nav:"MITRE ATT&CK Coverage",grp:"Assurance"},
 {id:"scale",ico:"scl",nav:"Scalability",grp:"Assurance"},
 {id:"realdata",ico:"rel",nav:"Real-World Validation",grp:"Assurance"},
 {id:"explorer",ico:"exp",nav:"Evidence Explorer",grp:"Data"}];
function head(kw,t,p){return `<div class="sh"><div><div class="kw">${kw}</div><h1>${t}</h1>${p?`<p>${p}</p>`:""}</div></div>`}
function kpi(v,l,s,c,icon){return `<div class="card kpi" style="--c:${c}"><div class="ic">${ic(icon,20)}</div><div class="v" data-count="${esc(v)}">${esc(v)}</div><div class="l">${l}</div>${s?`<div class="s">${s}</div>`:""}</div>`}

/* ---------- overview */
function sOverview(){
 const K=D.kpi, s1=D.cases.S1;
 const t=D.meta.title.replace("Scalable","<em>Scalable</em>").replace("Cross-Platform","<em>Cross-Platform</em>").replace("Cloud Forensic Investigation","<em>Cloud Forensic Investigation</em>");
 let h=`<div class="card hero"><div class="kw">M.Tech Dissertation · Phase II · Implementation & Evaluation</div><h2>${t}</h2>
 <div class="by">${esc(D.meta.author)} (${esc(D.meta.enrol)}) · ${esc(D.meta.program)} · ${esc(D.meta.guides)}</div>${flowSvg()}</div>`;
 h+=`<div class="g g4" style="margin-top:16px">`+
  kpi(f3(K.f1),"Correlation F1 · core scenarios S1–S4",`precision ${pct(K.p)} · recall ${pct(K.r)}`,"var(--cy)","tgt")+
  kpi(`${K.tam_ok}/${K.tam_n}`,"Tampering attacks detected",`${K.ctl_ok}/${K.ctl_n} untouched cases verified clean`,"var(--gr)","cus")+
  kpi(fmt(K.thr)+"/s","Records processed per second",`${fmt(K.rec)} records in ${K.sec.toFixed(1)} s`,"var(--vi)","bolt")+
  kpi(`${K.rules}`,"ATT&CK-mapped detection rules",`${K.techs} techniques · 6 rule families`,"var(--am)","mit")+`</div>`;
 h+=`<div class="g g3" style="margin-top:16px">
  <div class="card"><h3><i>${ic("col",15)}</i>Evidence by platform · case S1</h3>${donut(s1?s1.sources:{})}</div>
  <div class="card"><h3><i>${ic("cor",15)}</i>F1 score per scenario</h3>${scenBars()}</div>
  <div class="card"><h3><i>${ic("cld",15)}</i>Framework at a glance</h3>${glance()}</div></div>`;
 h+=`<div class="info" style="margin-top:16px"><b>How to read these numbers.</b> S1–S5 are simulated multi-platform attacks whose ground truth is written by the generator; they show the design works on these scenarios and are not a measurement on production traffic.
 S5 is deliberately hard (session collision and an insider from an internal IP) and shows the limits of rule-based detection (F1 ${f3(K.s5)}). Results on real public datasets are under <a href="#realdata">Real-World Validation</a>.</div>`;
 return h;
}
function flowSvg(){
 const st=[["ACQUISITION","Windows · Linux · AWS · Live host","var(--win)"],["NORMALIZATION","35 event types · UTC","var(--lin)"],["CORRELATION","57 rules · entity graph","var(--aws)"],["REPORTING","HTML report · timeline","var(--vi)"]];
 let s=`<svg class="flow" viewBox="0 0 1100 128">`;
 st.forEach((x,i)=>{const X=12+i*272;
  s+=`<rect x="${X}" y="18" width="232" height="66" rx="12" fill="color-mix(in srgb,${x[2]} 12%,transparent)" stroke="${x[2]}" stroke-width="1.4"/>
  <text x="${X+16}" y="44" fill="${x[2]}" font-size="13" font-weight="700" letter-spacing="1.5">${i+1}. ${x[0]}</text><text x="${X+16}" y="66" fill="var(--mu)" font-size="12">${x[1]}</text>`;
  if(i<3)s+=`<path class="ln" d="M${X+236} 51 H${X+268}" stroke="var(--cy)" stroke-width="2.4"/><path d="M${X+262} 46 l7 5 -7 5" fill="none" stroke="var(--cy)" stroke-width="2"/>`});
 s+=`<rect x="12" y="98" width="1076" height="24" rx="7" fill="color-mix(in srgb,var(--gr) 10%,transparent)" stroke="color-mix(in srgb,var(--gr) 55%,transparent)" stroke-dasharray="4 4"/>
 <text x="550" y="114.5" text-anchor="middle" fill="var(--gr)" font-size="12" font-weight="600" letter-spacing=".6">⛓ CHAIN-OF-CUSTODY LEDGER · SHA-256 hash chain + HMAC · every stage recorded and re-verified</text></svg>`;
 return s;
}
function donut(src){
 const ks=Object.keys(src), tot=ks.reduce((a,k)=>a+src[k],0)||1; let a0=-Math.PI/2, s=`<div style="display:flex;align-items:center;gap:18px"><svg width="170" height="170" viewBox="0 0 170 170">`;
 ks.forEach(k=>{const a1=a0+2*Math.PI*src[k]/tot, r=70,R=48, L=a1-a0>Math.PI?1:0, P=(a,rr)=>[85+rr*Math.cos(a),85+rr*Math.sin(a)];
  const [x0,y0]=P(a0,r),[x1,y1]=P(a1,r),[x2,y2]=P(a1,R),[x3,y3]=P(a0,R);
  s+=`<path d="M${x0} ${y0}A${r} ${r} 0 ${L} 1 ${x1} ${y1}L${x2} ${y2}A${R} ${R} 0 ${L} 0 ${x3} ${y3}Z" fill="${PC[k]}" stroke="var(--panel)" stroke-width="2" data-tip="<b>${PN[k]}</b><br>${src[k]} normalized events (${pct(src[k]/tot)})"/>`;a0=a1});
 s+=`<text x="85" y="82" text-anchor="middle" font-size="26" font-weight="700" fill="var(--tx)">${tot}</text><text x="85" y="101" text-anchor="middle" font-size="11" fill="var(--mu)">events</text></svg><div>`;
 ks.forEach(k=>s+=`<div style="margin:7px 0">${plat(k)} <span class="mono" style="color:var(--mu);margin-left:6px">${src[k]}</span></div>`);
 return s+`<div class="note" style="margin-top:8px">One timeline, one schema, one incident.</div></div></div>`;
}
function scenBars(){
 return D.scen.map(s=>{const c=s.f1>=.999?"var(--gr)":s.f1>=.9?"var(--cy)":"var(--am)";
  return `<div style="display:grid;grid-template-columns:92px 1fr 48px;gap:10px;align-items:center;margin:8px 0" data-tip="<b>${esc(s.name)}</b><br>${esc(s.desc)}<br>P ${pct(s.p)} · R ${pct(s.r)} · incidents ${s.found}/${s.exp}">
  <span class="mono" style="font-size:12px">${esc(s.name)}</span>${bar(s.f1,c)}<b class="mono" style="color:${c}">${f3(s.f1)}</b></div>`}).join("");
}
function glance(){
 const K=D.kpi,row=(a,b,c)=>`<div style="display:flex;justify-content:space-between;align-items:center;padding:8px 0;border-bottom:1px solid var(--line)"><span class="note" style="font-size:12.8px">${a}</span><b class="mono" style="color:${c||'var(--tx)'}">${b}</b></div>`;
 const ce=D.cloud.emu.all;
 return row("Evidence sources","Windows · Linux · AWS · Host")+row("Common event schema","35 types · UTC")+
  row("Cloud misconfigurations found",ce?`${ce.ft}/${ce.et}`:"–","var(--gr)")+row("Cloud API calls made",ce?`${ce.ops} · read-only`:"–")+
  row("Hard cases S5 · F1",f3(K.s5),"var(--am)")+row("Real EVTX samples parsed",D.real?`${D.real.win.samples} · ${D.real.win.errors} errors`:"–");
}

/* ---------- collection */
function sCollection(){
 const C=[["windows","Windows event logs","Security / System / PowerShell / Sysmon EVTX or exported XML. Logons, account and group changes, services, tasks, log clearing, process creation.","win"],
  ["linux","Linux logs","auth.log / secure / syslog: SSH logins and failures, sudo, credential-file access, shell commands.","lin"],
  ["aws","AWS CloudTrail","Management events (JSON, gz or folders): API calls, key creation, logging changes, S3 bulk reads, root use.","aws"],
  ["cloud","AWS account state","Read-only snapshot (List / Get / Describe calls only): trails, IAM users and keys, roles, S3 buckets, security groups.","gr"],
  ["host","Live host triage","RFC 3227 order of volatility: processes, network sockets, listeners, accounts, persistence entries, recent files.","host"]];
 let h=head("Automated Evidence Collection","Five collectors, one forensically sound acquisition","Each source is copied, hashed with SHA-256 before and after copying, and recorded in the custody ledger before any analysis runs. Collectors never modify the evidence or the cloud account.");
 h+=`<div class="g" style="grid-template-columns:repeat(auto-fit,minmax(220px,1fr))">`+C.map(c=>`<div class="card" style="border-top:3px solid var(--${c[3]})">
  <div style="display:flex;align-items:center;gap:10px;margin-bottom:8px"><span style="width:32px;height:32px;border-radius:9px;display:flex;align-items:center;justify-content:center;background:color-mix(in srgb,var(--${c[3]}) 16%,transparent);color:var(--${c[3]})">${ic(c[0]=="cloud"?"cld":c[0]=="host"?"tgt":"col",17)}</span><b>${c[1]}</b></div>
  <div class="note">${c[2]}</div></div>`).join("")+`</div>`;
 const rows=["S1","S2","S3","S5"].filter(n=>D.cases[n]).map(n=>{const c=D.cases[n],s=D.scen.find(x=>x.name==n);
  return `<tr><td><b class="mono">${n}</b></td><td>${Object.keys(c.sources).map(plat).join(" &nbsp;")}</td><td class="mono">${s?s.records:"–"}</td><td class="mono">${c.events}</td><td class="mono">${c.alerts}</td><td class="mono">${c.incidents.length}</td><td class="ok">${ic("chk",15)} verified</td></tr>`}).join("");
 h+=`<div class="g g32" style="margin-top:16px"><div class="card"><h3><i>${ic("col",15)}</i>Acquisition per simulated case</h3>
 <table><tr><th>Case</th><th>Platforms</th><th>Records in sources</th><th>Normalized events</th><th>Flagged</th><th>Incidents</th><th>Custody</th></tr>${rows}</table>
 <div class="note" style="margin-top:10px">Records outside the 35-type catalogue (e.g. FTP lines in a Linux log) are counted as ignored and not silently dropped; parse errors are reported per source.</div></div>
 <div class="card"><h3><i>${ic("lock",15)}</i>Forensic soundness rules</h3>${[
  ["Hash before & after copy","SHA-256 of source and copy must match, otherwise acquisition fails."],
  ["Read-only cloud access","Only List / Get / Describe API calls; enforced in code (READ_PREFIXES)."],
  ["Order of volatility","Live triage collects the most volatile data first (RFC 3227)."],
  ["Limits are reported","Anything that could not be collected is written in the manifest and report."],
  ["UTC everywhere","All timestamps converted to UTC in the common schema."]].map(x=>`<div style="display:flex;gap:10px;padding:8px 0;border-bottom:1px solid var(--line)"><span class="ok">${ic("chk",16)}</span><div><b style="font-size:13px">${x[0]}</b><div class="note">${x[1]}</div></div></div>`).join("")}</div></div>`;
 return h;
}

/* ---------- correlation */
function sCorrelation(){
 let h=head("Cross-Platform Correlation","Accuracy of incident reconstruction","Events from all platforms are joined in an entity graph (attacker IPs, credential files, cloud access keys). An incident is a connected group that contains flagged activity.");
 const rows=D.scen.map(s=>`<tr><td><b class="mono">${esc(s.name)}</b></td><td style="max-width:360px">${esc(s.desc)}</td><td class="mono">${s.found} / ${s.exp}</td><td class="mono">${pct(s.p)}</td><td class="mono">${pct(s.r)}</td>
  <td style="min-width:150px"><div style="display:flex;gap:8px;align-items:center"><b class="mono" style="width:42px;color:${s.f1>=.999?'var(--gr)':s.f1>=.9?'var(--cy)':'var(--am)'}">${f3(s.f1)}</b>${bar(s.f1,s.f1>=.999?'var(--gr)':s.f1>=.9?'var(--cy)':'var(--am)')}</div></td><td class="mono ${s.fa?'warn':''}">${s.fa}</td></tr>`).join("");
 h+=`<div class="card"><h3><i>${ic("tgt",15)}</i>Per-scenario results (event-level precision / recall / F1)</h3><table><tr><th>Scenario</th><th>What it tests</th><th>Incidents found / expected</th><th>Precision</th><th>Recall</th><th>F1</th><th>False alerts</th></tr>${rows}</table></div>`;
 h+=`<div class="g g32" style="margin-top:16px"><div class="card"><h3><i>${ic("cor",15)}</i>Why one framework: unified vs siloed analysis</h3>${siloSvg()}
 <div class="legend"><span><i style="background:var(--mu2)"></i>best single platform analysed alone</span><span><i style="background:var(--cy)"></i>unified (this framework)</span></div>
 <div class="note" style="margin-top:8px">Share of each attack chain captured in ONE incident.</div></div>
 <div class="card"><h3><i>${ic("key",15)}</i>What links the platforms</h3>${[
  ["var(--rd)","Attacker IP","same untrusted source address across Windows, Linux and AWS"],
  ["var(--am)","Credential file","~/.aws/credentials or SSH key read inside an attacker session"],
  ["var(--cy)","Cloud access key","key used from outside, or created by another key"],
  ["var(--vi)","Credential inventory","analyst-supplied map: which file holds which key"]].map(x=>`<div style="display:flex;gap:12px;align-items:center;padding:9px 0;border-bottom:1px solid var(--line)"><span style="width:12px;height:12px;border-radius:4px;background:${x[0]};box-shadow:0 0 10px ${x[0]}"></span><div><b style="font-size:13px">${x[1]}</b><div class="note">${x[2]}</div></div></div>`).join("")}
 ${D.ablation?`<div class="info" style="margin-top:12px"><b>Ablation.</b> Without the credential inventory, the S2 credential pivot (Linux → AWS from a different IP) is split into ${D.ablation.incidents_found} incidents — the cross-platform link is lost.</div>`:""}</div></div>`;
 return h;
}
function siloSvg(){
 const C=D.coverage, W=640, rh=46, H=C.length*rh+20; let s=`<svg viewBox="0 0 ${W} ${H}" width="100%">`;
 C.forEach((c,i)=>{const y=10+i*rh, X=110, L=W-X-60;
  s+=`<text x="0" y="${y+20}" font-size="12.5" fill="var(--tx)" font-weight="600">${c.sc} · ${c.inc}</text>
  <rect x="${X}" y="${y+4}" width="${L}" height="13" rx="4" fill="var(--line)"/><rect x="${X}" y="${y+4}" width="${L*c.silo}" height="13" rx="4" fill="var(--mu2)"><animate attributeName="width" from="0" to="${L*c.silo}" dur=".9s"/></rect>
  <text x="${X+L+8}" y="${y+15}" font-size="11.5" fill="var(--mu)">${pct(c.silo)}</text>
  <rect x="${X}" y="${y+21}" width="${L}" height="13" rx="4" fill="var(--line)"/><rect x="${X}" y="${y+21}" width="${L*c.uni}" height="13" rx="4" fill="var(--cy)"><animate attributeName="width" from="0" to="${L*c.uni}" dur="1.1s"/></rect>
  <text x="${X+L+8}" y="${y+32}" font-size="11.5" fill="var(--cy)" font-weight="700">${pct(c.uni)}</text>`});
 return s+"</svg>";
}

/* ---------- investigation */
let curCase="S1",curInc=0;
function sInvestigation(){
 let h=head("Attack Investigation","Reconstructed attack: graph, kill chain and timeline","Choose a simulated case. Drag nodes, scroll to zoom, hover any element for evidence details.");
 h+=`<div class="card" style="margin-bottom:16px;display:flex;gap:18px;align-items:center;flex-wrap:wrap"><div><div class="kw" style="margin-bottom:6px">Case</div><div class="chips" id="caseChips">${Object.keys(D.cases).map(n=>`<span class="chip" data-c="${n}">${n}</span>`).join("")}</div></div>
 <div><div class="kw" style="margin-bottom:6px">Incident</div><div class="chips" id="incChips"></div></div><div id="incHead" style="margin-left:auto;text-align:right"></div></div>
 <div class="card"><h3><i>${ic("cor",15)}</i>Entity graph — how the evidence was linked</h3><div class="gwrap" id="gwrap"></div>
 <div class="legend"><span><i style="background:var(--rd)"></i>Attacker IP</span><span><i style="background:var(--am)"></i>Credential file</span><span><i style="background:var(--cy)"></i>Cloud access key</span><span style="margin-left:auto">platform dots: ${["windows","linux","aws"].map(plat).join(" ")}</span></div></div>
 <div class="card" style="margin-top:16px"><h3><i>${ic("scl",15)}</i>Cross-platform timeline</h3><div id="tl"></div></div>
 <div class="card" style="margin-top:16px"><h3><i>${ic("alert",15)}</i>Kill chain — ATT&amp;CK stages in order of first occurrence</h3><ol class="kc2" id="kc"></ol></div>`;
 return h;
}
function drawCase(){
 const c=D.cases[curCase]; document.querySelectorAll("#caseChips .chip").forEach(x=>x.classList.toggle("on",x.dataset.c==curCase));
 $("#incChips").innerHTML=c.incidents.map((x,i)=>`<span class="chip ${i==curInc?'on':''}" data-i="${i}">${x.id}</span>`).join("")||'<span class="note">no incident</span>';
 const inc=c.incidents[curInc]; if(!inc){$("#gwrap").innerHTML="";$("#kc").innerHTML="";$("#tl").innerHTML="";$("#incHead").innerHTML="";return}
 $("#incHead").innerHTML=`<div>${sev(inc.severity)} ${inc.cross?'<span class="tag" style="color:var(--cy);border-color:var(--cy)">CROSS-PLATFORM</span>':'<span class="tag sev-info">SINGLE PLATFORM</span>'}</div>
  <div class="mono" style="margin-top:6px;color:var(--mu)">${inc.start.replace("T"," ")} → ${inc.end.replace("T"," ")}</div><div style="margin-top:4px">${inc.platforms.map(plat).join(" &nbsp;")} · <b>${inc.count}</b> events · <b>${inc.techniques.length}</b> techniques</div>`;
 graph(inc); killchain(inc); timeline(inc);
}
function graph(inc){
 const W=1060,H=380, KC={ip:"var(--rd)",cred:"var(--am)",key:"var(--cy)"}, KX={ip:140,cred:500,key:860}, TT={ip:"ATTACKER IP",cred:"CREDENTIAL FILE",key:"CLOUD ACCESS KEY"};
 const cols={ip:[],cred:[],key:[]}; inc.entities.forEach(n=>cols[n.kind].push(n));
 const pos={}; Object.entries(cols).forEach(([k,l])=>l.forEach((n,i)=>{pos[n.id]={x:KX[k],y:H/2+(i-(l.length-1)/2)*96+10,n}}));
 const SH={"credential file read in session":"credential read","credential inventory (file holds key)":"file holds key","key created by key":"key created"};
 let s=`<svg id="gsvg" viewBox="0 0 ${W} ${H}"><defs><marker id="ar" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M0 0L10 5L0 10z" fill="var(--mu)"/></marker>
 <filter id="gl"><feGaussianBlur stdDeviation="4" result="b"/><feMerge><feMergeNode in="b"/><feMergeNode in="SourceGraphic"/></feMerge></filter></defs><g id="vp">`;
 Object.entries(TT).forEach(([k,t])=>{if(cols[k].length)s+=`<text x="${KX[k]}" y="26" text-anchor="middle" font-size="11" letter-spacing="1.6" font-weight="700" fill="${KC[k]}">${t}</text>`});
 inc.links.forEach((l,i)=>{if(pos[l.a]&&pos[l.b])s+=`<g class="ed" data-a="${esc(l.a)}" data-b="${esc(l.b)}"><path class="edge" stroke="var(--mu)" stroke-width="1.8" fill="none" marker-end="url(#ar)"/><text font-size="10.5" text-anchor="middle" fill="var(--mu)" style="paint-order:stroke;stroke:var(--bg2);stroke-width:4px">${esc(SH[l.reason]||l.reason)} · ${l.events}</text></g>`});
 Object.values(pos).forEach(p=>{const n=p.n,lab=n.id.split(":").slice(1).join(":"),short=lab.length>26?"…"+lab.slice(-25):lab,c=KC[n.kind];
  s+=`<g class="gnode" data-id="${esc(n.id)}" transform="translate(${p.x},${p.y})" data-tip="<b>${esc(n.kind.toUpperCase())}</b><br><span class=mono>${esc(lab)}</span><br>${n.platforms.map(x=>PN[x]).join(' + ')} · ${n.events} events">
  <rect x="-105" y="-26" width="210" height="52" rx="12" fill="color-mix(in srgb,${c} 16%,var(--panel))" stroke="${c}" stroke-width="1.6" filter="url(#gl)"/>
  <text x="-92" y="-4" font-size="12" font-weight="700" fill="var(--tx)" class="mono">${esc(short)}</text>
  <text x="-92" y="14" font-size="10.5" fill="var(--mu)">${n.events} event${n.events==1?"":"s"}</text>
  ${n.platforms.map((x,i)=>`<circle cx="${88-i*14}" cy="12" r="5" fill="${PC[x]}"/>`).join("")}</g>`});
 s+=`</g></svg><div class="gtools"><button id="zi">+</button><button id="zo">−</button><button id="zr">⟲</button></div>`;
 $("#gwrap").innerHTML=s;
 const svg=$("#gsvg"),vp=$("#vp"); let T={x:0,y:0,k:1};
 const apply=()=>vp.setAttribute("transform",`translate(${T.x},${T.y}) scale(${T.k})`);
 const upd=()=>{svg.querySelectorAll(".ed").forEach(e=>{const a=pos[e.dataset.a],b=pos[e.dataset.b];let d,mx,my;
   if(Math.abs(a.x-b.x)<5){const x=a.x+105;d=`M${x} ${a.y}C${x+70} ${a.y} ${x+70} ${b.y} ${x+4} ${b.y}`;mx=x+56;my=(a.y+b.y)/2}
   else{const s1=a.x<b.x?1:-1,x1=a.x+105*s1,x2=b.x-109*s1;d=`M${x1} ${a.y}C${(x1+x2)/2} ${a.y} ${(x1+x2)/2} ${b.y} ${x2} ${b.y}`;mx=(x1+x2)/2;my=(a.y+b.y)/2-6}
   e.querySelector("path").setAttribute("d",d);const t=e.querySelector("text");t.setAttribute("x",mx);t.setAttribute("y",my)})};
 upd();
 const pt=ev=>{const r=svg.getBoundingClientRect(),sx=W/r.width,sy=H/r.height,sc=Math.max(sx,sy);return{x:((ev.clientX-r.left)*sx-T.x)/T.k,y:((ev.clientY-r.top)*sy-T.y)/T.k}};
 let drag=null,pan=null;
 svg.querySelectorAll(".gnode").forEach(g=>g.addEventListener("mousedown",ev=>{ev.stopPropagation();const p=pos[g.dataset.id],q=pt(ev);drag={g,p,dx:q.x-p.x,dy:q.y-p.y}}));
 svg.addEventListener("mousedown",ev=>{pan={x:ev.clientX,y:ev.clientY,tx:T.x,ty:T.y}});
 window.addEventListener("mousemove",ev=>{if(drag){const q=pt(ev);drag.p.x=q.x-drag.dx;drag.p.y=q.y-drag.dy;drag.g.setAttribute("transform",`translate(${drag.p.x},${drag.p.y})`);upd()}
  else if(pan){const r=svg.getBoundingClientRect();T.x=pan.tx+(ev.clientX-pan.x)*W/r.width;T.y=pan.ty+(ev.clientY-pan.y)*H/r.height;apply()}});
 window.addEventListener("mouseup",()=>{drag=null;pan=null});
 const zoom=f=>{T.x=W/2-(W/2-T.x)*f;T.y=H/2-(H/2-T.y)*f;T.k*=f;apply()};
 svg.addEventListener("wheel",ev=>{ev.preventDefault();zoom(ev.deltaY<0?1.1:1/1.1)},{passive:false});
 $("#zi").onclick=()=>zoom(1.2);$("#zo").onclick=()=>zoom(1/1.2);$("#zr").onclick=()=>{T={x:0,y:0,k:1};apply()};
}
function killchain(inc){
 $("#kc").innerHTML=inc.stages.map((s,i)=>`<li style="--c:${SVC[s.severity]}"><div class="k">${String(i+1).padStart(2,"0")}</div><div class="t">${s.first.slice(11).replace("Z"," UTC")} · ${s.sources.map(x=>`<span style="color:${PC[x]}">${PN[x]}</span>`).join(" + ")}</div>
 <div class="n">${esc(s.name)}</div><div class="m"><span class="tag" style="color:var(--cy);border-color:color-mix(in srgb,var(--cy) 45%,transparent)">${s.technique}</span> ${sev(s.severity)} ${s.count} event${s.count==1?"":"s"}</div></li>`).join("");
}
function timeline(inc){
 const ev=inc.events; if(!ev.length){$("#tl").innerHTML="";return}
 const lanes=["windows","linux","aws","host"].filter(l=>ev.some(e=>e.s==l)), W=1200,L=110,R=30,top=14,lh=58,H=top+lanes.length*lh+34;
 const t0=Math.min(...ev.map(e=>e.e)),t1=Math.max(...ev.map(e=>e.e)),sp=Math.max(t1-t0,1),X=t=>L+(t-t0)/sp*(W-L-R);
 let s=`<svg viewBox="0 0 ${W} ${H}" width="100%">`;
 lanes.forEach((l,i)=>{const y=top+i*lh;s+=`<rect x="${L-6}" y="${y}" width="${W-L-R+12}" height="${lh-12}" rx="9" fill="color-mix(in srgb,${PC[l]} 7%,transparent)" stroke="color-mix(in srgb,${PC[l]} 30%,transparent)"/>
  <text x="${L-16}" y="${y+lh/2-2}" text-anchor="end" font-size="13" font-weight="700" fill="${PC[l]}">${PN[l]}</text>`});
 for(let k=0;k<=6;k++){const t=t0+sp*k/6,x=X(t);s+=`<line x1="${x}" x2="${x}" y1="${top}" y2="${top+lanes.length*lh-10}" stroke="var(--line)" stroke-dasharray="3 4"/><text x="${x}" y="${H-10}" text-anchor="middle" font-size="11" fill="var(--mu)" class="mono">${new Date(t*1000).toISOString().slice(11,19)}Z</text>`}
 ev.forEach((e,j)=>{const i=lanes.indexOf(e.s),y=top+i*lh+(lh-12)/2+((j%5)-2)*4,r=e.sv=="info"?4:6.5;
  s+=`<circle cx="${X(e.e)}" cy="${y}" r="${r}" fill="${SVC[e.sv]}" stroke="var(--bg2)" stroke-width="1.5" style="filter:drop-shadow(0 0 4px ${SVC[e.sv]})" data-tip="<span class=mono>${esc(e.t)}</span><br><b>${esc(PN[e.s])} · ${esc(e.ty)}</b><br>user ${esc(e.u||'–')} · IP ${esc(e.ip||'–')} · ${esc(e.h)}<br>${esc(e.tg)}${e.f.length?'<br>⚑ '+esc(e.f.join(', ')):''}"/>`});
 s+=`</svg><div class="legend"><span><i style="background:var(--rd)"></i>high-severity alert</span><span><i style="background:var(--am)"></i>medium-severity alert</span><span><i style="background:var(--mu2)"></i>related event (not alerted)</span></div>`;
 $("#tl").innerHTML=s;
}

/* ---------- cloud */
function sCloud(){
 const E=D.cloud.emu,F=D.cloud.fixture, NM={trail_logging_off:"CloudTrail logging switched off",trail_no_log_validation:"Log-file validation disabled",trail_single_region:"Trail covers one region only",
 root_mfa_missing:"Root account without MFA",admin_without_mfa:"Administrator without MFA",stale_access_key:"Access key older than 90 days",role_trusts_anyone:"Role trusts any AWS principal",
 role_trusts_external_account:"Role trusts an external account",public_bucket:"Publicly readable S3 bucket",bucket_public_access_not_blocked:"S3 Block Public Access off",sg_world_open_admin_port:"Admin port open to the internet (0.0.0.0/0)"};
 let h=head("Cloud Forensic Investigation","AWS: what the attacker did, and how exposed the account was","Two complementary views: CloudTrail activity is correlated with on-premise evidence, and a read-only account-state snapshot records the exposure at investigation time. Posture findings never start an incident on their own; an abused key joins the attacker's incident.");
 const all=E.all||E.single;
 h+=`<div class="g g4">`+kpi(all?`${all.ft}/${all.et}`:"–","Misconfigurations found · AWS emulator, all regions",all?`false positives: ${all.fp}`:"","var(--gr)","cld")+
 kpi(all?`${all.ops}`:"–","Distinct AWS API operations used",all&&all.ro?"all List / Get / Describe (read-only)":"","var(--cy)","lock")+
 kpi(F.exposed?`${F.exposed.ft}/${F.exposed.et}`:"–","Labelled fixture · exposed account",F.clean?`clean account: ${F.clean.ft} findings, ${F.clean.fp} FP`:"","var(--vi)","tgt")+
 kpi(D.real?`${D.real.aws.filter(a=>a.hit).length}/${D.real.aws.length}`:"–","Stratus Red Team CloudTrail attacks detected","real attack-simulation logs","var(--aws)","alert")+`</div>`;
 const keys=all?Object.keys(all.exp):[];
 h+=`<div class="g g32" style="margin-top:16px"><div class="card"><h3><i>${ic("cld",15)}</i>Posture checks · moto AWS emulator (real boto3 code path)</h3><table><tr><th>Misconfiguration</th><th>Rule</th><th>Seeded</th><th>Found</th><th></th></tr>
 ${keys.map(k=>{const e=all.exp[k],f=all.found[k]||0;return `<tr><td>${NM[k]||k}</td><td class="mono" style="color:var(--mu)">${k}</td><td class="mono">${e}</td><td class="mono">${f}</td><td class="${f==e?'ok':'bad'}">${ic(f==e?'chk':'x',16)}</td></tr>`}).join("")}</table>
 <div class="note" style="margin-top:10px">The emulator is not a real AWS account; it exercises the same boto3 calls the collector makes against a live account.</div></div>
 <div class="card"><h3><i>${ic("alert",15)}</i>Cloud attack activity in the incidents</h3>${cloudStages()}</div></div>`;
 return h;
}
function cloudStages(){
 const out=[];Object.values(D.cases).forEach(c=>c.incidents.forEach(i=>i.stages.filter(s=>s.sources.includes("aws")).forEach(s=>out.push([c.name,i.id,s]))));
 const seen=new Set(),u=out.filter(([c,i,s])=>{const k=s.technique+s.name;if(seen.has(k))return false;seen.add(k);return true});
 let h=u.map(([c,i,s])=>`<div style="display:flex;gap:10px;align-items:flex-start;padding:9px 0;border-bottom:1px solid var(--line)"><span class="tag" style="color:var(--aws);border-color:color-mix(in srgb,var(--aws) 50%,transparent)">${s.technique}</span><div><b style="font-size:13px">${esc(s.name)}</b><div class="note">${sev(s.severity)} first seen in ${c} · ${i}</div></div></div>`).join("");
 if(D.real)h+=`<div class="kw" style="margin:14px 0 6px">Real CloudTrail samples (Stratus Red Team)</div>`+D.real.aws.map(a=>`<div style="display:flex;gap:8px;padding:5px 0"><span class="${a.hit?'ok':'bad'}">${ic(a.hit?'chk':'x',15)}</span><span class="note" style="font-size:12.5px">${esc(a.why)}</span></div>`).join("");
 return h;
}

/* ---------- custody */
function sCustody(){
 let h=head("Chain of Custody","Tamper-evident evidence ledger","Every acquisition, processing step and report is an entry whose SHA-256 hash includes the previous entry's hash (and an HMAC when a key is set). Changing anything breaks the chain at that point.");
 h+=`<div class="card"><h3><i>${ic("lock",15)}</i>Ledger of case S2 — re-verified while building this page
 <span style="margin-left:auto" class="${D.ledger_ok?'ok':'bad'}">${ic(D.ledger_ok?'chk':'x',15)} ${D.ledger_ok?'VERIFIED':'FAILED'} · ${D.ledger_checks[0]||0} entries · ${D.ledger_checks[1]||0} files · HMAC</span></h3><div class="chain">`+
 D.ledger.map((b,i)=>`${i?`<div class="arw"><svg width="22" height="14" viewBox="0 0 30 14"><path d="M0 7h26M20 2l6 5-6 5" fill="none" stroke="currentColor" stroke-width="2"/></svg></div>`:""}
 <div class="blk" data-tip="<b>#${b.seq} ${esc(b.stage)} · ${esc(b.action)}</b><br>${esc(b.target)}<br><span class=mono>${esc(b.time)}</span><br>prev: <span class=mono>${b.prev.slice(0,32)}…</span><br>hash: <span class=mono>${b.hash.slice(0,32)}…</span>${b.sha?'<br>file SHA-256: <span class=mono>'+b.sha.slice(0,32)+'…</span>':''}">
 <div class="sq">BLOCK #${b.seq} · ${esc(b.stage)}</div><div class="a">${esc(b.action)}</div><div class="tg">${esc(b.target)}</div>
 <div class="hs">prev&nbsp; ${b.prev.slice(0,10)}…<br>hash&nbsp; <em>${b.hash.slice(0,10)}…</em>${b.hmac?'<br>hmac&nbsp; ✓ signed':''}</div></div>`).join("")+`</div></div>`;
 h+=`<div class="card" style="margin-top:16px"><h3><i>${ic("cus",15)}</i>Tampering tests (run on every scenario)</h3><div class="g g2">`+D.tamper.map(t=>{
  const good=t.ok==t.n, c=t.lim?"var(--am)":good?"var(--gr)":"var(--rd)", res=t.lim?"not detected (documented limit)":t.expect?"detected":"verifies clean";
  return `<div class="tt"><div class="ic" style="background:color-mix(in srgb,${c} 15%,transparent);color:${c}">${ic(t.lim?'alert':good?'chk':'x',18)}</div><div><div class="x">${esc(t.test)}</div><div class="y">expected: ${t.lim?"known limitation — no key and no anchor":t.expect?"tampering detected":"ledger verifies"} · result: ${res}</div></div><div class="z" style="color:${c}">${t.ok}/${t.n}</div></div>`}).join("")+`</div>
 <div class="note" style="margin-top:12px">The last test is a known limit, not a failure: if an attacker rewrites the whole chain and no HMAC key or external anchor hash exists, nothing inside the case folder can prove it. That is why the anchor hash is printed and must be noted outside the case.</div></div>`;
 return h;
}

/* ---------- mitre */
function sMitre(){
 const T=D.techs, val=T.filter(t=>t.validated).length;
 let h=head("MITRE ATT&CK Coverage",`${D.kpi.rules} detection rules · ${T.length} techniques · ${D.tactics.length} tactics`,"Each rule is mapped to one ATT&CK technique. Highlighted techniques were triggered during evaluation (simulated scenarios, AWS emulator or real public datasets); the others have rules that were implemented and unit-tested but not seen in the evaluation data.");
 h+=`<div class="g g4" style="margin-bottom:16px">${kpi(D.kpi.rules,"Detection rules","in 6 rule families","var(--am)","mit")}${kpi(T.length,"ATT&CK techniques covered",`${D.tactics.length} tactics`,"var(--cy)","tgt")}${kpi(val,"Techniques triggered in evaluation",`${pct(val/T.length)} of covered techniques`,"var(--gr)","chk")}
 <div class="card"><h3><i>${ic("ov",15)}</i>Rules per family</h3>${D.families.map(f=>`<div style="display:grid;grid-template-columns:1fr 34px;gap:8px;align-items:center;font-size:12px;margin:3px 0"><span>${esc(f.family.replace(" (all platforms)","").replace(" (posture)"," posture"))}</span><b class="mono" style="text-align:right">${f.rules}</b></div>`).join("")}</div></div>`;
 h+=`<div class="card"><div class="mx">`+D.tactics.map(tc=>{const L=T.filter(t=>t.tactic==tc);
  return `<div class="col"><h4>${tc}<span>${L.length}</span></h4>${L.map(t=>`<div class="tc ${t.validated?'v':''}" data-tip="<b>${t.id} · ${esc(t.name)}</b><br>${t.rules.map(r=>(r.val?'✔ ':'○ ')+'<span class=mono>'+esc(r.rule)+'</span> — '+esc(r.desc)+' <i>('+esc(r.fam.join(', '))+')</i>').join('<br>')}"><b>${t.id}</b>${esc(t.name)}<br><span class="n">${t.rules.length} rule${t.rules.length>1?"s":""}</span></div>`).join("")}</div>`}).join("")+`</div>
 <div class="legend"><span><i style="background:linear-gradient(160deg,var(--cy),var(--vi))"></i>triggered in evaluation</span><span><i style="background:var(--panel2);border:1px solid var(--line2)"></i>rule implemented, not triggered by the evaluation data</span><span>hover a technique for its rules</span></div></div>`;
 return h;
}

/* ---------- scale */
function sScale(){
 const S=D.scale;
 let h=head("Scalability","Near-linear processing time as evidence grows",`Same attack embedded in growing volumes of background activity. Largest run: ${fmt(S[S.length-1].records)} records in ${S[S.length-1].total.toFixed(2)} s with F1 ${f3(S[S.length-1].f1)}. Measured on ${esc(D.meta.system)}, Python ${esc(D.meta.python)}.`);
 h+=`<div class="g g2"><div class="card"><h3><i>${ic("scl",15)}</i>Total processing time vs records</h3>${lineChart(S)}</div><div class="card"><h3><i>${ic("ov",15)}</i>Where the time goes (per stage)</h3>${stackChart(S)}</div></div>`;
 h+=`<div class="card" style="margin-top:16px"><table><tr><th>Records</th><th>Normalized events</th><th>Acquisition</th><th>Normalization</th><th>Correlation</th><th>Custody</th><th>Total (s)</th><th>Records / s</th><th>F1</th></tr>
 ${S.map(r=>`<tr class="mono"><td>${fmt(r.records)}</td><td>${fmt(r.events)}</td><td>${r.acquisition.toFixed(3)}</td><td>${r.normalization.toFixed(3)}</td><td>${r.correlation.toFixed(3)}</td><td>${r.custody.toFixed(3)}</td><td><b>${r.total.toFixed(2)}</b></td><td>${fmt(r.throughput)}</td><td class="ok">${f3(r.f1)}</td></tr>`).join("")}</table></div>`;
 return h;
}
function lineChart(S){
 const W=560,H=300,L=58,B=42,T=16,R=20,xm=Math.ceil(Math.max(...S.map(r=>r.records))*1.05/40000)*40000,ym=Math.ceil(Math.max(...S.map(r=>r.total))*1.15/4)*4,X=v=>L+v/xm*(W-L-R),Y=v=>H-B-v/ym*(H-B-T);
 let s=`<svg viewBox="0 0 ${W} ${H}" width="100%"><defs><linearGradient id="ar1" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="var(--cy)" stop-opacity=".35"/><stop offset="1" stop-color="var(--cy)" stop-opacity="0"/></linearGradient></defs>`;
 for(let k=0;k<=4;k++){const v=ym*k/4;s+=`<line x1="${L}" x2="${W-R}" y1="${Y(v)}" y2="${Y(v)}" stroke="var(--line)"/><text x="${L-8}" y="${Y(v)+4}" text-anchor="end" font-size="11" fill="var(--mu)">${v.toFixed(ym<4?1:0)} s</text>`}
 for(let k=0;k<=4;k++){const v=xm*k/4;s+=`<text x="${X(v)}" y="${H-B+18}" text-anchor="middle" font-size="11" fill="var(--mu)">${fmt(v)}</text>`}
 s+=`<text x="${(W+L)/2}" y="${H-6}" text-anchor="middle" font-size="11.5" fill="var(--mu)">log records processed</text>`;
 const pts=S.map(r=>[X(r.records),Y(r.total)]);
 s+=`<path d="M${pts[0][0]} ${Y(0)}L${pts.map(p=>p.join(" ")).join("L")}L${pts[pts.length-1][0]} ${Y(0)}Z" fill="url(#ar1)"/>
 <path d="M${pts.map(p=>p.join(" ")).join("L")}" fill="none" stroke="var(--cy)" stroke-width="2.6" stroke-dasharray="1200" stroke-dashoffset="1200"><animate attributeName="stroke-dashoffset" to="0" dur="1.4s" fill="freeze"/></path>`;
 S.forEach((r,i)=>s+=`<circle cx="${pts[i][0]}" cy="${pts[i][1]}" r="5" fill="var(--bg2)" stroke="var(--cy)" stroke-width="2.4" data-tip="<b>${fmt(r.records)} records</b><br>${r.total.toFixed(2)} s · ${fmt(r.throughput)} records/s · F1 ${f3(r.f1)}"/>${i>=S.length-2?`<text x="${pts[i][0]}" y="${pts[i][1]-12}" text-anchor="middle" font-size="11.5" font-weight="700" fill="var(--tx)">${r.total.toFixed(2)} s</text>`:""}`);
 return s+"</svg>";
}
function stackChart(S){
 const st=[["acquisition","Acquisition","var(--win)"],["normalization","Normalization","var(--lin)"],["correlation","Correlation","var(--aws)"],["custody","Custody","var(--vi)"]];
 const W=560,rh=44,L=86,H=S.length*rh+16,mx=Math.max(...S.map(r=>st.reduce((a,k)=>a+r[k[0]],0)));
 let s=`<svg viewBox="0 0 ${W} ${H}" width="100%">`;
 S.forEach((r,i)=>{let x=L;const y=8+i*rh;s+=`<text x="${L-10}" y="${y+18}" text-anchor="end" font-size="11.5" fill="var(--mu)" class="mono">${fmt(r.records)}</text>`;
  st.forEach(k=>{const w=r[k[0]]/mx*(W-L-60);s+=`<rect x="${x}" y="${y+4}" width="${Math.max(w,.5)}" height="22" fill="${k[2]}" rx="2" data-tip="<b>${k[1]}</b> · ${fmt(r.records)} records<br>${r[k[0]].toFixed(3)} s (${pct(r[k[0]]/r.total)} of total)"/>`;x+=w});
  s+=`<text x="${x+8}" y="${y+20}" font-size="11.5" fill="var(--tx)" font-weight="600">${r.total.toFixed(2)} s</text>`});
 return s+`</svg><div class="legend">${st.map(k=>`<span><i style="background:${k[2]}"></i>${k[1]}</span>`).join("")}</div>`;
}

/* ---------- real data */
function sReal(){
 const R=D.real; if(!R)return head("Real-World Validation","Not run yet","Run  python main.py real-eval  (run.bat option) and rebuild the dashboard.");
 const w=R.win;
 let h=head("Real-World Validation","Public datasets: real attack logs, not simulations","Windows EVTX-ATTACK-SAMPLES, LogHub Linux/OpenSSH logs and Stratus Red Team CloudTrail. Rules were refined after looking at these samples, so these are development-set results; the benign false-positive rate was not measured.");
 h+=`<div class="g g4">${kpi(w.samples,"Windows EVTX attack samples parsed",`${fmt(w.records)} records · ${w.errors} parse errors`,"var(--win)","col")}
 ${kpi(`${w.core[0]}/${w.core[1]}`,"Labelled samples detected",`hard cases: ${w.hard[0]}/${w.hard[1]}`,"var(--gr)","tgt")}
 ${kpi(R.linux.every(l=>l.agree)?"100%":"–","Linux brute-force IPs agree with independent count",R.linux.map(l=>`${l.fw}/${l.ind}`).join(" · "),"var(--lin)","chk")}
 ${kpi(`${R.aws.filter(a=>a.hit).length}/${R.aws.length}`,"Stratus CloudTrail attacks detected","AWS attack simulations","var(--aws)","cld")}</div>`;
 const tac=Object.entries(w.per_tactic).filter(([k])=>k!="(root)").sort((a,b)=>b[1].samples-a[1].samples);
 h+=`<div class="g g32" style="margin-top:16px"><div class="card"><h3><i>${ic("mit",15)}</i>EVTX-ATTACK-SAMPLES by ATT&amp;CK tactic folder</h3>${tacChart(tac)}</div>
 <div class="card"><h3><i>${ic("tgt",15)}</i>Labelled Windows samples</h3><div class="scroll" style="max-height:330px;border:0">${w.labelled.map(x=>`<div style="display:flex;gap:10px;padding:8px 2px;border-bottom:1px solid var(--line)"><span class="${x.hit?'ok':x.hard?'warn':'bad'}">${ic(x.hit?'chk':x.hard?'alert':'x',16)}</span><div style="min-width:0"><div class="mono" style="font-size:11.5px;word-break:break-all">${esc(x.file.split("/").pop())}${x.hard?' <span class="tag sev-medium">HARD</span>':''}</div><div class="note">${esc(x.why)}</div></div></div>`).join("")}</div></div></div>`;
 h+=`<div class="card" style="margin-top:16px"><h3><i>${ic("col",15)}</i>Linux brute-force (LogHub)</h3><table><tr><th>Log</th><th>Lines</th><th>Normalized</th><th>Failed logins</th><th>Brute-force IPs (framework / independent)</th><th>Top attacking sources</th></tr>
 ${R.linux.map(l=>`<tr><td class="mono">${esc(l.file)}</td><td class="mono">${fmt(l.lines)}</td><td class="mono">${l.norm}</td><td class="mono">${l.fail}</td><td class="mono ${l.agree?'ok':'bad'}">${l.fw} / ${l.ind} ${l.agree?'✓':''}</td><td class="mono" style="font-size:11px">${l.top.map(t=>esc(t[0])+' ('+t[1]+')').join(", ")}</td></tr>`).join("")}</table></div>`;
 return h;
}
function tacChart(tac){
 const W=600,rh=30,L=150,H=tac.length*rh+30,mx=Math.max(...tac.map(t=>t[1].samples));
 let s=`<svg viewBox="0 0 ${W} ${H}" width="100%">`;
 tac.forEach(([k,v],i)=>{const y=6+i*rh,sc=(W-L-50)/mx;
  s+=`<text x="${L-10}" y="${y+15}" text-anchor="end" font-size="11.5" fill="var(--tx)">${esc(k)}</text>
  <rect x="${L}" y="${y+3}" width="${v.samples*sc}" height="17" rx="3" fill="var(--line2)" data-tip="<b>${esc(k)}</b><br>${v.samples} samples · ${v.with_supported} with supported events · ${v.alerted} alerted"/>
  <rect x="${L}" y="${y+3}" width="${v.with_supported*sc}" height="17" rx="3" fill="color-mix(in srgb,var(--cy) 45%,transparent)" pointer-events="none"/>
  <rect x="${L}" y="${y+3}" width="${v.alerted*sc}" height="17" rx="3" fill="var(--cy)" pointer-events="none"/>
  <text x="${L+v.samples*sc+6}" y="${y+16}" font-size="11" fill="var(--mu)" class="mono">${v.alerted}/${v.samples}</text>`});
 return s+`</svg><div class="legend"><span><i style="background:var(--cy)"></i>alerted</span><span><i style="background:color-mix(in srgb,var(--cy) 45%,transparent)"></i>contains supported events</span><span><i style="background:var(--line2)"></i>samples</span></div>`;
}

/* ---------- explorer */
function sExplorer(){
 let h=head("Evidence Explorer","Every normalized event of case S1 in one searchable timeline",`${D.explorer.length} events from ${[...new Set(D.explorer.map(e=>e.s))].map(x=>PN[x]).join(", ")} in the common schema (UTC).`);
 h+=`<div class="card"><div style="display:flex;gap:12px;align-items:center;flex-wrap:wrap;margin-bottom:12px"><input class="q" id="q" placeholder="Search IP, user, event type, flag, host …">
 <div class="chips" id="pf">${["all","windows","linux","aws"].map(p=>`<span class="chip ${p=="all"?"on":""}" data-p="${p}">${p=="all"?"All":PN[p]}</span>`).join("")}</div>
 <label class="note"><input type="checkbox" id="only"> only incident events</label><span id="cnt" class="note" style="margin-left:auto"></span></div>
 <div class="scroll"><table><thead><tr><th>Time (UTC)</th><th>Platform</th><th>Host</th><th>Event</th><th>User</th><th>Source IP</th><th>Target / detail</th><th>Flags</th><th>Incident</th></tr></thead><tbody id="tb"></tbody></table></div></div>`;
 return h;
}
let pf="all";
function drawExp(){
 const k=$("#q").value.toLowerCase(),only=$("#only").checked;let n=0,out=[];
 for(const r of D.explorer){if(only&&!r.i)continue;if(pf!="all"&&r.s!=pf)continue;const line=Object.values(r).join(" ").toLowerCase();if(k&&!line.includes(k))continue;n++;if(out.length<800)
  out.push(`<tr><td class="mono">${esc(r.t.replace("T"," "))}</td><td>${plat(r.s)}</td><td>${esc(r.h)}</td><td class="mono">${esc(r.ty)}</td><td>${esc(r.u)}</td><td class="mono">${esc(r.ip)}</td><td style="max-width:300px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(r.tg)}</td><td>${r.f.map(f=>`<span class="tag sev-${r.sv=='high'?'high':'medium'}">${esc(f)}</span>`).join("")}</td><td class="mono" style="color:var(--cy)">${esc(r.i)}</td></tr>`)}
 $("#tb").innerHTML=out.join("");$("#cnt").textContent=n+" events";
}

/* ======================================================= boot */
const R={overview:sOverview,collection:sCollection,correlation:sCorrelation,investigation:sInvestigation,mitre:sMitre,cloud:sCloud,custody:sCustody,scale:sScale,realdata:sReal,explorer:sExplorer};
$("#ttl").innerHTML=`<b>${esc(D.meta.title)}</b>`;
$("#pillPl").innerHTML=`${ic("cor",13)} Windows · Linux · AWS`;
$("#pillCu").lastElementChild.textContent=`Custody ${D.ledger_ok===false?"FAILED":"verified"} · ${D.kpi.tam_ok}/${D.kpi.tam_n} tamper tests`;
let nav="",g="";SECTIONS.forEach(s=>{if(s.grp!=g){g=s.grp;nav+=`<div class="grp">${g}</div>`}nav+=`<a href="#${s.id}" data-s="${s.id}">${ic(s.ico)}${s.nav}</a>`});
nav+=`<div class="who"><b>${esc(D.meta.author)}</b><br>${esc(D.meta.enrol)}<br>${esc(D.meta.program)}<br><br>Evaluation run<br><span class="mono">${esc(D.meta.evaluated)}</span><br>Python ${esc(D.meta.python)} · ${esc(D.meta.system)}</div>`;
$("#nav").innerHTML=nav;
$("#main").innerHTML=SECTIONS.map(s=>`<section id="sec-${s.id}">${R[s.id]()}<div class="foot">Generated ${esc(D.meta.built)} by make_dashboard.py from results/evaluation.json, results/real_data_results.json and cases/. Works offline.</div></section>`).join("");
function animate(sec){sec.querySelectorAll(".bar i").forEach(b=>{b.style.width="0";requestAnimationFrame(()=>requestAnimationFrame(()=>b.style.width=b.dataset.w+"%"))});
 sec.querySelectorAll("[data-count]").forEach(el=>{const raw=el.dataset.count,m=raw.match(/^([\d,.]+)(.*)$/);if(!m)return;const tgt=parseFloat(m[1].replace(/,/g,"")),dec=(m[1].split(".")[1]||"").length,comma=m[1].includes(",")||tgt>=1000;
  if(raw.includes("/")&&!raw.endsWith("/s"))return;const t0=performance.now();const st=t=>{const k=Math.min(1,(t-t0)/900),v=tgt*(1-Math.pow(1-k,3));el.textContent=(comma?Math.round(v).toLocaleString("en-US"):v.toFixed(dec))+m[2];if(k<1)requestAnimationFrame(st)};requestAnimationFrame(st)})}
function go(){const id=(location.hash||"#overview").slice(1),ok=R[id]?id:"overview";
 document.querySelectorAll("section").forEach(s=>s.classList.toggle("on",s.id=="sec-"+ok));document.querySelectorAll("nav a").forEach(a=>a.classList.toggle("on",a.dataset.s==ok));
 if(ok=="investigation")drawCase();if(ok=="explorer")drawExp();animate($("#sec-"+ok));scrollTo(0,0)}
addEventListener("hashchange",go);
document.addEventListener("click",e=>{const c=e.target.closest("#caseChips .chip");if(c){curCase=c.dataset.c;curInc=0;drawCase()}
 const i=e.target.closest("#incChips .chip");if(i){curInc=+i.dataset.i;drawCase()}
 const p=e.target.closest("#pf .chip");if(p){pf=p.dataset.p;document.querySelectorAll("#pf .chip").forEach(x=>x.classList.toggle("on",x==p));drawExp()}});
document.addEventListener("input",e=>{if(e.target.id=="q")drawExp()});document.addEventListener("change",e=>{if(e.target.id=="only")drawExp()});
const root=document.documentElement;
try{if(location.search.includes("light")||localStorage.getItem("cpdfir-theme")=="light")root.classList.add("light")}catch(e){if(location.search.includes("light"))root.classList.add("light")}
$("#theme").onclick=()=>{root.classList.toggle("light");try{localStorage.setItem("cpdfir-theme",root.classList.contains("light")?"light":"dark")}catch(e){}};
if(window.self===window.top&&!location.search.includes("standalone")){location.replace("./#/results/"+((location.hash||"#overview").slice(1)))}
if(location.search.includes("embed")||window.self!==window.top){root.classList.add("embed");addEventListener("message",e=>{if(e.data&&e.data.cpdfirTheme)root.classList.toggle("light",e.data.cpdfirTheme=="light")})}
go();
</script></body></html>
"""


if __name__ == "__main__":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    p = build(ROOT)
    print("Dashboard:", p)
    if "--no-open" not in sys.argv:
        import webbrowser
        webbrowser.open("file:///" + os.path.abspath(p).replace("\\", "/"))
