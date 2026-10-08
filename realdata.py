"""Validation on REAL public data (nothing here is simulated).

Datasets (downloaded from GitHub on first use into real_data/, not shipped in the zip):
  Windows  EVTX-ATTACK-SAMPLES (S. Bousseaden)  278 real .evtx captures of attack techniques, grouped by ATT&CK tactic
           https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES
  Linux    LogHub OpenSSH_2k and Linux_2k        real /var/log/auth.log style logs of an Internet-facing SSH server
           https://github.com/logpai/loghub   (He, Zhu, He, Lyu, "Loghub: A Large Collection of System Log Datasets towards Automated Log Analytics", arXiv:2008.06448, 2020)
  AWS      Stratus Red Team CloudTrail samples   real CloudTrail events from real attack detonations (Datadog format)
           https://github.com/zmallen/cloudtrail2sightings  (cloudtrail.zip)

What is measured and what is NOT
  * Coverage: how many real records/samples the parsers understand.
  * Detection on labelled samples: for a hand-made list of samples whose file name states the technique
    (e.g. '..._7045', '..._sysmon_10_lsass_...'), did the framework raise the matching alert?
  * Linux: parser agreement with independent regex counting, and brute-force IPs found.
  NOT measured: false-positive rate on real benign traffic (no labelled benign real logs are available here),
  and correlation quality on real multi-platform incidents (no public dataset has real Windows+Linux+AWS
  logs of one incident). Rules were written after looking at these samples, so results on them are
  development-set results and are optimistic.
"""
import collections
import json
import os
import re
import time
import urllib.parse
import urllib.request
import zipfile
from datetime import datetime, timezone
from html import escape as h

import config
import correlate
import normalize

EVTX_BASE = "https://raw.githubusercontent.com/sbousseaden/EVTX-ATTACK-SAMPLES/master/"
LOGHUB_BASE = "https://raw.githubusercontent.com/logpai/loghub/master/"
CT_ZIP = "https://raw.githubusercontent.com/zmallen/cloudtrail2sightings/master/cloudtrail.zip"

# --------------------------------------------------------------------------------------------
# Expectations, taken from the dataset's own file names (my reading of them - see docstring).
# value = (set of acceptable flags, why the sample is expected to raise it)
WIN_EXPECT = {
    "Defense Evasion/DE_1102_security_log_cleared.evtx": ({"log_cleared"}, "Security log cleared (1102)"),
    "Defense Evasion/DE_104_system_log_cleared.evtx": ({"log_cleared"}, "System log cleared (104)"),
    "Lateral Movement/LM_Remote_Service02_7045.evtx": ({"service_installed"}, "service installed remotely (7045)"),
    "Execution/temp_scheduled_task_4698_4699.evtx": ({"scheduled_task_created"}, "scheduled task created (4698)"),
    "Lateral Movement/LM_Remote_Service01_5145_svcctl.evtx": ({"remote_service_control"}, "svcctl over SMB (5145)"),
    "Lateral Movement/LM_ScheduledTask_ATSVC_target_host.evtx": ({"remote_service_control"}, "atsvc over SMB"),
    "Lateral Movement/LM_REMCOM_5145_TargetHost.evtx": ({"admin_share_access", "remote_service_control"}, "RemCom over admin share (5145)"),
    "Lateral Movement/LM_renamed_psexecsvc_5145.evtx": ({"admin_share_access", "remote_service_control"}, "renamed PsExec service (5145)"),
    "Lateral Movement/LM_5145_Remote_FileCopy.evtx": ({"admin_share_access"}, "remote file copy to admin share (5145)"),
    "Credential Access/sysmon_10_lsass_mimikatz_sekurlsa_logonpasswords.evtx": ({"lsass_access", "credential_dump_tool"}, "mimikatz sekurlsa (Sysmon 10)"),
    "Credential Access/sysmon_10_11_lsass_memdump.evtx": ({"lsass_access", "credential_dump_tool"}, "LSASS memory dump (Sysmon 10/11)"),
    "Credential Access/sysmon_10_1_memdump_comsvcs_minidump.evtx": ({"lsass_access", "credential_dump_tool"}, "comsvcs MiniDump (Sysmon 10/1)"),
    "Credential Access/sysmon_3_10_Invoke-Mimikatz_hosted_Github.evtx": ({"lsass_access", "credential_dump_tool", "suspicious_powershell"}, "Invoke-Mimikatz"),
    "Credential Access/sysmon_rdrleakdiag_lsass_dump.evtx": ({"lsass_access"}, "rdrleakdiag LSASS dump"),
    "Credential Access/sysmon_2x10_lsass_with_different_pid_RtlCreateProcessReflection.evtx": ({"lsass_access"}, "LSASS access via process reflection"),
    "Credential Access/Powershell_4104_MiniDumpWriteDump_Lsass.evtx": ({"suspicious_powershell", "credential_dump_tool"}, "MiniDumpWriteDump (PowerShell 4104)"),
    "Persistence/evasion_persis_hidden_run_keyvalue_sysmon_13.evtx": ({"registry_persistence"}, "hidden Run key value (Sysmon 13)"),
    "Persistence/sysmon_13_1_persistence_via_winlogon_shell.evtx": ({"registry_persistence"}, "Winlogon shell (Sysmon 13)"),
    "Execution/exec_sysmon_lobin_regsvr32_sct.evtx": ({"lolbin_abuse"}, "regsvr32 scriptlet"),
    "Execution/exec_sysmon_1_11_lolbin_rundll32_openurl_FileProtocolHandler.evtx": ({"lolbin_abuse"}, "rundll32 FileProtocolHandler"),
    "Execution/exec_sysmon_1_11_lolbin_rundll32_shdocvw_openurl.evtx": ({"lolbin_abuse"}, "rundll32 shdocvw"),
    "Execution/exec_sysmon_1_11_lolbin_rundll32_zipfldr_RouteTheCall.evtx": ({"lolbin_abuse"}, "rundll32 zipfldr"),
    "Execution/exec_sysmon_1_lolbin_rundll32_advpack_RegisterOCX.evtx": ({"lolbin_abuse"}, "rundll32 advpack"),
    "Execution/exec_sysmon_1_rundll32_pcwutl_LaunchApplication.evtx": ({"lolbin_abuse"}, "rundll32 pcwutl"),
    "Execution/exec_sysmon_1_lolbin_pcalua.evtx": ({"lolbin_abuse"}, "pcalua"),
    "Execution/sysmon_mshta_sharpshooter_stageless_meterpreter.evtx": ({"lolbin_abuse", "lolbin_network"}, "mshta payload"),
    # hard / out-of-scope on purpose: the framework has no rule for these, they document the limits
    "Execution/exec_sysmon_1_lolbin_renamed_regsvr32_scrobj.evtx": ({"lolbin_abuse"}, "REPORTED HARD CASE: renamed regsvr32"),
    "Execution/exec_msxsl_xsl_sysmon_1_7.evtx": ({"lolbin_abuse"}, "REPORTED HARD CASE: msxsl is not in the LOLBin list"),
    "Credential Access/CA_hashdump_4663_4656_lsass_access.evtx": ({"lsass_access"}, "REPORTED HARD CASE: needs Security 4656/4663 (not supported)"),
    "Credential Access/CA_teamviewer-dumper_sysmon_10.evtx": ({"lsass_access"}, "REPORTED HARD CASE: credentials dumped from TeamViewer memory, target is not LSASS"),
    "Credential Access/kerberos_pwd_spray_4771.evtx": ({"brute_force"}, "REPORTED HARD CASE: Kerberos password spray (4771 not supported)"),
}
AWS_EXPECT = {
    "aws.defense-evasion.cloudtrail-delete.json": ({"logging_disabled"}, "DeleteTrail (T1562.008)"),
    "aws.exfiltration.ec2-share-ebs-snapshot.json": ({"snapshot_shared"}, "EBS snapshot shared (T1537)"),
    "aws.credential-access.secretsmanager-retrieve-secrets.json": ({"secrets_bulk_retrieval"}, "10 x GetSecretValue (T1555.006)"),
    "aws.execution.ec2-user-data.json": ({"user_data_modified"}, "EC2 user data modified"),
}


def _get(url, dest, tries=3):
    os.makedirs(os.path.dirname(dest), exist_ok=True)
    for k in range(tries):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "dfir-framework-thesis"})
            with urllib.request.urlopen(req, timeout=60) as r, open(dest, "wb") as f:
                f.write(r.read())
            return True
        except Exception:
            time.sleep(1 + k)
    return False


def fetch_all(root, log=print):
    rd = os.path.join(root, "real_data")
    failed = []
    names = [l.strip() for l in open(os.path.join(rd, "evtx_files.txt"), encoding="utf-8") if l.strip()]
    todo = [n for n in names if not os.path.exists(os.path.join(rd, "evtx", n))]
    if todo:
        log(f"Downloading {len(todo)} real Windows EVTX samples (about 44 MB, first time only) ...")
    for i, n in enumerate(todo, 1):
        if not _get(EVTX_BASE + urllib.parse.quote(n), os.path.join(rd, "evtx", n)):
            failed.append(n)
        if i % 40 == 0:
            log(f"  {i}/{len(todo)}")
    for f, sub in (("OpenSSH_2k.log", "OpenSSH"), ("Linux_2k.log", "Linux")):
        d = os.path.join(rd, "linux", f)
        if not os.path.exists(d) and not _get(f"{LOGHUB_BASE}{sub}/{f}", d):
            failed.append(f)
    zpath = os.path.join(rd, "aws", "cloudtrail.zip")
    if not os.path.exists(os.path.join(rd, "aws", "aws.defense-evasion.cloudtrail-delete.json")):
        if _get(CT_ZIP, zpath):
            with zipfile.ZipFile(zpath) as z:
                z.extractall(os.path.join(rd, "aws"))
        else:
            failed.append("cloudtrail.zip")
    return failed


# --------------------------------------------------------------------------------------------
def _flags(ev, cfg):
    for i, e in enumerate(ev, 1):
        e["event_id"] = f"E{i}"
    c = correlate.correlate(ev, cfg) if ev else dict(incidents=[])
    fl = collections.Counter(f for e in ev for f in e["flags"])
    return fl, c


def windows_sweep(root, log=print):
    rd = os.path.join(root, "real_data")
    cfg = config.load_case_config(None)
    names = [l.strip() for l in open(os.path.join(rd, "evtx_files.txt"), encoding="utf-8") if l.strip()]
    rows, ignored = [], collections.Counter()
    t0 = time.time()
    for i, n in enumerate(names, 1):
        p = os.path.join(rd, "evtx", n)
        if not os.path.exists(p):
            continue
        ev, st = normalize.parse_windows(p)
        for k, v in (st.get("ignored_ids") or {}).items():
            ignored[k] += v
        fl, _ = _flags(ev, cfg)
        rows.append(dict(file=n, tactic=n.split("/")[0] if "/" in n else "(root)", records=st["records_seen"], supported=st["normalized"],
                         errors=st["errors"], flags=dict(fl)))
        if i % 60 == 0:
            log(f"  parsed {i}/{len(names)} samples")
    return rows, ignored, time.time() - t0


def windows_summary(rows, ignored):
    n = len(rows)
    per = collections.OrderedDict()
    for r in rows:
        b = per.setdefault(r["tactic"], dict(samples=0, with_supported=0, alerted=0))
        b["samples"] += 1
        b["with_supported"] += r["supported"] > 0
        b["alerted"] += bool(r["flags"])
    labelled = []
    for f, (ok, why) in WIN_EXPECT.items():
        r = next((x for x in rows if x["file"] == f), None)
        if r is None:
            continue
        hit = bool(set(r["flags"]) & ok)
        labelled.append(dict(file=f, why=why, expected=sorted(ok), flags=sorted(r["flags"]), hit=hit, hard=why.startswith("REPORTED HARD")))
    return dict(samples=n, records=sum(r["records"] for r in rows), errors=sum(r["errors"] for r in rows),
                with_supported=sum(r["supported"] > 0 for r in rows), alerted=sum(bool(r["flags"]) for r in rows),
                supported_events=sum(r["supported"] for r in rows), per_tactic=per,
                flags=dict(collections.Counter(f for r in rows for f in r["flags"])),
                top_ignored=ignored.most_common(12), labelled=labelled)


# --------------------------------------------------------------------------------------------
def _independent_bruteforce(path, year, min_n, window_min):
    """Separate, naive implementation (regex + O(n^2) window, repeat-weighted) used only to cross-check the framework.
    Returns (total weighted failures, set of IPs that reach min_n failures inside window_min minutes)."""
    ts_pat = re.compile(r"^([A-Z][a-z]{2})\s+(\d+)\s+(\d\d):(\d\d):(\d\d)\s+\S+\s+sshd(?:\([^)]*\))?\[\d+\]:\s+(.*)$")
    mon = {m: i for i, m in enumerate("Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec".split(), 1)}
    lines = open(path, encoding="utf-8", errors="replace").read().splitlines()
    pam = not any("Failed password" in l for l in lines)
    per, total = collections.defaultdict(list), 0
    for line in lines:
        m = ts_pat.match(line)
        if not m:
            continue
        msg, w = m.group(6), 1
        rm = re.match(r"message repeated (\d+) times?: \[ ?(.*?) ?\]$", msg)
        if rm:
            w, msg = int(rm.group(1)), rm.group(2)
        ip = None
        fm = re.search(r"Failed password for (?:invalid user )?\S+ from (\S+) port", msg)
        if fm:
            ip = fm.group(1)
        elif pam:
            pm = re.search(r"authentication failure;.*?rhost=(\S+)", msg)
            ip = pm.group(1) if pm else None
        if ip:
            t = datetime(year, mon[m.group(1)], int(m.group(2)), int(m.group(3)), int(m.group(4)), int(m.group(5))).timestamp()
            per[ip].append((t, w))
            total += w
    hit = set()
    for ip, items in per.items():
        items.sort()
        for t, _ in items:
            if sum(w for u, w in items if t <= u <= t + window_min * 60) >= min_n:
                hit.add(ip)
                break
    return total, hit


def _template(line):
    m = re.match(r"^\w{3}\s+\d+\s+[\d:]+\s+\S+\s+(\S+?)(?:\[\d+\])?:\s+(.*)$", line.rstrip("\r\n"))
    if not m:
        return "(not syslog format)"
    s = m.group(2)
    s = re.sub(r"\b\d{1,3}(\.\d{1,3}){3}\b", "<IP>", s)
    s = re.sub(r"\b\d+\b", "<N>", s)
    s = re.sub(r"(user|for) \S+", r"\1 <U>", s)
    s = re.sub(r"\S+\.\S+\.\S+", "<HOST>", s)
    return f"{m.group(1)}: {s[:64]}"


def linux_eval(root):
    rd = os.path.join(root, "real_data", "linux")
    out = {}
    cfg = dict(config.DEFAULT_CASE, linux_log_year=2015, linux_timezone_offset="+00:00")
    for fname in ("OpenSSH_2k.log", "Linux_2k.log"):
        p = os.path.join(rd, fname)
        if not os.path.exists(p):
            continue
        lines = [l for l in open(p, encoding="utf-8", errors="replace") if l.strip()]
        ev, st = normalize.parse_linux(p, cfg["linux_timezone_offset"], cfg["linux_log_year"])
        fl, c = _flags(ev, cfg)
        types = collections.Counter(e["event_type"] for e in ev)
        ignored_t = collections.Counter(_template(l) for l in lines)
        ignored = collections.Counter()
        parsed_lines = {e["line_ref"] for e in ev}
        for k, l in enumerate(open(p, encoding="utf-8", errors="replace"), 1):
            if l.strip() and k not in parsed_lines:
                ignored[_template(l)] += 1
        res = dict(lines=len(lines), normalized=st["normalized"], ignored=st["ignored"], errors=st["errors"], types=dict(types),
                   flags=dict(fl), top_ignored=ignored.most_common(6), incidents=len(c["incidents"]))
        if True:
            fails, ips = _independent_bruteforce(p, 2015, config.BRUTE_FORCE_MIN_FAILURES, config.BRUTE_FORCE_WINDOW_MIN)
            fw_ips = {e["src_ip"] for e in ev if "brute_force" in e["flags"]}
            per_ip = collections.Counter()
            for e in ev:
                if e["event_type"] == "auth_failure":
                    per_ip[e["src_ip"]] += (e.get("extra") or {}).get("repeat", 1)
            res.update(independent_failed_password=fails, framework_auth_failure=sum(per_ip.values()),
                       independent_bf_ips=len(ips), framework_bf_ips=len(fw_ips), bf_ips_agree=(ips == fw_ips),
                       accepted=types.get("auth_success", 0), bf_success=fl.get("brute_force_success", 0),
                       top_attackers=[(ip, per_ip[ip]) for ip, _ in per_ip.most_common(8)],
                       distinct_failing_ips=len(per_ip))
        out[fname] = res
    return out


def aws_eval(root):
    rd = os.path.join(root, "real_data", "aws")
    cfg = config.load_case_config(None)
    v1 = {}
    pv = os.path.join(root, "real_data", "baseline_v1_aws.json")
    if os.path.exists(pv):
        v1 = json.load(open(pv))
    rows = []
    for f, (ok, why) in AWS_EXPECT.items():
        p = os.path.join(rd, f)
        if not os.path.exists(p):
            continue
        ev, st = normalize.parse_cloudtrail(p)
        fl, _ = _flags(ev, cfg)
        b = v1.get(f, {})
        v1_state = "crashed (invalid JSON)" if "crashed" in b else ("hit" if set(b.get("flags", {})) & ok else "miss")
        rows.append(dict(file=f, why=why, records=st["records_seen"], normalized=st["normalized"], errors=st["errors"],
                         expected=sorted(ok), flags=dict(fl), hit=bool(set(fl) & ok), v1=v1_state))
    return rows


# --------------------------------------------------------------------------------------------
def _pct(a, b):
    return f"{100 * a / b:.1f}%" if b else "n/a"


def build_report(data):
    from report import CSS, _table
    w, lx, aw = data["windows"], data["linux"], data["aws"]
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    v1 = data.get("windows_v1") or {}
    o = [f"<!doctype html><html><head><meta charset='utf-8'><title>Real data validation</title><style>{CSS}</style></head><body>"
         f"<header><h1>Validation on REAL public data</h1><p>Generated {now} · no simulated logs in this report</p></header><main>"]
    lab = [x for x in w["labelled"]]
    core = [x for x in lab if not x["hard"]]
    hard = [x for x in lab if x["hard"]]
    o.append('<div class="cards">')
    o.append(f'<div class="card"><b>{w["samples"]}</b><span>real Windows attack captures ({w["records"]:,} records)</span></div>')
    o.append(f'<div class="card"><b>{_pct(w["with_supported"], w["samples"])}</b><span>of samples contain events the framework understands'
             + (f' (was {_pct(v1.get("with_supported", 0), w["samples"])} before Sysmon support)' if v1 else '') + '</span></div>')
    o.append(f'<div class="card"><b>{sum(x["hit"] for x in core)}/{len(core)}</b><span>labelled samples detected (development set)</span></div>')
    o.append(f'<div class="card"><b>{sum(x["hit"] for x in hard)}/{len(hard)}</b><span>deliberately hard / unsupported cases detected</span></div>')
    o.append(f'<div class="card"><b>{sum(r["hit"] for r in aw)}/{len(aw)}</b><span>real CloudTrail attack samples detected</span></div>')
    o.append("</div>")
    o.append("<p class='note'><b>Read this first.</b> These are real logs, so the numbers are honest but limited: (1) the detection rules were written "
             "after looking at these samples, so the labelled results are <i>development-set</i> results and optimistic; "
             "(2) the false-positive rate on real benign traffic is <b>not</b> measured, because no labelled real benign logs were available; "
             "(3) correlation across platforms on a real incident is <b>not</b> measured, because no public dataset has real Windows + Linux + AWS logs of one incident "
             "(cross-platform correlation is evaluated only on the simulated scenarios).</p>")

    o.append("<h2>1. Windows: 278 real attack captures</h2>")
    o.append(f"<p>{w['records']:,} records parsed with <b>{w['errors']} parse errors</b>. {w['supported_events']:,} records ({_pct(w['supported_events'], w['records'])}) are events in the framework's catalogue; "
             f"{w['with_supported']} of {w['samples']} samples contain at least one, and {w['alerted']} samples raised at least one alert.</p>")
    o.append(_table(["ATT&CK tactic (folder)", "Samples", "With supported events", "Raised an alert"],
                    [[h(k), v["samples"], v["with_supported"], v["alerted"]] for k, v in w["per_tactic"].items()]))
    o.append("<p class='note'>An alert on a sample is not the same as detecting <i>its</i> technique: several samples contain a Security-log-cleared event (1102) that comes from how the dataset was captured. The labelled table below is the proper detection test.</p>")
    o.append("<h3>Labelled samples (expected alert taken from the sample's file name)</h3>")
    o.append(_table(["Sample", "Behaviour", "Expected alert", "Alerts raised", "Result"],
                    [[h(x["file"]), h(x["why"]), h(", ".join(x["expected"])), h(", ".join(x["flags"]) or "none"),
                      '<span class="ok">HIT</span>' if x["hit"] else '<span class="bad">MISS</span>'] for x in lab]))
    o.append("<h3>What the framework still does not read (top ignored event types, all samples)</h3>")
    o.append(_table(["Channel | Event ID", "Records"], [[h(k), v] for k, v in w["top_ignored"]]))
    if v1:
        o.append(f"<p class='note'>Before this work, run on the same samples with the first version's catalogue (Security log events only): {v1.get('with_supported', 0)} of {w['samples']} samples had a supported event and "
                 f"{v1.get('alerted', 0)} raised an alert. The first version also could not read binary .evtx files or the time format of real exports; both were found and fixed with this data.</p>")

    o.append("<h2>2. Linux: real SSH server logs (LogHub)</h2>")
    rows = []
    for f, r in lx.items():
        rows.append([h(f), r["lines"], r["normalized"], _pct(r["normalized"], r["lines"]), r["errors"], r["incidents"]])
    o.append(_table(["File", "Lines", "Events normalized", "Share of lines", "Parse errors", "Incidents"], rows))
    s = lx.get("OpenSSH_2k.log")
    if s:
        o.append(f"<p><b>OpenSSH_2k.log</b> (real Internet-facing SSH server): the independent regex count finds {s['independent_failed_password']} failed-password lines; "
                 f"the framework normalized {s['framework_auth_failure']} as authentication failures "
                 f"({'agree' if s['independent_failed_password'] == s['framework_auth_failure'] else 'DO NOT agree'}). "
                 f"An independent naive brute-force detector finds {s['independent_bf_ips']} attacker IPs, the framework finds {s['framework_bf_ips']} "
                 f"({'same set' if s['bf_ips_agree'] else 'different sets'}). {s['distinct_failing_ips']} distinct IPs failed to log in; "
                 f"{s['accepted']} successful login(s) in the file; {s['bf_success']} of them right after a brute-force burst.</p>")
        o.append(_table(["Top failing source IPs (real attackers)", "Failed logins"], [[h(ip), n] for ip, n in s["top_attackers"]]))
        o.append("<p class='note'>This checks that parsing and the brute-force logic work correctly on real data. It is an implementation cross-check, not a measure of detection quality: there is no ground-truth label for these attackers.</p>")
        o.append("<h3>Most common line types that are NOT turned into events</h3>")
        o.append(_table(["Line type", "Lines"], [[h(k), v] for k, v in s["top_ignored"]]))

    o.append("<h2>3. AWS: real CloudTrail events from real attack detonations</h2>")
    o.append(_table(["Sample", "Behaviour", "Records", "Expected alert", "Alerts raised", "First version", "This version"],
                    [[h(x["file"]), h(x["why"]), x["records"], h(", ".join(x["expected"])), h(", ".join(f"{k}×{v}" for k, v in x["flags"].items()) or "none"),
                      h(x["v1"]), '<span class="ok">HIT</span>' if x["hit"] else '<span class="bad">MISS</span>'] for x in aw]))
    o.append("<p class='note'>Only 4 files (15 events). They are in Datadog's enriched format: the first version crashed on one file (records glued together without commas) and read no source IP from any of them. Both are fixed. These samples are far too few to say anything about accuracy; they show the parser works on real CloudTrail exports.</p>")

    o.append("<h2>4. Sources</h2><ul class='note'>"
             "<li>Windows: sbousseaden/EVTX-ATTACK-SAMPLES (GitHub). Sample labels here come from folder and file names.</li>"
             "<li>Linux: LogHub, He, Zhu, He and Lyu, <i>Loghub: A Large Collection of System Log Datasets towards Automated Log Analytics</i>, arXiv:2008.06448, 2020 (OpenSSH_2k, Linux_2k).</li>"
             "<li>AWS: zmallen/cloudtrail2sightings cloudtrail.zip, containing CloudTrail events produced by DataDog/stratus-red-team detonations.</li></ul>")
    o.append("</main></body></html>")
    return "".join(o)


def run(root, log=print):
    failed = fetch_all(root, log)
    if failed:
        log(f"Warning: could not download {len(failed)} file(s): {failed[:3]} ... Check the internet connection and run again.")
    log("Windows sweep (real .evtx captures) ...")
    rows, ignored, secs = windows_sweep(root, log)
    ws = windows_summary(rows, ignored)
    v1 = None
    pv = os.path.join(root, "real_data", "baseline_v1_windows.json")
    if os.path.exists(pv):
        b = [r for r in json.load(open(pv)) if "error" not in r]
        v1 = dict(with_supported=sum(r["supported"] > 0 for r in b), alerted=sum(bool(r["flags"]) for r in b))
    log("Linux (real SSH logs) ...")
    lx = linux_eval(root)
    log("AWS (real CloudTrail samples) ...")
    aw = aws_eval(root)
    data = dict(generated=datetime.now(timezone.utc).isoformat(), windows=ws, windows_v1=v1, linux=lx, aws=aw, windows_seconds=secs, windows_rows=rows)
    os.makedirs(os.path.join(root, "results"), exist_ok=True)
    with open(os.path.join(root, "results", "real_data_results.json"), "w", encoding="utf-8") as f:
        json.dump(data, f, indent=1)
    with open(os.path.join(root, "results", "real_data_report.html"), "w", encoding="utf-8") as f:
        f.write(build_report(data))
    return data
