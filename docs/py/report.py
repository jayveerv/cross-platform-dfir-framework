"""Reporting layer: self-contained HTML report (no internet, no JavaScript needed)."""
from datetime import datetime, timezone
from html import escape as h

BROWN, ORANGE, TINT = "#0E4A6E", "#0EA5E9", "#EEF5FB"
SEV_COL = {"high": "#E11D48", "medium": "#D97706", "info": "#94A3B8"}
PLAT_NAME = {"windows": "Windows", "linux": "Linux", "aws": "AWS", "host": "Live host", "cloud": "AWS account state"}
CLOUD_STATE_TYPES = ("trail_state", "account_state", "iam_user_state", "access_key_state", "bucket_state", "sg_state")

CSS = f"""
body{{font-family:"Segoe UI",Inter,Calibri,Arial,sans-serif;margin:0;color:#0F172A;background:#F3F6FA;font-size:14px}}
header{{background:linear-gradient(110deg,#070B14 0%,#0B1A33 55%,#12284A 100%);color:#E6EDF7;padding:22px 36px;border-bottom:3px solid #22D3EE}}
header h1{{margin:0;font-size:24px;letter-spacing:.2px}} header h1 small{{display:block;font-size:11px;letter-spacing:2px;color:#22D3EE;font-weight:600;margin-bottom:6px;text-transform:uppercase}}
header p{{margin:6px 0 0;color:#8EA0BF;font-size:12.5px}}
main{{padding:10px 36px 48px;max-width:1280px;margin:auto}}
h2{{color:#0B1A33;border-left:4px solid {ORANGE};padding:2px 0 2px 12px;margin-top:36px;font-size:20px}}
h3{{color:{BROWN};margin:22px 0 6px}}
.cards{{display:flex;gap:14px;flex-wrap:wrap;margin:20px 0}}
.card{{background:#fff;border:1px solid #DCE4EF;border-left:4px solid {ORANGE};border-radius:10px;padding:12px 18px;min-width:160px;box-shadow:0 2px 10px rgba(15,23,42,.05)}}
.card b{{display:block;font-size:27px;color:#0B1A33}} .card b span{{font-size:22px}} .card span{{font-size:12px;color:#475569}}
table{{border-collapse:separate;border-spacing:0;width:100%;font-size:12.5px;margin:8px 0;background:#fff;border:1px solid #DCE4EF;border-radius:8px;overflow:hidden}}
th{{background:#0B1A33;color:#E6EDF7;text-align:left;padding:7px 9px;font-weight:600}}
td{{border-top:1px solid #E5EBF3;padding:6px 9px;vertical-align:top}} tr:nth-child(even) td{{background:{TINT}}}
.ok{{color:#059669;font-weight:bold}} .bad{{color:#E11D48;font-weight:bold}}
.tag{{display:inline-block;padding:1px 7px;border-radius:5px;font-size:11px;color:#fff;margin:1px;font-weight:600}}
.note{{font-size:12.5px;color:#475569}} code{{background:#E8EEF6;padding:1px 4px;font-size:11.5px;border-radius:3px}}
.mono{{font-family:Consolas,"Cascadia Code",monospace;font-size:11.5px;word-break:break-all}}
details{{margin:10px 0}} summary{{cursor:pointer;color:{BROWN};font-weight:bold}}
svg text{{font-family:"Segoe UI",Calibri,Arial,sans-serif}}
"""


def _sev(s):
    return f'<span class="tag" style="background:{SEV_COL.get(s.lower(), "#999")}">{h(s.upper())}</span>'


def _table(head, rows, cls=""):
    out = [f'<table class="{cls}"><tr>' + "".join(f"<th>{h(c)}</th>" for c in head) + "</tr>"]
    for r in rows:
        out.append("<tr>" + "".join(f"<td>{c}</td>" for c in r) + "</tr>")
    out.append("</table>")
    return "".join(out)


SHORT = {"credential file read in session": "credential read", "same API call": "same API call",
         "credential inventory (file holds key)": "file holds key", "key created by key": "key created",
         "same event": "same event"}


def graph_svg(inc):
    cols = {"ip": [], "cred": [], "key": []}
    for n in inc["entities"]:
        cols[n["kind"]].append(n)
    xs = {"ip": 20, "cred": 420, "key": 820}
    w, hh = 250, 34
    pos = {}
    rows = max(len(v) for v in cols.values()) if any(cols.values()) else 1
    height = 50 + rows * 62
    parts = [f'<svg width="1200" height="{height}" xmlns="http://www.w3.org/2000/svg" style="background:#fff;border:1px solid #DCE4EF;border-radius:8px">']
    titles = {"ip": "Attacker IP", "cred": "Credential file", "key": "Cloud access key"}
    for k, x in xs.items():
        if cols[k]:
            parts.append(f'<text x="{x}" y="18" font-size="12" font-weight="bold" fill="{BROWN}">{titles[k]}</text>')
    for k, lst in cols.items():
        for i, n in enumerate(lst):
            y = 30 + i * 62
            pos[n["id"]] = (xs[k], y)
    for l in inc["links"]:
        if l["a"] in pos and l["b"] in pos:
            (x1, y1), (x2, y2) = pos[l["a"]], pos[l["b"]]
            a_right = x1 + w if x1 < x2 else x1
            b_left = x2 if x1 < x2 else x2 + w
            if x1 == x2:
                a_right, b_left = x1 + w, x2 + w
                parts.append(f'<path d="M{a_right} {y1 + hh / 2} h22 V{y2 + hh / 2} h-22" fill="none" stroke="#6B7280" stroke-width="1.6"/>')
                parts.append(f'<text x="{a_right + 28}" y="{(y1 + y2) / 2 + hh / 2 + 4}" font-size="10" fill="#374151">{h(SHORT.get(l["reason"], l["reason"]))}</text>')
                continue
            parts.append(f'<line x1="{a_right}" y1="{y1 + hh / 2}" x2="{b_left}" y2="{y2 + hh / 2}" stroke="#6B7280" stroke-width="1.6"/>')
            mx, my = (a_right + b_left) / 2, (y1 + y2) / 2 + hh / 2
            parts.append(f'<text x="{mx}" y="{my - 3}" font-size="10" text-anchor="middle" fill="#374151" '
                         f'style="paint-order:stroke;stroke:#fff;stroke-width:3px">{h(SHORT.get(l["reason"], l["reason"]))}</text>')
    for n in inc["entities"]:
        x, y = pos[n["id"]]
        label = n["id"].split(":", 1)[1]
        label = label if len(label) < 40 else "..." + label[-37:]
        plat = "/".join(PLAT_NAME[p] for p in n["platforms"])
        parts.append(f'<rect x="{x}" y="{y}" width="{w}" height="{hh}" rx="4" fill="{TINT}" stroke="{BROWN}"/>')
        parts.append(f'<text x="{x + 8}" y="{y + 15}" font-size="11.5" font-weight="bold" fill="#1F2937">{h(label)}</text>')
        parts.append(f'<text x="{x + 8}" y="{y + 28}" font-size="10" fill="#4B5563">{h(plat)} · {n["events"]} event{"s" if n["events"] != 1 else ""}</text>')
    parts.append("</svg>")
    return "".join(parts)


def timeline_svg(inc, by_id):
    evs = [by_id[i] for i in inc["event_ids"]]
    t0, t1 = evs[0]["epoch"], evs[-1]["epoch"]
    span = max(t1 - t0, 1)
    lanes = ["windows", "linux", "aws", "host"]
    lanes = [l for l in lanes if l in inc["platforms"]]
    W, left, top, lh = 1060, 90, 30, 46
    height = top + lh * len(lanes) + 40
    parts = [f'<svg width="{W}" height="{height}" xmlns="http://www.w3.org/2000/svg" style="background:#fff;border:1px solid #DCE4EF;border-radius:8px">']
    for i, l in enumerate(lanes):
        y = top + i * lh + lh / 2
        parts.append(f'<text x="10" y="{y + 4}" font-size="12" font-weight="bold" fill="{BROWN}">{PLAT_NAME[l]}</text>')
        parts.append(f'<line x1="{left}" y1="{y}" x2="{W - 20}" y2="{y}" stroke="#E2E8F0"/>')
    for e in evs:
        i = lanes.index(e["source"])
        x = left + (e["epoch"] - t0) / span * (W - left - 30)
        y = top + i * lh + lh / 2
        parts.append(f'<circle cx="{x:.1f}" cy="{y}" r="{5 if e["severity"] != "info" else 3.5}" fill="{SEV_COL[e["severity"]]}"><title>{h(e["time_utc"] + " " + e["event_type"] + " " + str(e["flags"]))}</title></circle>')
    base = top + lh * len(lanes) + 6
    for k in range(6):
        t = t0 + span * k / 5
        x = left + (t - t0) / span * (W - left - 30)
        lab = datetime.fromtimestamp(t, timezone.utc).strftime("%H:%M:%S")
        parts.append(f'<text x="{x:.0f}" y="{base + 14}" font-size="10" text-anchor="middle" fill="#4B5563">{lab}Z</text>')
    parts.append(f'<circle cx="{W - 260}" cy="{height - 8}" r="4" fill="{SEV_COL["high"]}"/><text x="{W - 252}" y="{height - 4}" font-size="10">high</text>')
    parts.append(f'<circle cx="{W - 210}" cy="{height - 8}" r="4" fill="{SEV_COL["medium"]}"/><text x="{W - 202}" y="{height - 4}" font-size="10">medium</text>')
    parts.append(f'<circle cx="{W - 140}" cy="{height - 8}" r="3" fill="{SEV_COL["info"]}"/><text x="{W - 132}" y="{height - 4}" font-size="10">related (not alerted)</text>')
    parts.append("</svg>")
    return "".join(parts)


def _event_row(e):
    flags = " ".join(f'<span class="tag" style="background:{SEV_COL["high" if e["severity"] == "high" else "medium"]}">{h(f)}</span>' for f in e["flags"])
    return [h(e["time_utc"].replace("T", " ")), PLAT_NAME[e["source"]], h(e["host"] or ""), h(e["event_type"]),
            h(e["user"] or ""), h(e["src_ip"] or ""), h((e["target"] or e["detail"] or "")[:70]), flags]


def build_report(ctx):
    events, corr, cfg = ctx["events"], ctx["corr"], ctx["cfg"]
    by_id = {e["event_id"]: e for e in events}
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    incs = corr["incidents"]
    o = [f"<!doctype html><html><head><meta charset='utf-8'><title>DFIR Report {h(cfg['case_id'])}</title><style>{CSS}</style></head><body>"]
    o.append(f"<header><h1><small>CP-DFIR · Cross-Platform DFIR Framework</small>DFIR Investigation Report — {h(cfg['case_id'])}</h1>"
             f"<p>Cross-Platform DFIR Framework · Investigator: {h(cfg.get('investigator', ''))} · Generated: {now}</p></header><main>")
    ok = ctx["custody_ok"]
    o.append('<div class="cards">')
    for val, lab in [(len(events), "events normalized"), (len(ctx["stats"]), "evidence sources"),
                     (corr["alert_events"], "events flagged"), (len(incs), "incidents found"),
                     ('<span class="ok">VERIFIED</span>' if ok else '<span class="bad">FAILED</span>', "chain of custody")]:
        o.append(f'<div class="card"><b>{val}</b><span>{lab}</span></div>')
    o.append("</div>")

    o.append("<h2>1. Incidents</h2>")
    if not incs:
        o.append("<p>No incident was found: no flagged event could be tied to an untrusted entity.</p>")
    for inc in incs:
        plats = " + ".join(PLAT_NAME[p] for p in inc["platforms"])
        o.append(f"<h3>{inc['id']} {_sev(inc['severity'])} &nbsp; {h(inc['start'].replace('T', ' '))} → {h(inc['end'].replace('T', ' '))}</h3>")
        o.append(f'<p class="note">Platforms: <b>{plats}</b> ({"cross-platform" if inc["cross_platform"] else "single platform"}) · '
                 f'{inc["event_count"]} events · {inc["alert_count"]} flagged · ATT&amp;CK: {h(", ".join(inc["techniques"]))}</p>')
        o.append("<p style='margin:18px 0 6px'><b>Attack stages (in order of first occurrence)</b></p>")
        o.append(_table(["First seen (UTC)", "Technique", "Stage", "Events", "Where"],
                        [[h(r["first"].replace("T", " ")), h(r["technique"]), h(r["name"]) + " " + _sev(r["severity"]), r["count"],
                          h(", ".join(f"{PLAT_NAME[s]}" for s in r["sources"]) + " / " + ", ".join(r["hosts"]))] for r in inc["stages"]]))
        o.append("<p style='margin:18px 0 6px'><b>How the evidence was linked</b></p>")
        o.append("<div>" + graph_svg(inc) + "</div>")
        o.append(_table(["From", "To", "Reason", "Events"], [[h(l["a"]), h(l["b"]), h(l["reason"]), l["events"]] for l in inc["links"]]))
        o.append("<p style='margin:18px 0 6px'><b>Timeline</b></p>")
        o.append("<div>" + timeline_svg(inc, by_id) + "</div>")
        o.append(f"<details><summary>All {inc['event_count']} events of {inc['id']}</summary>")
        o.append(_table(["Time (UTC)", "Platform", "Host", "Event", "User", "Source IP", "Target / detail", "Flags"],
                        [_event_row(by_id[i]) for i in inc["event_ids"]]))
        o.append("</details>")
    if corr["unlinked_alerts"]:
        o.append("<h3>Alerts not linked to any incident</h3>")
        o.append(_table(["Time (UTC)", "Platform", "Host", "Event", "User", "Source IP", "Target / detail", "Flags"],
                        [_event_row(by_id[i]) for i in corr["unlinked_alerts"]]))

    o.append("<h2>2. Chain of custody</h2>")
    o.append(f'<p>Result of re-verifying the whole ledger and every evidence file: {"<span class=ok>ALL CHECKS PASSED</span>" if ok else "<span class=bad>TAMPERING OR ERROR DETECTED</span>"}. '
             f'Signed with HMAC: <b>{"yes" if ctx.get("hmac_used") else "no (plain hash chain: a fully rewritten chain would not be detected without the anchor)"}</b>. '
             f'Ledger head hash at verification: <span class="mono">{h(ctx["head_hash"] or "")}</span><br>'
             f'<span class="note">The final anchor hash (after this report was recorded in the ledger) is printed on the console and saved in <code>custody_head.txt</code>. Note it down outside the case folder: it is what detects deletion of the last ledger entries.</span></p>')
    o.append("<b>Evidence acquired</b>")
    o.append(_table(["Source", "File", "Size (bytes)", "SHA-256", "Copy verified"],
                    [[PLAT_NAME[a["source"]], h(a["file"]), a["size"], f'<span class="mono">{a["sha256"]}</span>',
                      '<span class="ok">yes</span>' if a["copy_verified"] else '<span class="bad">NO</span>'] for a in ctx["acquired"]]))
    for m in ctx["acquire_msgs"]:
        o.append(f"<p class='note'>{h(m)}</p>")
    o.append("<details><summary>Verification details (every ledger entry and file)</summary>")
    o.append(_table(["Type", "Item", "Result", "Note"], [[c["type"], h(c["item"]), '<span class="ok">OK</span>' if c["ok"] else '<span class="bad">FAIL</span>', h(c["note"])] for c in ctx["custody_checks"]]))
    o.append("</details>")

    host_ev = [e for e in events if e["source"] == "host"]
    if host_ev:
        import collections
        import json as _json
        import os as _os
        cnt = collections.Counter(e["event_type"] for e in host_ev)
        col = next((e for e in host_ev if e["event_type"] == "collection"), None)
        o.append("<h2>2b. Live host evidence</h2>")
        if col:
            o.append(f"<p>{h(col['detail'] or '')} · host <b>{h(col['host'])}</b> · collected {h(col['time_utc'].replace('T', ' '))}</p>")
        o.append(_table(["Processes", "Network sockets", "Listeners", "Accounts", "Persistence entries", "Recent files", "Flagged"],
                        [[cnt["process_snapshot"], cnt["connection_snapshot"], cnt["listener_snapshot"], cnt["account_snapshot"],
                          cnt["persistence_entry"], cnt["file_snapshot"], sum(1 for e in host_ev if e["flags"])]]))
        mp = _os.path.join(ctx["case_dir"], "evidence", "host", "manifest.json")
        if _os.path.exists(mp):
            man = _json.load(open(mp, encoding="utf-8"))
            if man.get("limited"):
                o.append("<p class='note'><b>Collection limits (evidence that could NOT be collected):</b></p><ul class='note'>" +
                         "".join(f"<li>{h(v)}</li>" for v in man["limited"].values()) + "</ul>")
            o.append(f"<details><summary>Commands run and errors during collection</summary><p class='note'>Collector v{h(str(man.get('collector_version')))}, "
                     f"{man.get('duration_s')} s. Commands: {h('; '.join(c['cmd'] + ' (rc ' + str(c['rc']) + ')' for c in man.get('commands', [])) or 'none')}. "
                     f"Errors: {h('; '.join(man.get('errors', [])) or 'none')}.</p></details>")

    cloud_ev = [e for e in events if e["source"] == "aws" and e["event_type"] in CLOUD_STATE_TYPES]
    if cloud_ev:
        import collections as _c
        import json as _json
        import os as _os
        cc = _c.Counter(e["event_type"] for e in cloud_ev)
        o.append("<h2>2c. Cloud account state (AWS)</h2>")
        o.append("<p class='note'>Configuration of the account when the investigation started. Findings here describe exposure and are listed under alerts; they only join an incident when they touch an entity of that incident.</p>")
        o.append(_table(["Trails", "Users", "Access keys", "Buckets", "Security groups", "Findings"],
                        [[cc["trail_state"], cc["iam_user_state"], cc["access_key_state"], cc["bucket_state"], cc["sg_state"], sum(1 for e in cloud_ev if e["flags"])]]))
        mp = _os.path.join(ctx["case_dir"], "evidence", "cloud", "manifest.json")
        if _os.path.exists(mp):
            man = _json.load(open(mp, encoding="utf-8"))
            if man.get("limited") or man.get("errors"):
                o.append("<p class='note'><b>Cloud state that could NOT be collected:</b></p><ul class='note'>" + "".join(f"<li>{h(v)}</li>" for v in man.get("limited", {}).values()) +
                         "".join(f"<li>{h(v)}</li>" for v in man.get("errors", [])) + "</ul>")

    o.append("<h2>3. Processing summary</h2>")
    o.append(_table(["Source", "Records seen", "Normalized", "Ignored (outside catalogue)", "Parse errors"],
                    [[PLAT_NAME[k], v["records_seen"], v["normalized"], v["ignored"], v["errors"]] for k, v in ctx["stats"].items()]))
    tm = ctx["timings"]
    o.append(_table(["Stage", "Time (s)"], [[k.replace("_", " "), f"{v:.3f}"] for k, v in tm.items() if k != "total"]))

    o.append("<h2>4. Limitations of this analysis</h2><ul class='note'>"
             "<li>Detection is rule-based; thresholds are in <code>config.py</code>.</li>"
             "<li>Linux session attribution assumes a command belongs to the latest login of the same user on the same host (auth.log has no session id for sudo).</li>"
             "<li>The credential link uses the analyst-supplied <code>credential_inventory</code> in <code>case_config.json</code>; the logs alone do not show which key is stored in a file.</li>"
             "<li>&ldquo;Internal&rdquo; addresses are private ranges plus <code>internal_ranges</code> in the case config.</li></ul>")

    o.append("<h2>5. Full normalized timeline</h2>")
    lim = 1500
    o.append(f"<details><summary>Show events (first {min(lim, len(events))} of {len(events)})</summary>")
    o.append(_table(["Time (UTC)", "Platform", "Host", "Event", "User", "Source IP", "Target / detail", "Flags"], [_event_row(e) for e in events[:lim]]))
    o.append("</details></main></body></html>")
    return "".join(o)


def write_report(ctx, path):
    with open(path, "w", encoding="utf-8") as f:
        f.write(build_report(ctx))
