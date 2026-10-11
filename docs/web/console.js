"use strict";
const $ = s => document.querySelector(s);
const esc = v => String(v ?? "").replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
const PN = {windows:"Windows", linux:"Linux", aws:"AWS", host:"Live host", cloud:"AWS state"};
const PC = {windows:"var(--win)", linux:"var(--lin)", aws:"var(--aws)", host:"var(--host)", cloud:"var(--cloud)"};
const KC = {ip:"var(--rd)", key:"var(--aws)", cred:"var(--lin)", user:"var(--win)", host:"var(--host)", session:"var(--vi)", pid:"var(--host)"};
const plat = p => `<span class="plat" style="--pc:${PC[p]||"var(--mu)"}">${esc(PN[p]||p)}</span>`;
const sev = s => `<span class="badge b-${esc(String(s||"none").toLowerCase())}">${esc(s||"None")}</span>`;
const fmtB = n => n==null ? "" : n<1024 ? n+" B" : n<1048576 ? (n/1024).toFixed(1)+" KB" : (n/1048576).toFixed(1)+" MB";
let INFO = {}, CUR = null, PICKED = [];
const MODE = window.CPDFIR_MODE || "local";          // "local" = Flask server, "browser" = GitHub Pages + Pyodide
const REPO = "https://github.com/jayveerv/cross-platform-dfir-framework";
const DASH = MODE === "browser" ? "dashboard.html" : "/dashboard";

// ------------------------------------------------------------------ in-browser backend (Pyodide worker)
const B = (() => {
  if (MODE !== "browser") return null;
  let seq = 0, readyRes, readyRej, info = null;
  const pend = {}, JOBS = {}, Q = {}, blobs = {};
  const ready = new Promise((res, rej) => { readyRes = res; readyRej = rej; });
  const w = new Worker("web/worker.js" + location.search);
  const setStatus = (msg, cls) => { const e = $("#engine"); if (e) { e.textContent = msg; e.className = "chip " + (cls||"warn"); } };
  w.onmessage = ev => {
    const d = ev.data;
    if (d.type === "status") return setStatus(d.msg);
    if (d.type === "ready") { info = d.info; setStatus(`Python ${d.info.python} engine ready · runs in your browser`, "ok"); return readyRes(d.info); }
    if (d.type === "fatal") { setStatus("Engine failed to load", "warn"); toast("The Python engine could not load: " + d.msg, true); return readyRej(new Error(d.msg)); }
    if (d.job) { (Q[d.job] = Q[d.job] || []).push(d); return; }
    const p = pend[d.id]; if (!p) return; delete pend[d.id];
    d.ok ? p.res(d.result) : p.rej(new Error(d.error));
  };
  const call = (cmd, args, transfer) => new Promise((res, rej) => { const id = ++seq; pend[id] = {res, rej}; w.postMessage({id, cmd, args}, transfer || []); });
  // job events arrive in a burst; show them at a readable pace (display only, the analysis itself is already done)
  setInterval(() => {
    for (const [jid, q] of Object.entries(Q)) {
      const j = JOBS[jid]; if (!j || !q.length) continue;
      const d = q.shift(), now = Date.now();
      if (d.type === "log") j.log.push({t: new Date().toTimeString().slice(0,8), msg: d.msg});
      if (d.type === "files") j.files = d.files;
      if (d.type === "stage") { if (j.stage !== d.stage && !j.stages_done.includes(j.stage)) j.stages_done.push(j.stage); j.stage = d.stage; }
      if (d.type === "done") { Object.assign(j, {state: "done", stage: "done", case: d.case, finished: now, stages_done: ["intake","acquisition","normalization","correlation","custody","reporting","done"]}); }
      if (d.type === "error") { Object.assign(j, {state: "error", error: d.error, finished: now}); j.log.push({t: new Date().toTimeString().slice(0,8), msg: "ERROR: " + d.error}); }
    }
  }, 140);
  const safe = n => (String(n||"").trim().replace(/[^A-Za-z0-9_.-]+/g, "-").replace(/^[-.]+|[-.]+$/g, "").slice(0, 60)) || ("CASE-" + new Date().toISOString().slice(0,19).replace(/[-:T]/g, ""));
  function job(kind, kase, form, files) {
    const jid = Math.random().toString(16).slice(2, 14);
    JOBS[jid] = {id: jid, kind, case: kase, state: "running", stage: "intake", stages_done: [], log: [], files: [], error: null, started: Date.now(), finished: null};
    const transfer = files ? files.map(f => f.data) : [];
    ready.then(() => call("job", {jid, kind, case: kase, form, files}, transfer)).catch(e => {
      if (!(Q[jid]||[]).some(x => x.type === "error")) (Q[jid] = Q[jid] || []).push({type: "error", error: e.message});
    });
    return {job: jid, case: kase};
  }
  async function handle(url, opt) {
    const u = new URL(url, location.href), p = u.pathname.replace(/^.*?\/api\//, "/api/"), m = (opt && opt.method) || "GET";
    const body = opt && opt.body ? JSON.parse(opt.body) : {};
    let r;
    if (p === "/api/info") return info || await ready;
    if (r = p.match(/^\/api\/jobs\/(\w+)$/)) { const j = JOBS[r[1]]; if (!j) throw new Error("job not found"); return Object.assign({}, j, {elapsed: (((j.finished || Date.now()) - j.started) / 1000).toFixed(1)}); }
    await ready;
    if (p === "/api/cases") return call("list");
    if (r = p.match(/^\/api\/cases\/([^/]+)\/events$/)) return call("events", {name: decodeURIComponent(r[1]), q: u.searchParams.get("q"), source: u.searchParams.get("source"), alerts: u.searchParams.get("alerts") === "1"});
    if (r = p.match(/^\/api\/cases\/([^/]+)\/verify$/)) return call("verify", {name: decodeURIComponent(r[1]), anchor: body.anchor});
    if (r = p.match(/^\/api\/cases\/([^/]+)\/tamper$/)) return call("tamper", {name: decodeURIComponent(r[1]), what: body.what});
    if (r = p.match(/^\/api\/cases\/([^/]+)$/)) return call("detail", {name: decodeURIComponent(r[1])});
    if (p === "/api/sample") return job("sample", safe(body.case_name || "SAMPLE-" + body.scenario), body);
    throw new Error("This action needs the desktop version (start_web.bat): live triage, INPUT folder and AWS collection read your own computer.");
  }
  async function upload(picked, form) {
    const files = [];
    for (const [f, path] of picked) files.push({path, data: await f.arrayBuffer()});
    return job("upload", safe(form.case_name), form, files);
  }
  async function fileURL(name, f, type) {
    const k = name + "/" + f;
    if (!blobs[k]) blobs[k] = URL.createObjectURL(new Blob([await call("file", {name, f})], {type}));
    return blobs[k];
  }
  function dropCase(name) { for (const k of Object.keys(blobs)) if (k.startsWith(name + "/")) { URL.revokeObjectURL(blobs[k]); delete blobs[k]; } }
  async function downloadZip(name) {
    const url = URL.createObjectURL(new Blob([await call("zip", {name})], {type: "application/zip"}));
    const a = Object.assign(document.createElement("a"), {href: url, download: name + ".zip"}); document.body.appendChild(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 30000);
  }
  return {handle, upload, fileURL, downloadZip, dropCase, ready};
})();

// links to a case's files: real URLs on the local server, blob URLs made by the in-browser engine on GitHub Pages
function caseButtons(name, report) {
  const n = encodeURIComponent(name);
  if (MODE !== "browser")
    return `${report?`<a class="btn pri" href="/cases/${n}/report.html" target="_blank" rel="noopener">Full forensic report ↗</a>`:""}
      <a class="btn" href="/cases/${n}/timeline.csv">Timeline CSV</a><a class="btn" href="/api/cases/${n}/download">Download case .zip</a>`;
  return `<a class="btn pri" data-blob="report.html" data-type="text/html" target="_blank" rel="noopener" href="#">Full forensic report ↗</a>
      <a class="btn" data-blob="timeline.csv" data-type="text/csv" download="${esc(name)}_timeline.csv" href="#">Timeline CSV</a><a class="btn" data-zip="1" href="#">Download case .zip</a>`;
}
async function wireCaseButtons(name, root) {
  if (MODE !== "browser") return;
  B.dropCase(name);
  for (const a of (root || document).querySelectorAll("a[data-blob]")) {
    a.style.opacity = .5;
    try { a.href = await B.fileURL(name, a.dataset.blob, a.dataset.type); a.style.opacity = ""; } catch (e) { a.title = e.message; }
  }
  for (const a of (root || document).querySelectorAll("a[data-zip]")) a.onclick = e => { e.preventDefault(); B.downloadZip(name).catch(x => toast(x.message, true)); };
}

async function api(url, opt) {
  if (MODE === "browser") return B.handle(url, opt);
  const r = await fetch(url, opt);
  const t = await r.text();
  let j; try { j = JSON.parse(t); } catch { j = {error: t.slice(0, 300)}; }
  if (!r.ok) throw new Error(j.error || ("HTTP " + r.status));
  return j;
}
const post = (url, body) => api(url, {method:"POST", headers:{"Content-Type":"application/json"}, body:JSON.stringify(body||{})});
function toast(msg, err) {
  const d = document.createElement("div"); if (err) d.className = "e"; d.textContent = msg;
  $("#toast").appendChild(d); setTimeout(() => d.remove(), err ? 7000 : 3500);
}

// ------------------------------------------------------------------ theme
(function(){
  let t = null; try { t = localStorage.getItem("cpdfir-theme"); } catch {}
  if (t) document.documentElement.dataset.theme = t;
  $("#theme").onclick = () => {
    const n = document.documentElement.dataset.theme === "light" ? "dark" : "light";
    document.documentElement.dataset.theme = n; try { localStorage.setItem("cpdfir-theme", n); } catch {}
  };
})();

// ------------------------------------------------------------------ router
async function route() {
  const h = location.hash.replace(/^#\/?/, "") || "new";
  const [page, a, b] = h.split("/").map(decodeURIComponent);
  document.querySelectorAll(".side a[data-nav]").forEach(x => x.classList.toggle("on", x.dataset.nav === page || (page==="case" && x.dataset.nav==="cases")));
  try {
    if (page === "new") return viewNew();
    if (page === "cases") return viewCases();
    if (page === "job") return viewJob(a);
    if (page === "case") return viewCase(a, b || "overview");
    if (page === "about") return viewAbout();
    viewNew();
  } catch (e) { $("#view").innerHTML = `<div class="card empty">${esc(e.message)}</div>`; }
}
window.addEventListener("hashchange", route);

async function boot() {
  if (MODE === "browser") {
    $("#chips").innerHTML = `<span class="chip warn" id="engine">Starting the Python engine ...</span><span class="chip ok">Evidence never leaves this computer</span>`;
    $("#who").innerHTML = `<b>Jayveer Vasava</b>M.Tech CSE (Cyber Security)<br>PIET, Parul University<br><span class="mono">framework running in your browser</span>`;
    route();
    try { INFO = await api("/api/info"); } catch (e) { INFO = {}; }
    $("#chips").insertAdjacentHTML("beforeend", `<span class="chip ok">${esc(INFO.rules||57)} rules · ${esc(INFO.techniques||"")} ATT&CK techniques</span>`);
    if (location.hash.replace(/^#\/?/, "").startsWith("new") || !location.hash) route();
    refreshCount();
    return;
  }
  try { INFO = await api("/api/info"); } catch (e) { INFO = {}; }
  $("#chips").innerHTML =
    `<span class="chip">${esc(INFO.host||"")}</span>` +
    `<span class="chip ${INFO.admin?"ok":"warn"}">${INFO.admin?"Administrator":"Not administrator"}</span>` +
    `<span class="chip ${INFO.hmac?"ok":""}">${INFO.hmac?"HMAC custody key set":"Hash-chain custody"}</span>` +
    `<span class="chip ok">${esc(INFO.rules||57)} rules · ${esc(INFO.techniques||"")} ATT&CK techniques</span>`;
  $("#who").innerHTML = `<b>${esc(INFO.investigator||"Investigator")}</b>M.Tech CSE (Cyber Security)<br>PIET, Parul University<br><span class="mono">listening on 127.0.0.1 only</span>`;
  refreshCount(); route();
}
async function refreshCount() {
  try { const c = await api("/api/cases"); $("#ncases").textContent = c.length || ""; } catch {}
}

// ------------------------------------------------------------------ NEW INVESTIGATION
function viewNew() {
  $("#casenav").innerHTML = "";
  const sc = Object.entries(INFO.scenarios||{}).map(([k,v]) => `<option value="${esc(k)}">${esc(k)} - ${esc(v)}</option>`).join("");
  const inbox = INFO.inbox||[];
  $("#view").innerHTML = `
  <h1>New investigation</h1>
  <p class="lead">Give the framework evidence from any of the three platforms. File names do not matter: every file is opened and recognised
  from its content (Windows event log, Linux auth log, AWS CloudTrail). Originals are never changed; their SHA-256 goes into the chain of custody.</p>
  <div class="grid g2">
    <div class="card">
      <h2>1 · Upload evidence</h2>
      <div class="drop" id="drop">
        <svg width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6"><path d="M12 16V4M7 9l5-5 5 5"/><path d="M4 16v3a1 1 0 001 1h14a1 1 0 001-1v-3"/></svg>
        <div class="big">Drop log files or a whole folder here</div>
        <div class="muted small">.evtx · Event Viewer XML · auth.log / secure · CloudTrail .json · .zip · .gz — any file name</div>
        <div class="row" style="justify-content:center;margin-top:14px">
          <button class="btn sm" id="pickf">Choose files</button><button class="btn sm" id="pickd">Choose folder</button>
        </div>
        <input type="file" id="ff" multiple hidden><input type="file" id="fd" webkitdirectory multiple hidden>
      </div>
      <div id="flist"></div>
      <div class="grid g2" style="grid-template-columns:1fr 1fr;gap:12px">
        <div><label class="f">Case name</label><input type="text" id="cname" placeholder="e.g. CASE-WEB01-BREACH (optional)"></div>
        <div><label class="f">Investigator</label><input type="text" id="inv" value="${esc(INFO.investigator||"")}"></div>
      </div>
      <details><summary>Advanced case settings (optional)</summary>
        <div class="grid" style="grid-template-columns:1fr 1fr;gap:12px">
          <div><label class="f">Linux log time zone</label><input type="text" id="tz" value="+05:30"></div>
          <div><label class="f">Year of Linux log lines (syslog has no year)</label><input type="text" id="yr" value="${new Date().getFullYear()}"></div>
        </div>
        <label class="f">Internal networks (office NAT, VPN) — comma separated CIDRs</label><input type="text" id="nets" placeholder="198.51.100.0/24, 10.20.0.0/16">
        <label class="f">Credential inventory — one per line: host:/path/to/credentials = AKIA... (links a Linux file read to the AWS key it holds)</label>
        <textarea id="creds" placeholder="web01:/home/ubuntu/.aws/credentials = AKIAEXAMPLE0001"></textarea>
      </details>
      <div class="row" style="margin-top:16px"><button class="btn pri" id="go" disabled>Start analysis</button><span class="muted small" id="gohint">Add at least one file</span></div>
    </div>
    <div class="card">
      <h2>2 · Or collect / use evidence from here</h2>
      <div class="opt"><div class="ic">⚔</div><div style="flex:1"><b>Built-in attack scenario</b><p>Generates realistic Windows + Linux + AWS logs of a known attack and investigates them. Good for the demo.</p>
        <select id="scen">${sc}</select><div class="row" style="margin-top:8px"><button class="btn sm" id="runsc">Run scenario</button></div></div></div>
${MODE === "browser" ? `      <div class="opt"><div class="ic">🔒</div><div style="flex:1"><b>Runs entirely in your browser</b><p>This page loads the framework's own Python code (the same <span class="mono">intake.py</span>, <span class="mono">normalize.py</span>, <span class="mono">correlate.py</span>, <span class="mono">custody.py</span> …) into the browser with WebAssembly. Your log files are analysed here and are <b style="display:inline;color:var(--gr)">never uploaded</b> anywhere. Cases stay in this tab — download the .zip to keep one.</p></div></div>
      <div class="opt"><div class="ic">🖥</div><div style="flex:1"><b>Live triage, INPUT folder, AWS collection</b><p>These read evidence directly from a computer or an AWS account, so they need the desktop version: download the repository and double-click <span class="mono">start_web.bat</span>.</p>
        <div class="row"><a class="btn sm" href="${REPO}" target="_blank" rel="noopener">GitHub repository ↗</a><a class="btn sm" href="${REPO}/archive/refs/heads/main.zip">Download desktop version (.zip)</a></div></div></div>
      <div class="opt"><div class="ic">📊</div><div style="flex:1"><b>Framework evaluation</b><p>Accuracy on S1–S5, 25/25 tamper tests, AWS checks, scalability to 100,000 records and validation on real public data.</p>
        <div class="row"><a class="btn sm" href="${DASH}" target="_blank" rel="noopener">Open evaluation dashboard ↗</a></div></div></div>
` : `      <div class="opt"><div class="ic">📂</div><div style="flex:1"><b>INPUT folder</b><p>Copy logs into <span class="mono">${esc(INFO.inbox_path||"INPUT")}</span> with Explorer, then analyse them all at once.</p>
        <div class="small muted">${inbox.length ? `${inbox.length} item(s) waiting: ${inbox.slice(0,4).map(esc).join(", ")}${inbox.length>4?" …":""}` : "Folder is empty right now."}</div>
        <div class="row" style="margin-top:8px"><button class="btn sm" id="runin" ${inbox.length?"":"disabled"}>Analyse INPUT folder</button><button class="btn sm" id="rein">Refresh</button></div></div></div>
      <div class="opt"><div class="ic">🖥</div><div style="flex:1"><b>Triage this computer (live)</b><p>Collects live evidence from <span class="mono" style="color:var(--tx)">${esc(INFO.host||"this computer")}</span>: running processes, network connections, accounts, startup / scheduled-task persistence, recent files and security logs — then analyses it.</p>
        ${INFO.admin?"":`<div class="small" style="color:var(--am)">Not running as Administrator: some evidence (Security log, other users' processes) will be limited. Start the console with “Run as administrator” for a full triage.</div>`}
        <div class="row" style="margin-top:8px"><button class="btn sm" id="runtr">Start live triage</button></div></div></div>
      <div class="opt"><div class="ic">📊</div><div style="flex:1"><b>Framework evaluation</b><p>Re-runs accuracy (S1–S5), tamper tests, cloud checks and scalability, then rebuilds the evaluation dashboard.</p>
        <div class="row"><button class="btn sm" id="runev">Run evaluation (~1-2 min)</button><a class="btn sm" href="${DASH}" target="_blank" rel="noopener">Open dashboard ↗</a></div></div></div>
`}
    </div>
  </div>
  <div class="card help">
    <h2>Where do I get the logs?</h2>
    <div class="grid g3">
      <div style="--pc:var(--win)"><b>Windows</b><ol><li>Open <i>Event Viewer</i> → Windows Logs → <i>Security</i></li><li>Right-click → <i>Save All Events As…</i> → .evtx</li><li>Drop the .evtx here (any name). Sysmon / PowerShell / System logs also work.</li></ol></div>
      <div style="--pc:var(--lin)"><b>Linux</b><ol><li>Copy <span class="mono">/var/log/auth.log</span> (Ubuntu/Kali) or <span class="mono">/var/log/secure</span> (RedHat)</li><li>Rotated <span class="mono">auth.log.2.gz</span> files work too</li><li>Drop them here</li></ol></div>
      <div style="--pc:var(--aws)"><b>AWS</b><ol><li>AWS Console → <i>CloudTrail</i> → <i>Event history</i></li><li><i>Download events</i> → JSON</li><li>Drop the .json here. Or run <span class="mono">run.bat → AWS</span> to pull events + account state with credentials.</li></ol></div>
    </div>
  </div>`;

  const drop = $("#drop");
  $("#pickf").onclick = e => { e.stopPropagation(); $("#ff").click(); };
  $("#pickd").onclick = e => { e.stopPropagation(); $("#fd").click(); };
  drop.onclick = () => $("#ff").click();
  $("#ff").onchange = e => addFiles([...e.target.files].map(f => [f, f.name]));
  $("#fd").onchange = e => addFiles([...e.target.files].map(f => [f, f.webkitRelativePath || f.name]));
  drop.ondragover = e => { e.preventDefault(); drop.classList.add("over"); };
  drop.ondragleave = () => drop.classList.remove("over");
  drop.ondrop = async e => {
    e.preventDefault(); drop.classList.remove("over");
    const items = [...(e.dataTransfer.items||[])].map(i => i.webkitGetAsEntry && i.webkitGetAsEntry()).filter(Boolean);
    if (items.length) { const out = []; for (const it of items) await walk(it, "", out); addFiles(out); }
    else addFiles([...e.dataTransfer.files].map(f => [f, f.name]));
  };
  $("#go").onclick = startUpload;
  $("#runsc").onclick = () => startJob(post("/api/sample", {scenario:$("#scen").value, investigator:$("#inv").value}));
  if (MODE !== "browser") {
    $("#runin").onclick = () => startJob(post("/api/inbox", formVals()));
    $("#rein").onclick = async () => { INFO = await api("/api/info"); viewNew(); };
    $("#runtr").onclick = () => startJob(post("/api/triage", {investigator:$("#inv").value}));
    $("#runev").onclick = () => startJob(post("/api/evaluate", {}));
  }
  PICKED = []; renderPicked();
}
function walk(entry, path, out) {
  return new Promise(res => {
    if (entry.isFile) entry.file(f => { out.push([f, path + f.name]); res(); }, () => res());
    else if (entry.isDirectory) {
      const r = entry.createReader(), all = [];
      const read = () => r.readEntries(async es => {
        if (!es.length) { for (const x of all) await walk(x, path + entry.name + "/", out); res(); }
        else { all.push(...es); read(); }
      }, () => res());
      read();
    } else res();
  });
}
function addFiles(list) {
  for (const [f, p] of list) if (!PICKED.some(x => x[1] === p && x[0].size === f.size)) PICKED.push([f, p]);
  renderPicked();
}
function renderPicked() {
  const total = PICKED.reduce((a, [f]) => a + f.size, 0);
  $("#flist").innerHTML = PICKED.length ? `<div class="flist">${PICKED.map(([f,p],i) =>
    `<div><span class="mono">${esc(p)}</span><span class="muted">${fmtB(f.size)} <a href="#" data-rm="${i}" title="remove">✕</a></span></div>`).join("")}</div>
    <div class="small muted" style="margin-top:6px">${PICKED.length} file(s), ${fmtB(total)}</div>` : "";
  document.querySelectorAll("[data-rm]").forEach(a => a.onclick = e => { e.preventDefault(); PICKED.splice(+a.dataset.rm, 1); renderPicked(); });
  $("#go").disabled = !PICKED.length;
  $("#gohint").textContent = PICKED.length ? (MODE === "browser" ? "Files are recognised by content, here in your browser" : "Files are recognised by content on the server") : "Add at least one file";
}
function formVals() {
  const g = id => ($("#"+id)||{}).value || "";
  return {case_name:g("cname"), investigator:g("inv"), tz:g("tz"), year:g("yr"), internal_ranges:g("nets"), credentials:g("creds")};
}
async function startUpload() {
  if (MODE === "browser") {
    $("#go").disabled = true; $("#gohint").innerHTML = `<span class="spin"></span> Reading ${PICKED.length} file(s)…`;
    return startJob(B.upload(PICKED, formVals()));
  }
  const fd = new FormData();
  for (const [f, p] of PICKED) { fd.append("files", f, f.name); fd.append("paths", p); }
  for (const [k, v] of Object.entries(formVals())) fd.append(k, v);
  $("#go").disabled = true; $("#gohint").innerHTML = `<span class="spin"></span> Uploading ${PICKED.length} file(s)…`;
  startJob(api("/api/analyze", {method:"POST", body:fd}));
}
async function startJob(promise) {
  try { const r = await promise; location.hash = "#/job/" + r.job; }
  catch (e) { toast(e.message, true); const g = $("#go"); if (g) { g.disabled = !PICKED.length; $("#gohint").textContent = ""; } }
}

// ------------------------------------------------------------------ JOB (live progress)
const STEPS = [
  ["intake","Intake","recognise each file by content"],
  ["acquisition","Acquisition","copy + SHA-256 before/after"],
  ["normalization","Normalization","one schema, all times UTC"],
  ["correlation","Correlation","57 ATT&CK rules + entity graph"],
  ["custody","Chain of custody","hash-chained ledger verified"],
  ["reporting","Report","forensic HTML report"]];
let POLL = null;
function viewJob(id) {
  $("#casenav").innerHTML = "";
  $("#view").innerHTML = `<h1 id="jt">Investigation running…</h1><p class="lead" id="jl">Every stage below is the real framework running on your evidence.</p>
    <div class="steps">${STEPS.map(([k,t,d],i) => `<div class="step" id="st-${k}"><div class="n">${String(i+1).padStart(2,"0")}</div><div class="t">${t}</div><div class="d">${d}</div></div>`).join("")}</div>
    <div class="grid g2"><div><h3>Live log</h3><div class="term" id="term"></div></div><div><h3>Evidence recognised</h3><div id="jfiles" class="card" style="padding:0"><div class="empty small">waiting…</div></div></div></div>
    <div class="row" style="margin-top:16px" id="jbtn"></div>`;
  clearInterval(POLL);
  let seen = 0;
  const tick = async () => {
    let j; try { j = await api("/api/jobs/" + id); } catch (e) { clearInterval(POLL); $("#jt").textContent = "Job not found (the console was restarted?)"; return; }
    const term = $("#term"); if (!term) { clearInterval(POLL); return; }
    for (const l of j.log.slice(seen)) {
      const cls = l.msg.startsWith("ERROR") ? "e" : (/VERIFIED|recognised:|Finished|incident/.test(l.msg) ? "k" : "");
      term.insertAdjacentHTML("beforeend", `<div><span class="t">${esc(l.t)}</span>  <span class="${cls}">${esc(l.msg)}</span></div>`);
    }
    if (j.log.length > seen) term.scrollTop = term.scrollHeight;
    seen = j.log.length;
    for (const [k] of STEPS) {
      const el = $("#st-"+k); el.className = "step" + (j.stages_done.includes(k) ? " ok" : j.stage === k ? (j.state==="error"?" err":" run") : "");
    }
    if (j.files && j.files.length) $("#jfiles").innerHTML = filesTable(j.files, true);
    if (j.kind === "evaluate") $("#jfiles").innerHTML = `<div class="empty small">Evaluation runs the framework on the simulated scenarios S1–S5 with ground truth.</div>`;
    if (j.state !== "running") {
      clearInterval(POLL);
      if (j.state === "done") {
        $("#jt").textContent = j.kind === "evaluate" ? "Evaluation finished" : "Investigation complete";
        $("#jl").textContent = `Finished in ${j.elapsed} s.`;
        $("#jbtn").innerHTML = j.case ? `<a class="btn pri" href="#/case/${encodeURIComponent(j.case)}">Open case ${esc(j.case)} →</a>${caseButtons(j.case, true).replace("btn pri", "btn")}`
                                      : `<a class="btn pri" href="${DASH}" target="_blank" rel="noopener">Open evaluation dashboard ↗</a>`;
        if (j.case) wireCaseButtons(j.case, $("#jbtn"));
        refreshCount();
        CUR = null;
        if (j.case) setTimeout(() => { if (location.hash === "#/job/" + id) location.hash = "#/case/" + encodeURIComponent(j.case); }, 1800);
      } else {
        $("#jt").textContent = "Investigation stopped"; $("#jl").innerHTML = `<span style="color:var(--rd)">${esc(j.error)}</span>`;
        $("#jbtn").innerHTML = `<a class="btn" href="#/new">← Back</a>`;
      }
    }
  };
  tick(); POLL = setInterval(tick, 500);
}
function filesTable(files, compact) {
  return `<div class="tw" style="border:0;max-height:${compact?360:600}px"><table><tr><th>File</th><th>Recognised as</th>${compact?"":"<th>Why</th><th>Size</th><th>SHA-256 (original)</th>"}<th>Records</th></tr>
  ${files.map(r => `<tr><td class="mono">${esc(r.name)}</td><td>${r.used ? `<span class="badge b-ok">${esc(r.label)}</span>` : `<span class="badge b-fail">${esc(r.label)}</span>`}</td>
    ${compact?"":`<td class="small muted">${esc(r.reason)}</td><td class="small" style="white-space:nowrap">${fmtB(r.size)}</td><td class="mono small" style="word-break:break-all;min-width:220px">${esc(r.sha256)}</td>`}
    <td class="mono">${r.records ?? ""}</td></tr>`).join("")}</table></div>`;
}

// ------------------------------------------------------------------ CASES
async function viewCases() {
  $("#casenav").innerHTML = "";
  const cs = await api("/api/cases");
  $("#view").innerHTML = `<h1>Cases</h1><p class="lead">${MODE === "browser" ? "Investigations made on this page are kept in this browser tab (nothing is uploaded). Each case has the evidence copy, normalized events, incidents, timeline, custody ledger and report — download the case .zip to keep it." : "Every investigation is kept in its own folder under <span class=\"mono\">cases/</span> with the evidence copy, normalized events, incidents, timeline, custody ledger and report."}</p>
  <div class="card" style="padding:0">${cs.length ? `<div class="tw" style="border:0"><table><tr><th>Case</th><th>Created</th><th>Severity</th><th>Incidents</th><th>Alerts</th><th>Platforms in incidents</th><th></th></tr>
  ${cs.map(c => `<tr class="click" data-c="${esc(c.name)}"><td><b>${esc(c.name)}</b></td><td class="mono small">${esc(c.created)}</td><td>${sev(c.severity)}</td><td class="mono">${c.incidents}</td><td class="mono">${c.alerts}</td><td>${c.platforms.map(plat).join("")}</td><td><a href="#/case/${encodeURIComponent(c.name)}">Open →</a></td></tr>`).join("")}
  </table></div>` : `<div class="empty">No cases yet. <a href="#/new">Start a new investigation</a>.</div>`}</div>`;
  document.querySelectorAll("tr[data-c]").forEach(r => r.onclick = () => location.hash = "#/case/" + encodeURIComponent(r.dataset.c));
}

// ------------------------------------------------------------------ CASE
const TABS = [["overview","Overview"],["incidents","Incidents & kill chain"],["evidence","Evidence"],["custody","Chain of custody"],["events","Events"]];
async function viewCase(name, tab) {
  if (!CUR || CUR.name !== name || tab === "overview") CUR = await api("/api/cases/" + encodeURIComponent(name));
  const c = CUR, b = c.brief;
  $("#casenav").innerHTML = TABS.map(([k,t]) => `<a class="sub ${k===tab?"on":""}" href="#/case/${encodeURIComponent(name)}/${k}">${t}</a>`).join("");
  $("#view").innerHTML = `
  <div class="casehead"><div><div class="small muted">CASE</div><h1>${esc(name)}</h1>
    <div class="row small muted">${sev(b.severity)} <span>created ${esc(b.created)}</span> ${c.custody.ok ? `<span class="badge b-ok">Custody verified</span>` : `<span class="badge b-fail">Custody FAILED</span>`} ${c.custody.hmac?`<span class="badge b-ok">HMAC signed</span>`:""}</div></div>
    <div class="row">${caseButtons(name, c.report)}</div></div>
  <div class="tabs">${TABS.map(([k,t]) => `<a class="${k===tab?"on":""}" href="#/case/${encodeURIComponent(name)}/${k}">${t}</a>`).join("")}</div>
  <div id="tab"></div>`;
  ({overview:tOverview, incidents:tIncidents, evidence:tEvidence, custody:tCustody, events:tEvents}[tab] || tOverview)(c);
  wireCaseButtons(name, $(".casehead"));
}
function kpi(v, l, c) { return `<div class="card kpi" style="--c:${c||"var(--tx)"}"><div class="v">${esc(v)}</div><div class="l">${l}</div></div>`; }
function tOverview(c) {
  const srcs = Object.entries(c.per_source).sort((a,b) => b[1]-a[1]), mx = Math.max(1, ...srcs.map(x => x[1]));
  const rules = Object.entries(c.rules).sort((a,b) => b[1].count - a[1].count);
  const verdict = c.incidents.length
    ? `<b style="color:var(--rd)">${c.incidents.length} incident(s) found.</b> ${(n => n === 1 ? (c.incidents.length === 1 ? "It spans" : "1 of them spans") : `${n} of them span`)(c.incidents.filter(i=>i.cross_platform).length)} more than one platform. ${c.alert_events} of ${c.total_events} events raised alerts mapped to ${c.techniques.length} MITRE ATT&CK technique(s).`
    : c.alert_events ? `<b style="color:var(--am)">No incident</b>, but ${c.alert_events} alert(s) / posture findings were raised — see Events.`
    : `<b style="color:var(--gr)">No attack activity found.</b> ${c.total_events} events were analysed and none matched the 57 detection rules.`;
  $("#tab").innerHTML = `
  <div class="card" style="margin-bottom:16px;font-size:14.5px">${verdict}</div>
  <div class="grid g5" style="margin-bottom:16px">${kpi(c.total_events,"events normalized")}${kpi(c.alert_events,"events flagged","var(--am)")}${kpi(c.incidents.length,"incidents","var(--rd)")}${kpi(c.techniques.length,"ATT&CK techniques","var(--vi)")}${kpi(c.custody.ok?"OK":"FAIL","chain of custody",c.custody.ok?"var(--gr)":"var(--rd)")}</div>
  <div class="grid g2">
    <div class="card"><h2>Detections (rules that fired)</h2>${rules.length ? `<div class="tw" style="border:0"><table><tr><th>Technique</th><th>Detection</th><th>Severity</th><th>Events</th></tr>
      ${rules.map(([k,r]) => `<tr><td><span class="tech">${esc(r.technique)}</span></td><td>${esc(r.name)}</td><td>${sev(r.severity)}</td><td class="mono">${r.count}</td></tr>`).join("")}</table></div>` : `<div class="empty small">No rule fired.</div>`}</div>
    <div class="card"><h2>Events per platform</h2><div class="bars">${srcs.map(([s,n]) => `<div><span>${plat(s)}</span><span class="tr"><i style="width:${Math.max(2,100*n/mx)}%;--pc:${PC[s]||"var(--mu)"}"></i></span><span class="mono">${n}</span></div>`).join("")}</div>
      <h2 style="margin-top:22px">Incidents</h2>${c.incidents.length ? c.incidents.map(i => `<div class="row" style="justify-content:space-between;padding:8px 0;border-bottom:1px solid var(--line)"><span><b>${esc(i.id)}</b> ${sev(i.severity)} ${i.platforms.map(plat).join("")}</span><a href="#/case/${encodeURIComponent(c.name)}/incidents">${i.event_count} events →</a></div>`).join("") : `<div class="muted small">none</div>`}</div>
  </div>`;
}
function tIncidents(c) {
  if (!c.incidents.length) { $("#tab").innerHTML = `<div class="card empty">No incidents in this case.${c.unlinked.length?` ${c.unlinked.length} alert(s) were not linked to an incident — see the Events tab.`:""}</div>`; return; }
  $("#tab").innerHTML = c.incidents.map(i => `
  <div class="card" style="margin-bottom:18px">
    <div class="row" style="justify-content:space-between;margin-bottom:12px"><div><h2 style="margin:0">${esc(i.id)} ${sev(i.severity)} ${i.cross_platform?`<span class="badge b-medium">cross-platform</span>`:""}</h2>
      <div class="mono small muted" style="margin-top:4px">${esc(i.start)} → ${esc(i.end)} · ${i.event_count} events · ${i.alert_count} alerts</div></div><div>${i.platforms.map(plat).join("")}</div></div>
    <h3>Timeline</h3><div>${timelineSVG(c.incident_events[i.id]||[], i)}</div>
    <div class="grid g2" style="margin-top:14px">
      <div><h3>Kill chain — attack stages in order</h3><ol class="chain">${(i.stages||[]).map((s,n) => `<li style="--c:${s.severity==="high"?"var(--rd)":"var(--am)"}"><div class="k">${String(n+1).padStart(2,"0")}</div>
        <div><div class="nm">${esc(s.name)}</div><div class="meta">${esc((s.first||"").replace("T"," ").replace("Z"," UTC"))} · ${(s.sources||[]).map(x=>esc(PN[x]||x)).join(" + ")} · ${(s.hosts||[]).map(esc).join(", ")}</div></div>
        <div style="text-align:right"><span class="tech">${esc(s.technique)}</span><div class="small muted">${s.count} event(s)</div></div></li>`).join("")}</ol></div>
      <div><h3>How the platforms were linked</h3>${graphSVG(i)}
        <div class="tw" style="margin-top:10px"><table><tr><th>From</th><th>To</th><th>Reason</th><th>Ev.</th></tr>${(i.links||[]).map(l => `<tr><td class="mono small" style="word-break:break-all">${esc(l.a)}</td><td class="mono small" style="word-break:break-all">${esc(l.b)}</td><td class="small">${esc(l.reason)}</td><td class="mono">${l.events}</td></tr>`).join("") || `<tr><td colspan=4 class="muted small">single entity</td></tr>`}</table></div></div>
    </div>
  </div>`).join("");
}
function timelineSVG(evs, inc) {
  if (!evs.length) return `<div class="muted small">no events</div>`;
  const lanes = [...new Set(evs.map(e => e.source))], W = 1000, LH = 34, H = lanes.length*LH + 30, L = 96, PADR = 46;
  const t0 = Math.min(...evs.map(e => Date.parse(e.time_utc))), t1 = Math.max(...evs.map(e => Date.parse(e.time_utc)));
  const x = t => L + 14 + (t1===t0 ? (W-L-PADR)/2 : (t - t0)/(t1 - t0)*(W-L-14-PADR));
  const ticks = [0,.25,.5,.75,1].map(f => t0 + f*(t1-t0));
  return `<svg viewBox="0 0 ${W} ${H}" width="100%" role="img" aria-label="incident timeline">
    ${lanes.map((s,i) => `<rect x="${L}" y="${i*LH+6}" width="${W-L-10}" height="${LH-10}" rx="6" fill="var(--panel2)"/><text x="${L-12}" y="${i*LH+LH/2+5}" text-anchor="end" font-size="12" fill="${PC[s]||"var(--mu)"}">${esc(PN[s]||s)}</text>`).join("")}
    ${evs.map(e => { const i = lanes.indexOf(e.source); const c = e.severity==="high"?"var(--rd)":e.severity==="medium"?"var(--am)":"var(--mu2)";
      return `<circle cx="${x(Date.parse(e.time_utc)).toFixed(1)}" cy="${i*LH+LH/2+1}" r="${e.flags&&e.flags.length?6:4}" fill="${c}" fill-opacity=".85" stroke="var(--panel)" stroke-width="1.5"><title>${esc(e.time_utc)} ${esc(e.host)} ${esc(e.event_type)} ${esc(e.user||"")} ${esc(e.src_ip||"")} ${esc((e.flags||[]).join(", "))}</title></circle>`; }).join("")}
    ${ticks.map((t,k) => `<text x="${x(t)}" y="${H-4}" font-size="10.5" text-anchor="${k===0?"start":k===4?"end":"middle"}" fill="var(--mu2)">${new Date(t).toISOString().slice(11,19)}Z</text>`).join("")}
  </svg>`;
}
function graphSVG(inc) {
  const ents = inc.entities || [], n = ents.length;
  if (!n) return "";
  const W = 460, H = n <= 2 ? 200 : Math.min(340, 230 + n*12), cx = W/2, cy = H/2 - 8, RX = n <= 2 ? cx - 110 : cx - 95, RY = n <= 2 ? 0 : cy - 40;
  const pos = {}; ents.forEach((e,i) => { const a = Math.PI + i*2*Math.PI/n; pos[e.id] = n===1 ? [cx,cy] : [cx + RX*Math.cos(a), cy + RY*Math.sin(a)]; });
  const lab = id => { const [k, ...r] = id.split(":"); const s = r.join(":"); return [k, s.length > 26 ? "…" + s.slice(-25) : s]; };
  return `<svg viewBox="0 0 ${W} ${H}" width="100%" style="background:var(--panel2);border-radius:10px" role="img" aria-label="entity graph">
   ${(inc.links||[]).filter(l => pos[l.a] && pos[l.b]).map(l => `<line x1="${pos[l.a][0]}" y1="${pos[l.a][1]}" x2="${pos[l.b][0]}" y2="${pos[l.b][1]}" stroke="var(--line2)" stroke-width="${Math.min(5,1+Math.log2(1+l.events))}"><title>${esc(l.reason)}</title></line>`).join("")}
   ${ents.map(e => { const [k, s] = lab(e.id), [x, y] = pos[e.id];
     return `<g><circle cx="${x}" cy="${y}" r="${10+Math.min(10,Math.log2(1+e.events)*2)}" fill="${KC[k]||"var(--cy)"}" fill-opacity=".9" stroke="var(--panel)" stroke-width="2"><title>${esc(e.id)} · ${e.events} events · ${e.platforms.join(", ")}</title></circle>
     <text x="${x}" y="${y+30}" text-anchor="middle" font-size="10.5" fill="var(--tx)">${esc(s)}</text><text x="${x}" y="${y+42}" text-anchor="middle" font-size="9.5" fill="var(--mu)">${esc(k.toUpperCase())}</text></g>`; }).join("")}
  </svg>`;
}
function tEvidence(c) {
  $("#tab").innerHTML = `
  <div class="card" style="margin-bottom:16px"><h2>Files supplied by the investigator</h2><p class="muted small" style="margin-top:-6px">Each original was opened and recognised by its content; its SHA-256 is stored in <span class="mono">intake_manifest.json</span>, which is the first entry of the custody ledger.</p>
    ${c.intake.length ? filesTable(c.intake, false) : `<div class="muted small">This case was created from the command line with standard file names (no intake manifest).</div>`}</div>
  <div class="card"><h2>Evidence acquired into the case</h2><p class="muted small" style="margin-top:-6px">Copied into <span class="mono">cases/${esc(c.name)}/evidence/</span>; hash checked before and after the copy.</p>
    <div class="tw"><table><tr><th>Evidence file</th><th>Source</th><th>Size</th><th>Copy verified</th><th>SHA-256</th></tr>
    ${c.evidence.map(e => `<tr><td class="mono">${esc(e.file)}</td><td>${plat(e.source)}</td><td class="small" style="white-space:nowrap">${fmtB(e.size)}</td><td>${e.verified?`<span class="badge b-ok">yes</span>`:`<span class="badge b-fail">no</span>`}</td><td class="mono small" style="word-break:break-all">${esc(e.sha256)}</td></tr>`).join("")}</table></div></div>`;
}
function tCustody(c) {
  const cu = c.custody;
  $("#tab").innerHTML = `
  <div class="card" style="margin-bottom:16px"><div class="row" style="justify-content:space-between"><h2 style="margin:0">Hash-chained custody ledger · ${cu.entries.length} entries</h2>
    <div class="row"><input type="text" id="anc" class="mono" style="width:340px" placeholder="anchor hash you noted (optional)" value=""><button class="btn sm pri" id="rever">Re-verify now</button></div></div>
    <p class="muted small">Each block stores the SHA-256 of the file it touched and the hash of the previous block${cu.hmac?", plus an HMAC made with the secret key":""}. Anchor hash of this case: <span class="mono">${esc(cu.anchor||"-")}</span></p>
    <div class="blocks">${cu.entries.map(e => `<div class="blk" id="blk${e.seq}"><div class="h">BLOCK #${e.seq} · ${esc(e.stage)}</div><div class="a">${esc(e.action)} ${esc(e.target)}</div>
      <div class="m">file ${esc((e.sha256||"").slice(0,16))}…</div><div class="m">prev ${esc((e.prev_hash||"").slice(0,16))}…</div><div class="m">hash ${esc((e.entry_hash||"").slice(0,16))}…</div><div class="m">${e.hmac?"hmac ✓":"no hmac"} · ${esc((e.time_utc||"").slice(11,19))}Z</div></div>`).join("")}</div>
    <div id="verres"></div></div>
  <div class="card"><h2>Tamper test (on a copy — this case is not touched)</h2><p class="muted small">Shows the examiner that the framework detects changes. A temporary copy of this case is altered and then verified.</p>
    <div class="row"><button class="btn danger" data-t="evidence">Change 1 byte of an evidence file</button><button class="btn danger" data-t="ledger">Edit a ledger entry</button><button class="btn danger" data-t="delete">Delete a ledger entry</button></div>
    <div id="tamres"></div></div>`;
  const showChecks = (ok, checks, at) => `<div class="res ${ok?"good":"bad"}"><b>${ok?"VERIFIED — evidence and ledger are intact":"TAMPERING DETECTED"}</b> ${at?`<span class="muted small">(${esc(at)})</span>`:""}
    <div class="tw" style="margin-top:8px;max-height:260px"><table>${checks.map(k => `<tr><td>${k.ok?`<span class="badge b-ok">OK</span>`:`<span class="badge b-fail">FAIL</span>`}</td><td class="mono small">${esc(k.item)}</td><td class="small">${esc(k.note)}</td></tr>`).join("")}</table></div></div>`;
  $("#rever").onclick = async () => {
    $("#verres").innerHTML = `<div class="res"><span class="spin"></span> verifying…</div>`;
    try { const r = await post(`/api/cases/${encodeURIComponent(c.name)}/verify`, {anchor:$("#anc").value.trim()}); $("#verres").innerHTML = showChecks(r.ok, r.checks, r.at); }
    catch (e) { toast(e.message, true); }
  };
  document.querySelectorAll("[data-t]").forEach(b => b.onclick = async () => {
    $("#tamres").innerHTML = `<div class="res"><span class="spin"></span> altering a copy and verifying…</div>`;
    try {
      const r = await post(`/api/cases/${encodeURIComponent(c.name)}/tamper`, {what:b.dataset.t});
      $("#tamres").innerHTML = `<div class="res ${r.detected?"good":"bad"}"><div><b>Change made:</b> <span class="mono small">${esc(r.action)}</span></div>
        <div style="margin:6px 0"><b>Result:</b> ${r.detected?`<span class="badge b-ok">DETECTED</span> the framework caught the tampering`:`<span class="badge b-fail">NOT DETECTED</span>`} · original case still ${r.original_still_ok?"verified ✓":"FAILED"}</div>
        ${r.failed.length?`<div class="tw" style="max-height:200px"><table>${r.failed.map(k => `<tr><td><span class="badge b-fail">FAIL</span></td><td class="mono small">${esc(k.item)}</td><td class="small">${esc(k.note)}</td></tr>`).join("")}</table></div>`:""}</div>`;
    } catch (e) { toast(e.message, true); $("#tamres").innerHTML = ""; }
  });
}
async function tEvents(c) {
  const srcs = Object.keys(c.per_source);
  $("#tab").innerHTML = `<div class="card"><div class="row" style="margin-bottom:12px"><input type="text" id="q" placeholder="Search IP, user, host, technique (T1110), event type…" style="flex:1;min-width:220px">
    <select id="src" style="width:auto"><option value="">All platforms</option>${srcs.map(s => `<option value="${esc(s)}">${esc(PN[s]||s)}</option>`).join("")}</select>
    <label class="small muted"><input type="checkbox" id="al" ${c.alert_events?"checked":""}> alerts only</label></div>
    <div class="small muted" id="evn"></div><div class="tw" style="max-height:620px;margin-top:6px" id="evt"></div></div>`;
  let timer;
  const load = async () => {
    const u = `/api/cases/${encodeURIComponent(c.name)}/events?q=${encodeURIComponent($("#q").value)}&source=${encodeURIComponent($("#src").value)}&alerts=${$("#al").checked?1:0}`;
    const r = await api(u);
    $("#evn").textContent = `${r.total} matching event(s)${r.total > r.events.length ? `, first ${r.events.length} shown` : ""}`;
    $("#evt").innerHTML = `<table><tr><th>Time (UTC)</th><th>Platform</th><th>Host</th><th>Event</th><th>User</th><th>Source IP</th><th>Detail</th><th>Detection</th><th>Incident</th><th>Origin</th></tr>
      ${r.events.map(e => `<tr><td class="mono small" style="white-space:nowrap">${esc((e.time_utc||"").replace("T"," ").replace("Z",""))}</td><td>${plat(e.source)}</td><td class="small">${esc(e.host)}</td><td class="small">${esc(e.event_type)}</td><td class="small">${esc(e.user||"")}</td><td class="mono small">${esc(e.src_ip||"")}</td>
        <td class="small" style="max-width:300px">${esc(e.detail||"")}${e.target?` <span class="muted">→ ${esc(e.target)}</span>`:""}</td>
        <td>${(e.techniques||[]).map(t => `<span class="tech">${esc(t)}</span>`).join("")} ${e.severity?sev(e.severity):""}</td><td class="mono small">${esc(e.incident||"")}</td><td class="mono small muted" style="white-space:nowrap">${esc(e.source_file)}:${esc(e.line_ref)}</td></tr>`).join("")}</table>`;
  };
  $("#q").oninput = () => { clearTimeout(timer); timer = setTimeout(load, 250); };
  $("#src").onchange = load; $("#al").onchange = load;
  load();
}

// ------------------------------------------------------------------ ABOUT
function viewAbout() {
  $("#casenav").innerHTML = "";
  $("#view").innerHTML = `<h1>How the framework works</h1><p class="lead">Four layers run on every case. The console only drives them; the same code runs from <span class="mono">python main.py</span>.</p>
  <div class="flow" style="margin-bottom:16px">
   <div><b>0 · Intake</b>Opens every supplied file and recognises Windows EVTX/XML, Linux auth logs and CloudTrail JSON by content; unpacks .zip/.gz.</div>
   <div><b>1 · Acquisition</b>Copies evidence into the case, SHA-256 before and after copy, live collectors for Windows, Linux (SSH), AWS (boto3, read-only) and host triage.</div>
   <div><b>2 · Normalization</b>35 event types from all platforms into one schema with UTC time, user, IP, host, session, key.</div>
   <div><b>3 · Correlation</b>57 detection rules mapped to MITRE ATT&CK, then an entity graph (IP, session, credential file, access key) joins events across platforms into incidents.</div>
   <div><b>4 · Custody & report</b>Every action is a block in a SHA-256 hash chain (optional HMAC). Verified before the HTML report is written.</div>
  </div>
  <div class="card"><h2>Inputs supported</h2><table>
   <tr><td>${plat("windows")}</td><td>Security 4624 4625 4634 4672 4688 4698 4720 4732 5145 1102 · System 7045 104 · Sysmon 1 3 10 13 · PowerShell 4104 — .evtx or XML</td></tr>
   <tr><td>${plat("linux")}</td><td>auth.log / secure: sshd failed/accepted, sudo, su, useradd, PAM; classic and ISO timestamps; rotated .gz</td></tr>
   <tr><td>${plat("aws")}</td><td>CloudTrail JSON (Records, list, JSON Lines, glued objects); account state: IAM users/roles, keys, MFA, S3, security groups, trails</td></tr>
   <tr><td>${plat("host")}</td><td>Live triage: processes, sockets, accounts, cron/systemd/Run keys/scheduled tasks/startup, recent files, timestomping</td></tr></table></div>`;
}

boot();
