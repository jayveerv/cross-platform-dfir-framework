/* CP-DFIR in-browser engine (GitHub Pages).
 * Runs the framework's own Python modules (intake, normalize, correlate, custody, pipeline, report) inside the
 * browser with Pyodide (CPython compiled to WebAssembly). Evidence files never leave the visitor's computer.
 */
"use strict";
const PARAMS = new URLSearchParams(self.location.search);
const PYODIDE = PARAMS.get("pyodide") || "https://cdn.jsdelivr.net/pyodide/v0.26.4/full/";
let py = null;

const status = msg => self.postMessage({type: "status", msg});

const BOOT = `
import sys, os, json
sys.path.insert(0, "/app")
import casestore, correlate, config, generate_data
CASES, UPLOADS = "/cases", "/uploads"
os.makedirs(CASES, exist_ok=True)

def api_info():
    return json.dumps(dict(mode="browser", host="your browser", admin=False, scenarios=casestore.SCENARIOS, inbox=[], inbox_path="",
                           dashboard=True, rules=len(correlate.FLAGS), techniques=len({v[0] for v in correlate.FLAGS.values()}),
                           hmac=False, investigator=config.DEFAULT_CASE["investigator"], python=sys.version.split()[0]))

def api_list():
    return json.dumps(casestore.list_cases(CASES))

def api_detail(name):
    return json.dumps(casestore.case_detail(CASES, name))

def api_events(name, q, src, al, limit):
    return json.dumps(casestore.case_events(CASES, name, q, src, bool(al), limit))

def api_verify(name, anchor):
    return json.dumps(casestore.verify(CASES, name, anchor or None))

def api_tamper(name, what):
    return json.dumps(casestore.tamper(CASES, name, what))

def api_zip(name):
    p = "/tmp/case.zip"
    with open(p, "wb") as f:
        f.write(casestore.case_zip(CASES, name))
    return p

def api_file(name, f):
    if f not in casestore.CASE_FILES:
        raise ValueError("not a case file")
    return os.path.join(casestore.case_dir(CASES, name), f)

def run_job(jid, kind, case, form_json, log, stage, on_files):
    form = json.loads(form_json or "{}")
    case = casestore.safe_case(case)
    if kind == "sample":
        sc = form.get("scenario", "S1")
        src = "/samples/" + sc
        generate_data.build(sc, src)
        sources = [(os.path.join(src, f), f) for f in sorted(os.listdir(src))]
    else:
        top = os.path.join(UPLOADS, jid, "files")
        sources = [(os.path.join(top, e), e) for e in sorted(os.listdir(top))]
    files, ctx = casestore.analyse(sources, os.path.join(UPLOADS, jid, "_staged"), CASES, case, form,
                                   log=lambda m: log(str(m)), stage=lambda s: stage(str(s)),
                                   on_files=lambda fl: on_files(json.dumps(fl)))
    return case
`;

async function init() {
  status("Loading the Python engine (Pyodide, first visit ~10 MB) ...");
  importScripts(PYODIDE + "pyodide.js");
  py = await loadPyodide({indexURL: PYODIDE});
  status("Loading the framework modules ...");
  const base = new URL("../py/", self.location.href).href;
  const V = PARAMS.get("v") ? "?v=" + PARAMS.get("v") : "";
  const man = await (await fetch(base + "manifest.json" + V, {cache: "no-cache"})).json();
  for (const w of man.wheels) py.unpackArchive(new Uint8Array(await (await fetch(base + w + V)).arrayBuffer()), "wheel");
  py.FS.mkdirTree("/app");
  for (const m of man.modules) py.FS.writeFile("/app/" + m.split("/").pop(), new Uint8Array(await (await fetch(base + m + V, {cache: "no-cache"})).arrayBuffer()));
  py.runPython(BOOT);
  self.postMessage({type: "ready", info: JSON.parse(py.globals.get("api_info")())});
}
const READY = init().catch(e => { self.postMessage({type: "fatal", msg: String(e && e.message || e)}); throw e; });

function pyErr(e) {
  const m = String(e && e.message || e).trim().split("\n");
  return m[m.length - 1] || "error";
}
function mkdirp(path) { try { py.FS.mkdirTree(path); } catch (e) { /* exists */ } }

self.onmessage = async ev => {
  const {id, cmd, args = {}} = ev.data;
  try { await READY; } catch (e) { self.postMessage({id, ok: false, error: "The Python engine could not start: " + pyErr(e)}); return; }
  const g = n => py.globals.get(n);
  try {
    let result, transfer = [];
    switch (cmd) {
      case "info": result = JSON.parse(g("api_info")()); break;
      case "list": result = JSON.parse(g("api_list")()); break;
      case "detail": result = JSON.parse(g("api_detail")(args.name)); break;
      case "events": result = JSON.parse(g("api_events")(args.name, args.q || "", args.source || "", args.alerts ? 1 : 0, args.limit || 500)); break;
      case "verify": result = JSON.parse(g("api_verify")(args.name, args.anchor || "")); break;
      case "tamper": result = JSON.parse(g("api_tamper")(args.name, args.what || "evidence")); break;
      case "file": { const p = g("api_file")(args.name, args.f); result = py.FS.readFile(p); transfer = [result.buffer]; break; }
      case "zip": { const p = g("api_zip")(args.name); result = py.FS.readFile(p); transfer = [result.buffer]; break; }
      case "job": {
        const jid = args.jid, J = (type, extra) => self.postMessage(Object.assign({job: jid, type}, extra));
        if (args.files) {
          for (const f of args.files) {
            const parts = f.path.split(/[\\/]+/).filter(p => p && p !== "." && p !== "..").map(p => p.replace(/[^A-Za-z0-9_.() -]/g, "_"));
            const dest = `/uploads/${jid}/files/` + (parts.length ? parts.join("/") : "file");
            mkdirp(dest.slice(0, dest.lastIndexOf("/")));
            py.FS.writeFile(dest, new Uint8Array(f.data));
          }
        }
        try {
          const t = Date.now();
          const name = g("run_job")(jid, args.kind, args.case, JSON.stringify(args.form || {}),
            m => J("log", {msg: m}), s => J("stage", {stage: s}), fl => J("files", {files: JSON.parse(fl)}));
          J("done", {case: name, ms: Date.now() - t});
          result = {case: name};
        } catch (e) { J("error", {error: pyErr(e)}); throw e; }
        finally { try { py.runPython(`import shutil; shutil.rmtree("/uploads/${jid}", ignore_errors=True)`); } catch (e) {} }
        break;
      }
      default: throw new Error("unknown command " + cmd);
    }
    self.postMessage({id, ok: true, result}, transfer);
  } catch (e) {
    self.postMessage({id, ok: false, error: pyErr(e)});
  }
};
