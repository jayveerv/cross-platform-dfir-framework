"""Build the GitHub Pages site in docs/ : the web console running the framework inside the browser.

    python make_pages.py

docs/index.html      the CP-DFIR console (same web/console.js as the desktop web console) in "browser" mode
docs/web/            console.css, console.js and worker.js (the Pyodide engine)
docs/py/             the framework's own Python modules, loaded into the browser unchanged
docs/py/vendor/      pure-Python wheels used in the browser: networkx (BSD-3), python-evtx (Apache-2.0), hexdump (public domain)
docs/dashboard.html  the evaluation dashboard (copy of results/dashboard.html)

Pyodide (CPython for WebAssembly) is loaded from the jsDelivr CDN; everything else is served from this repository.
"""
import json
import os
import shutil

ROOT = os.path.dirname(os.path.abspath(__file__))
DOCS = os.path.join(ROOT, "docs")
MODULES = ["config", "normalize", "correlate", "custody", "collect", "pipeline", "report", "intake", "generate_data", "casestore"]
VENDOR = os.path.join(DOCS, "py", "vendor")

INDEX = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>CP-DFIR Console</title>
<meta name="description" content="Cross-Platform DFIR Framework: upload Windows, Linux and AWS logs and investigate them in the browser. The framework's Python code runs locally with WebAssembly; evidence never leaves the computer.">
<link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24'%3E%3Cpath d='M12 2l8 3v6c0 5-3.4 9.4-8 11-4.6-1.6-8-6-8-11V5z' fill='%2322D3EE'/%3E%3C/svg%3E">
<link rel="stylesheet" href="web/console.css?v=__V__">
<script>window.CPDFIR_MODE = "browser";</script>
</head>
<body>
<div class="app">
  <header class="top">
    <a class="brand" href="#/new">
      <svg viewBox="0 0 24 24" width="26" height="26"><path d="M12 2l8 3v6c0 5-3.4 9.4-8 11-4.6-1.6-8-6-8-11V5z" fill="none" stroke="currentColor" stroke-width="1.8"/><path d="M8.5 12l2.5 2.5 4.5-5" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/></svg>
      <span><b>CP-DFIR</b><small>Investigation Console</small></span>
    </a>
    <div class="title">A Scalable Cross-Platform DFIR Framework for Automated Evidence Collection, Correlation, and Cloud Forensic Investigation</div>
    <div class="chips" id="chips"></div>
    <button class="iconbtn" id="theme" title="Light / dark">◐</button>
  </header>

  <nav class="side" id="side"></nav>

  <main id="view"></main>
</div>
<div id="toast"></div>
<script src="web/console.js?v=__V__"></script>
</body>
</html>
"""


def build():
    os.makedirs(os.path.join(DOCS, "web"), exist_ok=True)
    os.makedirs(VENDOR, exist_ok=True)
    for f in ("console.css", "console.js", "worker.js"):
        shutil.copy2(os.path.join(ROOT, "web", f), os.path.join(DOCS, "web", f))
    for m in MODULES:
        shutil.copy2(os.path.join(ROOT, m + ".py"), os.path.join(DOCS, "py", m + ".py"))
    wheels = sorted(f for f in os.listdir(VENDOR) if f.endswith(".whl"))
    extra = sorted(f for f in os.listdir(VENDOR) if f.endswith(".py"))
    if not any(w.startswith("networkx-") for w in wheels):
        raise SystemExit("docs/py/vendor/ needs the networkx wheel (pip download --no-deps networkx==3.3 -d docs/py/vendor)")
    with open(os.path.join(DOCS, "py", "manifest.json"), "w") as f:
        json.dump({"modules": [m + ".py" for m in MODULES] + ["vendor/" + e for e in extra],
                   "wheels": ["vendor/" + w for w in wheels]}, f, indent=1)
    import hashlib
    ver = hashlib.sha256(b"".join(open(os.path.join(ROOT, "web", x), "rb").read() for x in ("console.css", "console.js", "worker.js"))
                         + json.dumps(json.load(open(os.path.join(DOCS, "py", "manifest.json")))).encode()
                         + b"".join(open(os.path.join(ROOT, m + ".py"), "rb").read() for m in MODULES)).hexdigest()[:10]
    with open(os.path.join(DOCS, "index.html"), "w", encoding="utf-8") as f:
        f.write(INDEX.replace("__V__", ver))     # new file names on every change, so browsers never mix old and new files
    dash = os.path.join(ROOT, "results", "dashboard.html")
    if os.path.exists(dash):
        shutil.copy2(dash, os.path.join(DOCS, "dashboard.html"))
    print("GitHub Pages site written to", DOCS)


if __name__ == "__main__":
    build()
