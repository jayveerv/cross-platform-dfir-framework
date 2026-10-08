"""Live host evidence collection (Windows / Linux / macOS).

Collects, in order of volatility (RFC 3227): system state, network connections, processes, accounts,
persistence mechanisms, recently written files in temporary locations, and the security logs.
Everything is read-only. Each artifact is written as JSON with its SHA-256 in host/manifest.json, together
with every command that was run, every error, and every place where access was denied, so the collection
itself is documented and repeatable.

Cross-platform parts use psutil (processes, connections, users, services). OS-specific parts:
  Linux   /etc/passwd, /etc/group, sudoers, cron, systemd units, authorized_keys, ld.so.preload, auth.log / journal
  Windows net user / net localgroup, Run keys (winreg), startup folders, schtasks, services, wevtutil exports
  macOS   LaunchAgents / LaunchDaemons (plist)

Tested here: the Linux paths, on a real system (see tests/ and README). The Windows and macOS paths follow
documented command and registry formats but could not be run on those systems while this was written.
"""
import csv
import glob
import hashlib
import io
import json
import os
import platform
import re
import socket
import subprocess
import sys
import time
from datetime import datetime, timedelta, timezone

VERSION = "1.0"
HASH_MAX_BYTES = 200 * 1024 * 1024


def _iso(ts):
    return datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ") if ts else None


def sha256_file(path, cap=HASH_MAX_BYTES):
    try:
        if os.path.getsize(path) > cap:
            return None
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return None


def default_runner(cmd, timeout=90):
    try:
        r = subprocess.run(cmd, capture_output=True, timeout=timeout)
        return r.returncode, r.stdout.decode("utf-8", "replace"), r.stderr.decode("utf-8", "replace")
    except FileNotFoundError:
        return 127, "", "command not found"
    except subprocess.TimeoutExpired:
        return 124, "", "timeout"


def _magic(path):
    try:
        with open(path, "rb") as f:
            b = f.read(4)
    except OSError:
        return None
    if b[:4] == b"\x7fELF":
        return "ELF"
    if b[:2] == b"MZ":
        return "PE"
    if b[:2] == b"#!":
        return "script"
    if b[:4] == b"\xcf\xfa\xed\xfe" or b[:4] == b"\xca\xfe\xba\xbe":
        return "Mach-O"
    return None


def _local_offset():
    secs = -(time.altzone if time.daylight and time.localtime().tm_isdst else time.timezone)
    sign = "+" if secs >= 0 else "-"
    secs = abs(secs)
    return f"{sign}{secs // 3600:02d}:{(secs % 3600) // 60:02d}"


# --------------------------------------------------------------------- pure parsers (unit-tested)
def parse_passwd(text):
    out = []
    for line in text.splitlines():
        p = line.split(":")
        if len(p) >= 7 and not line.startswith("#"):
            try:
                out.append(dict(name=p[0], uid=int(p[2]), gid=int(p[3]), home=p[5], shell=p[6]))
            except ValueError:
                pass
    return out


def parse_group(text, names=("sudo", "wheel", "admin", "adm", "root")):
    out = {}
    for line in text.splitlines():
        p = line.split(":")
        if len(p) >= 4 and p[0] in names:
            out[p[0]] = [m for m in p[3].split(",") if m]
    return out


def parse_authorized_keys(text):
    keys = []
    for line in text.splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        toks = s.split()
        for i, t in enumerate(toks):
            if t.startswith(("ssh-", "ecdsa-", "sk-")) and i + 1 < len(toks):
                blob = toks[i + 1]
                keys.append(dict(type=t, fingerprint_sha256=hashlib.sha256(blob.encode()).hexdigest()[:32],
                                 comment=" ".join(toks[i + 2:])[:80], options=" ".join(toks[:i])[:120]))
                break
    return keys


def parse_crontab(text):
    return [l.strip() for l in text.splitlines() if l.strip() and not l.strip().startswith("#") and "=" not in l.split()[0]]


def parse_systemd_unit(text):
    return [l.split("=", 1)[1].strip() for l in text.splitlines() if l.strip().startswith(("ExecStart=", "ExecStartPre=", "ExecStartPost="))]


def parse_net_user(text):
    """`net user` / `net localgroup X` output: names sit between the dashed line and the 'command completed' line."""
    lines = text.splitlines()
    start = next((i for i, l in enumerate(lines) if l.strip().startswith("---")), None)
    if start is None:
        return []
    names = []
    for l in lines[start + 1:]:
        if not l.strip() or re.search(r"command completed|completed successfully", l, re.I):
            break
        names += l.split()
    return names


def parse_schtasks_csv(text):
    """`schtasks /query /fo csv /v /nh` -> list of dicts. Column positions follow the documented verbose output."""
    out = []
    for row in csv.reader(io.StringIO(text)):
        if len(row) < 9 or row[1].strip().lower() == "taskname":
            continue
        out.append(dict(task=row[1], status=row[3] if len(row) > 3 else "", run=row[8],
                        run_as=row[14] if len(row) > 14 else ""))
    return out


# --------------------------------------------------------------------- collector
class HostCollector:
    def __init__(self, out_dir, fs_root="/", homes=None, runner=None, hash_limit=400, days=7, now=None, log=print,
                 include_logs=True, file_scan_limit=20000):
        self.out_dir = out_dir
        self.host_dir = os.path.join(out_dir, "host")
        self.fs_root = fs_root
        self.extra_homes = homes or []
        self.runner = runner or default_runner
        self.hash_limit = hash_limit
        self.days = days
        self.now = now or time.time()
        self.log = log
        self.include_logs = include_logs
        self.file_scan_limit = file_scan_limit
        self.os = platform.system()
        self.manifest = dict(collector_version=VERSION, artifacts=[], commands=[], errors=[], limited={})
        os.makedirs(self.host_dir, exist_ok=True)

    # helpers
    def fs(self, rel):
        return os.path.join(self.fs_root, rel.lstrip("/"))

    def run(self, cmd, timeout=90):
        rc, out, err = self.runner(cmd, timeout)
        self.manifest["commands"].append(dict(cmd=" ".join(cmd), rc=rc))
        if rc != 0:
            self.manifest["errors"].append(f"{' '.join(cmd)} -> rc {rc}: {err.strip()[:160]}")
        return rc, out, err

    def read(self, path, cap=2_000_000):
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                return f.read(cap)
        except OSError:
            return None

    def write(self, name, obj, note=""):
        path = os.path.join(self.host_dir, name)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(obj, f, indent=1)
        n = len(obj) if isinstance(obj, list) else (len(obj.get("items", [])) if isinstance(obj, dict) and "items" in obj else None)
        self.manifest["artifacts"].append(dict(name=name, sha256=sha256_file(path), size=os.path.getsize(path), records=n, note=note))
        self.log(f"  {name}: {n if n is not None else 'ok'}")

    def is_admin(self):
        try:
            if self.os == "Windows":
                import ctypes
                return bool(ctypes.windll.shell32.IsUserAnAdmin())
            return os.geteuid() == 0
        except Exception:
            return False

    def homes(self):
        homes = set(self.extra_homes)
        txt = self.read(self.fs("/etc/passwd"))
        for a in parse_passwd(txt or ""):
            if a["home"] and a["home"] not in ("/", "/nonexistent") and a["shell"] not in ("/usr/sbin/nologin", "/bin/false", "/sbin/nologin"):
                homes.add(a["home"])
        if self.os == "Darwin":
            homes |= set(glob.glob("/Users/*"))
        if self.os == "Windows":
            homes |= set(glob.glob(os.path.join(os.environ.get("SystemDrive", "C:") + os.sep, "Users", "*")))
        return sorted(h for h in homes if os.path.isdir(self.fs(h)) or os.path.isdir(h))

    # --------------------------------------------------------------- run everything
    def collect(self):
        try:
            import psutil  # noqa: F401
        except ImportError:
            raise RuntimeError("Live host collection needs psutil:  pip install psutil")
        t0 = time.time()
        self.log("Collecting live host evidence (order of volatility) ...")
        self.system()
        conns = self.connections()
        procs = self.processes()
        self.write("connections.json", dict(collected_at=_iso(time.time()), items=conns), "network sockets (psutil)")
        self.write("processes.json", dict(collected_at=_iso(time.time()), items=procs), "process list with executable hashes (psutil)")
        self.accounts()
        self.persistence()
        self.recent_files()
        if self.include_logs:
            self.logs()
        self.manifest["duration_s"] = round(time.time() - t0, 2)
        self.manifest["finished_utc"] = _iso(time.time())
        path = os.path.join(self.host_dir, "manifest.json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump(self.manifest, f, indent=1)
        return self.manifest

    # --------------------------------------------------------------- artifacts
    def system(self):
        import psutil
        info = dict(collected_at=_iso(self.now), hostname=socket.gethostname(), fqdn=socket.getfqdn(), os=self.os,
                    release=platform.release(), version=platform.version()[:200], machine=platform.machine(),
                    boot_time=_iso(psutil.boot_time()), uptime_s=int(self.now - psutil.boot_time()),
                    timezone_offset=_local_offset(), is_admin=self.is_admin(), collector_version=VERSION,
                    python=platform.python_version(), psutil=psutil.__version__,
                    logged_in=[dict(name=u.name, terminal=u.terminal, host=u.host, started=_iso(u.started)) for u in psutil.users()])
        try:
            info["run_as"] = os.getlogin()
        except OSError:
            info["run_as"] = os.environ.get("USER") or os.environ.get("USERNAME")
        if not info["is_admin"]:
            self.manifest["limited"]["not_admin"] = "Not running as Administrator/root: other users' processes, some sockets and protected logs may be missing."
        self.manifest["host"] = dict(hostname=info["hostname"], os=self.os, is_admin=info["is_admin"])
        self.write("system.json", info, "host identity and collection context")

    def connections(self):
        import psutil
        rows, limited = [], False
        try:
            conns = psutil.net_connections(kind="inet")
        except (psutil.AccessDenied, PermissionError):
            limited, conns = True, []
            for p in psutil.process_iter():
                try:
                    fn = getattr(p, "net_connections", None) or getattr(p, "connections")
                    conns += fn(kind="inet")
                except (psutil.AccessDenied, psutil.NoSuchProcess, PermissionError):
                    pass
        for c in conns:
            proto = "tcp" if c.type == socket.SOCK_STREAM else "udp"
            if c.family == socket.AF_INET6:
                proto += "6"
            rows.append(dict(proto=proto, local_ip=c.laddr.ip if c.laddr else None, local_port=c.laddr.port if c.laddr else None,
                             remote_ip=c.raddr.ip if c.raddr else None, remote_port=c.raddr.port if c.raddr else None,
                             status=c.status, pid=c.pid))
        if limited or (not self.is_admin() and any(r["pid"] is None for r in rows)):
            self.manifest["limited"]["connections"] = "Some sockets have no owning process (needs Administrator/root)."
        return rows

    def processes(self):
        import psutil
        procs, denied = [], 0
        exe_hash = {}
        for p in psutil.process_iter(["pid", "ppid", "name", "exe", "cmdline", "username", "create_time", "status"], ad_value=None):
            i = dict(p.info)
            try:
                i["cwd"] = p.cwd()
            except Exception:
                i["cwd"] = None
            exe = i.get("exe") or ""
            deleted = exe.endswith(" (deleted)")
            if deleted:
                exe = exe[: -len(" (deleted)")]
            if self.os == "Linux" and not deleted:
                # psutil silently removes the ' (deleted)' suffix when the path no longer exists, so read the raw link
                try:
                    raw = os.readlink(f"/proc/{i['pid']}/exe")
                    if raw.endswith(" (deleted)"):
                        deleted, exe = True, raw[: -len(" (deleted)")]
                except OSError:
                    pass
            if not exe:
                denied += 1
            i["exe"] = exe or None
            i["exe_deleted"] = deleted
            i["create_time_utc"] = _iso(i.pop("create_time", None))
            i["cmdline"] = i.get("cmdline") or []
            procs.append(i)
        for i in procs:
            e = i["exe"]
            if e and not i["exe_deleted"]:
                if e not in exe_hash and len(exe_hash) < self.hash_limit:
                    exe_hash[e] = sha256_file(e)
                i["exe_sha256"] = exe_hash.get(e)
            else:
                i["exe_sha256"] = None
        if denied:
            self.manifest["limited"]["processes"] = f"{denied} process(es) with no readable executable path (kernel threads or access denied)."
        return procs

    def accounts(self):
        acc = dict(collected_at=_iso(time.time()), items=[])
        if self.os == "Windows":
            rc, out, _ = self.run(["net", "user"])
            rc2, out2, _ = self.run(["net", "localgroup", "Administrators"])
            acc["items"] = [dict(name=n, kind="local_user") for n in parse_net_user(out)]
            acc["administrators"] = parse_net_user(out2)
            acc["raw"] = dict(net_user=out[:4000], net_localgroup_administrators=out2[:4000])
        else:
            txt = self.read(self.fs("/etc/passwd"))
            for a in parse_passwd(txt or ""):
                a["kind"] = "local_user"
                acc["items"].append(a)
            acc["groups"] = parse_group(self.read(self.fs("/etc/group")) or "")
            sud = []
            for f in [self.fs("/etc/sudoers")] + sorted(glob.glob(self.fs("/etc/sudoers.d/*"))):
                t = self.read(f)
                if t:
                    sud += [f"{os.path.basename(f)}: {l.strip()}" for l in t.splitlines() if l.strip() and not l.strip().startswith("#")][:50]
            acc["sudoers"] = sud
        self.write("accounts.json", acc, "local accounts, admin groups")

    def persistence(self):
        items = []
        add = lambda kind, name, value, mtime=None, **k: items.append(dict(kind=kind, name=name, value=value, mtime=_iso(mtime), **k))
        if self.os in ("Linux", "Darwin"):
            crons = [self.fs("/etc/crontab")] + sorted(glob.glob(self.fs("/etc/cron.d/*"))) + \
                sorted(glob.glob(self.fs("/var/spool/cron/crontabs/*")) + glob.glob(self.fs("/var/spool/cron/*")))
            for f in crons:
                if not os.path.isfile(f):
                    continue
                for l in parse_crontab(self.read(f) or ""):
                    add("cron", f, l, os.path.getmtime(f))
            for d in ("/etc/cron.hourly", "/etc/cron.daily", "/etc/cron.weekly", "/etc/cron.monthly"):
                for f in sorted(glob.glob(self.fs(d + "/*"))):
                    add("cron_script", f, os.path.basename(f), os.path.getmtime(f), sha256=sha256_file(f))
            units = glob.glob(self.fs("/etc/systemd/system/*.service")) + glob.glob(self.fs("/etc/systemd/system/*/*.service"))
            for h in self.homes():
                units += glob.glob(self.fs(h + "/.config/systemd/user/*.service"))
            for f in sorted(set(units)):
                if os.path.isfile(f):
                    for cmd in parse_systemd_unit(self.read(f) or ""):
                        add("systemd", f, cmd, os.path.getmtime(f))
            for f in (self.fs("/etc/rc.local"), ):
                t = self.read(f)
                if t:
                    for l in t.splitlines():
                        if l.strip() and not l.strip().startswith("#") and l.strip() != "exit 0":
                            add("rc_local", f, l.strip(), os.path.getmtime(f))
            t = self.read(self.fs("/etc/ld.so.preload"))
            if t and t.strip():
                add("ld_preload", "/etc/ld.so.preload", t.strip()[:300], os.path.getmtime(self.fs("/etc/ld.so.preload")))
            for h in self.homes():
                f = self.fs(h + "/.ssh/authorized_keys")
                if os.path.isfile(f):
                    for k in parse_authorized_keys(self.read(f) or ""):
                        add("authorized_keys", f, f"{k['type']} {k['fingerprint_sha256']} {k['comment']}".strip(), os.path.getmtime(f), options=k["options"])
            if self.os == "Darwin":
                import plistlib
                for d in ["/Library/LaunchAgents", "/Library/LaunchDaemons"] + [h + "/Library/LaunchAgents" for h in self.homes()]:
                    for f in sorted(glob.glob(d + "/*.plist")):
                        try:
                            pl = plistlib.load(open(f, "rb"))
                            cmd = " ".join(pl.get("ProgramArguments") or [pl.get("Program", "")])
                        except Exception:
                            cmd = "(unreadable)"
                        add("launchd", f, cmd, os.path.getmtime(f))
        elif self.os == "Windows":
            try:
                import winreg
                for hive, hn in ((winreg.HKEY_LOCAL_MACHINE, "HKLM"), (winreg.HKEY_CURRENT_USER, "HKCU")):
                    for sub in (r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
                                r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"):
                        try:
                            with winreg.OpenKey(hive, sub) as k:
                                i = 0
                                while True:
                                    try:
                                        n, v, _ = winreg.EnumValue(k, i)
                                    except OSError:
                                        break
                                    add("run_key", f"{hn}\\{sub}\\{n}", str(v))
                                    i += 1
                        except OSError:
                            pass
            except ImportError:
                pass
            for d in (os.path.expandvars(r"%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup"),
                      os.path.expandvars(r"%ProgramData%\Microsoft\Windows\Start Menu\Programs\StartUp")):
                for f in glob.glob(os.path.join(d, "*")):
                    add("startup_folder", f, os.path.basename(f), os.path.getmtime(f))
            rc, out, _ = self.run(["schtasks", "/query", "/fo", "csv", "/v", "/nh"], timeout=120)
            for t in parse_schtasks_csv(out):
                add("schtask", t["task"], t["run"], None, run_as=t["run_as"], status=t["status"])
            try:
                import psutil
                for s in psutil.win_service_iter():
                    try:
                        add("service", s.name(), s.binpath(), None, start_type=s.start_type(), run_as=s.username(), status=s.status())
                    except Exception:
                        pass
            except Exception as e:
                self.manifest["errors"].append(f"services: {e}")
        self.write("persistence.json", dict(collected_at=_iso(time.time()), items=items), "autostart / persistence mechanisms")

    def recent_files(self):
        dirs = []
        if self.os == "Windows":
            dirs = [os.environ.get("TEMP", ""), os.path.expandvars(r"%LOCALAPPDATA%\Temp"), r"C:\Users\Public", r"C:\Windows\Temp"]
            dirs += [os.path.join(h, "Downloads") for h in self.homes()]
        else:
            dirs = ["/tmp", "/var/tmp", "/dev/shm"] + [os.path.join(h, "Downloads") for h in self.homes()]
            dirs = [self.fs(d) if d.startswith("/") and self.fs_root != "/" else d for d in dirs]
        cutoff = self.now - self.days * 86400
        own = os.path.realpath(self.out_dir)
        found, scanned, hashed = [], 0, 0
        for base in dict.fromkeys(d for d in dirs if d and os.path.isdir(d)):
            stack = [(base, 0)]
            while stack and scanned < self.file_scan_limit:
                d, depth = stack.pop()
                try:
                    with os.scandir(d) as it:
                        for en in it:
                            scanned += 1
                            try:
                                if os.path.realpath(en.path).startswith(own):
                                    continue
                                if en.is_dir(follow_symlinks=False):
                                    if depth < 3:
                                        stack.append((en.path, depth + 1))
                                    continue
                                st = en.stat(follow_symlinks=False)
                            except OSError:
                                continue
                            newest = max(st.st_mtime, st.st_ctime)      # ctime moves when timestamps are forged (Linux) / is creation time (Windows)
                            if newest < cutoff:
                                continue
                            mg = _magic(en.path)
                            rec = dict(path=en.path, size=st.st_size, mtime=_iso(st.st_mtime), changed=_iso(st.st_ctime), magic=mg, sha256=None,
                                       timestomped=bool(st.st_ctime - st.st_mtime > 3600) if self.os != "Windows" else False)
                            if mg and hashed < self.hash_limit:
                                rec["sha256"] = sha256_file(en.path, 50 * 1024 * 1024)
                                hashed += 1
                            found.append(rec)
                except OSError:
                    continue
        if scanned >= self.file_scan_limit:
            self.manifest["limited"]["files"] = f"File scan stopped after {self.file_scan_limit} entries."
        found.sort(key=lambda r: r["changed"], reverse=True)          # newest change first ...
        found.sort(key=lambda r: r["magic"] is None)                 # ... but executables and scripts always before plain files
        keep = 1000
        if len(found) > keep:
            self.manifest["limited"]["files"] = f"{len(found)} recent files found; kept the first {keep} (executables and scripts first, newest first)."
        self.write("files.json", dict(collected_at=_iso(time.time()), window_days=self.days, scanned=scanned, total_recent=len(found), items=found[:keep]),
                   "files written in temporary / download locations in the last %d days" % self.days)

    def logs(self):
        if self.os == "Windows":
            chans = {"Security": "Security.evtx", "System": "System.evtx", "Microsoft-Windows-PowerShell/Operational": "PowerShell.evtx"}
            rc, out, _ = self.run(["wevtutil", "el"])
            if "Microsoft-Windows-Sysmon/Operational" in out:
                chans["Microsoft-Windows-Sysmon/Operational"] = "Sysmon.evtx"
            for ch, fn in chans.items():
                dst = os.path.join(self.out_dir, fn)
                if os.path.exists(dst):
                    os.remove(dst)
                rc, _, err = self.run(["wevtutil", "epl", ch, dst])
                if rc == 0:
                    self.manifest["artifacts"].append(dict(name=fn, sha256=sha256_file(dst), size=os.path.getsize(dst), records=None, note=f"wevtutil export of {ch}"))
                elif "Security" == ch:
                    self.manifest["limited"]["security_log"] = "Security log could not be exported (needs Administrator)."
        elif self.os == "Linux":
            for src in ("/var/log/auth.log", "/var/log/secure"):
                s = self.fs(src)
                if os.path.exists(s) and os.access(s, os.R_OK):
                    dst = os.path.join(self.out_dir, "auth.log")
                    with open(s, "rb") as a, open(dst, "wb") as b:
                        b.write(a.read())
                    self.manifest["artifacts"].append(dict(name="auth.log", sha256=sha256_file(dst), size=os.path.getsize(dst), records=None, note=f"copy of {src}"))
                    return
            rc, out, _ = self.run(["journalctl", "--no-pager", "-o", "short-iso", "--since", f"-{self.days}d", "_COMM=sshd", "+", "_COMM=sudo", "+", "_COMM=useradd"], timeout=120)
            has_lines = any(re.match(r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d", l) for l in out.splitlines())
            if rc == 0 and has_lines:
                dst = os.path.join(self.out_dir, "auth.log")
                with open(dst, "w", encoding="utf-8") as f:
                    f.write(out)
                self.manifest["artifacts"].append(dict(name="auth.log", sha256=sha256_file(dst), size=os.path.getsize(dst), records=None, note="journalctl (sshd, sudo, useradd)"))
            else:
                self.manifest["limited"]["auth_log"] = "No readable /var/log/auth.log or /var/log/secure and no journal output."


def collect_host(out_dir, **kw):
    return HostCollector(out_dir, **kw).collect()
