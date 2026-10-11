"""Normalization layer: converts three different log formats into one common schema.

Common schema (one dict per event):
  event_id, time_utc, epoch, source (windows|linux|aws), host, event_type, user,
  src_ip, target, outcome, detail, session_id, key_id, new_key_id, logon_type,
  source_file, line_ref, raw

All timestamps are converted to UTC (Windows and CloudTrail are already UTC, Linux
auth.log is local time without a year, so the offset and year come from case_config.json).

Supported event catalogue (anything else is counted as 'ignored', not as an error):
  Windows Security: 4624 4625 4634 4672 4688 4698 4720 4732 5145 1102
  Windows System:   7045 104
  Sysmon:           1 (process create) 3 (network) 10 (process access) 13 (registry set)
  AWS state:        trails, IAM account summary, users, access keys, roles, S3 buckets, security groups (cloudstate.py)
  PowerShell:       4104 (script block)
  Linux:   sshd Failed/Accepted password|publickey, sudo COMMAND, useradd
  AWS:     every CloudTrail record
"""
import json
import os
import re
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta, timezone

MONTHS = {m: i for i, m in enumerate(["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], 1)}
_XMLNS = re.compile(r"""\sxmlns(?::\w+)?=(?:"[^"]*"|'[^']*')""")
_EVENT = re.compile(r"<Event[ >].*?</Event>", re.S)
_SYSLOG = re.compile(r"^([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d\d):(\d\d):(\d\d)\s+(\S+)\s+([^\[:\s]+)(?:\[\d+\])?:\s+(.*)$")
_ISOLOG = re.compile(r"^(\d{4})-(\d\d)-(\d\d)T(\d\d):(\d\d):(\d\d)(?:\.\d+)?(Z|[+-]\d\d:?\d\d)\s+(\S+)\s+([^\[:\s]+)(?:\[\d+\])?:\s+(.*)$")
_FAILED = re.compile(r"Failed (?:password|publickey) for (?:invalid user )?(\S+) from (\S+) port \d+")
_ACCEPT = re.compile(r"Accepted (?:password|publickey|keyboard-interactive/pam) for (\S+) from (\S+) port \d+")
_SUDO = re.compile(r"^\s*(\S+)\s+:\s+(?:.*?;\s*)?USER=(\S+)\s*;\s*COMMAND=(.*)$")
_REPEAT = re.compile(r"^message repeated (\d+) times?: \[ ?(.*?) ?\]$")
_PAMFAIL = re.compile(r"authentication failure;.*?rhost=(\S*)(?:\s+user=(\S+))?")
_USERADD = re.compile(r"new user: name=([^,\s]+)")


def _blank():
    return dict(event_id=None, time_utc=None, epoch=None, source=None, host=None, event_type=None, user=None,
                src_ip=None, target=None, outcome=None, detail=None, session_id=None, key_id=None, new_key_id=None,
                logon_type=None, source_file=None, line_ref=None, raw=None, extra=None)


def _tz(offset):
    if ":" not in offset.lstrip("+-"):
        offset = offset[:3] + ":" + offset[3:]          # journalctl short-iso prints +0000
    sign = -1 if offset.startswith("-") else 1
    h, m = offset.lstrip("+-").split(":")
    return timezone(sign * timedelta(hours=int(h), minutes=int(m)))


def _fmt(dt):
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


_TS = re.compile(r"(\d{4})-(\d\d)-(\d\d)[T ](\d\d):(\d\d):(\d\d)(?:\.\d+)?\s*(Z|[+-]\d\d:?\d\d)?")


def _parse_ts(ts):
    """ISO-like timestamps: '...T...Z', '... ...+00:00', with or without fractions. No offset means UTC."""
    m = _TS.match(ts.strip())
    if not m:
        raise ValueError(ts)
    y, mo, d, hh, mi, ss, off = m.groups()
    if off in (None, "Z"):
        tz = timezone.utc
    else:
        o = off if ":" in off else off[:3] + ":" + off[3:]
        tz = _tz(o)
    return datetime(int(y), int(mo), int(d), int(hh), int(mi), int(ss), tzinfo=tz)


def _ip(v):
    if not v or v in ("-", "::1", "127.0.0.1", "::"):
        return None
    if v.startswith("::ffff:"):
        v = v[7:]
    return v


# ------------------------------------------------------------------ Windows
def _windows_chunks(path):
    """Yield one XML string per event, from a wevtutil XML export or a binary .evtx file."""
    if path.lower().endswith(".evtx"):
        try:
            from Evtx.Evtx import Evtx
        except ImportError:
            raise RuntimeError("Reading .evtx files needs the 'python-evtx' package:  pip install python-evtx")
        with Evtx(path) as log:
            it = log.records()
            while True:
                try:
                    rec = next(it)
                except StopIteration:
                    break
                except Exception:
                    yield None       # damaged record: counted as a parse error
                    continue
                try:
                    yield _XMLNS.sub("", rec.xml())
                except Exception:
                    yield None
    else:
        with open(path, encoding="utf-8", errors="replace") as f:
            text = _XMLNS.sub("", f.read())
        for chunk in _EVENT.findall(text):
            yield chunk


def parse_windows(path):
    ev, st = [], dict(records_seen=0, normalized=0, ignored=0, errors=0)
    fname = os.path.basename(path)
    for n, chunk in enumerate(_windows_chunks(path), 1):
        if chunk is None:
            st["records_seen"] += 1
            st["errors"] += 1
            continue
        st["records_seen"] += 1
        try:
            root = ET.fromstring(chunk)
            eid = int(root.findtext("System/EventID"))
            ts = root.find("System/TimeCreated").get("SystemTime")
            host = root.findtext("System/Computer") or "unknown"
            channel = (root.findtext("System/Channel") or "").strip()
            prov = root.find("System/Provider")
            provider = prov.get("Name", "") if prov is not None else ""
            if not channel and provider in ("Microsoft-Windows-Security-Auditing", "Microsoft-Windows-Eventlog"):
                channel = "Security"          # exports without a Channel element (e.g. hand-made XML): trust only the Security providers
            dt = _parse_ts(ts)
            data = {d.get("Name"): (d.text or "") for d in root.findall("EventData/Data")}
            ud = root.find("UserData")
            if ud is not None:
                for child in ud:
                    for x in child:
                        data[x.tag] = x.text or ""
        except Exception:
            st["errors"] += 1
            continue
        e = _blank()
        e.update(source="windows", host=host, time_utc=_fmt(dt), epoch=dt.timestamp(),
                 source_file=fname, line_ref=n, raw=f"{channel or 'Security'} EventID {eid}")
        sec = channel == "Security"
        sid = lambda k: (data.get(k) or "").lower() or None      # logon ids: compare case-insensitively
        if sec and eid == 4625:
            e.update(event_type="auth_failure", user=data.get("TargetUserName"), src_ip=_ip(data.get("IpAddress")),
                     logon_type=data.get("LogonType"), outcome="failure", detail=f"failed logon status {data.get('Status', '')}")
        elif sec and eid == 4624:
            e.update(event_type="auth_success", user=data.get("TargetUserName"), src_ip=_ip(data.get("IpAddress")),
                     logon_type=data.get("LogonType"), session_id=sid("TargetLogonId"), outcome="success",
                     detail=f"logon type {data.get('LogonType', '')}")
        elif sec and eid == 4634:
            e.update(event_type="logoff", user=data.get("TargetUserName"), session_id=sid("TargetLogonId"), outcome="success")
        elif sec and eid == 4672:
            e.update(event_type="priv_assign", user=data.get("SubjectUserName"), session_id=sid("SubjectLogonId"),
                     outcome="success", detail=data.get("PrivilegeList", "").strip())
        elif sec and eid == 4688:
            e.update(event_type="process_create", user=data.get("SubjectUserName"), session_id=sid("SubjectLogonId"),
                     target=data.get("NewProcessName"), outcome="success", detail=data.get("CommandLine"),
                     extra={"parent": data.get("ParentProcessName")})
        elif sec and eid == 4720:
            e.update(event_type="account_created", user=data.get("SubjectUserName"), session_id=sid("SubjectLogonId"),
                     target=data.get("TargetUserName"), outcome="success", detail="local account created")
        elif sec and eid == 4732:
            e.update(event_type="group_add", user=data.get("SubjectUserName"), session_id=sid("SubjectLogonId"),
                     target=data.get("TargetUserName"), outcome="success", detail=f"member {data.get('MemberName', '')}")
        elif sec and eid == 4698:
            e.update(event_type="scheduled_task", user=data.get("SubjectUserName"), session_id=sid("SubjectLogonId"),
                     target=data.get("TaskName"), outcome="success", detail="scheduled task created")
        elif sec and eid == 5145:
            e.update(event_type="share_access", user=data.get("SubjectUserName"), session_id=sid("SubjectLogonId"),
                     src_ip=_ip(data.get("IpAddress")), target=f"{data.get('ShareName', '')}\\{data.get('RelativeTargetName', '')}",
                     outcome="success", detail="network share object access",
                     extra={"share": data.get("ShareName", ""), "name": data.get("RelativeTargetName", "")})
        elif (sec and eid == 1102) or (channel == "System" and eid == 104):
            e.update(event_type="log_cleared", user=data.get("SubjectUserName"), session_id=sid("SubjectLogonId"),
                     outcome="success", detail="audit log cleared" if eid == 1102 else "system log cleared")
        elif channel == "System" and eid == 7045:
            e.update(event_type="service_install", user=data.get("AccountName"), target=data.get("ServiceName"),
                     outcome="success", detail=data.get("ImagePath"))
        elif channel == "Microsoft-Windows-Sysmon/Operational" and eid == 1:
            e.update(event_type="process_create", user=data.get("User"), session_id=sid("LogonId"), target=data.get("Image"),
                     outcome="success", detail=data.get("CommandLine"), extra={"parent": data.get("ParentImage")})
        elif channel == "Microsoft-Windows-Sysmon/Operational" and eid == 3:
            e.update(event_type="network_connect", user=data.get("User"), src_ip=None, target=f"{data.get('DestinationIp', '')}:{data.get('DestinationPort', '')}",
                     outcome="success", detail=data.get("Image"), extra={"dst_ip": data.get("DestinationIp"), "initiated": data.get("Initiated")})
        elif channel == "Microsoft-Windows-Sysmon/Operational" and eid == 10:
            e.update(event_type="process_access", user=None, target=data.get("TargetImage"), outcome="success",
                     detail=data.get("SourceImage"), extra={"source": data.get("SourceImage"), "access": data.get("GrantedAccess")})
        elif channel == "Microsoft-Windows-Sysmon/Operational" and eid == 13:
            e.update(event_type="registry_set", user=data.get("User"), target=data.get("TargetObject"), outcome="success",
                     detail=data.get("Details"), extra={"image": data.get("Image")})
        elif channel == "Microsoft-Windows-PowerShell/Operational" and eid == 4104:
            e.update(event_type="script_block", target="PowerShell", outcome="success", detail=(data.get("ScriptBlockText") or "")[:2000])
        else:
            st["ignored"] += 1
            key = f"{channel or provider or 'unknown'}|{eid}"
            st.setdefault("ignored_ids", {})
            st["ignored_ids"][key] = st["ignored_ids"].get(key, 0) + 1
            continue
        ev.append(e)
        st["normalized"] += 1
    return ev, st


# ------------------------------------------------------------------ Linux
def parse_linux(path, tz_offset="+05:30", year=2026):
    tz = _tz(tz_offset)
    ev, st = [], dict(records_seen=0, normalized=0, ignored=0, errors=0)
    with open(path, encoding="utf-8", errors="replace") as f:
        all_lines = f.read().splitlines()
    # Older systems (e.g. RedHat) log failed SSH logins only as PAM 'authentication failure' lines. Newer sshd logs
    # BOTH a 'Failed password' line and a PAM line for the same attempt, so PAM lines are used only when the file
    # has no 'Failed password' lines at all (otherwise every failure would be counted twice).
    pam_mode = not any("Failed password" in l for l in all_lines)
    if True:
        for n, line in enumerate(all_lines, 1):
            line = line.rstrip("\r\n")
            if not line.strip():
                continue
            st["records_seen"] += 1
            m = _SYSLOG.match(line)
            try:
                if m:   # traditional syslog: local time, no year -> offset/year from case_config
                    mon, day, hh, mm, ss, host, proc, msg = m.groups()
                    dt = datetime(year, MONTHS[mon], int(day), int(hh), int(mm), int(ss), tzinfo=tz)
                else:   # ISO 8601 (Ubuntu 24.04 / Debian 12): the offset is in the line itself
                    m = _ISOLOG.match(line)
                    if not m:
                        st["errors"] += 1
                        continue
                    y_, mo_, d_, hh, mm, ss, off, host, proc, msg = m.groups()
                    dt = datetime(int(y_), int(mo_), int(d_), int(hh), int(mm), int(ss),
                                  tzinfo=timezone.utc if off == "Z" else _tz(off))
            except Exception:
                st["errors"] += 1
                continue
            proc = re.sub(r"\(.*\)$", "", proc)          # 'sshd(pam_unix)' -> 'sshd'
            repeat = 1
            rm = _REPEAT.match(msg)                       # syslog folds identical lines: 'message repeated 5 times: [ ... ]'
            if rm:
                repeat, msg = int(rm.group(1)), rm.group(2)
            e = _blank()
            e.update(source="linux", host=host, time_utc=_fmt(dt), epoch=dt.timestamp(),
                     source_file="auth.log", line_ref=n, raw=line)
            if repeat > 1:
                e["extra"] = {"repeat": repeat}
            if proc == "sshd" and (mm_ := _FAILED.search(msg)):
                e.update(event_type="auth_failure", user=mm_.group(1), src_ip=_ip(mm_.group(2)), outcome="failure",
                         detail="ssh failed login")
            elif proc == "sshd" and pam_mode and (mm_ := _PAMFAIL.search(msg)) and mm_.group(1):
                e.update(event_type="auth_failure", user=mm_.group(2), src_ip=_ip(mm_.group(1)), outcome="failure",
                         detail="ssh failed login (PAM)")
            elif proc == "sshd" and (mm_ := _ACCEPT.search(msg)):
                e.update(event_type="auth_success", user=mm_.group(1), src_ip=_ip(mm_.group(2)), outcome="success",
                         detail="ssh login")
            elif proc == "sudo" and (mm_ := _SUDO.match(msg)):
                e.update(event_type="command_exec", user=mm_.group(1), target=mm_.group(3).strip(), outcome="success",
                         detail=f"sudo as {mm_.group(2)}")
            elif proc == "useradd" and (mm_ := _USERADD.search(msg)):
                e.update(event_type="account_created", target=mm_.group(1), outcome="success", detail="local account created")
            else:
                st["ignored"] += 1
                continue
            ev.append(e)
            st["normalized"] += 1
    return ev, st


# ------------------------------------------------------------------ AWS
def _lenient_records(text):
    """Recover records from real-world exports that are not valid JSON: objects glued together without
    commas, JSON Lines (also pretty-printed), or a truncated tail. Undecodable parts become None (error)."""
    dec, out = json.JSONDecoder(), []
    i = text.find("[", text.find('"Records"')) + 1 if '"Records"' in text else 0
    while i < len(text):
        while i < len(text) and (text[i].isspace() or text[i] in ",]}"):
            i += 1
        if i >= len(text):
            break
        if text[i] != "{":
            i += 1
            continue
        try:
            obj, i = dec.raw_decode(text, i)
            out.append(obj)
        except ValueError:
            out.append(None)
            break
    return out


def parse_cloudtrail(path):
    ev, st = [], dict(records_seen=0, normalized=0, ignored=0, errors=0)
    with open(path, encoding="utf-8-sig") as f:
        text = f.read()
    try:
        doc = json.loads(text)
        records = doc.get("Records", [doc]) if isinstance(doc, dict) else doc
    except ValueError:
        records = _lenient_records(text)
    for n, r in enumerate(records, 1):
        if not isinstance(r, dict):
            st["records_seen"] += 1
            st["errors"] += 1
            continue
        st["records_seen"] += 1
        try:
            dt = datetime.strptime(r["eventTime"][:19], "%Y-%m-%dT%H:%M:%S").replace(tzinfo=timezone.utc)
            name = r["eventName"]
        except Exception:
            st["errors"] += 1
            continue
        ident = r.get("userIdentity") or {}
        params = r.get("requestParameters") or {}
        resp = r.get("responseElements") or {}
        user = ident.get("userName") or (ident.get("arn") or "").split("/")[-1] or ident.get("invokedBy")
        src_ip = r.get("sourceIPAddress") or ((r.get("network") or {}).get("client") or {}).get("ip")   # enriched exports keep it here
        e = _blank()
        e.update(source="aws", host=r.get("awsRegion") or "aws", time_utc=_fmt(dt), epoch=dt.timestamp(),
                 source_file="cloudtrail.json", line_ref=n, user=user, src_ip=_ip(src_ip) or src_ip,
                 key_id=ident.get("accessKeyId"), outcome="failure" if r.get("errorCode") else "success",
                 raw=name, detail=(r.get("eventSource") or "").replace(".amazonaws.com", ""))
        if name == "ConsoleLogin":
            ok = (resp.get("ConsoleLogin") == "Success")
            e.update(event_type="auth_success" if ok else "auth_failure", outcome="success" if ok else "failure",
                     detail="console login")
        elif name in ("StopLogging", "DeleteTrail", "UpdateTrail"):
            e.update(event_type="logging_stopped", target=params.get("name"), detail=name)
        elif name == "CreateAccessKey":
            new = (resp.get("accessKey") or {}).get("accessKeyId")
            e.update(event_type="access_key_created", new_key_id=new, target=params.get("userName"), detail=name)
        elif name == "GetObject":
            e.update(event_type="data_download", target=f"{params.get('bucketName', '')}/{params.get('key', '')}", detail=name)
        elif name in ("AttachUserPolicy", "PutUserPolicy", "CreateUser", "AddUserToGroup", "CreateLoginProfile", "AttachRolePolicy"):
            e.update(event_type="iam_change", target=params.get("userName") or params.get("roleName"), detail=name)
        else:
            e.update(event_type="api_call", target=params.get("bucketName") or params.get("userName"), detail=name)
        if name == "ModifyInstanceAttribute":
            e["extra"] = {"user_data": "userData" in params}
        ev.append(e)
        st["normalized"] += 1
    return ev, st


def parse_host(host_dir):
    """Live host artifacts written by hostcollect.py -> events (source 'host')."""
    ev, st = [], dict(records_seen=0, normalized=0, ignored=0, errors=0)

    def load(name):
        p = os.path.join(host_dir, name)
        if not os.path.exists(p):
            return None
        try:
            with open(p, encoding="utf-8") as f:
                return json.load(f)
        except ValueError:
            st["errors"] += 1
            return None

    sysj = load("system.json") or {}
    host = sysj.get("hostname") or "host"
    try:
        coll = _parse_ts(sysj["collected_at"])
    except Exception:
        coll = datetime.now(timezone.utc)

    def add(fname, idx, dt, **kw):
        e = _blank()
        e.update(source="host", host=host, time_utc=_fmt(dt), epoch=dt.timestamp(), source_file=f"host/{fname}", line_ref=idx, outcome="success")
        e.update(kw)
        ev.append(e)
        st["normalized"] += 1

    def when(ts):
        try:
            return _parse_ts(ts) if ts else coll
        except Exception:
            return coll

    if sysj:
        st["records_seen"] += 1
        add("system.json", 1, coll, event_type="collection", user=sysj.get("run_as"), target=host,
            detail=f"live collection on {sysj.get('os', '')} {sysj.get('release', '')}, admin={sysj.get('is_admin')}, boot {sysj.get('boot_time')}",
            extra={"admin": sysj.get("is_admin")}, raw="system.json")
    procs = (load("processes.json") or {}).get("items", [])
    pid_name = {p.get("pid"): p.get("name") for p in procs}
    for i, p in enumerate(procs, 1):
        st["records_seen"] += 1
        cmd = " ".join(p.get("cmdline") or [])
        add("processes.json", i, when(p.get("create_time_utc")), event_type="process_snapshot", user=p.get("username"),
            target=p.get("exe") or p.get("name"), detail=cmd or p.get("name"),
            extra=dict(pid=p.get("pid"), ppid=p.get("ppid"), parent=pid_name.get(p.get("ppid")), name=p.get("name"),
                       exe_deleted=bool(p.get("exe_deleted")), sha256=p.get("exe_sha256"), cwd=p.get("cwd")), raw=f"pid {p.get('pid')}")
    for i, c in enumerate((load("connections.json") or {}).get("items", []), 1):
        st["records_seen"] += 1
        pid = c.get("pid")
        base = dict(pid=pid, proc=pid_name.get(pid), status=c.get("status"), local=f"{c.get('local_ip')}:{c.get('local_port')}")
        if c.get("remote_ip"):
            rip = _ip(c["remote_ip"])
            add("connections.json", i, coll, event_type="connection_snapshot", src_ip=rip, target=f"{rip}:{c.get('remote_port')}",
                detail=pid_name.get(pid) or "unknown process", extra=dict(base, dst_ip=rip), raw=c.get("status"))
        elif c.get("status") == "LISTEN":
            add("connections.json", i, coll, event_type="listener_snapshot", target=f"{c.get('local_ip')}:{c.get('local_port')}",
                detail=pid_name.get(pid) or "unknown process", extra=base, raw="LISTEN")
    acc = load("accounts.json") or {}
    for i, a in enumerate(acc.get("items", []), 1):
        st["records_seen"] += 1
        add("accounts.json", i, coll, event_type="account_snapshot", user=a.get("name"), target=f"uid {a.get('uid')}" if "uid" in a else "local user",
            detail=a.get("shell") or "", extra=dict(uid=a.get("uid"), shell=a.get("shell"), home=a.get("home")), raw="account")
    for i, p in enumerate((load("persistence.json") or {}).get("items", []), 1):
        st["records_seen"] += 1
        add("persistence.json", i, when(p.get("mtime")), event_type="persistence_entry", target=p.get("name"), detail=p.get("value"),
            extra=dict(kind=p.get("kind"), run_as=p.get("run_as")), raw=p.get("kind"))
    for i, f in enumerate((load("files.json") or {}).get("items", []), 1):
        st["records_seen"] += 1
        add("files.json", i, when(f.get("changed") or f.get("mtime")), event_type="file_snapshot", target=f.get("path"), detail=f"{f.get('size')} bytes",
            extra=dict(magic=f.get("magic"), sha256=f.get("sha256"), size=f.get("size"), timestomped=bool(f.get("timestomped"))), raw=f.get("magic") or "file")
    return ev, st


def parse_cloud(cloud_dir):
    """AWS account-state artefacts written by cloudstate.py -> events (source 'aws', state event types)."""
    ev, st = [], dict(records_seen=0, normalized=0, ignored=0, errors=0)

    def load(name):
        p = os.path.join(cloud_dir, name)
        if not os.path.exists(p):
            return None
        try:
            with open(p, encoding="utf-8") as f:
                return json.load(f)
        except ValueError:
            st["errors"] += 1
            return None

    ident = load("identity.json") or {}
    try:
        coll = _parse_ts(ident["collected_at"])
    except Exception:
        coll = datetime.now(timezone.utc)
    account = ident.get("account") or "aws-account"

    def add(fname, idx, **kw):
        e = _blank()
        e.update(source="aws", host=account, time_utc=_fmt(coll), epoch=coll.timestamp(), source_file=f"cloud/{fname}", line_ref=idx, outcome="success")
        e.update(kw)
        ev.append(e)
        st["normalized"] += 1

    def days(ts):
        try:
            return (coll - _parse_ts(ts)).days if ts else None
        except Exception:
            return None

    tr = load("trails.json")
    if tr:
        st["records_seen"] += 1
        items = tr.get("items", [])
        if tr.get("listed") and not items:
            add("trails.json", 1, event_type="trail_state", target="(no trail configured)", detail="no CloudTrail trail found", extra={"none": True}, raw="no trail")
        for i, t in enumerate(items, 1):
            st["records_seen"] += 1
            add("trails.json", i, event_type="trail_state", target=t.get("name"), detail=f"trail logging={t.get('is_logging')}, multi-region={t.get('multi_region')}",
                extra=dict(is_logging=t.get("is_logging"), multi_region=t.get("multi_region"), stop_time=t.get("stop_logging_time"), validation=t.get("log_validation")), raw="trail")
    acc = load("iam_account.json")
    if acc and acc.get("known"):
        st["records_seen"] += 1
        add("iam_account.json", 1, event_type="account_state", target="root account", detail=f"root MFA enabled={acc.get('root_mfa')}", extra=dict(root_mfa=acc.get("root_mfa")), raw="account")
    for i, u in enumerate((load("iam_users.json") or {}).get("items", []), 1):
        st["records_seen"] += 1
        add("iam_users.json", i, event_type="iam_user_state", user=u.get("user"), target=u.get("user"),
            detail=f"admin={u.get('is_admin')}, MFA devices={u.get('mfa_devices')}, keys={len(u.get('keys', []))}",
            extra=dict(is_admin=bool(u.get("is_admin")), mfa=None if u.get("mfa_devices") is None else u["mfa_devices"] > 0, keys=len(u.get("keys", []))), raw="iam user")
        for k in u.get("keys", []):
            st["records_seen"] += 1
            add("iam_users.json", i, event_type="access_key_state", user=u.get("user"), key_id=k.get("key_id"), target=k.get("key_id"),
                detail=f"key {k.get('status')}, last used {k.get('last_used') or 'never'}",
                extra=dict(status=k.get("status"), age_days=days(k.get("created")), last_used_days=days(k.get("last_used")), is_admin=bool(u.get("is_admin")), service=k.get("last_service")), raw="access key")
    for i, r in enumerate((load("iam_roles.json") or {}).get("items", []), 1):
        st["records_seen"] += 1
        tr = r.get("trust") or []
        add("iam_roles.json", i, event_type="role_state", target=r.get("role"), detail=f"trusts {len(tr)} principal(s)" + (": " + ", ".join(t.get("principal", "") for t in tr[:3]) if tr else ""),
            extra=dict(trust=tr), raw="iam role")
    for i, b in enumerate((load("s3_buckets.json") or {}).get("items", []), 1):
        st["records_seen"] += 1
        add("s3_buckets.json", i, event_type="bucket_state", target=b.get("bucket"), detail=f"public access block complete={b.get('block_all')}, public policy={b.get('policy_public')}",
            extra=dict(block_all=bool(b.get("block_all")), public=bool(b.get("policy_public")), checked=bool(b.get("checked"))), raw="bucket")
    for i, g in enumerate((load("security_groups.json") or {}).get("items", []), 1):
        st["records_seen"] += 1
        opened = []
        for r in g.get("rules", []):
            if any(c in ("0.0.0.0/0", "::/0") for c in r.get("cidrs", [])):
                if r.get("protocol") in ("-1", None):
                    opened.append(("all", 0, 65535))
                else:
                    opened.append((r.get("protocol"), r.get("from_port") if r.get("from_port") is not None else 0, r.get("to_port") if r.get("to_port") is not None else 65535))
        add("security_groups.json", i, event_type="sg_state", target=g.get("group_id"), detail=g.get("name"), extra=dict(world_open=opened, region=g.get("region")), raw="security group")
    return ev, st


def normalize_case(evidence_dir, cfg):
    """Parse every available evidence file. Returns (sorted events, per-source stats)."""
    events, stats = [], {}
    win_files = [f for f in sorted(os.listdir(evidence_dir)) if f == "windows_security.xml" or f.lower().endswith(".evtx")] \
        if os.path.isdir(evidence_dir) else []
    for f in win_files:
        e, s = parse_windows(os.path.join(evidence_dir, f))
        events += e
        agg = stats.setdefault("windows", dict(records_seen=0, normalized=0, ignored=0, errors=0))
        for k in agg:
            agg[k] += s[k]
    p = os.path.join(evidence_dir, "auth.log")
    if os.path.exists(p):
        e, s = parse_linux(p, cfg.get("linux_timezone_offset", "+05:30"), cfg.get("linux_log_year", 2026))
        events += e
        stats["linux"] = s
    p = os.path.join(evidence_dir, "cloudtrail.json")
    if os.path.exists(p):
        e, s = parse_cloudtrail(p)
        events += e
        stats["aws"] = s
    cd = os.path.join(evidence_dir, "cloud")
    if os.path.isdir(cd):
        e, s = parse_cloud(cd)
        events += e
        stats["cloud"] = s
    hd = os.path.join(evidence_dir, "host")
    if os.path.isdir(hd):
        e, s = parse_host(hd)
        events += e
        stats["host"] = s
    events.sort(key=lambda x: (x["epoch"], x["source"], x["line_ref"]))
    for i, e in enumerate(events, 1):
        e["event_id"] = f"E{i:06d}"
    return events, stats
