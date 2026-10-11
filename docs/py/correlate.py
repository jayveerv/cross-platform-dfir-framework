"""Correlation layer.

Step 1  detect      - rule-based detectors flag suspicious events (each rule mapped to MITRE ATT&CK).
                      Rule families: Windows (Security, System, Sysmon, PowerShell), Linux auth.log, AWS CloudTrail,
                      live host artifacts (hostcollect.py) and AWS account state (cloudstate.py, "posture" rules).
Step 2  attribute   - attribute events to login sessions (Windows: LogonId, Linux: latest login of the same user on
                      the same host) so later actions inherit the login's source IP.
Step 3  graph       - build an entity graph with NetworkX. Nodes are attacker-side entities: an untrusted IP address,
                      an AWS access key used from outside, a credential file read in an untrusted session. An edge means
                      "these two appeared in the same event" or "the credential file holds this key" (credential_inventory).
Step 4  incidents   - every connected component that contains at least one flagged ACTIVITY event is an incident; all
                      events touching its entities belong to it. Posture findings (account configuration) never start an
                      incident on their own; they join one only through an entity of that incident (e.g. the abused key).

Only events that touch an untrusted entity (external IP, IP that brute-forced, admin logon from an unexpected source when
a policy is configured, key used from outside, credential read in an untrusted session) can join an incident, so normal
activity is not pulled in.
"""
import re
from collections import defaultdict

import networkx as nx

import config

# flag -> (ATT&CK technique, description, severity)   severity: high | medium
FLAGS = {
    # ---- authentication (Windows, Linux, AWS console)
    "brute_force": ("T1110", "Brute Force", "medium"),
    "brute_force_success": ("T1078", "Valid Accounts (login after brute force)", "high"),
    # ---- Windows
    "privileged_session": ("T1078", "Valid Accounts (privileged logon from untrusted IP)", "medium"),
    "privileged_logon_unexpected_source": ("T1078", "Valid Accounts (admin logon from a source outside the allowlist)", "high"),
    "account_created": ("T1136.001", "Create Account: Local Account", "high"),
    "privilege_group_add": ("T1098", "Account Manipulation (added to admin group)", "high"),
    "log_cleared": ("T1070.001", "Indicator Removal: Clear Windows Event Logs", "high"),
    "encoded_powershell": ("T1059.001", "PowerShell (encoded command)", "medium"),
    "suspicious_powershell": ("T1059.001", "PowerShell (download cradle / in-memory attack code)", "high"),
    "lolbin_abuse": ("T1218", "System Binary Proxy Execution (LOLBin)", "medium"),
    "lolbin_network": ("T1218", "System Binary Proxy Execution (LOLBin network connection)", "high"),
    "credential_dump_tool": ("T1003.001", "OS Credential Dumping: LSASS (tool or technique in command)", "high"),
    "lsass_access": ("T1003.001", "OS Credential Dumping: LSASS memory access", "high"),
    "service_installed": ("T1543.003", "Create or Modify System Process: Windows Service", "medium"),
    "scheduled_task_created": ("T1053.005", "Scheduled Task/Job: Scheduled Task", "medium"),
    "admin_share_access": ("T1021.002", "Remote Services: SMB/Windows Admin Shares", "medium"),
    "remote_service_control": ("T1569.002", "System Services: Service Execution (remote, over SMB pipe)", "high"),
    "registry_persistence": ("T1547.001", "Boot or Logon Autostart Execution: Registry Run Keys / Winlogon", "high"),
    # ---- Linux
    "sudo_untrusted": ("T1548.003", "Sudo and Sudo Caching (untrusted session)", "medium"),
    "credential_access": ("T1552.001", "Unsecured Credentials: Credentials In Files", "high"),
    # ---- AWS CloudTrail activity
    "external_api_use": ("T1078.004", "Valid Accounts: Cloud Accounts (use from outside network)", "medium"),
    "access_key_created": ("T1098.001", "Account Manipulation: Additional Cloud Credentials", "high"),
    "iam_change_external": ("T1098", "Account Manipulation (IAM change from outside)", "high"),
    "logging_disabled": ("T1562.008", "Impair Defenses: Disable or Modify Cloud Logs", "high"),
    "monitoring_disabled": ("T1562.001", "Impair Defenses: Disable or Modify Tools (GuardDuty, Config, flow logs)", "high"),
    "bulk_download": ("T1530", "Data from Cloud Storage (bulk download)", "high"),
    "secrets_bulk_retrieval": ("T1555.006", "Credentials from Password Stores: Cloud Secrets Management Stores", "high"),
    "snapshot_shared": ("T1537", "Transfer Data to Cloud Account (snapshot/image sharing)", "high"),
    "user_data_modified": ("T1059.009", "Cloud Administration Command (EC2 user data modified)", "high"),
    "bucket_policy_changed_external": ("T1530", "S3 bucket policy/ACL/public-access block changed from outside", "high"),
    "root_account_used": ("T1078.004", "Valid Accounts: Cloud Accounts (root user activity)", "medium"),
    # ---- live host (hostcollect.py)
    "process_from_temp": ("T1204.002", "Process running from a temporary directory", "high"),
    "deleted_executable_running": ("T1070.004", "Indicator Removal: executable deleted while running", "high"),
    "fileless_memfd_process": ("T1620", "Reflective Code Loading (process executing from memfd)", "high"),
    "shell_network_connection": ("T1059.004", "Command shell with a network connection", "high"),
    "reverse_shell_pattern": ("T1059.004", "Reverse shell command line", "high"),
    "cron_persistence": ("T1053.003", "Scheduled Task/Job: Cron (suspicious command)", "high"),
    "systemd_persistence": ("T1543.002", "Create or Modify System Process: Systemd Service (suspicious command)", "high"),
    "rc_local_persistence": ("T1037.004", "Boot or Logon Initialization Scripts: RC Scripts (suspicious command)", "high"),
    "ld_preload_set": ("T1574.006", "Hijack Execution Flow: Dynamic Linker Hijacking (/etc/ld.so.preload)", "high"),
    "authorized_keys_recent_change": ("T1098.004", "Account Manipulation: SSH Authorized Keys (recently changed)", "medium"),
    "uid0_duplicate": ("T1136.001", "Create Account: second account with UID 0", "high"),
    "executable_in_temp": ("T1105", "Ingress Tool Transfer (recent executable in a temporary directory)", "medium"),
    "timestomped_file": ("T1070.006", "Indicator Removal: Timestomp (modification time set back)", "high"),
    "startup_persistence": ("T1547.001", "Boot or Logon Autostart Execution: Startup Folder (executable/script)", "medium"),
    "autostart_suspicious_command": ("T1053.005", "Scheduled task / service / LaunchAgent with a suspicious command", "high"),
    # ---- AWS account state (cloudstate.py): posture findings
    "trail_logging_off": ("T1562.008", "No CloudTrail trail, or trail logging stopped", "high"),
    "trail_no_log_validation": ("T1565.001", "CloudTrail log-file validation off", "medium"),
    "trail_single_region": ("T1535", "CloudTrail trail covers one region only", "medium"),
    "root_mfa_missing": ("T1078.004", "Root account without MFA", "high"),
    "admin_without_mfa": ("T1078.004", "IAM administrator without MFA", "high"),
    "stale_access_key": ("T1078.004", "Active access key unused (or never used) for a long time", "medium"),
    "role_trusts_anyone": ("T1098", "IAM role can be assumed by anyone", "high"),
    "role_trusts_external_account": ("T1199", "IAM role trusts another AWS account", "medium"),
    "public_bucket": ("T1530", "S3 bucket is public (bucket policy)", "high"),
    "bucket_public_access_not_blocked": ("T1530", "S3 bucket without a complete public access block", "medium"),
    "sg_world_open_admin_port": ("T1133", "Security group opens SSH/RDP/all ports to the Internet", "high"),
}

POSTURE = {"trail_logging_off", "trail_no_log_validation", "trail_single_region", "root_mfa_missing", "admin_without_mfa",
           "stale_access_key", "role_trusts_anyone", "role_trusts_external_account", "public_bucket",
           "bucket_public_access_not_blocked", "sg_world_open_admin_port"}

RULE_FAMILIES = {
    "Authentication (all platforms)": ("brute_force", "brute_force_success"),
    "Windows": ("privileged_session", "privileged_logon_unexpected_source", "account_created", "privilege_group_add", "log_cleared",
                "encoded_powershell", "suspicious_powershell", "lolbin_abuse", "lolbin_network", "credential_dump_tool", "lsass_access",
                "service_installed", "scheduled_task_created", "admin_share_access", "remote_service_control", "registry_persistence"),
    "Linux": ("sudo_untrusted", "credential_access"),
    "AWS CloudTrail": ("external_api_use", "access_key_created", "iam_change_external", "logging_disabled", "monitoring_disabled",
                       "bulk_download", "secrets_bulk_retrieval", "snapshot_shared", "user_data_modified", "bucket_policy_changed_external",
                       "root_account_used"),
    "Live host": ("process_from_temp", "deleted_executable_running", "fileless_memfd_process", "shell_network_connection",
                  "reverse_shell_pattern", "cron_persistence", "systemd_persistence", "rc_local_persistence", "ld_preload_set",
                  "authorized_keys_recent_change", "uid0_duplicate", "executable_in_temp", "timestomped_file", "startup_persistence",
                  "autostart_suspicious_command", "lolbin_abuse", "registry_persistence"),
    "AWS account state (posture)": tuple(sorted(POSTURE)),
}

# ------------------------------------------------------------------ patterns
CRED_RE = re.compile(r"\.aws/credentials|id_rsa|id_ed25519|/etc/shadow|\.ssh/")
CRED_PATH_RE = re.compile(r"(\S*(?:\.aws/credentials|id_rsa|id_ed25519|/etc/shadow)\S*)")

_I = re.I
ENC_PS_RE = re.compile(r"(?:powershell|pwsh)\S*\s.*?[\s\"'][-/]e(?:n(?:c(?:o(?:d(?:e(?:d(?:c(?:o(?:m(?:m(?:a(?:n(?:d)?)?)?)?)?)?)?)?)?)?)?)?|c)?\s+[A-Za-z0-9+/=]{8,}", _I)
SUSP_PS_RE = re.compile(r"Invoke-Mimikatz|Invoke-Shellcode|Invoke-ReflectivePEInjection|DownloadString|DownloadFile|DownloadData|Net\.WebClient|"
                        r"Start-BitsTransfer|IEX\s*\(|Invoke-Expression\s*\(|FromBase64String|VirtualAlloc|GetDelegateForFunctionPointer|"
                        r"Reflection\.Assembly\]::Load|AmsiUtils|amsiInitFailed|MiniDumpWriteDump|Out-Minidump|-w(?:indowstyle)?\s+hidden.*-nop|"
                        r"-nop.*-w(?:indowstyle)?\s+hidden|System\.Net\.Sockets\.TCPClient", _I)
CRED_TOOL_RE = re.compile(r"mimikatz|sekurlsa|lsadump::|kerberos::|privilege::debug|pypykatz|nanodump|Out-Minidump|MiniDumpWriteDump|"
                          r"comsvcs(?:\.dll)?[\s,\"]+#?(?:24|MiniDump)|\bMiniDump\b|procdump(?:64)?(?:\.exe)?\s.*(?:-ma\s|lsass)|lsass\.dmp|"
                          r"sqldumper(?:\.exe)?\s.*0x0110|rdrleakdiag.*fullmemdmp|createdump(?:\.exe)?\s.*-f", _I)
LOLBIN = {  # binary -> suspicious argument pattern ('' = any use is suspicious)
    "regsvr32.exe": r"/i:|scrobj|https?://|\.sct\b",
    "rundll32.exe": r"javascript:|vbscript:|url\.dll|ieframe\.dll|shdocvw|zipfldr|advpack|pcwutl|FileProtocolHandler|OpenURL|RouteTheCall|"
                    r"RegisterOCX|LaunchINFSection|LaunchApplication|setupapi\.dll|syssetup\.dll|ShellExec_RunDLL|comsvcs|mshtml|https?://|\\\\[^\\]+\\",
    "mshta.exe": r"https?://|javascript:|vbscript:|\.hta\b",
    "pcalua.exe": r"-a\s",
    "certutil.exe": r"urlcache|-decode|-decodehex|verifyctl|https?://",
    "bitsadmin.exe": r"/transfer|/addfile|/SetNotifyCmdLine|https?://",
    "msiexec.exe": r"https?://",
    "cmstp.exe": r"\.inf\b|\.ini\b|/au\b",
    "installutil.exe": r"/u\b|/logfile",
    "regasm.exe": r"/u\b",
    "regsvcs.exe": r"\.dll\b",
    "wmic.exe": r"process\s+call\s+create|/format:|https?://",
    "forfiles.exe": r"/c\s",
    "hh.exe": r"https?://|\.chm\b",
    "odbcconf.exe": r"/a\s|regsvr|\.rsp\b",
    "xwizard.exe": r"RunWizard",
    "ieexec.exe": r"https?://",
    "infdefaultinstall.exe": r"\.inf\b",
    "mavinject.exe": r"/injectrunning",
    "desktopimgdownldr.exe": r"/lockscreenurl",
    "esentutl.exe": r"/vss|/y\s.*\\\\",
    "syncappvpublishingserver.vbs": r"",
}
LOLBIN_RE = {k: re.compile(v, _I) for k, v in LOLBIN.items()}
LOLBIN_NET = {"mshta.exe", "rundll32.exe", "regsvr32.exe", "certutil.exe", "bitsadmin.exe", "msiexec.exe", "cmstp.exe", "installutil.exe",
              "regasm.exe", "regsvcs.exe", "wmic.exe", "hh.exe", "odbcconf.exe", "msbuild.exe", "cscript.exe", "wscript.exe",
              "pcalua.exe", "forfiles.exe", "ieexec.exe", "esentutl.exe"}
LSASS_BENIGN = re.compile(r"\\(?:csrss|wininit|services|svchost|lsm|smss|winlogon|wmiprvse|lsaiso|MsMpEng|MsSense|SenseIR|"
                          r"vmtoolsd|VBoxService|taskhostw|SgrmBroker)\.exe$", _I)
REG_PERSIST_RE = re.compile(r"\\CurrentVersion\\Run(?:Once|OnceEx|Services|ServicesOnce)?\\|\\CurrentVersion\\Run(?:Once)?$|"
                            r"\\Winlogon\\(?:Shell|Userinit|Notify|Taskman)|\\Image File Execution Options\\.*\\(?:Debugger|GlobalFlag)|"
                            r"\\SilentProcessExit\\.*\\MonitorProcess|AppInit_DLLs|\\Command Processor\\AutoRun|"
                            r"\\Environment\\UserInitMprLogonScript|\\Explorer\\(?:User )?Shell Folders\\(?:Common )?Startup", _I)
SUSP_CMD_RE = re.compile(r"(?:^|[\s\"'=:])(?:/tmp/|/var/tmp/|/dev/shm/)|/\.[^/\s]+/|(?:curl|wget)\b[^|;]*\|\s*(?:ba|z|da|k)?sh\b|"
                         r"base64\s+(?:-d|--decode)|/dev/tcp/|/dev/udp/|\bnc(?:at)?\b.*\s-[ec]\s|\bsocat\b.*exec|\bmkfifo\b|"
                         r"python[23]?\s+-c\s|perl\s+-e\s|"
                         r"\\AppData\\(?:Local\\Temp|Roaming)\\|\\Users\\Public\\|\\Windows\\Temp\\|\\Temp\\|%TEMP%|%APPDATA%|"
                         r"powershell\S*\s.*(?:-e(?:nc)?\s|-w\S*\s+hidden|iex|downloadstring|frombase64)|"
                         r"mshta\S*\s+(?:https?:|javascript:|vbscript:)|rundll32\S*\s+javascript:|regsvr32\S*\s+/i:|cmd(?:\.exe)?\s+/c\s+.*(?:http|\\\\)", _I)
REVSHELL_RE = re.compile(r"/dev/tcp/|/dev/udp/|\bnc(?:at)?\b[^|;]*\s-[ec]\s|\bsocat\b.*\bexec:|\b(?:ba)?sh\s+-i\s*[<>]&|mkfifo\b.*\bnc\b|"
                         r"python[23]?\s+-c\s.*socket.*(?:subprocess|pty|os\.dup2)|perl\s+-e\s.*socket|"
                         r"System\.Net\.Sockets\.TCPClient", _I)
SHELLS = {"bash", "sh", "dash", "zsh", "ksh", "csh", "tcsh", "fish", "nc", "ncat", "netcat", "socat",
          "cmd.exe", "powershell.exe", "pwsh.exe", "pwsh"}
TEMP_EXE_RE = re.compile(r"^(?:/tmp/|/var/tmp/|/dev/shm/)|\\(?:Temp|tmp)\\|\\Users\\Public\\|\\Windows\\Temp\\", _I)
EXEC_MAGIC = {"ELF", "PE", "Mach-O"}
SCRIPT_EXT_RE = re.compile(r"\.(?:exe|dll|scr|bat|cmd|ps1|vbs|vbe|js|jse|wsf|hta|com|pif)$", _I)
ADMIN_SHARE_RE = re.compile(r"\\\\[^\\]*\\(?:ADMIN\$|[A-Z]\$)$", _I)
REMOTE_PIPES = {"svcctl", "atsvc", "\\svcctl", "\\atsvc"}

AWS_LOGGING = {"StopLogging", "DeleteTrail", "UpdateTrail"}
AWS_MONITORING = {"DeleteDetector", "UpdateDetector", "DisassociateFromMasterAccount", "DeleteFlowLogs", "StopConfigurationRecorder",
                  "DeleteConfigurationRecorder", "DeleteDeliveryChannel", "DisableSecurityHub", "DeleteRuleGroup"}
AWS_SHARE = {"ModifySnapshotAttribute", "ModifyImageAttribute", "ModifyDBSnapshotAttribute", "ModifyDBClusterSnapshotAttribute"}
AWS_BUCKET_EXPOSE = {"PutBucketPolicy", "PutBucketAcl", "DeleteBucketPublicAccessBlock", "DeleteAccountPublicAccessBlock", "PutBucketWebsite"}


def _base(path):
    return re.split(r"[\\/]", path or "")[-1].lower()


def _lolbin(image, cmd):
    b = _base(image)
    if not b and cmd:
        b = _base(cmd.strip().split(" ")[0].strip('"'))
    pat = LOLBIN_RE.get(b)
    if pat is None:
        return False
    return pat.pattern == "" or bool(pat.search(cmd or ""))


def _burst(group, min_n, window_s):
    """Events inside a time window that holds >= min_n events (weighted by syslog 'message repeated N times')."""
    w = [(e.get("extra") or {}).get("repeat", 1) if isinstance(e.get("extra"), dict) else 1 for e in group]
    hit, l, total = set(), 0, 0
    for r in range(len(group)):
        total += w[r]
        while group[r]["epoch"] - group[l]["epoch"] > window_s:
            total -= w[l]
            l += 1
        if total >= min_n:
            hit.update(range(l, r + 1))
    return [group[i] for i in sorted(hit)]


def _flag(e, name):
    if name not in e["flags"]:
        e["flags"].append(name)


def _x(e):
    return e.get("extra") if isinstance(e.get("extra"), dict) else {}


def _accounts(principal):
    return re.findall(r"(?<!\d)(\d{12})(?!\d)", principal or "")


def detect(events, cfg):
    """Flags events in place. Returns the set of untrusted IP addresses found by behaviour (brute force, policy)."""
    cfg = cfg or {}
    ext = lambda ip: bool(ip) and not config.is_internal(ip, cfg)
    allow = cfg.get("privileged_source_allowlist") or []
    events.sort(key=lambda e: (e["epoch"], e.get("source") or "", e.get("line_ref") or 0))
    for e in events:
        e["flags"] = []
        e["session_ip"] = None

    # --- brute force: failures per source/host/ip (weighted by repeats), then success from that ip
    fails = defaultdict(list)
    for e in events:
        if e["event_type"] == "auth_failure" and e["src_ip"]:
            fails[(e["source"], e["host"], e["src_ip"])].append(e)
    bf_ips, bf_last = set(), {}
    for key, grp in fails.items():
        hits = _burst(grp, config.BRUTE_FORCE_MIN_FAILURES, config.BRUTE_FORCE_WINDOW_MIN * 60)
        if hits:
            bf_ips.add(key[2])
            bf_last[key] = max(h["epoch"] for h in hits)
            for h in hits:
                _flag(h, "brute_force")
    for e in events:
        if e["event_type"] == "auth_success" and e["src_ip"]:
            last = bf_last.get((e["source"], e["host"], e["src_ip"]))
            if last is not None and 0 <= e["epoch"] - last <= config.BRUTE_FORCE_SUCCESS_WINDOW_MIN * 60:
                _flag(e, "brute_force_success")

    # --- admin-source policy (only when an allowlist is configured): privileged session from elsewhere
    policy_ips = set()
    if allow:
        sess = {}
        for e in events:
            if e["source"] != "windows":
                continue
            if e["event_type"] == "auth_success" and e["session_id"]:
                sess[(e["host"], e["session_id"])] = e["src_ip"]
            elif e["event_type"] == "priv_assign" and e["session_id"]:
                ip = sess.get((e["host"], e["session_id"]))
                if ip and not config.in_ranges(ip, allow):
                    policy_ips.add(ip)
                    _flag(e, "privileged_logon_unexpected_source")

    untrusted = lambda ip: bool(ip) and (ext(ip) or ip in bf_ips or ip in policy_ips)

    # --- live host context: collection time per host, owning process of untrusted sockets
    coll_t, pid_ips = {}, defaultdict(set)
    for e in events:
        if e["source"] == "host":
            if e["event_type"] == "collection":
                coll_t[e["host"]] = e["epoch"]
            else:
                coll_t.setdefault(e["host"], None)
    for h in coll_t:
        if coll_t[h] is None:
            coll_t[h] = max(x["epoch"] for x in events if x["source"] == "host" and x["host"] == h)
    for e in events:
        if e["source"] == "host" and e["event_type"] == "connection_snapshot" and untrusted(e["src_ip"]):
            pid_ips[(e["host"], _x(e).get("pid"))].add(e["src_ip"])

    # --- session attribution + per-event rules (events are time-ordered)
    win_sess, lin_sess = {}, {}
    for e in events:
        s, t, x = e["source"], e["event_type"], _x(e)
        cmd = e["detail"] or ""
        if s == "windows":
            sid = e["session_id"]
            if t == "auth_success" and sid:
                win_sess[(e["host"], sid)] = e["src_ip"] if untrusted(e["src_ip"]) else None
            elif sid:
                e["session_ip"] = win_sess.get((e["host"], sid))
            sip = e["session_ip"]
            if t == "priv_assign" and sip:
                _flag(e, "privileged_session")
            elif t == "account_created" and sip:
                _flag(e, "account_created")
            elif t == "group_add" and sip:
                _flag(e, "privilege_group_add")
            elif t == "log_cleared":
                _flag(e, "log_cleared")
            elif t == "process_create":
                full = f"{e['target'] or ''} {cmd}"
                if ENC_PS_RE.search(full):
                    _flag(e, "encoded_powershell")
                if re.search(r"powershell|pwsh", full, _I) and SUSP_PS_RE.search(cmd):
                    _flag(e, "suspicious_powershell")
                if _lolbin(e["target"], cmd):
                    _flag(e, "lolbin_abuse")
                if CRED_TOOL_RE.search(full):
                    _flag(e, "credential_dump_tool")
            elif t == "script_block":
                if SUSP_PS_RE.search(cmd):
                    _flag(e, "suspicious_powershell")
                if CRED_TOOL_RE.search(cmd):
                    _flag(e, "credential_dump_tool")
            elif t == "process_access":
                src = x.get("source") or e["detail"] or ""
                if _base(e["target"]) == "lsass.exe" and not LSASS_BENIGN.search(src):
                    try:
                        mask = int(str(x.get("access") or "0"), 16)
                    except ValueError:
                        mask = 0x10
                    system_dir = re.search(r"^[a-z]:\\(?:windows|program files( \(x86\))?)\\", src, _I)
                    if mask & 0x10 or mask in (0x1fffff, 0x1f0fff) or not system_dir:   # PROCESS_VM_READ / full access, or a tool outside system folders
                        _flag(e, "lsass_access")
                if CRED_TOOL_RE.search(src):
                    _flag(e, "credential_dump_tool")
            elif t == "network_connect":
                if _base(cmd) in LOLBIN_NET and ext(x.get("dst_ip")):
                    _flag(e, "lolbin_network")
            elif t == "registry_set":
                if REG_PERSIST_RE.search(e["target"] or ""):
                    _flag(e, "registry_persistence")
            elif t == "service_install":
                img = cmd
                benign = re.search(r"\\Program Files( \(x86\))?\\|\\System32\\drivers\\|^\"?\\?SystemRoot\\System32\\drivers\\|"
                                   r"\\Windows\\System32\\svchost\.exe\s+-k\s|\\Windows Defender\\|\\Microsoft\\Windows Defender", img, _I)
                if not benign or SUSP_CMD_RE.search(img):
                    _flag(e, "service_installed")
            elif t == "scheduled_task":
                _flag(e, "scheduled_task_created")
            elif t == "share_access":
                share, name = (x.get("share") or ""), (x.get("name") or "").strip().lower()
                if ADMIN_SHARE_RE.search(share):
                    _flag(e, "admin_share_access")
                if share.upper().endswith("\\IPC$") and name in REMOTE_PIPES:
                    _flag(e, "remote_service_control")
        elif s == "linux":
            if t == "auth_success":
                lin_sess[(e["host"], e["user"])] = (e["src_ip"] if untrusted(e["src_ip"]) else None, e["epoch"])
            elif t == "command_exec":
                ip, t0 = lin_sess.get((e["host"], e["user"]), (None, 0))
                if ip and e["epoch"] - t0 <= config.SESSION_MAX_HOURS * 3600:
                    e["session_ip"] = ip
            if t == "command_exec" and e["session_ip"]:
                _flag(e, "sudo_untrusted")
                if CRED_RE.search(e["target"] or ""):
                    _flag(e, "credential_access")
        elif s == "aws" and t in ("trail_state", "account_state", "iam_user_state", "access_key_state", "role_state", "bucket_state", "sg_state"):
            _posture(e, x, cfg)
        elif s == "aws":
            out = ext(e["src_ip"])
            name = e["raw"] or ""
            if out and t != "auth_failure":
                _flag(e, "external_api_use")
                if t == "access_key_created":
                    _flag(e, "access_key_created")
                if t == "iam_change":
                    _flag(e, "iam_change_external")
                if name in AWS_BUCKET_EXPOSE:
                    _flag(e, "bucket_policy_changed_external")
            if t == "logging_stopped" or name in AWS_LOGGING:
                _flag(e, "logging_disabled")
            if name in AWS_MONITORING:
                _flag(e, "monitoring_disabled")
            if name in AWS_SHARE and e["outcome"] == "success":
                _flag(e, "snapshot_shared")
            if name == "ModifyInstanceAttribute" and x.get("user_data"):
                _flag(e, "user_data_modified")
            if (e["user"] or "").endswith(":root") or (e["user"] or "") == "root":
                _flag(e, "root_account_used")
        elif s == "host":
            _host(e, x, untrusted, coll_t.get(e["host"]))

    # --- bulk download from outside, bulk secret retrieval
    dl, sec = defaultdict(list), defaultdict(list)
    for e in events:
        if e["source"] != "aws":
            continue
        if e["event_type"] == "data_download" and ext(e["src_ip"]):
            dl[(e["key_id"], e["src_ip"])].append(e)
        if e["raw"] == "GetSecretValue":
            sec[(e["key_id"] or e["user"], e["src_ip"])].append(e)
    for grp in dl.values():
        for h in _burst(grp, config.BULK_DOWNLOAD_MIN, config.BULK_DOWNLOAD_WINDOW_MIN * 60):
            _flag(h, "bulk_download")
    for grp in sec.values():
        for h in _burst(grp, config.BULK_SECRETS_MIN, config.BULK_SECRETS_WINDOW_MIN * 60):
            _flag(h, "secrets_bulk_retrieval")

    for e in events:
        rank = [FLAGS[f][2] for f in e["flags"]]
        e["severity"] = "high" if "high" in rank else ("medium" if rank else "info")
        e["techniques"] = sorted({FLAGS[f][0] for f in e["flags"]})
    return bf_ips | policy_ips


def _host(e, x, untrusted, collected_epoch):
    t = e["event_type"]
    if t == "process_snapshot":
        exe, cmd = e["target"] or "", e["detail"] or ""
        name = (x.get("name") or _base(exe)).lower()
        if exe.startswith("/memfd:"):
            memname = exe[len("/memfd:"):].split(" ")[0]
            if memname not in config.HOST_MEMFD_ALLOW:
                _flag(e, "fileless_memfd_process")
        elif x.get("exe_deleted"):
            _flag(e, "deleted_executable_running")
        if TEMP_EXE_RE.search(exe):
            _flag(e, "process_from_temp")
        if REVSHELL_RE.search(cmd):
            _flag(e, "reverse_shell_pattern")
        if _lolbin(exe or name, cmd):
            _flag(e, "lolbin_abuse")
        if ENC_PS_RE.search(cmd) or (re.search(r"powershell|pwsh", name, _I) and SUSP_PS_RE.search(cmd)):
            _flag(e, "suspicious_powershell")
        if CRED_TOOL_RE.search(cmd):
            _flag(e, "credential_dump_tool")
    elif t == "connection_snapshot":
        proc = (x.get("proc") or "").lower()
        if proc in SHELLS and e["src_ip"] and not e["src_ip"].startswith("127."):
            _flag(e, "shell_network_connection")
    elif t == "account_snapshot":
        if x.get("uid") == 0 and (e["user"] or "") != "root":
            _flag(e, "uid0_duplicate")
    elif t == "persistence_entry":
        kind, val = x.get("kind"), e["detail"] or ""
        if kind in ("cron", "cron_script"):
            if SUSP_CMD_RE.search(val) or REVSHELL_RE.search(val):
                _flag(e, "cron_persistence")
        elif kind == "systemd":
            if SUSP_CMD_RE.search(val) or REVSHELL_RE.search(val):
                _flag(e, "systemd_persistence")
        elif kind == "rc_local":
            if SUSP_CMD_RE.search(val) or REVSHELL_RE.search(val):
                _flag(e, "rc_local_persistence")
        elif kind == "ld_preload":
            _flag(e, "ld_preload_set")
        elif kind == "authorized_keys":
            if collected_epoch is not None and collected_epoch - e["epoch"] <= config.HOST_RECENT_DAYS * 86400:
                _flag(e, "authorized_keys_recent_change")
        elif kind == "run_key":
            if SUSP_CMD_RE.search(val) or _lolbin(val.strip('"').split('" ')[0].split(" ")[0], val) or re.search(r"\\ProgramData\\[^\\]+\.(?:exe|dll|bat|ps1|vbs)", val, _I):
                _flag(e, "registry_persistence")
        elif kind == "startup_folder":
            if SCRIPT_EXT_RE.search(e["target"] or ""):
                _flag(e, "startup_persistence")
        elif kind in ("schtask", "service", "launchd"):
            if SUSP_CMD_RE.search(val) or REVSHELL_RE.search(val):
                _flag(e, "autostart_suspicious_command")
    elif t == "file_snapshot":
        path, magic = e["target"] or "", x.get("magic")
        if magic in EXEC_MAGIC and TEMP_EXE_RE.search(path):
            _flag(e, "executable_in_temp")
        if x.get("timestomped") and (magic in EXEC_MAGIC or magic == "script"):
            _flag(e, "timestomped_file")


def _posture(e, x, cfg):
    t = e["event_type"]
    if t == "trail_state":
        if x.get("none") or x.get("is_logging") is False:
            _flag(e, "trail_logging_off")
        if x.get("validation") is False:
            _flag(e, "trail_no_log_validation")
        if x.get("multi_region") is False:
            _flag(e, "trail_single_region")
    elif t == "account_state":
        if x.get("root_mfa") is False:
            _flag(e, "root_mfa_missing")
    elif t == "iam_user_state":
        if x.get("is_admin") and x.get("mfa") is False:      # unknown MFA is not reported as missing
            _flag(e, "admin_without_mfa")
    elif t == "access_key_state":
        if (x.get("status") or "").lower() == "active":
            last, age = x.get("last_used_days"), x.get("age_days")
            ref = last if last is not None else age
            if ref is not None and ref > config.CLOUD_KEY_STALE_DAYS:
                _flag(e, "stale_access_key")
    elif t == "role_state":
        own = set(_accounts(e["host"]))
        trusted = set(cfg.get("cloud_trusted_accounts") or []) | own
        for tr in x.get("trust") or []:
            if tr.get("conditional"):
                continue
            p = tr.get("principal") or ""
            if tr.get("type") in ("*", "AWS") and p in ("*", "AWS:*") or p == "*":
                _flag(e, "role_trusts_anyone")
            elif tr.get("type") == "AWS" and any(a not in trusted for a in _accounts(p)):
                _flag(e, "role_trusts_external_account")
    elif t == "bucket_state":
        if x.get("checked"):
            if x.get("public"):
                _flag(e, "public_bucket")
            elif not x.get("block_all"):
                _flag(e, "bucket_public_access_not_blocked")
    elif t == "sg_state":
        for proto, lo, hi in x.get("world_open") or []:
            lo = 0 if lo is None else lo
            hi = 65535 if hi is None else hi
            if proto in ("all", "-1") or (str(proto) in ("tcp", "6") and any(lo <= p <= hi for p in (22, 3389))):
                _flag(e, "sg_world_open_admin_port")
                break


# ------------------------------------------------------------------ graph
def _entities(e, cfg, untrusted_ips, inventory, pid_ips):
    """Returns (nodes, edges) for one event. nodes = [(id, kind)], edges = [(a, b, reason)]."""
    ext = lambda ip: bool(ip) and not config.is_internal(ip, cfg)
    untrusted = lambda ip: bool(ip) and (ext(ip) or ip in untrusted_ips)
    nodes, edges = [], []
    ips = []
    if e["session_ip"]:
        ips.append(e["session_ip"])
    elif untrusted(e["src_ip"]):
        ips.append(e["src_ip"])
    x = _x(e)
    if e["source"] == "windows" and e["event_type"] == "network_connect" and ext(x.get("dst_ip")) and x.get("dst_ip") not in ips:
        ips.append(x.get("dst_ip"))
    if e["source"] == "host" and e["event_type"] == "process_snapshot":
        for ip in sorted(pid_ips.get((e["host"], x.get("pid")), ())):
            if ip not in ips:
                ips.append(ip)
    for ip in ips:
        nodes.append((f"ip:{ip}", "ip"))
    if e["source"] == "aws" and e["event_type"] == "access_key_state" and e["key_id"]:
        nodes.append((f"key:{e['key_id']}", "key"))
    elif e["source"] == "aws" and ext(e["src_ip"]):
        if e["key_id"]:
            nodes.append((f"key:{e['key_id']}", "key"))
        if e["new_key_id"] and e["new_key_id"] != e["key_id"]:
            nodes.append((f"key:{e['new_key_id']}", "key"))
    if e["source"] == "linux" and e["event_type"] == "command_exec" and "credential_access" in e["flags"]:
        m = CRED_PATH_RE.search(e["target"] or "")
        path = m.group(1) if m else (e["target"] or "")
        nodes.append((f"cred:{e['host']}:{path}", "cred"))
    ids = [n[0] for n in nodes]
    for i in range(1, len(ids)):
        a, b = ids[0], ids[i]
        if b.startswith("cred:"):
            reason = "credential file read in session"
        elif b.startswith("key:") and e["new_key_id"] and b == f"key:{e['new_key_id']}" and e["key_id"]:
            reason, a = "key created by key", f"key:{e['key_id']}"
        elif b.startswith("key:"):
            reason = "same API call"
        elif e["source"] == "host":
            reason = "process owns socket"
        else:
            reason = "same event"
        edges.append((a, b, reason))
    for nid, kind in list(nodes):
        if kind == "cred":
            k = inventory.get(nid[5:])
            if k:
                nodes.append((f"key:{k}", "key"))
                edges.append((nid, f"key:{k}", "credential inventory (file holds key)"))
    return nodes, edges


def build_incidents(events, cfg, untrusted_ips):
    inventory = cfg.get("credential_inventory", {}) or {}
    ext = lambda ip: bool(ip) and not config.is_internal(ip, cfg)
    pid_ips = defaultdict(set)
    for e in events:
        if e["source"] == "host" and e["event_type"] == "connection_snapshot" and e["src_ip"] and (ext(e["src_ip"]) or e["src_ip"] in untrusted_ips):
            pid_ips[(e["host"], _x(e).get("pid"))].add(e["src_ip"])
    G = nx.Graph()
    ev_nodes = {}
    for e in events:
        nodes, edges = _entities(e, cfg, untrusted_ips, inventory, pid_ips)
        ev_nodes[e["event_id"]] = [n[0] for n in nodes]
        for nid, kind in nodes:
            if nid not in G:
                G.add_node(nid, kind=kind, sources=set(), events=0)
            G.nodes[nid]["sources"].add(e["source"])
            G.nodes[nid]["events"] += 1
        for a, b, reason in edges:
            if G.has_edge(a, b):
                G[a][b]["events"].append(e["event_id"])
            else:
                G.add_edge(a, b, reason=reason, events=[e["event_id"]])
    comps = list(nx.connected_components(G))
    comp_of = {n: ci for ci, comp in enumerate(comps) for n in comp}
    members = defaultdict(list)
    for e in events:
        ns = ev_nodes[e["event_id"]]
        if ns:
            members[comp_of[ns[0]]].append(e)
    incidents = []
    for ci, evs in members.items():
        seeds = [e for e in evs if any(f not in POSTURE for f in e["flags"])]
        if not seeds:
            continue                     # no activity alert: exposure or normal traffic only
        sub = G.subgraph(comps[ci])
        stages = defaultdict(list)
        for e in evs:
            for f in e["flags"]:
                stages[f].append(e)
        stage_rows = []
        for f, lst in stages.items():
            tid, name, sev = FLAGS[f]
            stage_rows.append(dict(flag=f, technique=tid, name=name, severity=sev, count=len(lst), first=lst[0]["time_utc"],
                                   last=lst[-1]["time_utc"], sources=sorted({x["source"] for x in lst}),
                                   hosts=sorted({x["host"] or "" for x in lst}), first_epoch=lst[0]["epoch"], posture=f in POSTURE))
        stage_rows.sort(key=lambda r: (r["posture"], r["first_epoch"]))
        links = [dict(a=a, b=b, reason=d["reason"], events=len(d["events"])) for a, b, d in sub.edges(data=True)]
        platforms = sorted({e["source"] for e in evs})
        high = any(r["severity"] == "high" for r in stage_rows)
        incidents.append(dict(
            start=evs[0]["time_utc"], end=evs[-1]["time_utc"], start_epoch=evs[0]["epoch"],
            platforms=platforms, cross_platform=len(platforms) > 1, event_ids=[e["event_id"] for e in evs],
            event_count=len(evs), alert_count=sum(1 for e in evs if e["flags"]), severity="High" if high else "Medium",
            entities=[dict(id=n, kind=sub.nodes[n]["kind"], platforms=sorted(sub.nodes[n]["sources"]), events=sub.nodes[n]["events"]) for n in sub.nodes],
            links=links, stages=stage_rows, techniques=sorted({r["technique"] for r in stage_rows}),
        ))
    incidents.sort(key=lambda i: i["start_epoch"])
    for n, inc in enumerate(incidents, 1):
        inc["id"] = f"INC-{n}"
    in_inc = {eid for inc in incidents for eid in inc["event_ids"]}
    unlinked = [e for e in events if e["flags"] and e["event_id"] not in in_inc]
    return incidents, G, unlinked


def correlate(events, cfg):
    cfg = cfg or {}
    untrusted_ips = detect(events, cfg)
    for e in events:
        e.pop("incident", None)
    incidents, G, unlinked = build_incidents(events, cfg, untrusted_ips)
    by_id = {e["event_id"]: e for e in events}
    for inc in incidents:
        for eid in inc["event_ids"]:
            by_id[eid]["incident"] = inc["id"]
    fired = defaultdict(int)
    for e in events:
        for f in e["flags"]:
            fired[f] += 1
    return dict(incidents=incidents, graph=G, unlinked_alerts=[e["event_id"] for e in unlinked],
                alert_events=sum(1 for e in events if e["flags"]), rules_fired=dict(fired), rule_count=len(FLAGS))
