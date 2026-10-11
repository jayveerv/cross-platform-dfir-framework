"""Simulated log generator (Windows Security XML, Linux auth.log, AWS CloudTrail JSON).

Produces realistic-format logs for four attack scenarios plus background activity,
together with a ground_truth.json that records which records belong to which attack.
The ground truth is written by the generator, independently of the framework's parsers
and detectors, so the evaluation is not circular.

Record references: windows_security.xml#<n> (n-th <Event>), auth.log#<n> (line number),
cloudtrail.json#<n> (n-th record in Records).
"""
import json
import os
import random
from datetime import datetime, timedelta, timezone
from xml.sax.saxutils import escape

BASE = datetime(2026, 9, 20, tzinfo=timezone.utc)
IST = timezone(timedelta(hours=5, minutes=30))

ATT_A, ATT_B, ATT_C, ATT_D = "203.0.113.45", "203.0.113.99", "203.0.113.150", "203.0.113.210"
SCANNER = "192.0.2.77"          # external scanner, only 3 failures (below threshold)
OFFICE_NAT = "198.51.100.10"    # declared internal range in case_config.json
K_APP = "AKIAQ3EXAMPLEAPP0001"  # key stored in /home/ubuntu/.aws/credentials
K_NEW = "AKIAQ3EXAMPLENEW0002"
K_OPS = "AKIAQ3EXAMPLEOPS0009"  # legitimate devops key
K_DPL = "AKIAQ3EXAMPLEDPL0005"  # key stored in /home/deploy/.aws/credentials
K_NEW3 = "AKIAQ3EXAMPLENEW0003"

CASE_CONFIG = {
    "case_id": "CASE",
    "investigator": "Jayveer Vasava",
    "linux_timezone_offset": "+05:30",
    "linux_log_year": 2026,
    "internal_ranges": ["198.51.100.0/24"],
    "credential_inventory": {
        "web01:/home/ubuntu/.aws/credentials": K_APP,
        "db01:/home/deploy/.aws/credentials": K_DPL,
    },
}


def T(h, m=0, s=0):
    return BASE + timedelta(hours=h, minutes=m, seconds=s)


class Gen:
    def __init__(self, seed):
        self.r = random.Random(seed)
        self.win, self.lin, self.aws = [], [], []
        self.logon = 0x3E000

    # ---------- low-level record builders ----------
    def W(self, t, eid, host, data, inc=None, rel=True, provider="Microsoft-Windows-Security-Auditing", userdata=None):
        self.win.append(dict(t=t, eid=eid, host=host, data=data, inc=inc, rel=rel, provider=provider, userdata=userdata))

    def L(self, t, host, proc, msg, inc=None, rel=True):
        self.lin.append(dict(t=t, host=host, proc=proc, msg=msg, inc=inc, rel=rel))

    def A(self, t, name, ip, ident, inc=None, params=None, resp=None, err=None, src="ec2.amazonaws.com", etype="AwsApiCall"):
        self.aws.append(dict(t=t, name=name, ip=ip, ident=ident, inc=inc, params=params, resp=resp, err=err, src=src, etype=etype))

    def lid(self):
        self.logon += self.r.randint(0x100, 0x900)
        return hex(self.logon)

    # ---------- attack building blocks ----------
    def attack_windows_rdp(self, inc, t0, ip, host="WS-FIN-01", n_fail=7):
        t = t0
        for _ in range(n_fail):
            self.W(t, 4625, host, dict(TargetUserName="administrator", TargetDomainName="CORP", LogonType="10",
                                       IpAddress=ip, WorkstationName="-", Status="0xC000006D"), inc)
            t += timedelta(seconds=15)
        lid = self.lid()
        self.W(t, 4624, host, dict(TargetUserName="administrator", TargetDomainName="CORP", TargetLogonId=lid,
                                   LogonType="10", IpAddress=ip, WorkstationName="-"), inc)
        self.W(t + timedelta(seconds=1), 4672, host, dict(SubjectUserName="administrator", SubjectDomainName="CORP",
                                                          SubjectLogonId=lid, PrivilegeList="SeDebugPrivilege"), inc)
        self.W(t + timedelta(minutes=2), 4688, host, dict(SubjectUserName="administrator", SubjectLogonId=lid,
                                                          NewProcessName=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                                                          CommandLine="powershell.exe -nop -w hidden -enc SQBFAFgA"), inc)
        self.W(t + timedelta(minutes=3), 4720, host, dict(TargetUserName="svc_backup", SubjectUserName="administrator",
                                                          SubjectLogonId=lid), inc)
        self.W(t + timedelta(minutes=3, seconds=20), 4732, host, dict(MemberName="CN=svc_backup", TargetUserName="Administrators",
                                                                      SubjectUserName="administrator", SubjectLogonId=lid), inc)
        self.W(t + timedelta(minutes=6), 1102, host, {}, inc, provider="Microsoft-Windows-Eventlog",
               userdata=dict(SubjectUserName="administrator", SubjectDomainName="CORP", SubjectLogonId=lid))

    def attack_linux(self, inc, t0, ip, host="web01", user="ubuntu", n_fail=6):
        t = t0
        for i in range(n_fail):
            if i < 3:
                msg = f"Failed password for invalid user admin from {ip} port {40000 + i} ssh2"
            else:
                msg = f"Failed password for {user} from {ip} port {40000 + i} ssh2"
            self.L(t, host, "sshd", msg, inc)
            t += timedelta(seconds=12)
        self.L(t, host, "sshd", f"Accepted password for {user} from {ip} port 40010 ssh2", inc)
        self.L(t + timedelta(minutes=1), host, "sudo",
               f"{user} : TTY=pts/0 ; PWD=/home/{user} ; USER=root ; COMMAND=/bin/cat /home/{user}/.aws/credentials", inc)
        self.L(t + timedelta(minutes=2), host, "sudo",
               f"{user} : TTY=pts/0 ; PWD=/home/{user} ; USER=root ; COMMAND=/usr/bin/id", inc)

    def attack_aws(self, inc, t0, ip, stolen, new, user="app-uploader", bucket="finance-reports"):
        t = t0
        ident = lambda k: dict(type="IAMUser", userName=user, accessKeyId=k)
        self.A(t, "GetCallerIdentity", ip, ident(stolen), inc, src="sts.amazonaws.com")
        self.A(t + timedelta(seconds=40), "ListBuckets", ip, ident(stolen), inc, src="s3.amazonaws.com")
        self.A(t + timedelta(minutes=2), "CreateAccessKey", ip, ident(stolen), inc, params=dict(userName=user),
               resp=dict(accessKey=dict(accessKeyId=new, userName=user, status="Active")), src="iam.amazonaws.com")
        self.A(t + timedelta(minutes=3), "StopLogging", ip, ident(new), inc, params=dict(name="management-trail"),
               src="cloudtrail.amazonaws.com")
        for i in range(12):
            self.A(t + timedelta(minutes=4, seconds=10 * i), "GetObject", ip, ident(new), inc,
                   params=dict(bucketName=bucket, key=f"2026/q3/statement_{i:02d}.xlsx"), src="s3.amazonaws.com")

    # ---------- background (normal) activity ----------
    def noise(self, n_win, n_lin, n_aws, scripted_legit=True):
        r = self.r
        wh = ["WS-FIN-01", "WS-HR-02", "WS-DEV-03", "SRV-FILE-01"]
        wu = ["alice", "bob", "carol", "dave", "erin"]
        for i in range(n_win):
            t = T(r.uniform(3, 18), r.randint(0, 59), r.randint(0, 59))
            h, u = r.choice(wh), r.choice(wu)
            k = r.random()
            if k < 0.25:
                lid = self.lid()
                self.W(t, 4624, h, dict(TargetUserName=u, TargetDomainName="CORP", TargetLogonId=lid, LogonType="2",
                                        IpAddress="-", WorkstationName=h))
                self.W(t + timedelta(minutes=1), 4688, h, dict(SubjectUserName=u, SubjectLogonId=lid,
                                                               NewProcessName=r.choice([r"C:\Program Files\Google\Chrome\Application\chrome.exe",
                                                                                        r"C:\Program Files\Microsoft Office\root\Office16\EXCEL.EXE"]),
                                                               CommandLine="-"))
                self.W(t + timedelta(hours=r.uniform(1, 6)), 4634, h, dict(TargetUserName=u, TargetLogonId=lid, LogonType="2"))
            elif k < 0.45:
                lid = self.lid()
                self.W(t, 4624, h, dict(TargetUserName=u, TargetDomainName="CORP", TargetLogonId=lid, LogonType="3",
                                        IpAddress=f"10.0.5.{r.randint(10, 200)}", WorkstationName="-"))
            elif k < 0.6:
                self.W(t, 4672, h, dict(SubjectUserName="SYSTEM", SubjectDomainName="NT AUTHORITY", SubjectLogonId="0x3e7",
                                        PrivilegeList="SeTcbPrivilege"))
            elif k < 0.75:
                self.W(t, 4625, h, dict(TargetUserName=u, TargetDomainName="CORP", LogonType="2", IpAddress="-",
                                        WorkstationName=h, Status="0xC000006A"))
            elif k < 0.9:
                self.W(t, 5379, h, dict(SubjectUserName=u), rel=False)   # not in supported catalogue
            else:
                self.W(t, 4634, h, dict(TargetUserName=u, TargetLogonId="0x3e7", LogonType="5"))
        lh = ["web01", "db01", "app01", "bastion"]
        lu = ["devops", "admin1", "svc-app", "monitor"]
        for i in range(n_lin):
            t = T(r.uniform(3, 18), r.randint(0, 59), r.randint(0, 59))
            h, u = r.choice(lh), r.choice(lu)
            ip = f"10.0.{r.randint(1, 9)}.{r.randint(10, 200)}"
            k = r.random()
            if k < 0.3:
                self.L(t, h, "sshd", f"Accepted publickey for {u} from {ip} port {r.randint(30000, 60000)} ssh2")
                self.L(t + timedelta(minutes=1), h, "sudo", f"{u} : TTY=pts/0 ; PWD=/home/{u} ; USER=root ; COMMAND=/usr/bin/apt update")
            elif k < 0.45:
                self.L(t, h, "sshd", f"Failed password for {u} from {ip} port {r.randint(30000, 60000)} ssh2")
                self.L(t + timedelta(seconds=20), h, "sshd", f"Accepted password for {u} from {ip} port {r.randint(30000, 60000)} ssh2")
            elif k < 0.75:
                self.L(t, h, "CRON", "pam_unix(cron:session): session opened for user root(uid=0) by (uid=0)", rel=False)
            elif k < 0.9:
                self.L(t, h, "systemd-logind", f"New session {r.randint(1, 999)} of user {u}.", rel=False)
            else:
                self.L(t, h, "useradd", f"new user: name=svc{r.randint(10, 99)}, UID={r.randint(1001, 1999)}, GID={r.randint(1001, 1999)}")
        hosts_ops = ["ec2.amazonaws.com", "s3.amazonaws.com", "iam.amazonaws.com"]
        for i in range(n_aws):
            t = T(r.uniform(3, 18), r.randint(0, 59), r.randint(0, 59))
            k = r.random()
            if k < 0.35:
                self.A(t, "DescribeInstances", OFFICE_NAT, dict(type="IAMUser", userName="devops", accessKeyId=K_OPS))
            elif k < 0.55:
                self.A(t, "ListBuckets", OFFICE_NAT, dict(type="IAMUser", userName="devops", accessKeyId=K_OPS), src="s3.amazonaws.com")
            elif k < 0.7:
                self.A(t, "PutObject", OFFICE_NAT, dict(type="IAMUser", userName="app-uploader", accessKeyId=K_APP),
                       params=dict(bucketName="app-uploads", key=f"u/{r.randint(1000, 9999)}.bin"), src="s3.amazonaws.com")
            elif k < 0.8:
                self.A(t, "GetObject", OFFICE_NAT, dict(type="IAMUser", userName="devops", accessKeyId=K_OPS),
                       params=dict(bucketName="build-artifacts", key=f"b/{r.randint(1, 500)}.zip"), src="s3.amazonaws.com")
            else:
                self.A(t, "DescribeVolumes", "ec2.amazonaws.com", dict(type="AWSService", invokedBy="ec2.amazonaws.com"),
                       etype="AwsServiceEvent")
        if scripted_legit:
            # legitimate ubuntu@web01 sessions outside the attack window (each sudo follows its own login)
            self.L(T(7, 30), "web01", "sshd", "Accepted publickey for ubuntu from 10.0.3.21 port 51000 ssh2")
            self.L(T(7, 35), "web01", "sudo", "ubuntu : TTY=pts/1 ; PWD=/home/ubuntu ; USER=root ; COMMAND=/usr/bin/systemctl restart nginx")
            self.L(T(12, 0), "web01", "sshd", "Accepted publickey for ubuntu from 10.0.3.21 port 51420 ssh2")
            self.L(T(12, 5), "web01", "sudo", "ubuntu : TTY=pts/1 ; PWD=/home/ubuntu ; USER=root ; COMMAND=/usr/bin/tail /var/log/syslog")
            self.L(T(7, 0), "db01", "sshd", "Accepted publickey for deploy from 10.0.4.9 port 52000 ssh2")
            self.L(T(7, 5), "db01", "sudo", "deploy : TTY=pts/0 ; PWD=/home/deploy ; USER=root ; COMMAND=/usr/bin/systemctl status postgresql")
            self.L(T(13, 0), "db01", "sshd", "Accepted publickey for deploy from 10.0.4.9 port 52111 ssh2")
            # legitimate administrator logon from the admin workstation (fixed ids: no RNG draw)
            self.W(T(8, 0), 4624, "SRV-FILE-01", dict(TargetUserName="administrator", TargetDomainName="CORP", TargetLogonId="0x1a2b3",
                                                      LogonType="3", IpAddress="10.0.5.10", WorkstationName="-"))
            self.W(T(8, 0, 1), 4672, "SRV-FILE-01", dict(SubjectUserName="administrator", SubjectDomainName="CORP", SubjectLogonId="0x1a2b3",
                                                          PrivilegeList="SeBackupPrivilege"))
            # external scanner: only 3 failures (below the brute-force threshold) -> must NOT raise an incident
            for i in range(3):
                self.L(T(6, 20, 10 * i), "web01", "sshd", f"Failed password for invalid user test from {SCANNER} port {33000 + i} ssh2")

    # ---------- serialization ----------
    def write(self, out_dir):
        os.makedirs(out_dir, exist_ok=True)
        truth = {"relevant": [], "incident_events": {}, "counts": {}}

        def tag(ref, inc):
            truth["relevant"].append(ref)
            if inc:
                truth["incident_events"].setdefault(inc, []).append(ref)

        # Windows XML (wevtutil qe Security /f:xml style: concatenated <Event> elements)
        win = sorted(self.win, key=lambda e: e["t"])
        parts = []
        for i, e in enumerate(win, 1):
            ts = e["t"].strftime("%Y-%m-%dT%H:%M:%S.") + f"{e['t'].microsecond * 10:07d}Z"
            ns = ' xmlns="http://schemas.microsoft.com/win/2004/08/events/event"'
            if e["userdata"]:
                body = "<UserData><LogFileCleared xmlns=\"http://manifests.microsoft.com/win/2004/08/windows/eventlog\">" + \
                       "".join(f"<{k}>{escape(v)}</{k}>" for k, v in e["userdata"].items()) + "</LogFileCleared></UserData>"
            else:
                body = "<EventData>" + "".join(f'<Data Name="{k}">{escape(str(v))}</Data>' for k, v in e["data"].items()) + "</EventData>"
            parts.append(f'<Event{ns}><System><Provider Name="{e["provider"]}"/><EventID>{e["eid"]}</EventID>'
                         f'<TimeCreated SystemTime="{ts}"/><EventRecordID>{1000 + i}</EventRecordID>'
                         f'<Computer>{e["host"]}</Computer></System>{body}</Event>')
            if e["rel"]:
                tag(f"windows_security.xml#{i}", e["inc"])
        with open(os.path.join(out_dir, "windows_security.xml"), "w", encoding="utf-8") as f:
            f.write("\n".join(parts) + "\n")

        # Linux auth.log (syslog format, local time IST, no year)
        lin = sorted(self.lin, key=lambda e: e["t"])
        lines = []
        for i, e in enumerate(lin, 1):
            lt = e["t"].astimezone(IST)
            pid = 1000 + (i * 7) % 9000
            stamp = f"{lt.strftime('%b')} {lt.day:2d} {lt.strftime('%H:%M:%S')}"
            lines.append(f"{stamp} {e['host']} {e['proc']}[{pid}]: {e['msg']}")
            if e["rel"]:
                tag(f"auth.log#{i}", e["inc"])
        with open(os.path.join(out_dir, "auth.log"), "w", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")

        # AWS CloudTrail JSON
        aws = sorted(self.aws, key=lambda e: e["t"])
        recs = []
        for i, e in enumerate(aws, 1):
            rec = {
                "eventVersion": "1.08",
                "userIdentity": e["ident"],
                "eventTime": e["t"].strftime("%Y-%m-%dT%H:%M:%SZ"),
                "eventSource": e["src"],
                "eventName": e["name"],
                "awsRegion": "ap-south-1",
                "sourceIPAddress": e["ip"],
                "userAgent": "aws-cli/2.15.0",
                "requestParameters": e["params"],
                "responseElements": e["resp"],
                "eventID": f"{i:08d}-aaaa-bbbb-cccc-000000000000",
                "eventType": e["etype"],
            }
            if e["err"]:
                rec["errorCode"] = e["err"]
            recs.append(rec)
            tag(f"cloudtrail.json#{i}", e["inc"])
        with open(os.path.join(out_dir, "cloudtrail.json"), "w", encoding="utf-8") as f:
            json.dump({"Records": recs}, f, indent=1)

        truth["counts"] = {"windows": len(win), "linux": len(lin), "aws": len(aws)}
        truth["total_records"] = len(win) + len(lin) + len(aws)
        with open(os.path.join(out_dir, "ground_truth.json"), "w", encoding="utf-8") as f:
            json.dump(truth, f, indent=1)
        return truth


def build(name, out_dir, seed=7, noise=(60, 60, 50), inventory=True):
    g = Gen(seed)
    if name == "S1":
        g.attack_windows_rdp("INC-1", T(8, 30), ATT_A)
        g.attack_linux("INC-1", T(9, 10), ATT_A)
        g.attack_aws("INC-1", T(9, 40), ATT_A, K_APP, K_NEW)
    elif name == "S2":
        g.attack_linux("INC-1", T(9, 10), ATT_A)
        g.attack_aws("INC-1", T(9, 40), ATT_B, K_APP, K_NEW)          # different IP: linked only by credential
    elif name == "S3":
        g.attack_windows_rdp("INC-1", T(10, 0), ATT_C, host="WS-HR-02", n_fail=8)
        g.attack_linux("INC-2", T(10, 5), ATT_D, host="db01", user="deploy", n_fail=5)
        g.attack_aws("INC-2", T(10, 30), ATT_B, K_DPL, K_NEW3, user="deploy-bot", bucket="hr-payroll")
    elif name == "S4":
        pass  # benign only
    elif name == "S5":
        # Hard case 1: a legitimate ubuntu session is open when the attacker logs in as the same user.
        # The legitimate sudo at 09:20 belongs to the earlier (internal) session, but auth.log has no
        # session id, so the framework's "latest login" heuristic attributes it to the attacker.
        g.L(T(9, 0), "web01", "sshd", "Accepted publickey for ubuntu from 10.0.3.21 port 51900 ssh2")
        g.attack_linux("INC-1", T(9, 10), ATT_A, host="web01", user="ubuntu")
        g.L(T(9, 20), "web01", "sudo", "ubuntu : TTY=pts/2 ; PWD=/home/ubuntu ; USER=root ; COMMAND=/usr/bin/journalctl -u nginx")
        # Hard case 2: insider / lateral movement from an internal IP, no brute force. Rule-based
        # detection has no untrusted entity to work with, so this incident is expected to be missed.
        lid = g.lid()
        g.W(T(11, 0), 4624, "SRV-FILE-01", dict(TargetUserName="administrator", TargetDomainName="CORP", TargetLogonId=lid,
                                                LogonType="3", IpAddress="10.0.5.99", WorkstationName="-"), "INC-2")
        g.W(T(11, 0, 1), 4672, "SRV-FILE-01", dict(SubjectUserName="administrator", SubjectDomainName="CORP", SubjectLogonId=lid,
                                                    PrivilegeList="SeDebugPrivilege"), "INC-2")
        g.W(T(11, 2), 4720, "SRV-FILE-01", dict(TargetUserName="svc_temp", SubjectUserName="administrator", SubjectLogonId=lid), "INC-2")
        g.W(T(11, 2, 20), 4732, "SRV-FILE-01", dict(MemberName="CN=svc_temp", TargetUserName="Administrators",
                                                     SubjectUserName="administrator", SubjectLogonId=lid), "INC-2")
    else:
        raise ValueError(name)
    g.noise(*noise)
    truth = g.write(out_dir)
    cfg = dict(CASE_CONFIG)
    cfg["case_id"] = f"CASE-{name}"
    if not inventory:
        cfg["credential_inventory"] = {}
    with open(os.path.join(out_dir, "case_config.json"), "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2)
    return truth


def cloud_state(out_dir, exposed=True, stolen_key=K_APP):
    """AWS account-state files (as cloudstate.py writes them) for a labelled fixture.
    Returns the number of findings each rule is expected to raise. The exposed account has known misconfigurations AND
    look-alike harmless items that must NOT be flagged (an administrator WITH MFA, a recently used key, a world-open
    port 443, a fully blocked bucket)."""
    d = os.path.join(out_dir, "cloud")
    os.makedirs(d, exist_ok=True)
    now = BASE + timedelta(hours=12)
    ts = lambda days: (now - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")
    W = lambda name, obj: json.dump(obj, open(os.path.join(d, name), "w"), indent=1)
    W("identity.json", dict(collected_at=now.strftime("%Y-%m-%dT%H:%M:%SZ"), account="111122223333", arn="arn:aws:iam::111122223333:user/auditor", region="ap-south-1"))
    W("trails.json", dict(listed=True, items=[dict(name="management-trail", arn="arn:aws:cloudtrail:ap-south-1:111122223333:trail/management-trail", home_region="ap-south-1",
                                                   multi_region=True, organization=False, log_validation=True, bucket="trail-bucket", is_logging=not exposed, stop_logging_time=ts(0) if exposed else None,
                                                   latest_delivery=ts(0), delivery_error=None)]))
    W("iam_account.json", dict(known=True, root_mfa=not exposed, users=5, root_access_keys=0))
    key = lambda kid, age, last: dict(key_id=kid, status="Active", created=ts(age), last_used=ts(last) if last is not None else None, last_service="s3", last_region="ap-south-1")
    users = [
        dict(user="alice", is_admin=True, mfa_devices=0 if exposed else 1, keys=[key("AKIAQ3EXAMPLEALICE01", 300, 200 if exposed else 1)]),     # admin w/o MFA (exposed) + stale key
        dict(user="bob", is_admin=True, mfa_devices=0 if exposed else 1, keys=[]),                                                              # admin w/o MFA (exposed)
        dict(user="carol", is_admin=True, mfa_devices=1, keys=[key("AKIAQ3EXAMPLECAROL1", 200, 3)]),                                             # admin WITH MFA, recent key: must not flag
        dict(user="app-uploader", is_admin=False, mfa_devices=0, keys=[key(stolen_key, 250, 0)]),                                                # ordinary user, recent key
        dict(user="ci-bot", is_admin=False, mfa_devices=0, keys=[key("AKIAQ3EXAMPLECIBOT01", 400, 120 if exposed else 2), key("AKIAQ3EXAMPLECIBOT02", 150, None if exposed else 5)]),  # stale + never used (exposed)
    ]
    for u in users:
        u.update(created=ts(500), password_last_used=None, policies=["AdministratorAccess"] if u["is_admin"] else [], groups=[], group_policies=[])
    W("iam_users.json", dict(items=users))
    full = dict(BlockPublicAcls=True, IgnorePublicAcls=True, BlockPublicPolicy=True, RestrictPublicBuckets=True)
    partial = dict(BlockPublicAcls=True, IgnorePublicAcls=False, BlockPublicPolicy=True, RestrictPublicBuckets=False)
    bucket = lambda name, cfg, pub: dict(bucket=name, created=ts(300), block_config=cfg, block_all=cfg == full, policy_public=pub, checked=True)
    W("s3_buckets.json", dict(listed=True, items=[bucket("finance-reports", None if exposed else full, exposed), bucket("public-assets", None if exposed else full, exposed), bucket("hr-payroll", partial if exposed else full, False),
                                                  bucket("app-uploads", full, False), bucket("build-artifacts", full, False), bucket("backups", full, False)]))
    sg = lambda gid, name, rules: dict(group_id=gid, name=name, vpc="vpc-1", region="ap-south-1", rules=rules)
    rule = lambda lo, hi, cidr: dict(protocol="tcp", from_port=lo, to_port=hi, cidrs=[cidr])
    world = "0.0.0.0/0" if exposed else "10.0.0.0/8"
    W("security_groups.json", dict(region="ap-south-1", items=[
        sg("sg-ssh", "ssh", [rule(22, 22, world)]), sg("sg-rdp", "rdp", [rule(3389, 3389, world)]),
        sg("sg-web", "web", [rule(443, 443, "0.0.0.0/0")]),                                                    # world-open 443: normal, must not flag
        sg("sg-all", "all", [dict(protocol="-1", from_port=None, to_port=None, cidrs=[world])]),
        sg("sg-db", "db", [rule(5432, 5432, "10.0.0.0/8")]), sg("sg-app", "app", [rule(8080, 8080, "10.0.0.0/8")])]))
    expected = dict(trail_logging_off=1, root_mfa_missing=1, admin_without_mfa=2, stale_access_key=3, public_bucket=2, bucket_public_access_not_blocked=1, sg_world_open_admin_port=3) if exposed else {}
    return expected


def build_scaled(out_dir, total_events, seed=11):
    """One S1 attack hidden in roughly `total_events` events of background activity."""
    g = Gen(seed)
    g.attack_windows_rdp("INC-1", T(8, 30), ATT_A)
    g.attack_linux("INC-1", T(9, 10), ATT_A)
    g.attack_aws("INC-1", T(9, 40), ATT_A, K_APP, K_NEW)
    n = max(30, total_events - 45)
    # each noise draw yields ~1.5 raw records on average; tune split per source
    g.noise(int(n * 0.35 / 1.55), int(n * 0.35 / 1.25), int(n * 0.30))
    truth = g.write(out_dir)
    cfg = dict(CASE_CONFIG)
    cfg["case_id"] = f"CASE-SCALE-{total_events}"
    with open(os.path.join(out_dir, "case_config.json"), "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2)
    return truth


if __name__ == "__main__":
    import sys
    name = sys.argv[1] if len(sys.argv) > 1 else "S1"
    out = sys.argv[2] if len(sys.argv) > 2 else f"sample_logs/{name}"
    t = build(name, out)
    print(f"Generated {name} in {out}: {t['total_records']} records {t['counts']}")
