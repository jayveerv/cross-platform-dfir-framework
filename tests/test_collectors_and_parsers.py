import json
import os
import re
import shutil
import sys
import tempfile
import unittest
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import collect
import config
import correlate
import custody
import generate_data
import normalize
import pipeline


def ct_record(name, ip, key="AKIAQ3EXAMPLEAPP0001", t="2026-09-20T09:00:00Z", **kw):
    r = {"eventVersion": "1.08", "eventTime": t, "eventName": name, "eventSource": "s3.amazonaws.com", "awsRegion": "ap-south-1",
         "sourceIPAddress": ip, "userIdentity": {"type": "IAMUser", "userName": "app", "accessKeyId": key}}
    r.update(kw)
    return r


class AwsCollector(unittest.TestCase):
    def _client(self, pages, errors_first=0):
        import boto3
        from botocore.stub import Stubber
        client = boto3.client("cloudtrail", region_name="ap-south-1", aws_access_key_id="x", aws_secret_access_key="y")
        st = Stubber(client)
        for _ in range(errors_first):
            st.add_client_error("lookup_events", service_error_code="ThrottlingException", http_status_code=400)
        for i, recs in enumerate(pages):
            resp = {"Events": [{"EventId": f"id{i}{j}", "EventName": r["eventName"], "EventTime": datetime(2026, 9, 20, tzinfo=timezone.utc),
                                "CloudTrailEvent": json.dumps(r)} for j, r in enumerate(recs)]}
            if i < len(pages) - 1:
                resp["NextToken"] = f"tok{i}"
            st.add_response("lookup_events", resp)
        st.activate()
        return client, st

    def test_pagination_and_output(self):
        pages = [[ct_record("ListBuckets", "203.0.113.5", t="2026-09-20T09:01:00Z")],
                 [ct_record("GetObject", "203.0.113.5", t="2026-09-20T09:00:00Z")]]
        client, st = self._client(pages)
        d = tempfile.mkdtemp()
        out, n, calls = collect.collect_live_aws(d, days=1, client=client, pause=0)
        self.assertEqual((n, calls), (2, 2))
        st.assert_no_pending_responses()
        ev, stats = normalize.parse_cloudtrail(out)
        self.assertEqual(stats["errors"], 0)
        self.assertEqual([e["raw"] for e in ev], ["GetObject", "ListBuckets"])      # sorted by time
        self.assertTrue(all(e["src_ip"] == "203.0.113.5" for e in ev))
        shutil.rmtree(d)

    def test_throttling_is_retried(self):
        client, st = self._client([[ct_record("ListBuckets", "203.0.113.5")]], errors_first=2)
        d = tempfile.mkdtemp()
        import time
        real = time.sleep
        collect.time.sleep = lambda s: None           # no real waiting in the test
        try:
            out, n, calls = collect.collect_live_aws(d, client=client, pause=0)
        finally:
            collect.time.sleep = real
        self.assertEqual(n, 1)
        shutil.rmtree(d)

    def test_other_error_is_reported(self):
        import boto3
        from botocore.stub import Stubber
        client = boto3.client("cloudtrail", region_name="ap-south-1", aws_access_key_id="x", aws_secret_access_key="y")
        st = Stubber(client)
        st.add_client_error("lookup_events", service_error_code="AccessDeniedException", http_status_code=403)
        st.activate()
        with self.assertRaises(RuntimeError) as cm:
            collect.collect_live_aws(tempfile.mkdtemp(), client=client, pause=0)
        self.assertIn("AccessDenied", str(cm.exception))

    def test_collected_events_go_through_the_pipeline(self):
        recs = [ct_record("StopLogging", "203.0.113.9", key="AKIAQ3EXAMPLENEW0002", t="2026-09-20T09:05:00Z",
                          eventSource="cloudtrail.amazonaws.com", requestParameters={"name": "trail"})]
        client, _ = self._client([recs])
        d = tempfile.mkdtemp()
        collect.collect_live_aws(d, client=client, pause=0)
        ctx = pipeline.run_case(d, os.path.join(d, "case"), config.load_case_config(None), make_report=True)
        self.assertEqual(len(ctx["events"]), 1)
        self.assertIn("logging_disabled", ctx["events"][0]["flags"])
        self.assertTrue(ctx["custody_ok"])
        shutil.rmtree(d)


class LinuxCollector(unittest.TestCase):
    class R:
        def __init__(self, rc, out=b"", err=b""):
            self.returncode, self.stdout, self.stderr = rc, out, err

    def test_ssh_command_and_file(self):
        seen = {}

        def fake(cmd, **kw):
            seen["cmd"] = cmd
            return self.R(0, b"Sep 20 14:40:11 web01 sshd[1]: Failed password for root from 203.0.113.5 port 22 ssh2\n")
        d = tempfile.mkdtemp()
        out = collect.collect_linux_ssh("10.0.0.5", "ubuntu", d, key="k.pem", runner=fake)
        self.assertIn("ubuntu@10.0.0.5", seen["cmd"])
        self.assertIn("BatchMode=yes", seen["cmd"])
        self.assertEqual(seen["cmd"][seen["cmd"].index("-i") + 1], "k.pem")
        self.assertEqual(seen["cmd"][-1], "sudo cat /var/log/auth.log")
        ev, st = normalize.parse_linux(out, "+05:30", 2026)
        self.assertEqual(ev[0]["event_type"], "auth_failure")
        shutil.rmtree(d)

    def test_ssh_failure_message(self):
        with self.assertRaises(RuntimeError) as cm:
            collect.collect_linux_ssh("h", "u", tempfile.mkdtemp(), runner=lambda c, **k: self.R(255, b"", b"Permission denied (publickey)"))
        self.assertIn("Permission denied", str(cm.exception))

    def test_local_copy_missing(self):
        with self.assertRaises(RuntimeError):
            collect.collect_linux_local(tempfile.mkdtemp(), "/nonexistent/auth.log")


class Parsers(unittest.TestCase):
    def test_timestamp_formats(self):
        a = normalize._parse_ts("2019-03-19T23:35:07.5242000Z")
        b = normalize._parse_ts("2019-03-19 23:35:07.524200+00:00")
        c = normalize._parse_ts("2019-03-20 05:05:07+05:30")
        self.assertEqual(a, b)
        self.assertEqual(a.replace(microsecond=0), c.astimezone(timezone.utc))

    def _linux(self, text, **kw):
        d = tempfile.mkdtemp()
        p = os.path.join(d, "auth.log")
        open(p, "w", newline="").write(text)
        return normalize.parse_linux(p, **kw)

    def test_repeated_lines_and_crlf(self):
        ev, st = self._linux("Dec 10 07:13:56 h sshd[1]: message repeated 5 times: [ Failed password for root from 5.36.59.76 port 42393 ssh2]\r\n"
                             "Dec 10 07:14:00 h sshd[1]: Failed password for root from 5.36.59.76 port 42393 ssh2\r\n", tz_offset="+00:00", year=2015)
        self.assertEqual([(e["event_type"], (e["extra"] or {}).get("repeat", 1)) for e in ev], [("auth_failure", 5), ("auth_failure", 1)])
        correlate.detect(ev, {"internal_ranges": []})
        self.assertTrue(all("brute_force" in e["flags"] for e in ev))        # 6 failures in 10 minutes

    def test_pam_only_logs_use_pam_failures(self):
        ev, st = self._linux("Jun 14 15:16:01 combo sshd(pam_unix)[1]: authentication failure; logname= uid=0 euid=0 tty=NODEVssh ruser= rhost=218.188.2.4  user=root\n",
                             tz_offset="+00:00", year=2005)
        self.assertEqual(ev[0]["src_ip"], "218.188.2.4")
        ev2, _ = self._linux("Jun 14 15:16:01 c sshd[1]: Failed password for root from 1.2.3.4 port 5 ssh2\n"
                             "Jun 14 15:16:01 c sshd[1]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=1.2.3.4  user=root\n",
                             tz_offset="+00:00", year=2005)
        self.assertEqual(len(ev2), 1)                                        # not counted twice

    def test_iso_auth_log(self):
        ev, _ = self._linux("2026-09-20T09:10:11.123456+05:30 web01 sshd[9]: Accepted publickey for ubuntu from 10.0.0.9 port 22 ssh2\n")
        self.assertEqual(ev[0]["time_utc"], "2026-09-20T03:40:11Z")

    def test_cloudtrail_lenient_json(self):
        d = tempfile.mkdtemp()
        r = json.dumps(ct_record("GetObject", "1.2.3.4"), indent=1)
        p = os.path.join(d, "ct.json")
        open(p, "w").write('{"Records": [' + r + "\n" + r + "]}")            # objects glued together without a comma
        ev, st = normalize.parse_cloudtrail(p)
        self.assertEqual(len(ev), 2)
        open(p, "w").write(json.dumps(ct_record("GetObject", None, network={"client": {"ip": "9.9.9.9"}})))
        ev, _ = normalize.parse_cloudtrail(p)
        self.assertEqual(ev[0]["src_ip"], "9.9.9.9")                          # enriched export keeps the IP elsewhere

    def test_windows_single_quote_xml_and_unknown_channel(self):
        d = tempfile.mkdtemp()
        x = ("<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Eventlog'/>"
             "<EventID>1102</EventID><TimeCreated SystemTime='2019-03-19T23:35:07.5Z'/><Channel>Security</Channel><Computer>PC01</Computer></System>"
             "<UserData><LogFileCleared xmlns='x'><SubjectUserName>u</SubjectUserName></LogFileCleared></UserData></Event>")
        p = os.path.join(d, "windows_security.xml")
        open(p, "w").write(x)
        ev, st = normalize.parse_windows(p)
        self.assertEqual(ev[0]["event_type"], "log_cleared")
        self.assertEqual(ev[0]["user"], "u")


class Detection(unittest.TestCase):
    def _run(self, events, cfg=None):
        for i, e in enumerate(events, 1):
            e["event_id"] = f"E{i}"
        return correlate.correlate(events, cfg or config.load_case_config(None))

    def _ev(self, **kw):
        e = normalize._blank()
        e.update(source="windows", host="H", epoch=1000.0, time_utc="2026-09-20T09:00:00Z", line_ref=1, source_file="x")
        e.update(kw)
        return e

    def test_below_threshold_is_not_brute_force(self):
        evs = [self._ev(event_type="auth_failure", src_ip="203.0.113.7", epoch=1000.0 + i, line_ref=i) for i in range(4)]
        self._run(evs)
        self.assertFalse(any(e["flags"] for e in evs))

    def test_lsass_access_and_benign_source(self):
        bad = self._ev(event_type="process_access", target=r"C:\Windows\system32\lsass.exe", extra={"source": r"C:\Users\x\evil.exe", "access": "0x1010"})
        ok = self._ev(event_type="process_access", target=r"C:\Windows\system32\lsass.exe", extra={"source": r"C:\Windows\System32\csrss.exe", "access": "0x1010"}, line_ref=2)
        self._run([bad, ok])
        self.assertIn("lsass_access", bad["flags"])
        self.assertEqual(ok["flags"], [])

    def test_admin_source_policy(self):
        login = self._ev(event_type="auth_success", src_ip="10.0.5.99", session_id="0x1", user="administrator", line_ref=1)
        priv = self._ev(event_type="priv_assign", session_id="0x1", user="administrator", epoch=1001.0, line_ref=2)
        cfg = dict(config.DEFAULT_CASE, privileged_source_allowlist=["10.0.5.10/32"])
        self._run([login, priv], cfg)
        self.assertIn("privileged_logon_unexpected_source", priv["flags"])
        login2 = self._ev(event_type="auth_success", src_ip="10.0.5.10", session_id="0x2", user="administrator")
        priv2 = self._ev(event_type="priv_assign", session_id="0x2", user="administrator", epoch=1001.0, line_ref=2)
        self._run([login2, priv2], cfg)
        self.assertEqual(priv2["flags"], [])


class Custody(unittest.TestCase):
    def test_all_tampering_attacks_are_detected(self):
        import evaluate
        d = tempfile.mkdtemp()
        generate_data.build("S1", os.path.join(d, "in"))
        ctx = pipeline.run_case(os.path.join(d, "in"), os.path.join(d, "case"), make_report=False, key=evaluate.EVAL_KEY)
        res = evaluate.tamper_tests(os.path.join(d, "case"), ctx["final_head_hash"], evaluate.EVAL_KEY)
        self.assertTrue(all(r["passed"] for r in res), res)
        forged = [r for r in res if r["test"].startswith("Ledger forged")][0]
        self.assertTrue(forged["detected"])
        limitation = [r for r in res if r.get("limitation")][0]
        self.assertFalse(limitation["detected"])         # documented: the plain chain alone cannot see a fully rewritten chain
        shutil.rmtree(d)

    def test_hmac_key_is_required_to_verify_signed_ledger(self):
        d = tempfile.mkdtemp()
        generate_data.build("S1", os.path.join(d, "in"))
        ctx = pipeline.run_case(os.path.join(d, "in"), os.path.join(d, "case"), make_report=False, key=b"k")
        led = custody.CustodyLedger(os.path.join(d, "case", "custody_ledger.jsonl"))
        self.assertTrue(led.verify(None, b"k")[0])
        self.assertFalse(led.verify(None, b"wrong")[0])
        shutil.rmtree(d)


if __name__ == "__main__":
    unittest.main()
