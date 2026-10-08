"""Cloud state collector through the REAL boto3 code path against the moto AWS emulator.
Not a real AWS account: moto is an emulation, so this tests our code and the request/response handling, not AWS itself."""
import collections
import json
import os
import shutil
import sys
import tempfile
import unittest
import warnings
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
warnings.simplefilter("ignore")
try:
    from moto import mock_aws
    import boto3
    import freezegun  # noqa: F401
    HAVE = True
except ImportError:                                   # pragma: no cover
    HAVE = False
import cloud_emulation
import cloudstate
import config
import generate_data
import pipeline

LATER = lambda: datetime.now(timezone.utc) + timedelta(days=200)       # keys created "now" are 200 days old at collection


def flags(ctx):
    return collections.Counter(f for e in ctx["events"] for f in e["flags"])


@unittest.skipUnless(HAVE, "moto and freezegun needed")
class Emulated(unittest.TestCase):
    def collect(self, **kw):
        d = tempfile.mkdtemp()
        man = cloudstate.collect_cloud_state(d, region="us-east-1", now=LATER(), log=lambda *a: None, **kw)
        return d, man

    def analyze(self, d, extra=None):
        return pipeline.run_case(d, os.path.join(d, "case"), dict(config.DEFAULT_CASE, case_id="E", **(extra or {})), make_report=True)

    def test_exactly_the_seeded_findings_and_nothing_else(self):
        with mock_aws():
            info = cloud_emulation.seed()
            d, man = self.collect()
        self.assertEqual(man["errors"], [])
        ctx = self.analyze(d)
        self.assertEqual(dict(flags(ctx)), info["expected"])                   # every misconfiguration found, no look-alike flagged
        self.assertEqual(ctx["corr"]["incidents"], [])                         # exposure alone is not an incident
        self.assertTrue(ctx["custody_ok"])
        shutil.rmtree(d)

    def test_everything_created_was_collected(self):
        with mock_aws():
            info = cloud_emulation.seed()
            d, man = self.collect()
        load = lambda n: json.load(open(os.path.join(d, "cloud", n)))["items"]
        self.assertEqual(len(load("iam_users.json")), info["created"]["users"])
        self.assertEqual(len(load("iam_roles.json")), info["created"]["roles"])
        self.assertEqual(len(load("s3_buckets.json")), info["created"]["buckets"])
        self.assertEqual(len(load("trails.json")), info["created"]["trails"])
        users = {u["user"]: u for u in load("iam_users.json")}
        self.assertTrue(users["alice"]["is_admin"])                            # admin through a customer-managed policy (document check)
        self.assertTrue(users["bob"]["is_admin"] and users["bob"]["mfa_devices"] == 1)   # admin through a group, with MFA
        self.assertEqual(users["alice"]["keys"][0]["key_id"], info["keys"]["alice"])
        shutil.rmtree(d)

    def test_only_read_operations_are_used(self):
        with mock_aws():
            cloud_emulation.seed()
            d, man = self.collect(all_regions=True)
        self.assertGreater(len(man["api_operations"]), 10)
        for op in man["api_operations"]:
            self.assertTrue(op.startswith(cloudstate.READ_PREFIXES), f"write-capable operation used: {op}")
        shutil.rmtree(d)

    def test_all_regions_finds_the_group_in_the_second_region(self):
        with mock_aws():
            info = cloud_emulation.seed()
            d1, m1 = self.collect()
            d2, m2 = self.collect(all_regions=True)
        self.assertIn("security_groups", m1["limited"])                        # the report says only one region was read
        self.assertNotIn("security_groups", m2["limited"])
        self.assertEqual(dict(flags(self.analyze(d2))), info["expected_all_regions"])
        shutil.rmtree(d1); shutil.rmtree(d2)

    def test_pagination_of_many_users(self):
        with mock_aws():
            iam = boto3.client("iam", region_name="us-east-1", aws_access_key_id="x", aws_secret_access_key="y")
            for i in range(230):
                iam.create_user(UserName=f"user{i:03d}")
            d, man = self.collect()
        self.assertEqual(len(json.load(open(os.path.join(d, "cloud", "iam_users.json")))["items"]), 230)
        shutil.rmtree(d)

    def test_state_of_the_abused_key_joins_the_incident_and_others_do_not(self):
        with mock_aws():
            info = cloud_emulation.seed()
            d, man = self.collect()
        stolen = info["keys"]["app-uploader"]
        g = generate_data.Gen(3)
        g.attack_aws("INC-1", generate_data.T(9, 40), generate_data.ATT_A, stolen, "AKIAQ3EXAMPLENEW0002", user="app-uploader")
        g.write(d)                                                             # cloudtrail.json (+ empty windows and linux files) beside cloud/
        ctx = self.analyze(d)
        incs = ctx["corr"]["incidents"]
        self.assertEqual(len(incs), 1)
        ids = set(incs[0]["event_ids"])
        joined = [e for e in ctx["events"] if e["event_type"] == "access_key_state" and e["event_id"] in ids]
        self.assertEqual([e["key_id"] for e in joined], [stolen])              # only the abused key's account record joins
        self.assertIn("stale_access_key", joined[0]["flags"])                  # ... together with its posture finding: an old key was abused
        self.assertEqual(joined[0]["user"], "app-uploader")
        self.assertGreaterEqual(len(ctx["corr"]["unlinked_alerts"]), 8)        # the other posture findings stay separate
        shutil.rmtree(d)


if __name__ == "__main__":
    unittest.main()
