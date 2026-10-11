"""Evidence intake (files with any name) and the web console API."""
import gzip
import io
import json
import os
import shutil
import sys
import tempfile
import time
import unittest
import zipfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import generate_data  # noqa: E402
import intake  # noqa: E402
import pipeline  # noqa: E402

try:
    import flask  # noqa: F401
    HAVE_FLASK = True
except ImportError:
    HAVE_FLASK = False


class IntakeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp()
        cls.s1 = os.path.join(cls.tmp, "S1")
        generate_data.build("S1", cls.s1)
        cls.raw = os.path.join(cls.tmp, "raw")
        os.makedirs(cls.raw)
        # the same evidence with names a real investigator might have
        shutil.copy(os.path.join(cls.s1, "auth.log"), os.path.join(cls.raw, "web01 server log.txt"))
        shutil.copy(os.path.join(cls.s1, "windows_security.xml"), os.path.join(cls.raw, "export (1).xml"))
        with open(os.path.join(cls.s1, "cloudtrail.json"), "rb") as s, gzip.open(os.path.join(cls.raw, "trail-download.json.gz"), "wb") as d:
            d.write(s.read())
        shutil.copy(os.path.join(cls.s1, "case_config.json"), os.path.join(cls.raw, "case_config.json"))
        with open(os.path.join(cls.raw, "notes.txt"), "w") as f:
            f.write("meeting notes, not evidence\n")

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def test_detects_by_content_not_name(self):
        res = {r["name"]: r for r in intake.stage([(os.path.join(self.raw, f), f) for f in sorted(os.listdir(self.raw))],
                                                  os.path.join(self.tmp, "st1"))}
        self.assertEqual(res["web01 server log.txt"]["kind"], "linux")
        self.assertEqual(res["export (1).xml"]["kind"], "windows")
        self.assertEqual(res["trail-download.json"]["kind"], "aws")
        self.assertEqual(res["case_config.json"]["kind"], "config")
        self.assertEqual(res["notes.txt"]["kind"], "unknown")
        self.assertFalse(res["notes.txt"]["used"])

    def test_renamed_files_give_same_result_as_standard_names(self):
        st = os.path.join(self.tmp, "st2")
        files = intake.stage([(os.path.join(self.raw, f), f) for f in sorted(os.listdir(self.raw))], st)
        a = pipeline.run_case(self.s1, os.path.join(self.tmp, "caseA"), make_report=False)
        b = pipeline.run_case(st, os.path.join(self.tmp, "caseB"), make_report=False, intake=files)
        self.assertEqual(len(a["events"]), len(b["events"]))
        self.assertEqual(a["corr"]["alert_events"], b["corr"]["alert_events"])
        self.assertEqual(len(a["corr"]["incidents"]), len(b["corr"]["incidents"]))
        self.assertTrue(b["custody_ok"])
        led = [json.loads(l) for l in open(os.path.join(self.tmp, "caseB", "custody_ledger.jsonl"))]
        self.assertEqual(led[0]["action"], "intake")          # originals' hashes are the first custody entry

    def test_zip_archive_and_traversal_is_ignored(self):
        zp = os.path.join(self.tmp, "logs.zip")
        with zipfile.ZipFile(zp, "w") as z:
            z.write(os.path.join(self.s1, "auth.log"), "server/auth.log.1")
            z.writestr("../../escape.txt", "x")
        res = intake.stage([zp], os.path.join(self.tmp, "st3"))
        self.assertEqual([r["kind"] for r in res], ["linux"])
        self.assertFalse(os.path.exists(os.path.join(self.tmp, "escape.txt")))

    def test_multiple_files_of_one_platform_are_merged(self):
        a = os.path.join(self.tmp, "a.log")
        b = os.path.join(self.tmp, "b.log")
        lines = open(os.path.join(self.s1, "auth.log")).read().splitlines()
        open(a, "w").write("\n".join(lines[:50]) + "\n")
        open(b, "w").write("\n".join(lines[50:]) + "\n")
        st = os.path.join(self.tmp, "st4")
        intake.stage([a, b], st)
        self.assertEqual(len(open(os.path.join(st, "auth.log")).read().splitlines()), len(lines))


@unittest.skipUnless(HAVE_FLASK, "flask not installed")
class WebConsoleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import webapp
        cls.webapp = webapp
        cls.tmp = tempfile.mkdtemp()
        cls.old = (webapp.CASES, webapp.UPLOADS)
        webapp.CASES = os.path.join(cls.tmp, "cases")
        webapp.UPLOADS = os.path.join(cls.tmp, "uploads")
        os.makedirs(webapp.CASES)
        cls.c = webapp.app.test_client()
        cls.s1 = os.path.join(cls.tmp, "S1")
        generate_data.build("S1", cls.s1)

    @classmethod
    def tearDownClass(cls):
        cls.webapp.CASES, cls.webapp.UPLOADS = cls.old
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def _wait(self, job):
        for _ in range(200):
            j = self.c.get(f"/api/jobs/{job}").get_json()
            if j["state"] != "running":
                return j
            time.sleep(0.1)
        self.fail("job did not finish")

    def test_upload_analyse_verify_tamper(self):
        data = {"case_name": "WEB T1", "files": [], "paths": []}
        for src, name in (("auth.log", "srv.txt"), ("windows_security.xml", "dc.xml"), ("cloudtrail.json", "aws.json"),
                          ("case_config.json", "case_config.json")):
            data["files"].append((io.BytesIO(open(os.path.join(self.s1, src), "rb").read()), name))
            data["paths"].append(name)
        r = self.c.post("/api/analyze", data=data, content_type="multipart/form-data").get_json()
        self.assertEqual(r["case"], "WEB-T1")
        j = self._wait(r["job"])
        self.assertEqual(j["state"], "done", j.get("error"))
        self.assertIn("correlation", j["stages_done"])
        d = self.c.get("/api/cases/WEB-T1").get_json()
        self.assertEqual(len(d["incidents"]), 1)
        self.assertEqual(sorted(d["incidents"][0]["platforms"]), ["aws", "linux", "windows"])
        self.assertTrue(d["custody"]["ok"])
        self.assertTrue(self.c.post("/api/cases/WEB-T1/verify", json={}).get_json()["ok"])
        for what in ("evidence", "ledger", "delete"):
            t = self.c.post("/api/cases/WEB-T1/tamper", json={"what": what}).get_json()
            self.assertTrue(t["detected"], what)
            self.assertTrue(t["original_still_ok"], what)
        ev = self.c.get("/api/cases/WEB-T1/events?q=T1110&alerts=1").get_json()
        self.assertGreater(ev["total"], 0)
        self.assertEqual(self.c.get("/cases/WEB-T1/report.html").status_code, 200)
        self.assertEqual(self.c.get("/api/cases/WEB-T1/download").status_code, 200)

    def test_no_evidence_is_reported_not_crashed(self):
        r = self.c.post("/api/analyze", data={"files": [(io.BytesIO(b"hello"), "a.txt")], "paths": ["a.txt"]},
                        content_type="multipart/form-data").get_json()
        j = self._wait(r["job"])
        self.assertEqual(j["state"], "error")
        self.assertIn("None of the files", j["error"])

    def test_case_paths_cannot_escape(self):
        self.assertEqual(self.c.get("/api/cases/..").status_code, 404)
        self.assertEqual(self.c.get("/cases/WEB-T1/../../webapp.py").status_code, 404)


if __name__ == "__main__":
    unittest.main()
