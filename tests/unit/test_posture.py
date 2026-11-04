"""The security posture page collects every section on its own and gives each a verdict."""
import copy
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "panel"))
os.environ.setdefault("SHIELD_DATA", tempfile.mkdtemp())
import posture  # noqa: E402
import store  # noqa: E402


class Posture(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        store.init_db()

    def cfg(self):
        return store.load()

    def test_all_sections_are_present_with_a_valid_verdict(self):
        sections = posture.collect(self.cfg())
        titles = [s["title"] for s in sections]
        for t in ("Database", "Audit trail", "Backups", "Cluster", "Rate limiting", "Bot protection", "Threat intelligence", "Sites", "Accounts", "Alerting"):
            self.assertIn(t, titles)
        for s in sections:
            self.assertIn(s["state"], ("ok", "warn", "err", "info"))
            self.assertTrue(s["items"])

    def test_a_cluster_wide_limit_without_redis_is_flagged(self):
        cfg = self.cfg()
        site = copy.deepcopy(store.DEFAULT_SITE)
        site.update(id="p1", host="p1.test", upstream="http://10.0.0.1")
        site["rate_limit"] = {"enabled": True, "rps": 5, "burst": 5, "scope": "cluster"}
        cfg["sites"] = [site]
        sec = next(s for s in posture.collect(cfg) if s["title"] == "Rate limiting")
        self.assertEqual(sec["state"], "warn")
        self.assertTrue(any("per replica" in i["text"] for i in sec["items"]))

    def test_refused_upstreams_and_missing_https_are_reported(self):
        cfg = self.cfg()
        site = copy.deepcopy(store.DEFAULT_SITE)
        site.update(id="p2", host="p2.test", upstream="http://10.0.0.1", ssrf_blocked=["http://10.0.0.1"])
        cfg["sites"] = [site]
        secs = {s["title"]: s for s in posture.collect(cfg)}
        self.assertEqual(secs["Upstream network guard (SSRF)"]["state"], "err")
        self.assertEqual(secs["Sites"]["state"], "warn")

    def test_a_section_that_fails_does_not_hide_the_others(self):
        s = posture._section("x", lambda: 1 / 0)
        self.assertEqual(s["state"], "err")
        self.assertIn("could not be read", s["items"][0]["label"])


if __name__ == "__main__":
    unittest.main()
