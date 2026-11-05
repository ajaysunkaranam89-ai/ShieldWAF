"""Analytics (module P): the numbers on real rows (SQLite), including the edge cases that would make them wrong or unsafe."""
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "panel"))
os.environ.setdefault("SHIELD_DATA", tempfile.mkdtemp())
import analytics  # noqa: E402
import store  # noqa: E402

NOW = 1_800_000_000.0


class Analytics(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        store.init_db()

    def setUp(self):
        con = store.db()
        con.execute("DELETE FROM access")
        con.execute("DELETE FROM events")
        rows = []
        for i in range(100):                                   # 100 requests in the last hour and a half from 4 clients to 2 sites
            rows.append((NOW - 60 * i, f"203.0.113.{i % 4}", "a.test" if i % 2 == 0 else "b.test", 403 if i % 10 == 0 else 429 if i % 25 == 1 else 200, 0.01))
        rows.append((NOW - 86400 * 3, "198.51.100.9", "a.test", 200, 0.02))      # an older one
        con.executemany("INSERT INTO access(ts,ip,host,status,rt) VALUES(?,?,?,?,?)", rows)
        con.executemany("INSERT INTO events(ts,ip,host,method,uri,rule_id,msg,score,status,blocked) VALUES(?,?,?,?,?,?,?,?,?,?)", [
            (NOW - 100, "203.0.113.1", "a.test", "GET", "/login?id=1", "942100", "SQL injection", "5", 403, 1),
            (NOW - 200, "203.0.113.1", "a.test", "GET", "/login?id=2", "942100", "SQL injection", "5", 403, 1),
            (NOW - 300, "203.0.113.2", "b.test", "GET", "/page", "941100", "XSS", "5", 200, 0)])
        con.commit()

    def test_totals_for_the_last_24_hours(self):
        t = analytics.summary("24h", now=NOW)["totals"]
        self.assertEqual(t["requests"], 100)
        self.assertEqual(t["blocked"], 10)
        self.assertEqual(t["unique_clients"], 4)
        self.assertEqual(t["block_rate"], 10.0)
        self.assertGreaterEqual(t["rate_limited"], 3)

    def test_the_range_decides_what_is_counted(self):
        self.assertEqual(analytics.summary("1h", now=NOW)["totals"]["requests"], 61)       # the boundary minute is included
        self.assertEqual(analytics.summary("7d", now=NOW)["totals"]["requests"], 101)
        self.assertEqual(analytics.summary("nonsense", now=NOW)["range"], "24h")

    def test_filtering_by_site(self):
        d = analytics.summary("24h", host="b.test", now=NOW)
        self.assertEqual(d["totals"]["requests"], 50)
        self.assertEqual([r["host"] for r in d["top_hosts"]], ["b.test"])

    def test_the_series_has_one_point_per_bucket_and_adds_up(self):
        d = analytics.summary("24h", now=NOW)
        self.assertEqual(sum(p["requests"] for p in d["series"]), 100)
        self.assertEqual(sum(p["blocked"] for p in d["series"]), 10)
        self.assertGreaterEqual(len(d["series"]), 24)

    def test_top_lists(self):
        d = analytics.summary("24h", now=NOW)
        self.assertEqual(d["top_rules"][0]["rule_id"], "942100")
        self.assertEqual(d["top_rules"][0]["n"], 2)
        self.assertEqual(d["top_ips"][0]["ip"], "203.0.113.1")
        self.assertEqual(d["events"], {"matches": 3, "blocked": 2})
        self.assertEqual(d["top_hosts"][0]["n"], 50)

    def test_an_empty_range_gives_zeros_not_errors(self):
        d = analytics.summary("1h", now=NOW + 10 * 86400)
        self.assertEqual(d["totals"]["requests"], 0)
        self.assertEqual(d["totals"]["block_rate"], 0.0)
        self.assertEqual(d["top_rules"], [])

    def test_csv_cannot_run_a_client_chosen_value_as_a_formula(self):
        data = {"totals": {}, "series": [], "top_hosts": [], "top_rules": [], "top_ips": [], "top_countries": [],
                "top_uris": [{"uri": "=HYPERLINK(1)", "n": 1, "blocked": 0}, {"uri": "+cmd", "n": 1, "blocked": 0}, {"uri": "/plain", "n": 1, "blocked": 0}]}
        csv = analytics.csv_lines(data)
        self.assertIn("'=HYPERLINK(1)", csv)
        self.assertIn("'+cmd", csv)
        self.assertIn('"/plain"', csv)
        self.assertNotIn('"=HYPERLINK', csv)


if __name__ == "__main__":
    unittest.main()
