"""Threat-intelligence feeds (module I): a failing source keeps its last good copy, extra networks (CrowdSec) are merged, protected networks are never listed."""
import ipaddress
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "panel"))
os.environ.setdefault("SHIELD_DATA", tempfile.mkdtemp())
import feeds  # noqa: E402


class Feeds(unittest.TestCase):
    def setUp(self):
        feeds.FEED_DIR = tempfile.mkdtemp()
        self.cfg = {"settings": {"feeds": {"sources": [{"name": "A", "url": "https://a.example/list", "on": True}, {"name": "B", "url": "https://b.example/list", "on": True}]}}}
        self.data = {"https://a.example/list": ["45.9.148.0/24", "# comment", "91.92.240.1"], "https://b.example/list": ["185.220.101.0/24"]}
        self.down = set()
        feeds._fetch_lines = lambda url, cap: iter(self._lines(url))

    def _lines(self, url):
        if url in self.down:
            raise ValueError("connection refused")
        return [l + "\n" for l in self.data[url]]

    def listed(self):
        return open(os.path.join(feeds.FEED_DIR, "feed.geo")).read()

    def test_merge_of_all_sources_and_extra_networks(self):
        ok, n, err = feeds.refresh_feeds(self.cfg, [], [ipaddress.ip_network("8.8.8.0/24")])
        self.assertTrue(ok)
        self.assertEqual(err, "")
        out = self.listed()
        for net in ("45.9.148.0/24", "91.92.240.1/32", "185.220.101.0/24", "8.8.8.0/24"):
            self.assertIn(net, out)
        self.assertEqual(n, 4)

    def test_a_failing_source_keeps_its_last_good_copy(self):
        feeds.refresh_feeds(self.cfg, [])
        self.down.add("https://b.example/list")
        ok, n, err = feeds.refresh_feeds(self.cfg, [])
        self.assertTrue(ok)
        self.assertIn("185.220.101.0/24", self.listed())              # B is down but its entries stay
        self.assertIn("stays in use", err)

    def test_a_source_that_never_worked_adds_nothing_and_is_reported(self):
        self.down.add("https://b.example/list")
        ok, n, err = feeds.refresh_feeds(self.cfg, [])
        self.assertTrue(ok)
        self.assertNotIn("185.220.101.0/24", self.listed())
        self.assertIn("B:", err)

    def test_all_sources_down_without_a_copy_is_a_failure_and_keeps_the_old_list(self):
        feeds.refresh_feeds(self.cfg, [])
        before = self.listed()
        for f in os.listdir(feeds.FEED_DIR):
            if f.startswith("src-"):
                os.remove(os.path.join(feeds.FEED_DIR, f))
        self.down.update(self.data)
        ok, n, err = feeds.refresh_feeds(self.cfg, [])
        self.assertFalse(ok)
        self.assertEqual(self.listed(), before)

    def test_protected_networks_are_never_listed(self):
        ok, n, err = feeds.refresh_feeds(self.cfg, [ipaddress.ip_network("45.9.148.0/24")])
        self.assertNotIn("45.9.148", self.listed())

    def test_private_and_too_wide_entries_are_dropped(self):
        self.data["https://a.example/list"] = ["10.0.0.0/8", "192.168.1.0/24", "80.0.0.0/4", "45.9.148.0/24"]
        feeds.refresh_feeds(self.cfg, [])
        out = self.listed()
        self.assertIn("45.9.148.0/24", out)
        for bad in ("10.0.0.0", "192.168", "80.0.0.0"):
            self.assertNotIn(bad, out)


if __name__ == "__main__":
    unittest.main()
