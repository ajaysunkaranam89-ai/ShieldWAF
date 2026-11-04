"""Panel-only secrets are kept apart from the files the engine reads (module C)."""
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "panel"))
os.environ.setdefault("SHIELD_DATA", tempfile.mkdtemp())
import sharedfs  # noqa: E402
import store  # noqa: E402


class PrivatePaths(unittest.TestCase):
    def setUp(self):
        self.old = store.PRIVATE
        store.PRIVATE = "/private"
        sharedfs.DATA = "/data"

    def tearDown(self):
        store.PRIVATE = self.old

    def test_panel_only_secrets_go_to_the_private_folder(self):
        for rel in ("secret.key", "bootstrap.code", "secrets/acme_account.json", "secrets/oidc.json", "secrets/ch1.json"):
            with self.subTest(rel=rel):
                self.assertEqual(sharedfs._abs(rel), os.path.join("/private", *rel.split("/")))

    def test_what_the_engine_reads_stays_under_data(self):
        for rel in ("challenge.key", "certs/site1", "acme", "geo", "feeds/feed.geo", "crs/v4.30.0"):
            with self.subTest(rel=rel):
                self.assertEqual(sharedfs._abs(rel), os.path.join("/data", *rel.split("/")))


if __name__ == "__main__":
    unittest.main()
