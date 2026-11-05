"""Policy approval and site version history (module O): the rules, on a real database layer (SQLite)."""
import copy
import os
import sys
import tempfile
import time
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "panel"))
os.environ.setdefault("SHIELD_DATA", tempfile.mkdtemp())
import policy  # noqa: E402
import store  # noqa: E402


def site(host="a.test", **kw):
    s = copy.deepcopy(store.DEFAULT_SITE)
    s.update(id="sx1", host=host, upstream="http://10.0.0.5:80")
    s.update(kw)
    return s


class Policy(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        store.init_db()

    def setUp(self):
        con = store.db()
        con.execute("DELETE FROM policy_changes")
        con.execute("DELETE FROM policy_versions")
        con.commit()
        self.cfg = {"settings": {"policy": {"approval": True, "allow_self_approve": False}}, "sites": []}

    def test_diff_lists_changes_and_flags_the_risky_ones(self):
        old, new = site(), site()
        new["mode"] = "detect"
        new["rate_limit"]["enabled"] = True
        new["upstream"] = "http://10.0.0.6:80"
        d = {r["field"]: r for r in policy.diff(old, new)}
        self.assertEqual(set(d), {"mode", "rate_limit.enabled", "upstream"})
        self.assertTrue(d["mode"]["risky"] and d["upstream"]["risky"])
        self.assertEqual(d["mode"]["old"], "block")

    def test_background_job_fields_are_not_changes(self):
        old, new = site(), site()
        new["tls"]["acme_state"] = "issued"
        new["ssrf_seen"] = {"x": ["1.1.1.1"]}
        new["ssrf_blocked"] = ["http://bad"]
        self.assertEqual(policy.diff(old, new), [])
        self.assertEqual(policy.fingerprint(old), policy.fingerprint(new))

    def test_password_hashes_of_the_login_gate_are_never_shown(self):
        old, new = site(), site()
        new["auth"]["users"] = {"bob": "$6$secrethash"}
        rows = policy.diff(old, new)
        self.assertTrue(rows)
        self.assertNotIn("secrethash", repr(rows))

    def test_submit_get_and_listing(self):
        cid, err = policy.submit("update", "sx1", "a.test", "alice", site(), site(mode="off"))
        self.assertIsNone(err)
        ch = policy.get(cid)
        self.assertEqual((ch["status"], ch["author"], ch["kind"]), ("pending", "alice", "update"))
        self.assertEqual(ch["new"]["mode"], "off")
        self.assertTrue(policy.listing()[0]["risky"])

    def test_the_author_cannot_approve_their_own_change(self):
        cid, _ = policy.submit("update", "sx1", "a.test", "alice", site(), site(mode="off"))
        ch = policy.get(cid)
        self.assertFalse(policy.can_decide(self.cfg, ch, "alice")[0])
        self.assertTrue(policy.can_decide(self.cfg, ch, "bob")[0])
        self.cfg["settings"]["policy"]["allow_self_approve"] = True
        self.assertTrue(policy.can_decide(self.cfg, ch, "alice")[0])

    def test_a_decided_change_cannot_be_decided_again(self):
        cid, _ = policy.submit("create", "sx1", "a.test", "alice", None, site())
        policy.mark(cid, "approved", "bob")
        self.assertFalse(policy.can_decide(self.cfg, policy.get(cid), "carol")[0])
        policy.mark(cid, "rejected", "carol")                       # a late second decision does not overwrite the first
        self.assertEqual(policy.get(cid)["status"], "approved")

    def test_a_change_made_against_an_older_version_is_stale(self):
        live = site()
        cid, _ = policy.submit("update", "sx1", "a.test", "alice", live, site(mode="detect"))
        self.cfg["sites"] = [live]
        self.assertFalse(policy.stale(self.cfg, policy.get(cid)))
        self.cfg["sites"] = [site(paranoia=2)]                       # somebody else changed the site in the meantime
        self.assertTrue(policy.stale(self.cfg, policy.get(cid)))
        cid2, _ = policy.submit("create", "sx1", "a.test", "alice", None, site())
        self.assertTrue(policy.stale(self.cfg, policy.get(cid2)))   # creating something that now exists

    def test_pending_changes_expire(self):
        cid, _ = policy.submit("create", "sx1", "a.test", "alice", None, site())
        con = store.db()
        con.execute("UPDATE policy_changes SET ts=? WHERE id=?", (time.time() - policy.EXPIRE_S - 5, cid))
        con.commit()
        policy.expire_old()
        self.assertEqual(policy.get(cid)["status"], "expired")

    def test_versions_are_kept_in_order_with_who_and_diff(self):
        policy.record_version(site(), "created", "alice")
        policy.record_version(site(mode="detect"), "updated", "alice", "bob")
        vs = policy.versions("sx1")
        self.assertEqual([v["version"] for v in vs], [2, 1])
        self.assertEqual((vs[0]["author"], vs[0]["approver"]), ("alice", "bob"))
        self.assertEqual([r["field"] for r in policy.versions_diff("sx1", 1, 2)], ["mode"])
        self.assertEqual(policy.get_version("sx1", 1)["site"]["mode"], "block")

    def test_merge_volatile_keeps_what_background_jobs_wrote(self):
        live = site()
        live["tls"]["acme_state"] = "issued"
        live["ssrf_blocked"] = ["http://x"]
        merged = policy.merge_volatile(site(mode="off"), live)
        self.assertEqual(merged["tls"]["acme_state"], "issued")
        self.assertEqual(merged["ssrf_blocked"], ["http://x"])
        self.assertEqual(merged["mode"], "off")

    def test_settings_default_to_off(self):
        self.assertFalse(policy.enabled({"settings": {}}))
        self.assertTrue(policy.enabled(self.cfg))


if __name__ == "__main__":
    unittest.main()
