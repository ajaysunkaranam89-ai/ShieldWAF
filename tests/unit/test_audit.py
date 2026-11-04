"""Tests for the migrations and the tamper-evident audit trail (panel/store.py). Uses SQLite (no cluster)."""
import json
import os
import sys
import tempfile
import threading
import time
import unittest

os.environ["SHIELD_DATA"] = tempfile.mkdtemp()
os.environ["SHIELD_AUDIT_KEY"] = "unit-test-audit-key"
os.environ.pop("SHIELD_DB_URL", None)
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "panel"))
import store  # noqa: E402

store.init_db()


def raw(sql, params=()):
    con = store.db()
    cur = con.execute(sql, params)
    con.commit()
    return cur


class Migrations(unittest.TestCase):
    def test_all_migrations_are_recorded_once(self):
        rows = store.db().execute("SELECT version, name FROM schema_migrations ORDER BY version").fetchall()
        store.db().commit()
        self.assertEqual([r["version"] for r in rows], [1, 2])
        store.migrate()
        store.migrate()                                    # running again changes nothing
        again = store.db().execute("SELECT COUNT(*) c FROM schema_migrations").fetchone()["c"]
        store.db().commit()
        self.assertEqual(again, 2)
        self.assertEqual(store.current_schema_version(), 2)

    def test_the_audit_table_has_the_chain_columns(self):
        cols = {r[1] for r in store.db().raw.execute("PRAGMA table_info(audit)").fetchall()}
        self.assertTrue({"seq", "category", "request_id", "prev_hash", "hash"} <= cols)


class Chain(unittest.TestCase):
    def setUp(self):
        raw("DELETE FROM audit")
        raw("DELETE FROM meta WHERE k LIKE 'audit_anchor%'")

    def fill(self, n=5):
        return [store.audit("alice", f"site updated {i}", f"detail {i}", "10.0.0.1") for i in range(n)]

    def test_records_are_chained_in_order(self):
        recs = self.fill(4)
        self.assertEqual([r["seq"] for r in recs], [1, 2, 3, 4])
        self.assertEqual(recs[0]["prev_hash"], "genesis")
        for a, b in zip(recs, recs[1:]):
            self.assertEqual(b["prev_hash"], a["hash"])
        self.assertTrue(store.verify_audit()["ok"])

    def test_a_changed_record_is_detected_and_named(self):
        self.fill(6)
        raw("UPDATE audit SET detail='forged' WHERE seq=3")
        res = store.verify_audit()
        self.assertFalse(res["ok"])
        self.assertEqual(res["broken_at"], 3)
        self.assertIn("changed", res["reason"])

    def test_a_changed_actor_or_time_or_ip_is_detected(self):
        for col, val in (("username", "mallory"), ("ts", 1.0), ("ip", "6.6.6.6"), ("action", "nothing happened"), ("category", "admin")):
            self.setUp()
            self.fill(3)
            raw(f"UPDATE audit SET {col}=? WHERE seq=2", (val,))
            self.assertEqual(store.verify_audit()["broken_at"], 2, col)

    def test_a_removed_record_in_the_middle_is_detected(self):
        self.fill(5)
        raw("DELETE FROM audit WHERE seq=3")
        res = store.verify_audit()
        self.assertFalse(res["ok"])
        self.assertEqual(res["broken_at"], 3)
        self.assertIn("missing", res["reason"])

    def test_a_forged_record_without_the_key_is_detected(self):
        recs = self.fill(3)
        # an attacker who can only write to the database re-computes the hash with the algorithm but not the key
        import hashlib
        import hmac
        forged = {"seq": 4, "ts": time.time(), "username": "mallory", "action": "settings saved", "category": "policy", "detail": "x", "ip": "", "request_id": "", "prev_hash": recs[-1]["hash"]}
        body = json.dumps(forged, sort_keys=True, separators=(",", ":")).encode()
        forged["hash"] = hmac.new(b"guessed-key", body, hashlib.sha256).hexdigest()
        raw("INSERT INTO audit(seq,ts,username,action,detail,ip,category,request_id,prev_hash,hash) VALUES(?,?,?,?,?,?,?,?,?,?)",
            (4, forged["ts"], "mallory", "settings saved", "x", "", "policy", "", forged["prev_hash"], forged["hash"]))
        self.assertEqual(store.verify_audit()["broken_at"], 4)

    def test_swapping_two_records_is_detected(self):
        self.fill(4)
        raw("UPDATE audit SET seq=99 WHERE seq=2")
        raw("UPDATE audit SET seq=2 WHERE seq=3")
        raw("UPDATE audit SET seq=3 WHERE seq=99")
        self.assertFalse(store.verify_audit()["ok"])

    def test_a_different_key_cannot_verify(self):
        self.fill(3)
        old = os.environ["SHIELD_AUDIT_KEY"]
        os.environ["SHIELD_AUDIT_KEY"] = "another-key"
        try:
            self.assertFalse(store.verify_audit()["ok"])
        finally:
            os.environ["SHIELD_AUDIT_KEY"] = old
        self.assertTrue(store.verify_audit()["ok"])

    def test_concurrent_writers_keep_one_unbroken_chain(self):
        def work(n):
            for i in range(25):
                store.audit(f"u{n}", "login", f"{n}-{i}", "1.2.3.4")
        threads = [threading.Thread(target=work, args=(n,)) for n in range(6)]
        [t.start() for t in threads]
        [t.join() for t in threads]
        res = store.verify_audit()
        self.assertTrue(res["ok"], res)
        self.assertEqual(res["records"], 150)
        seqs = [r["seq"] for r in store.db().execute("SELECT seq FROM audit ORDER BY seq").fetchall()]
        store.db().commit()
        self.assertEqual(seqs, list(range(1, 151)))

    def test_categories_request_id_and_limits(self):
        store.set_request_id("req-abc-12345678")
        r = store.audit("a" * 100, "login " + "x" * 200, "d" * 5000, "i" * 200)
        self.assertEqual(r["category"], "auth")
        self.assertEqual(r["request_id"], "req-abc-12345678")
        self.assertEqual((len(r["username"]), len(r["action"]), len(r["detail"]), len(r["ip"])), (64, 80, 2000, 64))
        for action, cat in (("certificate requested", "certificate"), ("user added", "user"), ("backup-restore", "backup"), ("site updated", "policy"),
                            ("auto-ban", "security"), ("2fa enabled", "auth"), ("something else", "admin"), ("ssrf-upstream-blocked", "security")):
            self.assertEqual(store.categorize(action), cat, action)

    def test_a_failing_hook_never_breaks_the_audited_action(self):
        got = []
        store.audit_hooks.append(lambda rec: got.append(rec["seq"]))
        store.audit_hooks.append(lambda rec: 1 / 0)
        try:
            store.audit("x", "login", "")
        finally:
            store.audit_hooks.clear()
        self.assertEqual(len(got), 1)
        self.assertTrue(store.verify_audit()["ok"])


class Backfill(unittest.TestCase):
    def test_legacy_rows_are_chained_once_and_none_is_lost(self):
        raw("DELETE FROM audit")
        for i in range(4):
            raw("INSERT INTO audit(ts,username,action,detail,ip) VALUES(?,?,?,?,?)", (1000.0 + i, "old", "login", "legacy", "9.9.9.9"))
        raw("INSERT INTO audit(ts,username,action,detail,ip) VALUES(?,?,?,?,?)", (1000.0, "old", "login", "legacy", "9.9.9.9"))     # an exact duplicate
        self.assertEqual(store.backfill_audit_chain(), 5)
        self.assertEqual(store.backfill_audit_chain(), 0)
        res = store.verify_audit()
        self.assertTrue(res["ok"], res)
        self.assertEqual(res["records"], 5)


class ExportAndRetention(unittest.TestCase):
    def setUp(self):
        raw("DELETE FROM audit")
        raw("DELETE FROM meta WHERE k LIKE 'audit_anchor%'")
        for i in range(8):
            store.audit("alice", "site updated", f"d{i}", "1.1.1.1")

    def test_export_verifies_offline(self):
        lines = list(store.audit_export())
        self.assertEqual(len(lines), 9)
        self.assertTrue(json.loads(lines[0])["log_type"] == "audit" and "@timestamp" in json.loads(lines[0]))
        self.assertTrue(store.verify_export(lines)["ok"])

    def test_export_tampering_is_detected(self):
        lines = list(store.audit_export())
        d = json.loads(lines[3])
        d["detail"] = "forged"
        lines[3] = json.dumps(d)
        res = store.verify_export(lines)
        self.assertFalse(res["ok"])
        self.assertEqual(res["broken_at"], d["seq"])

    def test_cut_short_or_wrongly_signed_exports_are_refused(self):
        lines = list(store.audit_export())
        self.assertFalse(store.verify_export(lines[:-1])["ok"])                                     # no checkpoint
        cp = json.loads(lines[-1])
        cp["head_seq"] = 3
        self.assertFalse(store.verify_export(lines[:-1] + [json.dumps(cp)])["ok"])                  # signature no longer matches
        self.assertFalse(store.verify_export(lines[:3] + lines[4:])["ok"])                          # a record taken out

    def test_truncation_of_the_tail_is_caught_by_an_earlier_checkpoint(self):
        cp = json.loads(list(store.audit_export())[-1])
        self.assertTrue(store.check_checkpoint(cp)["ok"])
        raw("DELETE FROM audit WHERE seq>5")                       # the chain alone still verifies...
        self.assertTrue(store.verify_audit()["ok"])
        self.assertFalse(store.check_checkpoint(cp)["ok"])         # ...but the earlier export proves records are gone

    def test_retention_keeps_the_rest_verifiable(self):
        raw("UPDATE audit SET ts=? WHERE seq<=4", (time.time() - 100 * 86400,))
        removed = store.audit_purge(time.time() - 30 * 86400)
        self.assertEqual(removed, 4)
        res = store.verify_audit()
        self.assertTrue(res["ok"], res)
        self.assertEqual(res["records"], 4)
        store.audit("alice", "login", "after retention")
        self.assertTrue(store.verify_audit()["ok"])
        raw("DELETE FROM audit WHERE seq=6")
        self.assertFalse(store.verify_audit()["ok"])

    def test_checkpoint_of_removed_records_is_explained_by_the_anchor(self):
        cp = json.loads(list(store.audit_export(since_seq=0, until_seq=3))[-1])
        raw("UPDATE audit SET ts=? WHERE seq<=4", (time.time() - 100 * 86400,))
        store.audit_purge(time.time() - 30 * 86400)
        res = store.check_checkpoint(cp)
        self.assertTrue(res["ok"], res)


if __name__ == "__main__":
    unittest.main(verbosity=2)
