"""Tests for the authenticated backup format (panel/backupcrypt.py): AES-256-GCM chunks, tamper / truncation / reorder detection, key ring, rotation."""
import base64
import io
import os
import struct
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "panel"))
import backupcrypt as bc  # noqa: E402

KEY = os.urandom(32)
KID = "0a1b2c3d"
RING = {KID: KEY}
SMALL = 4096                                   # smallest chunk size the reader accepts: lets tests use several chunks cheaply


def enc(data, key=KEY, kid=KID, chunk=SMALL):
    out = io.BytesIO()
    bc.encrypt_stream(io.BytesIO(data), out, key, kid, chunk)
    return out.getvalue()


def dec(blob, ring=RING):
    out = io.BytesIO()
    bc.decrypt_stream(io.BytesIO(blob), out, ring)
    return out.getvalue()


class RoundTrip(unittest.TestCase):
    def test_sizes_around_the_chunk_boundary(self):
        for n in (0, 1, SMALL - 1, SMALL, SMALL + 1, 2 * SMALL, 2 * SMALL + 7, 10 * SMALL + 123):
            with self.subTest(n=n):
                data = os.urandom(n)
                self.assertEqual(dec(enc(data)), data)

    def test_the_file_does_not_contain_the_plaintext(self):
        data = b"PGDMP-this-is-a-secret-database-dump-" * 500
        blob = enc(data)
        self.assertNotIn(b"secret-database-dump", blob)
        self.assertNotIn(b"PGDMP", blob[bc.HEADER.size:])
        self.assertTrue(blob.startswith(bc.MAGIC))

    def test_size_is_header_plus_plaintext_plus_one_tag_per_chunk(self):
        data = os.urandom(3 * SMALL + 5)
        self.assertEqual(len(enc(data)), bc.HEADER.size + len(data) + 4 * bc.TAG)

    def test_streaming_returns_totals(self):
        out = io.BytesIO()
        total, chunks = bc.encrypt_stream(io.BytesIO(b"x" * (2 * SMALL + 1)), out, KEY, KID, SMALL)
        self.assertEqual((total, chunks), (2 * SMALL + 1, 3))


class Tampering(unittest.TestCase):
    def setUp(self):
        self.data = os.urandom(5 * SMALL + 100)
        self.blob = enc(self.data)

    def flip(self, offset, blob=None):
        b = bytearray(blob or self.blob)
        b[offset] ^= 0x01
        return bytes(b)

    def test_any_flipped_byte_anywhere_is_detected(self):
        step = max(1, len(self.blob) // 60)
        for off in list(range(0, len(self.blob), step)) + [len(self.blob) - 1]:
            with self.subTest(offset=off):
                with self.assertRaises(bc.BackupError):
                    dec(self.flip(off))

    def test_header_changes_are_detected(self):
        for off in (0, 4, 5, 8, 9, 16, 17, 20):                 # magic, version, key id, nonce prefix, chunk size
            with self.subTest(offset=off):
                with self.assertRaises(bc.BackupError):
                    dec(self.flip(off))

    def test_truncation_is_detected_everywhere(self):
        for cut in (bc.HEADER.size, bc.HEADER.size + 1, bc.HEADER.size + SMALL + bc.TAG, bc.HEADER.size + 2 * (SMALL + bc.TAG), len(self.blob) - 1, len(self.blob) - bc.TAG):
            with self.subTest(cut=cut):
                with self.assertRaises(bc.BackupError):
                    dec(self.blob[:cut])

    def test_dropping_the_last_chunk_at_a_boundary_is_detected(self):
        blob = enc(os.urandom(3 * SMALL))                    # exactly 3 full chunks
        with self.assertRaises(bc.BackupError):
            dec(blob[:bc.HEADER.size + 2 * (SMALL + bc.TAG)])

    def test_appended_data_is_detected(self):
        for extra in (b"\x00", os.urandom(SMALL + bc.TAG), b"x" * 5):
            with self.subTest(n=len(extra)):
                with self.assertRaises(bc.BackupError):
                    dec(self.blob + extra)

    def test_reordering_chunks_is_detected(self):
        h, size = bc.HEADER.size, SMALL + bc.TAG
        c0, c1 = self.blob[h:h + size], self.blob[h + size:h + 2 * size]
        swapped = self.blob[:h] + c1 + c0 + self.blob[h + 2 * size:]
        with self.assertRaises(bc.BackupError):
            dec(swapped)

    def test_duplicating_a_chunk_is_detected(self):
        h, size = bc.HEADER.size, SMALL + bc.TAG
        c0 = self.blob[h:h + size]
        with self.assertRaises(bc.BackupError):
            dec(self.blob[:h] + c0 + self.blob[h:])

    def test_chunks_from_another_backup_cannot_be_spliced_in(self):
        other = enc(os.urandom(5 * SMALL + 100))
        h, size = bc.HEADER.size, SMALL + bc.TAG
        spliced = self.blob[:h] + other[h:h + size] + self.blob[h + size:]
        with self.assertRaises(bc.BackupError):
            dec(spliced)

    def test_a_wrong_key_or_unknown_key_id_is_refused(self):
        with self.assertRaises(bc.BackupError):
            dec(self.blob, {KID: os.urandom(32)})
        with self.assertRaises(bc.BackupError) as cm:
            dec(self.blob, {"ffffffff": KEY})
        self.assertIn("key ring", str(cm.exception))

    def test_not_a_backup_and_old_formats_are_refused_with_a_clear_message(self):
        for blob in (b"", b"Salted__" + os.urandom(100), b"PGDMP" + os.urandom(100), b"SWBK"):
            with self.subTest(blob=blob[:8]):
                with self.assertRaises(bc.BackupError):
                    dec(blob)

    def test_a_damaged_chunk_size_in_the_header_is_refused(self):
        h = bytearray(self.blob)
        h[17:21] = struct.pack(">I", 1)
        with self.assertRaises(bc.BackupError):
            dec(bytes(h))

    def test_no_plaintext_is_released_before_the_tag_is_checked(self):
        out = io.BytesIO()
        bad = self.flip(bc.HEADER.size + 10)                  # damage inside the FIRST chunk
        with self.assertRaises(bc.BackupError):
            bc.decrypt_stream(io.BytesIO(bad), out, RING)
        self.assertEqual(out.getvalue(), b"")


class Nonces(unittest.TestCase):
    def test_every_chunk_of_every_file_uses_a_different_nonce(self):
        seen = set()
        for _ in range(40):
            blob = enc(os.urandom(6 * SMALL))
            _h, _k, prefix, _c = bc.read_header(io.BytesIO(blob))
            for i in range(6):
                n = bc._nonce(prefix, i)
                self.assertNotIn(n, seen)
                seen.add(n)
        self.assertEqual(len(seen), 240)

    def test_two_encryptions_of_the_same_data_differ(self):
        data = os.urandom(SMALL)
        self.assertNotEqual(enc(data), enc(data))


class KeyRing(unittest.TestCase):
    def make_dir(self, keys, current):
        d = tempfile.mkdtemp()
        for kid, k in keys.items():
            open(os.path.join(d, f"key-{kid}"), "w").write(base64.b64encode(k).decode())
        open(os.path.join(d, "current"), "w").write(current)
        return d

    def test_load_and_rotation(self):
        k1, k2 = os.urandom(32), os.urandom(32)
        d = self.make_dir({"11111111": k1, "22222222": k2}, "22222222")
        cur, ring = bc.load_keyring(d)
        self.assertEqual(cur, "22222222")
        old = enc(b"old backup", k1, "11111111")
        new = enc(b"new backup", ring[cur], cur)
        self.assertEqual(dec(old, ring), b"old backup")         # an old key stays in the ring: old backups remain readable
        self.assertEqual(dec(new, ring), b"new backup")
        self.assertEqual(bc.read_header(io.BytesIO(old))[1], "11111111")
        self.assertEqual(bc.read_header(io.BytesIO(new))[1], "22222222")

    def test_a_missing_or_short_key_is_a_clear_error(self):
        with self.assertRaises(bc.BackupError):
            bc.load_keyring(tempfile.mkdtemp())
        d = self.make_dir({"11111111": b"short"}, "11111111")
        with self.assertRaises(bc.BackupError):
            bc.load_keyring(d)
        d = self.make_dir({"11111111": os.urandom(32)}, "99999999")
        with self.assertRaises(bc.BackupError):
            bc.load_keyring(d)

    def test_new_keys_are_random_and_well_formed(self):
        ids = set()
        for _ in range(50):
            kid, material = bc.new_key()
            self.assertRegex(kid, r"^[0-9a-f]{8}$")
            self.assertEqual(len(base64.b64decode(material)), 32)
            ids.add(kid)
        self.assertGreater(len(ids), 45)


class Files(unittest.TestCase):
    def test_verify_file_and_resolve(self):
        d = tempfile.mkdtemp()
        p = os.path.join(d, "shieldwaf-20260101-000000.swbk")
        open(p, "wb").write(enc(b"data" * 1000))
        self.assertEqual(bc.verify_file(p, RING)[0], 4000)
        self.assertEqual(bc.resolve_file(d, "latest"), p)
        with self.assertRaises(bc.BackupError):
            bc.resolve_file(d, "../etc/passwd")                  # no path traversal through the file name
        with self.assertRaises(bc.BackupError):
            bc.resolve_file(d, "missing.swbk")

    def test_prune_keeps_recent_files_and_removes_old_ones(self):
        import time
        d = tempfile.mkdtemp()
        old, new = os.path.join(d, "shieldwaf-old.swbk"), os.path.join(d, "shieldwaf-new.swbk")
        for p in (old, new, old + ".json"):
            open(p, "wb").write(b"x")
        os.utime(old, (time.time() - 40 * 86400,) * 2)
        os.utime(old + ".json", (time.time() - 40 * 86400,) * 2)
        self.assertEqual(bc.prune(d, 14), 1)
        self.assertEqual(sorted(os.listdir(d)), ["shieldwaf-new.swbk"])

    def test_s3_refuses_plain_http(self):
        with self.assertRaises(bc.BackupError):
            bc.s3_put("http://example.com", "b", "k", __file__, "a", "s")


if __name__ == "__main__":
    unittest.main(verbosity=2)
