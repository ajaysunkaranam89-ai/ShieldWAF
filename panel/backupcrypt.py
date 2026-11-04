"""Authenticated, encrypted database backups (AES-256-GCM), key ring with rotation, verification, restore test and an S3-compatible off-cluster copy.

File format "SWBK" (streamed, so a large database never has to fit in memory):
    header  = magic "SWBK" | version 1 | key id (4 bytes) | random nonce prefix (8 bytes) | chunk size (4 bytes)      (21 bytes, authenticated as AAD of every chunk)
    chunk i = AES-256-GCM(key, nonce = prefix | i (4 bytes), aad = header | i | final-flag, plaintext chunk) || 16-byte tag
Every chunk has its own nonce (a random 64-bit prefix per FILE plus the chunk counter: unique for 2^32 chunks per file, and a new prefix for every file),
carries an authentication tag, and the AAD binds it to this header, this position and whether it is the last chunk: a flipped bit, a reordered or swapped
chunk, a chunk taken from another backup, or a file cut short is detected before any plaintext is released to the next stage.
Keys: a directory (default /keys, a Kubernetes secret that is NOT the database secret and is never stored next to the backups): `current` holds the id of the
key to encrypt with, `key-<id>` holds the base64 of 32 random bytes. Old keys stay in the ring so old backups remain readable; rotation = add a key, change `current`."""
import argparse
import base64
import datetime
import hashlib
import hmac
import json
import os
import secrets
import struct
import subprocess
import sys
import tempfile
import time
import urllib.parse
import urllib.request

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

MAGIC = b"SWBK"
VERSION = 1
CHUNK = 1024 * 1024
HEADER = struct.Struct(">4sB4s8sI")          # 21 bytes
TAG = 16
KEYS_DIR = os.environ.get("SHIELD_BACKUP_KEYS_DIR", "/keys")


class BackupError(Exception):
    pass


# ------------------------------------------------------------------------------------------------------------ keys
def load_keyring(directory=None):
    """Returns (current key id, {key id: 32-byte key}). Key ids are 8 hex characters."""
    d = directory or KEYS_DIR
    try:
        current = open(os.path.join(d, "current")).read().strip()
    except OSError as e:
        raise BackupError(f"no backup key found in {d}: create one with scripts/create-backup-key.sh") from e
    ring = {}
    for name in os.listdir(d):
        if name.startswith("key-") and len(name) == 12:
            raw = base64.b64decode(open(os.path.join(d, name)).read().strip())
            if len(raw) != 32:
                raise BackupError(f"key {name} is not 32 bytes")
            ring[name[4:]] = raw
    if current not in ring:
        raise BackupError(f"the current key id {current} is not in the key ring")
    return current, ring


def new_key():
    """(id, base64 key material) for a new ring entry."""
    return secrets.token_hex(4), base64.b64encode(secrets.token_bytes(32)).decode()


def _aad(header, index, last):
    return header + struct.pack(">IB", index, 1 if last else 0)


def _nonce(prefix, index):
    return prefix + struct.pack(">I", index)


# ------------------------------------------------------------------------------------------------------------ streams
def encrypt_stream(src, dst, key, key_id, chunk=CHUNK):
    """Encrypt everything read from `src` into `dst`. Returns (plaintext bytes, chunks)."""
    prefix = secrets.token_bytes(8)
    header = HEADER.pack(MAGIC, VERSION, bytes.fromhex(key_id), prefix, chunk)
    dst.write(header)
    aes, index, total = AESGCM(key), 0, 0
    buf = src.read(chunk)
    while True:
        nxt = src.read(chunk) if len(buf) == chunk else b""
        last = not nxt
        dst.write(aes.encrypt(_nonce(prefix, index), buf, _aad(header, index, last)))
        total += len(buf)
        index += 1
        if last:
            break
        if index >= 2 ** 32 - 1:
            raise BackupError("backup too large for one file")
        buf = nxt
    return total, index


def read_header(src):
    raw = src.read(HEADER.size)
    if len(raw) != HEADER.size:
        raise BackupError("not a ShieldWAF backup (too short)")
    magic, ver, kid, prefix, chunk = HEADER.unpack(raw)
    if magic != MAGIC or ver != VERSION:
        raise BackupError("not a ShieldWAF backup, or an unknown version (is it an old 2.3 backup? see docs/ROLLBACK_GUIDE.md)")
    if not 4096 <= chunk <= 64 * 1024 * 1024:
        raise BackupError("the header is damaged (chunk size)")
    return raw, kid.hex(), prefix, chunk


def decrypt_stream(src, dst, ring):
    """Decrypt `src` into `dst`, chunk by chunk. Raises BackupError on any authentication failure; plaintext of a chunk is only written after its tag is valid.
    Returns (plaintext bytes, chunks)."""
    header, kid, prefix, chunk = read_header(src)
    if kid not in ring:
        raise BackupError(f"this backup was made with key {kid}, which is not in the key ring")
    aes, index, total = AESGCM(ring[kid]), 0, 0
    size = chunk + TAG
    buf = src.read(size)
    if not buf:
        raise BackupError("the backup has no data")
    while True:
        nxt = src.read(size) if len(buf) == size else b""
        last = not nxt
        try:
            plain = aes.decrypt(_nonce(prefix, index), buf, _aad(header, index, last))
        except InvalidTag:
            raise BackupError(f"authentication failed at chunk {index}: the backup is damaged, was modified, is truncated, or the key is wrong") from None
        dst.write(plain)
        total += len(plain)
        index += 1
        if last:
            break
        buf = nxt
    return total, index


class _Null:
    def write(self, b):
        return len(b)


def verify_file(path, ring):
    with open(path, "rb") as f:
        return decrypt_stream(f, _Null(), ring)


# ------------------------------------------------------------------------------------------------------------ S3 (SigV4, no extra libraries)
def _sign(key, msg):
    return hmac.new(key, msg.encode(), hashlib.sha256).digest()


def _s3_call(method, url_base, bucket, key_name, access, secret, region="us-east-1", token=None, path=None, now=None):
    """One S3 request with AWS Signature V4 (path-style, HTTPS). A request body is a file; it is not hashed (UNSIGNED-PAYLOAD) because the backup is already authenticated."""
    u = urllib.parse.urlparse(url_base)
    if u.scheme != "https" and not os.environ.get("SHIELD_BACKUP_ALLOW_HTTP"):
        raise BackupError("the backup destination must be https:// (set SHIELD_BACKUP_ALLOW_HTTP=1 only for a local test)")
    now = now or datetime.datetime.utcnow()
    amz, day = now.strftime("%Y%m%dT%H%M%SZ"), now.strftime("%Y%m%d")
    canon_uri = "/" + urllib.parse.quote(bucket + ("/" + key_name if key_name else ""), safe="/-_.~")
    size = os.path.getsize(path) if path else 0
    headers = {"host": u.netloc, "x-amz-content-sha256": "UNSIGNED-PAYLOAD" if path else hashlib.sha256(b"").hexdigest(), "x-amz-date": amz}
    if path:
        headers["content-length"] = str(size)
    if token:
        headers["x-amz-security-token"] = token
    signed = ";".join(sorted(headers))
    canon = "\n".join([method, canon_uri, "", "".join(f"{k}:{headers[k]}\n" for k in sorted(headers)), signed, headers["x-amz-content-sha256"]])
    scope = f"{day}/{region}/s3/aws4_request"
    to_sign = "\n".join(["AWS4-HMAC-SHA256", amz, scope, hashlib.sha256(canon.encode()).hexdigest()])
    k = _sign(_sign(_sign(_sign(("AWS4" + secret).encode(), day), region), "s3"), "aws4_request")
    sig = hmac.new(k, to_sign.encode(), hashlib.sha256).hexdigest()
    send = {"Authorization": f"AWS4-HMAC-SHA256 Credential={access}/{scope}, SignedHeaders={signed}, Signature={sig}", "x-amz-date": amz,
            "x-amz-content-sha256": headers["x-amz-content-sha256"]}
    if token:
        send["x-amz-security-token"] = token
    fh = open(path, "rb") if path else None
    try:
        if fh:
            send["Content-Length"] = str(size)
        req = urllib.request.Request(f"{u.scheme}://{u.netloc}{canon_uri}", data=fh, method=method, headers=send)
        try:
            with urllib.request.urlopen(req, timeout=600) as r:  # nosec B310 - operator-configured destination, https enforced above
                return r.status, dict(r.headers)
        except urllib.error.HTTPError as e:
            return e.code, dict(e.headers)
    finally:
        if fh:
            fh.close()


def s3_put(url_base, bucket, key_name, path, access, secret, region="us-east-1", token=None, now=None):
    status, _h = _s3_call("PUT", url_base, bucket, key_name, access, secret, region, token, path, now)
    if status not in (200, 201):
        raise BackupError(f"the independent destination refused the upload (HTTP {status})")
    return os.path.getsize(path)


def s3_head(url_base, bucket, key_name, access, secret, region="us-east-1", token=None):
    """(HTTP status, size in bytes or None) of an object: used to prove the independent copy exists and has the right size."""
    status, h = _s3_call("HEAD", url_base, bucket, key_name, access, secret, region, token)
    return status, (int({k.lower(): v for k, v in h.items()}.get("content-length", -1)) if status == 200 else None)


def s3_make_bucket(url_base, bucket, access, secret, region="us-east-1", token=None):
    status, _h = _s3_call("PUT", url_base, bucket, "", access, secret, region, token)
    return status in (200, 409)


# ------------------------------------------------------------------------------------------------------------ database
def _log(kind, detail):
    """Tell the panel (it moves this into the audit chain). Never fails the backup."""
    try:
        import psycopg2
        c = psycopg2.connect(host=os.environ.get("PGHOST", "shieldwaf-db"), user=os.environ.get("PGUSER", "shieldwaf"), dbname=os.environ.get("PGDATABASE", "shieldwaf"),
                             password=os.environ.get("PGPASSWORD", ""), connect_timeout=10, sslmode=os.environ.get("PGSSLMODE", "prefer"))
        cur = c.cursor()
        cur.execute("INSERT INTO backup_log(ts, kind, detail) VALUES (%s, %s, %s)", (time.time(), kind, detail[:400]))
        c.commit()
        c.close()
    except Exception as e:  # noqa: BLE001
        print(f"[backup] could not write the audit event: {type(e).__name__}", file=sys.stderr)


def cmd_backup(a):
    current, ring = load_keyring()
    os.makedirs(a.out, exist_ok=True)
    stamp = time.strftime("%Y%m%d-%H%M%S", time.gmtime())
    final = os.path.join(a.out, f"shieldwaf-{stamp}.swbk")
    part = final + ".part"
    dump = subprocess.Popen(["pg_dump", "-Fc"], stdout=subprocess.PIPE)
    try:
        with open(part, "wb") as dst:
            os.chmod(part, 0o600)
            total, chunks = encrypt_stream(dump.stdout, dst, ring[current], current)
        if dump.wait() != 0:
            raise BackupError("pg_dump failed")
        if total < 100:
            raise BackupError("the dump is empty")
        t, _ = verify_file(part, ring)                      # read it back: every tag must be valid and the size must match
        if t != total:
            raise BackupError("read-back size differs")
        os.replace(part, final)
    finally:
        if dump.poll() is None:
            dump.kill()
        if os.path.exists(part):
            os.remove(part)
    meta = {"file": os.path.basename(final), "created": datetime.datetime.utcnow().isoformat() + "Z", "plain_bytes": total, "chunks": chunks, "key_id": current,
            "format": "SWBK v1 AES-256-GCM"}
    json.dump(meta, open(final + ".json", "w"))
    print(f"backup written and verified: {final} ({os.path.getsize(final)} bytes, key {current}, AES-256-GCM, {chunks} chunk(s))", flush=True)
    removed = prune(a.out, a.keep_days)
    detail = f"{os.path.basename(final)} {os.path.getsize(final)} bytes key {current}"
    if a.s3_bucket:
        up = os.environ
        size = s3_put(up["BACKUP_S3_ENDPOINT"], a.s3_bucket, (a.s3_prefix.strip("/") + "/" if a.s3_prefix else "") + os.path.basename(final), final,
                      up["AWS_ACCESS_KEY_ID"], up["AWS_SECRET_ACCESS_KEY"], up.get("AWS_REGION", "us-east-1"), up.get("AWS_SESSION_TOKEN"))
        print(f"copied to the independent destination: s3://{a.s3_bucket}/{a.s3_prefix} ({size} bytes)", flush=True)
        detail += " + independent copy"
    _log("backup", detail)
    print(f"removed {removed} old backup(s); backups on the volume:", flush=True)
    for f in sorted(x for x in os.listdir(a.out) if x.endswith(".swbk"))[-20:]:
        print("  " + f)


def prune(directory, keep_days):
    n = 0
    for f in os.listdir(directory):
        p = os.path.join(directory, f)
        if f.startswith("shieldwaf-") and f.endswith((".swbk", ".swbk.json")) and time.time() - os.path.getmtime(p) > keep_days * 86400:
            os.remove(p)
            n += f.endswith(".swbk")
        elif f.endswith(".part") and time.time() - os.path.getmtime(p) > 7200:
            os.remove(p)
    return n


def newest(directory):
    files = sorted(f for f in os.listdir(directory) if f.startswith("shieldwaf-") and f.endswith(".swbk"))
    return os.path.join(directory, files[-1]) if files else None


def resolve_file(directory, name):
    if name == "latest":
        p = newest(directory)
        if not p:
            raise BackupError("no backups found")
        return p
    if os.sep in name or name.startswith("."):
        raise BackupError("give the file name only")
    p = os.path.join(directory, name)
    if not os.path.isfile(p):
        raise BackupError(f"no such backup: {name}")
    return p


def cmd_verify(a):
    _cur, ring = load_keyring()
    p = resolve_file(a.dir, a.file)
    total, chunks = verify_file(p, ring)
    print(f"verified: {os.path.basename(p)}: {chunks} chunk(s), {total} bytes of dump, every authentication tag is valid", flush=True)
    if a.restore_test:
        restore_test(p, ring)
    _log("verify", f"{os.path.basename(p)} ok" + (" + restore test" if a.restore_test else ""))


def restore_test(path, ring):
    """Restore into a throw-away database on the same server, count the tables, drop it. Proves the backup is usable, not just intact."""
    name = "swverify_" + secrets.token_hex(4)
    subprocess.run(["createdb", name], check=True, capture_output=True)
    try:
        with open(path, "rb") as f:
            pr = subprocess.Popen(["pg_restore", "--no-owner", "--no-privileges", "-d", name], stdin=subprocess.PIPE, stderr=subprocess.PIPE)
            decrypt_stream(f, pr.stdin, ring)
            pr.stdin.close()
            err = pr.stderr.read().decode(errors="replace")
            if pr.wait() != 0:
                raise BackupError("restore test failed: " + err[-300:])
        out = subprocess.run(["psql", "-d", name, "-tAc", "SELECT count(*) FROM information_schema.tables WHERE table_schema='public'"], capture_output=True, text=True, check=True).stdout.strip()
        if int(out or 0) < 5:
            raise BackupError(f"restore test: only {out} tables came back")
        print(f"restore test passed: {out} tables restored into a temporary database and removed again", flush=True)
    finally:
        subprocess.run(["dropdb", "--if-exists", name], capture_output=True)


def cmd_restore(a):
    _cur, ring = load_keyring()
    p = resolve_file(a.dir, a.file)
    verify_file(p, ring)                                    # nothing is touched unless the whole file authenticates first
    print(f"restoring {os.path.basename(p)} (authenticated) ...", flush=True)
    with open(p, "rb") as f:
        pr = subprocess.Popen(["pg_restore", "--clean", "--if-exists", "--no-owner", "--no-privileges", "-d", os.environ.get("PGDATABASE", "shieldwaf")], stdin=subprocess.PIPE)
        decrypt_stream(f, pr.stdin, ring)
        pr.stdin.close()
        if pr.wait() != 0:
            raise BackupError("pg_restore reported errors")
    _log("restore", f"{os.path.basename(p)} restored")
    print(f"database restored from {os.path.basename(p)}", flush=True)


def cmd_reencrypt(a):
    """Re-encrypt old backups with the current key (after a rotation, before you retire an old key)."""
    current, ring = load_keyring()
    n = 0
    for f in sorted(os.listdir(a.dir)):
        if not (f.startswith("shieldwaf-") and f.endswith(".swbk")):
            continue
        p = os.path.join(a.dir, f)
        with open(p, "rb") as fh:
            _h, kid, _pre, _c = read_header(fh)
        if kid == current:
            continue
        tmp = p + ".part"
        with open(p, "rb") as src, tempfile.TemporaryFile() as mid:
            decrypt_stream(src, mid, ring)
            mid.seek(0)
            with open(tmp, "wb") as dst:
                encrypt_stream(mid, dst, ring[current], current)
        verify_file(tmp, ring)
        os.replace(tmp, p)
        n += 1
        print(f"re-encrypted {f}: key {kid} -> {current}", flush=True)
    print(f"{n} backup(s) re-encrypted", flush=True)


def cmd_list(a):
    for f in sorted(x for x in os.listdir(a.dir) if x.startswith("shieldwaf-") and x.endswith(".swbk")):
        p = os.path.join(a.dir, f)
        with open(p, "rb") as fh:
            try:
                _h, kid, _pre, _c = read_header(fh)
            except BackupError:
                kid = "?"
        print(f"{f}  {os.path.getsize(p)} bytes  key {kid}  {time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(os.path.getmtime(p)))} UTC")
    if not any(x.endswith(".swbk") for x in os.listdir(a.dir)):
        print("no backups yet")


def main(argv=None):
    ap = argparse.ArgumentParser(prog="backupcrypt")
    sub = ap.add_subparsers(dest="cmd", required=True)
    b = sub.add_parser("backup")
    b.add_argument("--out", default="/backups")
    b.add_argument("--keep-days", type=int, default=14)
    b.add_argument("--s3-bucket", default="")
    b.add_argument("--s3-prefix", default="")
    for name in ("verify", "restore"):
        v = sub.add_parser(name)
        v.add_argument("file")
        v.add_argument("--dir", default="/backups")
        if name == "verify":
            v.add_argument("--restore-test", action="store_true")
    for name in ("reencrypt", "list"):
        sub.add_parser(name).add_argument("--dir", default="/backups")
    a = ap.parse_args(argv)
    try:
        {"backup": cmd_backup, "verify": cmd_verify, "restore": cmd_restore, "reencrypt": cmd_reencrypt, "list": cmd_list}[a.cmd](a)
    except BackupError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
