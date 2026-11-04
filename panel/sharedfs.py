"""Shared files for high availability: certificates, keys, alert secrets, threat-feed data and OWASP rule sets must be identical on every replica.

Each replica keeps its own local copy under /data (the engine reads plain files), and this module mirrors the few files that must be shared
through the database: whoever writes a file calls publish(); every replica calls sync_in() when the shared-files version changes.

Security: everything stored in the database is encrypted and authenticated (Fernet, key from the secret SHIELD_DATA_KEY), so a database dump
does not reveal private keys, and somebody who can only write to the database cannot plant files on a replica. On top of that only a fixed
list of path shapes is ever written (never a path taken from the database), and archives are extracted with the same checks as rule-set downloads.
Without PostgreSQL or without the key the module is switched off and the panel works as a single instance."""
import hashlib
import io
import os
import re
import shutil
import tarfile
import time

import store

DATA = store.DATA
KEY = os.environ.get("SHIELD_DATA_KEY", "").strip()
_f = None
InvalidToken = Exception
if KEY and store.PG:
    try:
        from cryptography.fernet import Fernet, InvalidToken
        _f = Fernet(KEY.encode())
    except Exception as e:  # noqa: BLE001
        print(f"[shieldwaf] SHIELD_DATA_KEY is not usable ({type(e).__name__}); shared files are OFF: run a single replica only", flush=True)

# The only things that may be shared: single files and directories (trees).
_FILES = re.compile(r"^(secret\.key|challenge\.key|bootstrap\.code|feeds/feed\.geo|secrets/[A-Za-z0-9_-]{1,64}\.json)$")
_TREES = re.compile(r"^(geo|acme|certs/[A-Za-z0-9_-]{1,64}|crs/v[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})$")
_PRIVATE = re.compile(r"^(secret\.key|challenge\.key|bootstrap\.code|secrets/|certs/)")
MAX_UNIT = 40 * 1024 * 1024
MAX_FILES = 3000
_known = {}          # path -> sha of the content this replica has in place


def enabled():
    return _f is not None


def valid(rel):
    return bool(_FILES.match(rel) or _TREES.match(rel))


_PANEL_ONLY = re.compile(r"^(secret\.key|bootstrap\.code|secrets/)")


def _abs(rel):
    """Local place of a shared file. Panel-only secrets go to store.PRIVATE (not visible to the engine container); everything the engine reads stays under /data."""
    return os.path.join(store.PRIVATE if _PANEL_ONLY.match(rel) else DATA, *rel.split("/"))


def _is_tree(rel):
    return bool(_TREES.match(rel))


def _tree_files(root):
    out = []
    for base, _dirs, files in os.walk(root):
        for n in sorted(files):
            full = os.path.join(base, n)
            if os.path.isfile(full) and not os.path.islink(full) and not n.startswith("."):
                out.append((os.path.relpath(full, root).replace(os.sep, "/"), full))
    return sorted(out)


def local_sha(rel):
    """Content hash of this replica's copy ('' when it has none)."""
    p = _abs(rel)
    if not _is_tree(rel):
        if not os.path.isfile(p):
            return ""
        with open(p, "rb") as f:
            return hashlib.sha256(f.read()).hexdigest()
    if not os.path.isdir(p):
        return ""
    h = hashlib.sha256()
    for name, full in _tree_files(p):
        with open(full, "rb") as f:
            h.update(name.encode() + b"\0" + hashlib.sha256(f.read()).digest())
    return h.hexdigest()


def present(rel):
    """Does this replica have real content for the unit (a tree counts only when it holds at least one file)?"""
    p = _abs(rel)
    return bool(_tree_files(p)) if _is_tree(rel) and os.path.isdir(p) else os.path.isfile(p)


def _pack(rel):
    p = _abs(rel)
    if not _is_tree(rel):
        with open(p, "rb") as f:
            return f.read()
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for name, full in _tree_files(p):
            ti = tarfile.TarInfo(name)
            ti.size = os.path.getsize(full)
            ti.mode = 0o600 if _PRIVATE.match(rel) else 0o644
            ti.mtime = 0
            with open(full, "rb") as f:
                tf.addfile(ti, f)
    return buf.getvalue()


def _unpack(rel, data):
    """Write the content of one shared unit onto this replica's disk (atomically replacing the previous copy)."""
    p = _abs(rel)
    private = bool(_PRIVATE.match(rel))
    if not _is_tree(rel):
        os.makedirs(os.path.dirname(p), mode=0o700, exist_ok=True)
        tmp = p + ".incoming"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600 if private else 0o644)
        with os.fdopen(fd, "wb") as f:
            f.write(data)
        os.replace(tmp, p)
        return
    tmp = p + ".incoming"
    shutil.rmtree(tmp, ignore_errors=True)
    os.makedirs(tmp, mode=0o700)
    count = 0
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tf:
        for m in tf:
            if not m.isreg() or m.name.startswith("/") or ".." in m.name.split("/") or "\\" in m.name:
                raise ValueError("unsafe entry in a shared archive")
            count += 1
            if count > MAX_FILES:
                raise ValueError("too many files in a shared archive")
            dest = os.path.join(tmp, *m.name.split("/"))
            os.makedirs(os.path.dirname(dest), mode=0o700, exist_ok=True)
            fd = os.open(dest, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600 if private else 0o644)
            with tf.extractfile(m) as src, os.fdopen(fd, "wb") as out:
                shutil.copyfileobj(src, out)
    old = p + ".old"
    shutil.rmtree(old, ignore_errors=True)
    if os.path.exists(p):
        os.replace(p, old)
    os.makedirs(os.path.dirname(p), mode=0o700, exist_ok=True)
    os.replace(tmp, p)
    shutil.rmtree(old, ignore_errors=True)


def _bump(con):
    con.execute("INSERT INTO counters(k,v) VALUES('files_ver',1) ON CONFLICT(k) DO UPDATE SET v=counters.v+1")


def publish(rel, only_if_absent=False):
    """Make this replica's copy of `rel` the shared one. Returns True when it was stored."""
    if not enabled():
        return False
    if not valid(rel):
        raise ValueError("not a shareable path: " + rel)
    if not present(rel):
        return False                                  # never publish an empty directory
    data = _pack(rel)
    if len(data) > MAX_UNIT:
        raise ValueError("shared file too large")
    sha = local_sha(rel)
    token = _f.encrypt(data).decode()
    con = store.db()
    kind = "tree" if _is_tree(rel) else "file"
    conflict = "DO NOTHING" if only_if_absent else "DO UPDATE SET kind=excluded.kind, sha=excluded.sha, mode=excluded.mode, data=excluded.data, updated=excluded.updated"
    cur = con.execute(f"INSERT INTO sfiles(path,kind,sha,mode,data,updated) VALUES(?,?,?,?,?,?) ON CONFLICT(path) {conflict}",  # nosec B608 - fixed text
                      (rel, kind, sha, 0o600 if _PRIVATE.match(rel) else 0o644, token, time.time()))
    stored = cur.rowcount > 0
    if stored:
        _bump(con)
    con.commit()
    if stored:
        _known[rel] = sha
    return stored


def forget(rel):
    """Remove a shared unit (the site was deleted, the secret was removed ...). Other replicas delete their copy on their next sync."""
    if not enabled() or not valid(rel):
        return
    con = store.db()
    cur = con.execute("DELETE FROM sfiles WHERE path=?", (rel,))
    if cur.rowcount > 0:
        _bump(con)
    con.commit()
    _known.pop(rel, None)


def sync_in():
    """Bring this replica's copies up to date with the shared ones. Returns True when something changed."""
    if not enabled():
        return False
    con = store.db()
    rows = con.execute("SELECT path, kind, sha FROM sfiles").fetchall()
    con.commit()
    changed, present = False, set()
    for r in rows:
        rel, sha = r["path"], r["sha"]
        if not valid(rel):
            continue
        present.add(rel)
        if _known.get(rel) == sha:
            continue
        if local_sha(rel) == sha:
            _known[rel] = sha
            continue
        row = con.execute("SELECT data FROM sfiles WHERE path=?", (rel,)).fetchone()
        con.commit()
        if not row:
            continue
        try:
            data = _f.decrypt(row["data"].encode())
            _unpack(rel, data)
            if local_sha(rel) != sha:
                raise ValueError("content hash differs after unpacking")
        except (InvalidToken, ValueError, OSError, tarfile.TarError) as e:
            print(f"[shieldwaf] shared file {rel} rejected: {type(e).__name__}: {e}", flush=True)
            continue
        _known[rel] = sha
        changed = True
    for rel in [k for k in _known if k not in present]:       # removed by another replica
        p = _abs(rel)
        shutil.rmtree(p, ignore_errors=True) if _is_tree(rel) else (os.path.exists(p) and os.remove(p))
        _known.pop(rel, None)
        changed = True
    return changed


def ensure(rel, generate):
    """Create a shared unit exactly once across all replicas. `generate()` writes the local copy; the first replica to publish wins and
    the others adopt its copy (so two replicas starting together never end up with different keys)."""
    if not enabled():
        if not present(rel):
            generate()
        return
    sync_in()
    if present(rel) and _known.get(rel):
        return
    if not present(rel):
        generate()
    publish(rel, only_if_absent=True)
    sync_in()
