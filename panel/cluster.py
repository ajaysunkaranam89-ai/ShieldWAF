"""High availability: several identical replicas (pods) share one PostgreSQL database and behave as one firewall.

* Every replica renders and runs its own nginx from the shared configuration (the data path never depends on the database or on another replica).
* sync_loop(): when anybody saves a change (configuration version) or publishes a shared file (files version), every replica applies it itself.
* Administrator actions are serialised across replicas by a database lock (store._lock) and report whether every replica applied the change.
* Exactly one replica at a time is the *leader* (a PostgreSQL advisory lock held on a dedicated connection; it is released the moment that
  replica dies). Only the leader runs the jobs that must happen once: threat-feed and country downloads, rule-set checks, auto-ban,
  under-attack escalation, attack-spike alerts, certificate warnings, pruning.
* heartbeat(): every replica reports itself in the `nodes` table; the Cluster page and the "applied on N/N replicas" message read it."""
import hashlib
import json
import threading
import time
import urllib.request

import engine
import sharedfs
import store

LEADER_KEY = 724002
ALIVE_S = 12
_st = {"leader": not store.PG, "applied": (-1, -1), "ok": True, "msg": "starting", "fails": 0, "last_try": 0.0, "since_leader": 0.0}
_started = time.time()
_apply_lock = threading.Lock()
VERSION = "2.3"


def is_leader():
    return _st["leader"]


def leader_only(fn):
    """Wrap a background job so it only runs on the leader replica."""
    def run():
        if is_leader():
            fn()
    run.__name__ = fn.__name__
    return run


# ----------------------------------------------------------------------------------------------- leader election
def _leader_loop():
    if not store.PG:
        return
    con = None
    while True:
        try:
            if con is None or con.closed:
                con = store.psycopg2.connect(store.DB_URL, connect_timeout=10)
                con.autocommit = True
                _st["leader"] = False
            cur = con.cursor()
            if _st["leader"]:
                cur.execute("SELECT 1")                       # a dead connection raises here and leadership is dropped
            else:
                cur.execute("SELECT pg_try_advisory_lock(%s)", (LEADER_KEY,))
                if cur.fetchone()[0]:
                    _st["leader"], _st["since_leader"] = True, time.time()
                    print(f"[shieldwaf] {store.NODE} is now the leader", flush=True)
            cur.close()
        except Exception as e:  # noqa: BLE001
            if _st["leader"]:
                print(f"[shieldwaf] leadership lost ({type(e).__name__})", flush=True)
            _st["leader"] = False
            try:
                if con is not None:
                    con.close()
            except Exception:  # noqa: BLE001
                pass
            con = None
        time.sleep(2)


# ----------------------------------------------------------------------------------------------- applying changes
def _cfg_hash(cfg):
    return hashlib.sha1(json.dumps(cfg, sort_keys=True).encode()).hexdigest()  # nosec B324 - change detection only


def sync_once(force=False):
    """Apply whatever changed since this replica last applied. Cheap when nothing changed (one tiny query)."""
    ver = store.state_version()
    if ver == _st["applied"] and not force:
        return
    with _apply_lock:
        sharedfs.sync_in()
        ver = store.state_version()                          # read again: files may have been published while we pulled
        cfg = store.load(fresh=True)
        if (_cfg_hash(cfg), ver[1]) == engine.LAST.get("key"):
            _st.update(applied=ver, ok=True, msg="", fails=0)    # we rendered exactly this (we are the replica that made the change)
            return
        ok, msg = engine.render(cfg, files_ver=ver[1])
        if ok:
            _st.update(applied=ver, ok=True, msg="", fails=0)
        else:
            _st.update(ok=False, msg=str(msg)[:300], fails=_st["fails"] + 1)
            print(f"[shieldwaf] could not apply configuration v{ver[0]}: {msg}", flush=True)


def note_applied(cfg_ver, files_ver=None):
    """Called after this replica rendered and saved a change itself, so it does not render the same thing again."""
    cur = _st["applied"]
    _st["applied"] = (cfg_ver, files_ver if files_ver is not None else cur[1])


def _sync_loop():
    while True:
        try:
            if _st["ok"] or time.time() - _st["last_try"] > 5:      # after a failure retry every 5 s, not every second
                _st["last_try"] = time.time()
                sync_once()
        except Exception as e:  # noqa: BLE001
            _st.update(ok=False, msg=f"{type(e).__name__}: {e}"[:300])
            print(f"[shieldwaf] sync error: {e}", flush=True)
        time.sleep(1)


def mark_applied_now():
    """After a local, saved change: this replica is current (it rendered the config it just saved)."""
    ver = store.state_version()
    _st.update(applied=ver, ok=True, msg="", fails=0)
    heartbeat()


# ----------------------------------------------------------------------------------------------- the replicas
def _engine_ok():
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{engine.HTTP_PORT}/__shieldwaf_health", timeout=1) as r:  # nosec B310 - fixed loopback URL
            return r.status == 200
    except Exception:  # noqa: BLE001
        return False


def heartbeat():
    con = store.db()
    info = {"leader": is_leader(), **engine.LAST.get("stats", {})}
    con.execute(
        "INSERT INTO nodes(name,ts,started,applied_cfg,applied_files,ok,msg,version,engine_ok,info) VALUES(?,?,?,?,?,?,?,?,?,?) "
        "ON CONFLICT(name) DO UPDATE SET ts=excluded.ts, applied_cfg=excluded.applied_cfg, applied_files=excluded.applied_files, ok=excluded.ok, "
        "msg=excluded.msg, version=excluded.version, engine_ok=excluded.engine_ok, info=excluded.info",
        (store.NODE, time.time(), _started, _st["applied"][0], _st["applied"][1], 1 if _st["ok"] else 0, _st["msg"], VERSION,
         1 if _engine_ok() else 0, json.dumps(info)))
    con.commit()


def _heartbeat_loop():
    while True:
        try:
            heartbeat()
            if is_leader():
                store.db().execute("DELETE FROM nodes WHERE ts<?", (time.time() - 86400,))
                store.db().commit()
        except Exception as e:  # noqa: BLE001
            print(f"[shieldwaf] heartbeat error: {e}", flush=True)
        time.sleep(3)


def nodes():
    rows = store.db().execute("SELECT * FROM nodes ORDER BY name").fetchall()
    store.db().commit()
    now, out = time.time(), []
    for r in rows:
        r = dict(r)
        try:
            r["info"] = json.loads(r.get("info") or "{}")
        except ValueError:
            r["info"] = {}
        r["alive"] = now - float(r["ts"]) < ALIVE_S
        r["me"] = r["name"] == store.NODE
        out.append(r)
    return out


def wait_for_peers(cfg_ver, timeout=25.0):
    """After saving configuration version `cfg_ver`, wait until every live replica has applied it. Returns (done, total, text)."""
    end = time.time() + timeout
    while True:
        live = [n for n in nodes() if n["alive"]]
        done = [n for n in live if int(n["applied_cfg"]) >= cfg_ver and n["ok"]]
        if len(done) == len(live) or time.time() > end:
            break
        time.sleep(0.3)
    lag = [n["name"] for n in live if n not in done]
    text = f"applied on {len(done)}/{len(live)} replicas" if len(live) > 1 else ""
    if lag:
        text += f" ({', '.join(lag)} still applying: it keeps retrying and the Cluster page shows its status)"
    return len(done), len(live), text


def current_version():
    cfg_ver, _ = store.state_version()
    return cfg_ver


def start():
    """Start the leader election, the replica heartbeat and the change-applying loop."""
    for fn, name in ((_leader_loop, "leader"), (_heartbeat_loop, "heartbeat"), (_sync_loop, "sync")):
        threading.Thread(target=fn, daemon=True, name=name).start()
