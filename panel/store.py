"""Persistent state for ShieldWAF: JSON config (sites, settings, users, bans) + SQLite (events, access hits, audit)."""
import json
import os
import sqlite3
import tempfile
import threading
import time

DATA = os.environ.get("SHIELD_DATA", "/data")
CFG_PATH = os.path.join(DATA, "config.json")
DB_PATH = os.path.join(DATA, "shield.db")
_lock = threading.RLock()

DEFAULT_SETTINGS = {
    "trusted_proxies": "",          # CIDRs whose X-Forwarded-For is trusted (one per line)
    "never_ban": "127.0.0.1",       # IPs/CIDRs the auto-ban must never ban
    "autoban": {"enabled": False, "threshold": 10, "window_min": 5, "ban_min": 30},
    "retention_days": 7,
}

DEFAULT_SITE = {
    "id": "", "host": "", "upstream": "", "enabled": True,
    "mode": "block",                # block | detect | off
    "paranoia": 1,                  # OWASP CRS paranoia level 1..4
    "threshold": 5,                 # inbound anomaly score that triggers a block
    "maintenance": False,
    "down_page": True,
    "rate_limit": {"enabled": False, "rps": 10, "burst": 20},
    "allow_ips": [], "deny_ips": [],
    "block_bots": True, "sec_headers": True,
    "max_body_mb": 10,
    "exclusions": [],               # [{"rule": "942100", "path": "/api/upload"}]  (path optional)
    "custom_rules": "",
    "page_maint": "", "page_down": "",   # per-site override HTML (empty = use global page)
}


def _default_cfg():
    return {"users": {}, "settings": json.loads(json.dumps(DEFAULT_SETTINGS)), "sites": [], "bans": [], "pages": {"maintenance": "", "down": ""}}


def load():
    with _lock:
        try:
            with open(CFG_PATH, encoding="utf-8") as f:
                cfg = json.load(f)
        except (FileNotFoundError, ValueError):
            cfg = _default_cfg()
        base = _default_cfg()
        for k, v in base.items():
            cfg.setdefault(k, v)
        for k, v in DEFAULT_SETTINGS.items():
            cfg["settings"].setdefault(k, v)
        for k, v in DEFAULT_SETTINGS["autoban"].items():
            cfg["settings"]["autoban"].setdefault(k, v)
        for s in cfg["sites"]:
            for k, v in DEFAULT_SITE.items():
                s.setdefault(k, json.loads(json.dumps(v)))
        return cfg


def save(cfg):
    with _lock:
        os.makedirs(DATA, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=DATA, prefix=".cfg-")
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(cfg, f, indent=1)
        os.replace(tmp, CFG_PATH)


_local = threading.local()


def db():
    con = getattr(_local, "con", None)
    if con is None:
        os.makedirs(DATA, exist_ok=True)
        con = sqlite3.connect(DB_PATH, timeout=30)
        con.row_factory = sqlite3.Row
        con.execute("PRAGMA journal_mode=WAL")
        _local.con = con
    return con


def init_db():
    con = db()
    con.executescript("""
    CREATE TABLE IF NOT EXISTS events(id INTEGER PRIMARY KEY, ts REAL, ip TEXT, host TEXT, method TEXT, uri TEXT,
        rule_id TEXT, msg TEXT, score TEXT, status INTEGER, blocked INTEGER);
    CREATE INDEX IF NOT EXISTS ev_ts ON events(ts);
    CREATE TABLE IF NOT EXISTS access(ts REAL, ip TEXT, host TEXT, status INTEGER, rt REAL);
    CREATE INDEX IF NOT EXISTS ac_ts ON access(ts);
    CREATE TABLE IF NOT EXISTS audit(ts REAL, user TEXT, action TEXT, detail TEXT);
    CREATE TABLE IF NOT EXISTS meta(k TEXT PRIMARY KEY, v TEXT);
    CREATE TABLE IF NOT EXISTS counters(k TEXT PRIMARY KEY, v INTEGER);
    """)
    con.commit()


def audit(user, action, detail=""):
    con = db()
    con.execute("INSERT INTO audit VALUES(?,?,?,?)", (time.time(), user, action, detail[:500]))
    con.commit()


def meta_get(k, default=None):
    r = db().execute("SELECT v FROM meta WHERE k=?", (k,)).fetchone()
    return r["v"] if r else default


def meta_set(k, v):
    con = db()
    con.execute("INSERT INTO meta(k,v) VALUES(?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v", (k, str(v)))
    con.commit()


def counter_add(k, n=1):
    con = db()
    con.execute("INSERT INTO counters(k,v) VALUES(?,?) ON CONFLICT(k) DO UPDATE SET v=v+excluded.v", (k, n))
    con.commit()
