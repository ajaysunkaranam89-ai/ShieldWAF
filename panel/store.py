"""Persistent state for ShieldWAF: JSON config (sites, settings, users, bans) + SQLite (events, access hits, audit)."""
import json
import os
import sqlite3
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
    "panel_allow_ips": "",          # CIDRs allowed to reach the admin panel (empty = anyone who can reach the port)
    "upstream_allow": "",           # if set, upstream host names must end with one of these suffixes (one per line)
    "metrics_token": "",            # bearer token required for /metrics (generated at first start)
    "session_idle_min": 30,
    # IP reputation feeds (non-pattern defence): known-bad networks are refused before any rule runs
    "feeds": {"enabled": True, "refresh_hours": 6, "last_ok": 0, "last_count": 0, "last_error": "",
              "sources": [
                  {"name": "Spamhaus DROP (hijacked networks)", "url": "https://www.spamhaus.org/drop/drop.txt", "on": True},
                  {"name": "FireHOL level 1 (attackers, botnets)", "url": "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset", "on": True},
              ]},
    # alerting + SIEM export (channels are managed in the GUI; secrets live in /data/secrets, never here)
    "alerts": {"channels": [], "cooldown_s": 300, "spike": {"enabled": True, "blocked_per_min": 100},
               "events": {"engine_down": True, "engine_recovered": True, "config_failed": True, "under_attack": True, "attack_spike": True,
                          "auto_ban": True, "login_lockout": True, "admin_change": True, "cert_expiring": True, "feeds_failed": True,
                          "rules_update": True}},
    # OWASP rule-set updates (see crsupdate.py): "baked" = the version inside the image
    "crs": {"active": "baked", "previous": "", "staged": "", "staged_sha256": "", "staged_at": 0, "latest": "", "checked_at": 0,
            "error": "", "auto_stage": True},
    # layer-7 DoS defence: automatic "under attack" mode when one site receives too many requests per second
    "ddos": {"auto": False, "rps_threshold": 200, "window_s": 20, "hold_min": 15},
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
    "methods": "GET HEAD POST PUT DELETE PATCH OPTIONS",
    "tls": {"enabled": False, "source": "none",       # none | uploaded | selfsigned | mounted
            "redirect_http": True, "redirect_port": "", "hsts": True, "hsts_days": 365, "mounted_name": ""},
    "auth": {"enabled": False, "realm": "Restricted", "users": {}},      # users: name -> crypt hash (never shown)
    "challenge": {"enabled": False, "difficulty": 4, "ttl_hours": 12, "scope": "pages", "exclude_paths": ""},
    "positive": {"enabled": False, "paths": "", "content_types": "application/json application/x-www-form-urlencoded multipart/form-data text/plain",
                 "max_url": 2048},          # positive security model: only what is listed gets through
    "openapi": {"mode": "off", "spec": "", "strict": True, "unknown_paths": "allow", "report": []},   # OpenAPI request validation
    "crs_channel": "stable",        # stable = active rule set; canary = staged rule set in detect-only mode
    "geo": {"mode": "off", "countries": ""},      # off | deny | allow  + country codes such as CN RU
    "under_attack": False, "ua_until": 0,   # forces the challenge for everyone + a rate limit; ua_until>0 = automatic, ends by itself
    "exclusions": [],               # [{"rule": "942100", "path": "/api/upload"}]  (path optional)
    "custom_rules": "",
    "page_maint": "", "page_down": "",   # per-site override HTML (empty = use global page)
}


def _default_cfg():
    return {"users": {}, "settings": json.loads(json.dumps(DEFAULT_SETTINGS)), "sites": [], "bans": [], "pages": {"maintenance": "", "down": ""}}


def load():
    with _lock:
        cfg = _read_config()
        base = _default_cfg()
        for k, v in base.items():
            cfg.setdefault(k, v)
        for k, v in DEFAULT_SETTINGS.items():
            cfg["settings"].setdefault(k, v)
        for k, v in DEFAULT_SETTINGS["autoban"].items():
            cfg["settings"]["autoban"].setdefault(k, v)
        cfg["settings"]["feeds"].setdefault("sources", DEFAULT_SETTINGS["feeds"]["sources"])
        for k, v in DEFAULT_SETTINGS["feeds"].items():
            cfg["settings"]["feeds"].setdefault(k, v)
        for k, v in DEFAULT_SETTINGS["crs"].items():
            cfg["settings"].setdefault("crs", {}).setdefault(k, v)
        for k, v in DEFAULT_SETTINGS["alerts"].items():
            cfg["settings"].setdefault("alerts", {}).setdefault(k, json.loads(json.dumps(v)))
        for k, v in DEFAULT_SETTINGS["alerts"]["events"].items():
            cfg["settings"]["alerts"]["events"].setdefault(k, v)
        for k, v in DEFAULT_SETTINGS["ddos"].items():
            cfg["settings"].setdefault("ddos", {}).setdefault(k, v)
        for s in cfg["sites"]:
            for k, v in DEFAULT_SITE.items():
                s.setdefault(k, json.loads(json.dumps(v)))
            for k in ("positive", "openapi"):
                for kk, vv in DEFAULT_SITE[k].items():
                    s[k].setdefault(kk, json.loads(json.dumps(vv)))
        return cfg


_cache = {"t": 0.0, "raw": None}


def _read_config():
    """The saved configuration as a dict (defaults are merged by load()). Stored as JSON text in the `config` table."""
    now = time.time()
    raw = _cache["raw"] if _cache["raw"] is not None and now - _cache["t"] < 2.0 else None
    if raw is None:
        r = db().execute("SELECT data FROM config WHERE id=1").fetchone()
        if r:
            raw = r["data"]
        else:
            try:    # first start after an upgrade from the file-based store
                with open(CFG_PATH, encoding="utf-8") as f:
                    raw = f.read()
            except OSError:
                return _default_cfg()
        _cache.update(t=now, raw=raw)
    try:
        return json.loads(raw)
    except ValueError:
        return _default_cfg()


def save(cfg):
    with _lock:
        raw = json.dumps(cfg)
        con = db()
        con.execute("INSERT INTO config(id, data) VALUES(1, ?) ON CONFLICT(id) DO UPDATE SET data=excluded.data", (raw,))
        con.commit()
        _cache.update(t=time.time(), raw=raw)


# --------------------------------------------------------------------------------------------------- database
# PostgreSQL in production (SHIELD_DB_URL=postgresql://user:password@host:5432/dbname); SQLite only as a fallback for local tests.
DB_URL = os.environ.get("SHIELD_DB_URL", "")
PG = DB_URL.startswith(("postgres://", "postgresql://"))
if PG:
    import psycopg2
    import psycopg2.extras

HOUR = "CAST(FLOOR(ts/3600) AS INTEGER)" if PG else "CAST(ts/3600 AS INTEGER)"
_local = threading.local()


class _Conn:
    """The same tiny API for both databases: execute / executemany / commit, '?' placeholders, rows readable by column name."""

    def __init__(self):
        if PG:
            self.raw = psycopg2.connect(DB_URL, connect_timeout=10)
        else:
            os.makedirs(DATA, exist_ok=True)
            self.raw = sqlite3.connect(DB_PATH, timeout=30)
            self.raw.row_factory = sqlite3.Row
            self.raw.execute("PRAGMA journal_mode=WAL")

    def _cur(self):
        return self.raw.cursor(cursor_factory=psycopg2.extras.RealDictCursor) if PG else self.raw.cursor()

    @staticmethod
    def _sql(sql):
        return sql.replace("%", "%%").replace("?", "%s") if PG else sql

    def _run(self, fn):
        try:
            return fn()
        except Exception:
            try:
                self.raw.rollback()
            except Exception:  # noqa: BLE001
                _local.con = None          # connection is gone: reconnect on next use
            raise

    def execute(self, sql, params=()):
        def go():
            cur = self._cur()
            cur.execute(self._sql(sql), params)
            return cur
        return self._run(go)

    def executemany(self, sql, rows):
        def go():
            cur = self._cur()
            cur.executemany(self._sql(sql), rows)
            return cur
        return self._run(go)

    def commit(self):
        self._run(self.raw.commit)


def db():
    con = getattr(_local, "con", None)
    if con is None or (PG and con.raw.closed):
        con = _Conn()
        _local.con = con
    return con


def init_db():
    pk = "BIGSERIAL PRIMARY KEY" if PG else "INTEGER PRIMARY KEY"
    ddl = f"""
    CREATE TABLE IF NOT EXISTS config(id INTEGER PRIMARY KEY, data TEXT);
    CREATE TABLE IF NOT EXISTS events(id {pk}, ts DOUBLE PRECISION, ip TEXT, host TEXT, method TEXT, uri TEXT,
        rule_id TEXT, msg TEXT, score TEXT, status INTEGER, blocked INTEGER);
    CREATE INDEX IF NOT EXISTS ev_ts ON events(ts);
    CREATE TABLE IF NOT EXISTS access(ts DOUBLE PRECISION, ip TEXT, host TEXT, status INTEGER, rt DOUBLE PRECISION);
    CREATE INDEX IF NOT EXISTS ac_ts ON access(ts);
    CREATE TABLE IF NOT EXISTS audit(ts DOUBLE PRECISION, username TEXT, action TEXT, detail TEXT, ip TEXT DEFAULT '');
    CREATE TABLE IF NOT EXISTS meta(k TEXT PRIMARY KEY, v TEXT);
    CREATE TABLE IF NOT EXISTS sessions(sid TEXT PRIMARY KEY, username TEXT, created DOUBLE PRECISION, last DOUBLE PRECISION, ip TEXT);
    CREATE TABLE IF NOT EXISTS alert_log(ts DOUBLE PRECISION, channel TEXT, event TEXT, title TEXT, ok INTEGER, error TEXT);
    CREATE TABLE IF NOT EXISTS login_fail(ts DOUBLE PRECISION, username TEXT, ip TEXT);
    CREATE INDEX IF NOT EXISTS lf_ts ON login_fail(ts);
    CREATE TABLE IF NOT EXISTS counters(k TEXT PRIMARY KEY, v BIGINT);
    """
    for attempt in range(40):          # the database pod may still be starting
        try:
            con = db()
            for stmt in [x.strip() for x in ddl.split(";") if x.strip()]:
                con.execute(stmt)
            con.commit()
            return
        except Exception as e:  # noqa: BLE001
            if not PG or attempt == 39:
                raise
            print(f"[shieldwaf] waiting for the database ({type(e).__name__}) ...", flush=True)
            _local.con = None
            time.sleep(3)


def audit(user, action, detail="", ip=""):
    con = db()
    con.execute("INSERT INTO audit VALUES(?,?,?,?,?)", (time.time(), user, action, detail[:500], ip))
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
    con.execute("INSERT INTO counters(k,v) VALUES(?,?) ON CONFLICT(k) DO UPDATE SET v=counters.v+excluded.v", (k, n))
    con.commit()
