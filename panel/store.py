"""Persistent state for ShieldWAF: the configuration (sites, settings, users, bans), events, access hits, audit trail, sessions.
PostgreSQL in production; every replica of the panel talks to the same database (see cluster.py for high availability)."""
import contextlib
import hashlib
import hmac
import json
import os
import re
import sqlite3
import threading
import time

DATA = os.environ.get("SHIELD_DATA", "/data")
# Panel-only secrets (session key, setup code, alert and ACME/OIDC secrets) live here. In Kubernetes this is a volume that only the PANEL container mounts, so the
# engine container (which parses untrusted traffic) cannot read them. Unset = the same folder as DATA, as in 2.3.
PRIVATE = os.environ.get("SHIELD_PRIVATE", "") or DATA
CFG_PATH = os.path.join(DATA, "config.json")
DB_PATH = os.path.join(DATA, "shield.db")
NODE = os.environ.get("SHIELD_NODE") or os.environ.get("HOSTNAME") or "local"     # this replica (the pod name in Kubernetes)


class _ClusterLock:
    """A re-entrant lock that is also cluster-wide: with several replicas, only one administrator action at a time may run
    read-modify-write on the configuration. Inside a PostgreSQL deployment it is a session advisory lock; the code that already
    wrote `with store._lock:` is therefore safe across replicas without any other change. Without PostgreSQL it is a plain lock."""
    KEY = 724001
    WAIT = 60

    def __init__(self):
        self._r = threading.RLock()
        self._depth = 0
        self._con = None

    def __enter__(self):
        self._r.acquire()
        self._depth += 1
        if self._depth == 1:
            try:
                if PG:
                    con = db()
                    end = time.time() + self.WAIT
                    while not con.execute("SELECT pg_try_advisory_lock(?) AS ok", (self.KEY,)).fetchone()["ok"]:
                        con.commit()
                        if time.time() > end:
                            raise RuntimeError("another administrator or replica is changing the configuration (waited 60 s)")
                        time.sleep(0.05)
                    con.commit()
                    self._con = con
                _cache.update(t=0.0, raw=None)       # inside a critical section always read the newest saved state
            except BaseException:
                self._depth -= 1
                self._r.release()
                raise
        return self

    def __exit__(self, *exc):
        self._depth -= 1
        try:
            if self._depth == 0 and self._con is not None:
                con, self._con = self._con, None
                try:
                    con.execute("SELECT pg_advisory_unlock(?)", (self.KEY,))
                    con.commit()
                except Exception:  # noqa: BLE001 - a dead connection already released the lock on the server
                    pass
        finally:
            self._r.release()


_lock = _ClusterLock()          # the lock administrator actions use around read-modify-write of the configuration
_mem = threading.RLock()         # protects only the in-process cache

DEFAULT_SETTINGS = {
    "trusted_proxies": "",          # CIDRs whose X-Forwarded-For is trusted (one per line)
    "never_ban": "127.0.0.1",       # IPs/CIDRs the auto-ban must never ban
    "autoban": {"enabled": False, "threshold": 10, "window_min": 5, "ban_min": 30},
    "retention_days": 7,
    "panel_allow_ips": "",          # CIDRs allowed to reach the admin panel (empty = anyone who can reach the port)
    "upstream_allow": "",           # if set, upstream host names must end with one of these suffixes (one per line); matching names may use private addresses
    "upstream_private_allow": "10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 fc00::/7",   # private ranges an upstream may resolve to (loopback, link-local, metadata are never allowed)
    "upstream_pin_dns": False,      # true = nginx connects to the addresses validated by the panel instead of resolving names itself (closes DNS rebinding)
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
                          "auto_ban": True, "upstream_down": True, "ssrf_blocked": True, "audit_tamper": True, "login_lockout": True, "admin_change": True, "cert_expiring": True, "feeds_failed": True,
                          "rules_update": True}},
    # OWASP rule-set updates (see crsupdate.py): "baked" = the version inside the image
    "crs": {"active": "baked", "previous": "", "staged": "", "staged_sha256": "", "staged_at": 0, "latest": "", "checked_at": 0,
            "error": "", "auto_stage": True},
    # single sign-on for the admin panel (OpenID Connect), see oidc.py; the client secret lives in /data/secrets/oidc.json, never here
    "sso": {"enabled": False, "issuer": "", "client_id": "", "redirect_base": "", "scopes": "openid email profile", "allowed_domains": "",
            "allowed_emails": "", "admin_emails": "", "admin_groups": "", "default_role": "viewer", "require_verified_email": True,
            "button_label": "Sign in with SSO"},
    # automatic HTTPS certificates (ACME / Let's Encrypt), see acme.py
    "acme": {"email": "", "directory": "https://acme-v02.api.letsencrypt.org/directory", "agreed": False},
    # layer-7 DoS defence: automatic "under attack" mode when one site receives too many requests per second
    "ddos": {"auto": False, "rps_threshold": 200, "window_s": 20, "hold_min": 15},
    "audit_retention_days": 0,      # 0 = keep the audit trail forever; otherwise the leader removes older records from the start of the chain (keeping an anchor)
}

DEFAULT_SITE = {
    "id": "", "host": "", "upstream": "", "enabled": True,
    "ssrf_blocked": [],             # upstreams the leader found resolving to a forbidden address (taken out of use until they are clean again)
    "ssrf_seen": {},                # upstream -> addresses it resolved to at the last check (used by DNS pinning)
    "upstreams": [],                # more upstreams besides `upstream`: [{"url": "...", "weight": 1, "backup": False}]
    "lb_method": "round_robin",     # round_robin (weighted, random per request) | ip_hash (a client keeps its upstream)
    "health": {"enabled": False, "path": "/", "down": []},     # active checks by the leader; `down` = upstreams currently out of rotation
    "mode": "block",                # block | detect | off
    "paranoia": 1,                  # OWASP CRS paranoia level 1..4
    "threshold": 5,                 # inbound anomaly score that triggers a block
    "maintenance": False,
    "down_page": True,
    "rate_limit": {"enabled": False, "rps": 10, "burst": 20, "scope": "replica"},
    "bots": {"mode": "off", "threshold": 6, "exclude_paths": "", "allow_ua": ""},     # header-behaviour bot score: off | detect | block | challenge (needs the proof-of-work challenge)
    "allow_ips": [], "deny_ips": [],
    "block_bots": True, "sec_headers": True,
    "max_body_mb": 10,
    "methods": "GET HEAD POST PUT DELETE PATCH OPTIONS",
    "tls": {"enabled": False, "source": "none",       # none | uploaded | selfsigned | mounted
            "redirect_http": True, "redirect_port": "", "hsts": True, "hsts_days": 365, "mounted_name": "",
            "acme_state": "", "acme_error": "", "acme_expires": 0},          # acme_state: "" | pending | issued | error
    "auth": {"enabled": False, "realm": "Restricted", "users": {}},      # users: name -> crypt hash (never shown)
    "challenge": {"enabled": False, "difficulty": 4, "ttl_hours": 12, "scope": "pages", "exclude_paths": ""},
    "positive": {"enabled": False, "paths": "", "content_types": "application/json application/x-www-form-urlencoded multipart/form-data text/plain",
                 "max_url": 2048},          # positive security model: only what is listed gets through
    "openapi": {"mode": "off", "spec": "", "strict": True, "unknown_paths": "allow", "report": [], "max_body_kb": 1024, "max_depth": 10},   # OpenAPI request validation
    "crs_channel": "stable",        # stable = active rule set; canary = staged rule set in detect-only mode
    "geo": {"mode": "off", "countries": ""},      # off | deny | allow  + country codes such as CN RU
    "under_attack": False, "ua_until": 0,   # forces the challenge for everyone + a rate limit; ua_until>0 = automatic, ends by itself
    "exclusions": [],               # [{"rule": "942100", "path": "/api/upload"}]  (path optional)
    "custom_rules": "",
    "page_maint": "", "page_down": "",   # per-site override HTML (empty = use global page)
}


def _default_cfg():
    return {"users": {}, "settings": json.loads(json.dumps(DEFAULT_SETTINGS)), "sites": [], "bans": [], "pages": {"maintenance": "", "down": ""}}


def load(fresh=False):
    with _mem:
        if fresh:
            _cache.update(t=0.0, raw=None)
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
    """Persist the configuration and bump the configuration version, which tells every replica to apply it."""
    with _mem:
        raw = json.dumps(cfg)
        con = db()
        con.execute("INSERT INTO config(id, data) VALUES(1, ?) ON CONFLICT(id) DO UPDATE SET data=excluded.data", (raw,))
        con.execute("INSERT INTO counters(k,v) VALUES('cfg_ver',1) ON CONFLICT(k) DO UPDATE SET v=counters.v+1")
        con.commit()
        _cache.update(t=time.time(), raw=raw)


def state_version():
    """(configuration version, shared-files version): changes whenever any replica saved something the others must apply."""
    rows = {r["k"]: int(r["v"]) for r in db().execute("SELECT k,v FROM counters WHERE k IN ('cfg_ver','files_ver')").fetchall()}
    db().commit()
    return rows.get("cfg_ver", 0), rows.get("files_ver", 0)


# --------------------------------------------------------------------------------------------------- database
# PostgreSQL in production (SHIELD_DB_URL=postgresql://user:password@host:5432/dbname); SQLite only as a fallback for local tests.
DB_URL = os.environ.get("SHIELD_DB_URL", "")
PG = DB_URL.startswith(("postgres://", "postgresql://"))
# Least privilege (docs/SECURITY_HARDENING.md): SHIELD_DB_URL is the runtime role (no DDL, INSERT/SELECT only on the audit table). Migrations, grants and the audit
# retention job use SHIELD_DB_MIGRATE_URL (the schema owner). Unset = one role for everything, as in 2.3.
MIGRATE_URL = os.environ.get("SHIELD_DB_MIGRATE_URL", "") or DB_URL
APP_ROLE = os.environ.get("SHIELD_DB_APP_ROLE", "")        # when set, the migration step grants exactly the runtime privileges to this role
if PG:
    import psycopg2
    import psycopg2.extras
    from psycopg2 import sql as pgsql


def _int_env(name, default):
    try:
        return max(0, int(os.environ.get(name, default)))
    except ValueError:
        return default


def connect_args(owner=False):
    """Connection settings: TLS mode (SHIELD_DB_SSLMODE, default prefer; require / verify-full in production, with SHIELD_DB_SSLROOTCERT), TCP keepalives, and server-side
    timeouts so that a stuck query, a lock or an idle transaction cannot hold the database hostage. The owner (migration) connection has no statement timeout."""
    args = {"connect_timeout": _int_env("SHIELD_DB_CONNECT_TIMEOUT", 10), "keepalives": 1, "keepalives_idle": 30, "keepalives_interval": 10, "keepalives_count": 3,
            "application_name": "shieldwaf-" + ("migrate" if owner else "panel")}
    mode = os.environ.get("SHIELD_DB_SSLMODE", "")
    if mode:
        args["sslmode"] = mode
    if os.environ.get("SHIELD_DB_SSLROOTCERT"):
        args["sslrootcert"] = os.environ["SHIELD_DB_SSLROOTCERT"]
    st = 0 if owner else _int_env("SHIELD_DB_STATEMENT_TIMEOUT_MS", 30000)
    opts = f"-c statement_timeout={st} -c lock_timeout={_int_env('SHIELD_DB_LOCK_TIMEOUT_MS', 10000) if not owner else 60000} "            f"-c idle_in_transaction_session_timeout={_int_env('SHIELD_DB_IDLE_TX_TIMEOUT_MS', 60000)}"
    args["options"] = opts
    return args

HOUR = "CAST(FLOOR(ts/3600) AS INTEGER)" if PG else "CAST(ts/3600 AS INTEGER)"


def bucket_sql(seconds):
    """SQL for the time bucket of `ts` (seconds is a code constant, never user input)."""
    s = int(seconds)
    return f"CAST(FLOOR(ts/{s}) AS INTEGER)" if PG else f"CAST(ts/{s} AS INTEGER)"
_local = threading.local()


class _Conn:
    """The same tiny API for both databases: execute / executemany / commit, '?' placeholders, rows readable by column name."""

    def __init__(self, url=None, owner=False):
        self._n = 0                        # statements run since the last commit (a dead connection is retried only when this is 0)
        self._url, self._owner = url or DB_URL, owner
        if PG:
            self.raw = psycopg2.connect(self._url, **connect_args(owner))
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

    def _reconnect(self):
        try:
            self.raw.close()
        except Exception:  # noqa: BLE001
            pass
        self.raw = psycopg2.connect(self._url, **connect_args(self._owner))

    def _run(self, fn, write=True):
        """Run one database call. If the connection died (database restarted, failover) and nothing uncommitted would be lost,
        reconnect once and repeat the call, so a database restart costs no failed requests."""
        first = self._n == 0
        try:
            r = fn()
        except Exception as e:  # noqa: BLE001
            if PG and first and isinstance(e, (psycopg2.OperationalError, psycopg2.InterfaceError)):
                try:
                    self._reconnect()
                    r = fn()
                    self._n += 1 if write else 0
                    return r
                except Exception:  # noqa: BLE001
                    pass
            self._n = 0
            try:
                self.raw.rollback()
            except Exception:  # noqa: BLE001
                _local.con = None          # connection is gone: reconnect on next use
            raise
        self._n += 1 if write else 0
        return r

    def execute(self, sql, params=()):
        def go():
            cur = self._cur()
            cur.execute(self._sql(sql), params)
            return cur
        return self._run(go, write=not sql.lstrip()[:6].upper() == "SELECT")

    def executemany(self, sql, rows):
        def go():
            cur = self._cur()
            cur.executemany(self._sql(sql), rows)
            return cur
        return self._run(go, write=True)

    def commit(self):
        self._run(lambda: self.raw.commit())
        self._n = 0


def db():
    con = getattr(_local, "con", None)
    if con is None or (PG and con.raw.closed):
        con = _Conn()
        _local.con = con
    return con


@contextlib.contextmanager
def as_owner():
    """Run a block on the schema owner's connection (migrations, grants, audit retention). Without SHIELD_DB_MIGRATE_URL it is the normal connection."""
    if not PG or MIGRATE_URL == DB_URL:
        yield
        return
    prev = getattr(_local, "con", None)
    con = _Conn(MIGRATE_URL, owner=True)
    _local.con = con
    try:
        yield
    finally:
        try:
            con.raw.close()
        except Exception:  # noqa: BLE001
            pass
        _local.con = prev


def apply_grants(con, role=None):
    """Give the runtime role exactly what it needs and no more: DML on the tables, USAGE on the sequences, and on the audit trail only SELECT and INSERT, so a
    stolen runtime credential (or an SQL injection in the panel) cannot rewrite or delete audit records. Idempotent; runs after every migration."""
    role = role or APP_ROLE
    if not PG or not role:
        return False
    if not re.fullmatch(r"[a-z_][a-z0-9_]{0,62}", role):
        raise ValueError("SHIELD_DB_APP_ROLE is not a plain lower-case role name")
    if not con.execute("SELECT 1 FROM pg_roles WHERE rolname=?", (role,)).fetchone():
        con.commit()
        print(f"[shieldwaf] database role {role} does not exist yet: run panel/dbadmin.py roles (grants skipped)", flush=True)
        return False
    r = pgsql.Identifier(role)
    cur = con.raw.cursor()
    for stmt in (
        "GRANT CONNECT ON DATABASE {db} TO {r}", "GRANT USAGE ON SCHEMA public TO {r}", "REVOKE CREATE ON SCHEMA public FROM {r}",
        "GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO {r}",
        "REVOKE UPDATE, DELETE, TRUNCATE ON TABLE audit FROM {r}", "GRANT SELECT, INSERT ON TABLE audit TO {r}",
        "REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON TABLE schema_migrations FROM {r}",
        "GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO {r}",
    ):
        cur.execute(pgsql.SQL(stmt).format(r=r, db=pgsql.Identifier(con.raw.get_dsn_parameters()["dbname"])))
    con.raw.commit()
    return True


def _baseline_ddl():
    pk = "BIGSERIAL PRIMARY KEY" if PG else "INTEGER PRIMARY KEY"
    return f"""
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
    CREATE TABLE IF NOT EXISTS nodes(name TEXT PRIMARY KEY, ts DOUBLE PRECISION, started DOUBLE PRECISION, applied_cfg BIGINT, applied_files BIGINT,
        ok INTEGER, msg TEXT, version TEXT, engine_ok INTEGER, info TEXT);
    CREATE TABLE IF NOT EXISTS sso_pending(state TEXT PRIMARY KEY, nonce TEXT, verifier TEXT, binder TEXT, created DOUBLE PRECISION);
    CREATE TABLE IF NOT EXISTS sfiles(path TEXT PRIMARY KEY, kind TEXT, sha TEXT, mode INTEGER, data TEXT, updated DOUBLE PRECISION)
    """


# Versioned, forward-only schema migrations. Each runs once, in order, inside one transaction, under a cluster-wide lock (replicas starting together
# cannot race). Never edit an applied migration: add a new one. Rollback = restore the pre-upgrade backup (docs/ROLLBACK_GUIDE.md); migrations only ADD.
def _migrations():
    base = [x.strip() for x in _baseline_ddl().split(";") if x.strip()]
    big = "BIGINT"
    return [
        (1, "baseline schema (2.3)", base),
        (2, "tamper-evident audit trail and backup events", [
            f"ALTER TABLE audit ADD COLUMN seq {big}",
            "ALTER TABLE audit ADD COLUMN category TEXT DEFAULT ''",
            "ALTER TABLE audit ADD COLUMN request_id TEXT DEFAULT ''",
            "ALTER TABLE audit ADD COLUMN prev_hash TEXT DEFAULT ''",
            "ALTER TABLE audit ADD COLUMN hash TEXT DEFAULT ''",
            "CREATE UNIQUE INDEX IF NOT EXISTS audit_seq ON audit(seq)",
            "CREATE INDEX IF NOT EXISTS audit_ts ON audit(ts)",
            f"CREATE TABLE IF NOT EXISTS backup_log(id {'BIGSERIAL PRIMARY KEY' if PG else 'INTEGER PRIMARY KEY'}, ts DOUBLE PRECISION, kind TEXT, detail TEXT, ingested INTEGER DEFAULT 0)",
        ]),
    ]


MIGRATION_LOCK = 724004


def current_schema_version():
    try:
        r = db().execute("SELECT MAX(version) v FROM schema_migrations").fetchone()
        db().commit()
        return int(r["v"] or 0)
    except Exception:  # noqa: BLE001
        try:
            db().raw.rollback()
        except Exception:  # noqa: BLE001
            pass
        return 0


def migrate():
    """Apply every migration that has not run yet, on the schema owner's connection. Safe to call from every replica at the same time."""
    with as_owner():
        _migrate()


def _migrate():
    con = db()
    if PG:
        con.execute("SELECT pg_advisory_lock(?)", (MIGRATION_LOCK,))
        con.commit()
    try:
        con.execute("CREATE TABLE IF NOT EXISTS schema_migrations(version INTEGER PRIMARY KEY, name TEXT, applied_at DOUBLE PRECISION)")
        con.commit()
        done = {int(r["version"]) for r in con.execute("SELECT version FROM schema_migrations").fetchall()}
        con.commit()
        for version, name, stmts in _migrations():
            if version in done:
                continue
            try:
                for stmt in stmts:
                    con.execute(stmt)
                con.execute("INSERT INTO schema_migrations(version,name,applied_at) VALUES(?,?,?)", (version, name, time.time()))
                con.commit()                      # PostgreSQL: DDL is transactional, so a failed migration leaves nothing behind
                print(f"[shieldwaf] database migration {version} applied: {name}", flush=True)
            except Exception:
                try:
                    con.raw.rollback()
                except Exception:  # noqa: BLE001
                    pass
                raise
    finally:
        if PG:
            try:
                con.execute("SELECT pg_advisory_unlock(?)", (MIGRATION_LOCK,))
                con.commit()
            except Exception:  # noqa: BLE001
                pass
    backfill_audit_chain()
    apply_grants(db())


def init_db():
    for attempt in range(40):          # the database pod may still be starting
        try:
            migrate()
            return
        except Exception as e:  # noqa: BLE001
            if not PG or attempt == 39:
                raise
            print(f"[shieldwaf] waiting for the database ({type(e).__name__}) ...", flush=True)
            _local.con = None
            time.sleep(3)


# ----------------------------------------------------------------------------------------------- tamper-evident audit trail
# Every audit record carries seq, prev_hash and hash = HMAC-SHA256(key, canonical JSON of the record and prev_hash). The key (SHIELD_AUDIT_KEY, or derived
# from SHIELD_DATA_KEY) is not stored in the database, so somebody who can only write to the database cannot recompute the chain after editing a row:
# verify_audit() then names the first broken record. Somebody with code execution in the panel holds the key: for that case export the chain regularly
# (signed export, docs/DISASTER_RECOVERY.md) and keep the exports elsewhere; the database role of the panel also gets INSERT/SELECT only on this table
# (docs/SECURITY_HARDENING.md).
_audit_lock = threading.Lock()
_req = threading.local()
audit_hooks = []                 # callables(record dict): the SIEM forwarder registers here


def set_request_id(rid):
    _req.rid = (rid or "")[:64]


def _audit_key():
    k = os.environ.get("SHIELD_AUDIT_KEY", "")
    if k:
        return k.encode()
    d = os.environ.get("SHIELD_DATA_KEY", "")
    return hashlib.sha256(b"shieldwaf-audit-chain-v1:" + (d or "development-only-key").encode()).digest()


CATEGORIES = (("login", "auth"), ("logout", "auth"), ("2fa", "auth"), ("sso", "auth"), ("password", "auth"), ("lockout", "auth"), ("setup", "auth"),
              ("user", "user"), ("role", "user"), ("certificate", "certificate"), ("cert", "certificate"), ("acme", "certificate"),
              ("backup", "backup"), ("restore", "backup"), ("site", "policy"), ("settings", "policy"), ("config", "policy"), ("rule", "policy"),
              ("maintenance", "policy"), ("under-attack", "policy"), ("ban", "security"), ("auto-ban", "security"), ("ssrf", "security"),
              ("upstream", "security"), ("threat", "security"), ("feed", "security"), ("alert", "admin"), ("metrics", "admin"), ("audit", "admin"))


def categorize(action):
    a = (action or "").lower()
    for key, cat in CATEGORIES:
        if key in a:
            return cat
    return "admin"


def _record_hash(rec):
    body = json.dumps({k: rec[k] for k in ("seq", "ts", "username", "action", "category", "detail", "ip", "request_id", "prev_hash")}, sort_keys=True, separators=(",", ":"))
    return hmac.new(_audit_key(), body.encode(), hashlib.sha256).hexdigest()


def _anchor():
    """(seq, hash) the chain continues from after old records were removed by the retention job, or (0, 'genesis')."""
    try:
        return int(meta_get("audit_anchor_seq", 0)), meta_get("audit_anchor_hash", "genesis")
    except Exception:  # noqa: BLE001
        return 0, "genesis"


def _append(con, ts, user, action, detail, ip, category, rid):
    last = con.execute("SELECT seq, hash FROM audit WHERE seq IS NOT NULL ORDER BY seq DESC LIMIT 1").fetchone()
    seq0, h0 = (int(last["seq"]), last["hash"]) if last else _anchor()
    rec = {"seq": seq0 + 1, "ts": ts, "username": user, "action": action, "category": category, "detail": detail, "ip": ip, "request_id": rid, "prev_hash": h0}
    rec["hash"] = _record_hash(rec)
    con.execute("INSERT INTO audit(seq,ts,username,action,detail,ip,category,request_id,prev_hash,hash) VALUES(?,?,?,?,?,?,?,?,?,?)",
                (rec["seq"], ts, user, action, detail, ip, category, rid, h0, rec["hash"]))
    return rec


def audit(user, action, detail="", ip="", category=None):
    """Append one record to the audit trail (the only way records are written)."""
    ts, detail = time.time(), str(detail)[:2000]
    category = category or categorize(action)
    rid = getattr(_req, "rid", "")
    with _audit_lock:
        con = db()
        if PG:
            con.execute("SELECT pg_advisory_xact_lock(724003)")        # one writer at a time across all replicas: the chain has one order
        rec = _append(con, ts, str(user)[:64], str(action)[:80], detail, str(ip)[:64], category, rid)
        con.commit()
    for hook in audit_hooks:
        try:
            hook(rec)
        except Exception:  # noqa: BLE001 - forwarding must never break the action being audited
            pass
    return rec


def backfill_audit_chain():
    """Rows written before the chain existed (2.3) are added to it once, in time order, so nothing stays unprotected."""
    con = db()
    pending = con.execute("SELECT ts, username, action, detail, ip FROM audit WHERE seq IS NULL ORDER BY ts").fetchall()
    con.commit()
    if not pending:
        return 0
    with _audit_lock:
        con = db()
        if PG:
            con.execute("SELECT pg_advisory_xact_lock(724003)")
        # re-read under the lock: another replica may have done it
        pending = con.execute("SELECT ts, username, action, detail, ip FROM audit WHERE seq IS NULL ORDER BY ts").fetchall()
        n, seen = 0, {}
        for x in pending:
            r = dict(x)
            seen.setdefault((r["ts"], r["username"], r["action"], r["detail"], r["ip"]), 0)
            seen[(r["ts"], r["username"], r["action"], r["detail"], r["ip"])] += 1
        for (ts, user, action, detail, ip), count in seen.items():          # delete the unchained copies of a record, then chain `count` copies
            con.execute("DELETE FROM audit WHERE seq IS NULL AND ts=? AND username=? AND action=? AND detail=?", (ts, user, action, detail))
            for _ in range(count):
                _append(con, ts, user or "", action or "", detail or "", ip or "", categorize(action), "")
                n += 1
        con.commit()
    print(f"[shieldwaf] {n} older audit records added to the tamper-evident chain", flush=True)
    return n


def verify_audit(limit=None):
    """Re-compute the chain. Returns {"ok": bool, "records": n, "head_seq", "head_hash", "broken_at": seq or None, "reason": text}."""
    con = db()
    seq0, h0 = _anchor()
    rows = con.execute("SELECT seq, ts, username, action, category, detail, ip, request_id, prev_hash, hash FROM audit WHERE seq IS NOT NULL ORDER BY seq").fetchall()
    con.commit()
    expect_seq, expect_prev, n = None, None, 0
    for r in rows:
        r = dict(r)
        if expect_seq is None:
            expect_seq, expect_prev = (seq0 + 1, h0) if seq0 else (r["seq"], r["prev_hash"])
            if seq0 and r["seq"] != expect_seq:
                return {"ok": False, "records": n, "broken_at": r["seq"], "reason": f"records after the retention anchor are missing (expected #{expect_seq})"}
        if r["seq"] != expect_seq:
            return {"ok": False, "records": n, "broken_at": expect_seq, "reason": f"record #{expect_seq} is missing or was removed"}
        if r["prev_hash"] != expect_prev:
            return {"ok": False, "records": n, "broken_at": r["seq"], "reason": "the link to the previous record does not match"}
        if not hmac.compare_digest(r["hash"] or "", _record_hash(r)):
            return {"ok": False, "records": n, "broken_at": r["seq"], "reason": "the record was changed after it was written"}
        expect_seq, expect_prev, n = r["seq"] + 1, r["hash"], n + 1
        if limit and n >= limit:
            break
    return {"ok": True, "records": n, "head_seq": (expect_seq - 1) if expect_seq else seq0, "head_hash": expect_prev or h0, "broken_at": None, "reason": ""}


def audit_export(since_seq=0, until_seq=None):
    """Yield JSON lines (SIEM-compatible, one event per line) and a final signed checkpoint line. Keep exports off the cluster: they let you prove later that
    nothing before the checkpoint was changed, even by somebody who controls the panel."""
    con = db()
    rows = con.execute("SELECT seq, ts, username, action, category, detail, ip, request_id, prev_hash, hash FROM audit WHERE seq IS NOT NULL AND seq>? ORDER BY seq", (int(since_seq),)).fetchall()
    con.commit()
    last, n = None, 0
    for r in rows:
        r = dict(r)
        if until_seq and r["seq"] > until_seq:
            break
        yield json.dumps({"@timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(r["ts"])), "ts": r["ts"], "app": "shieldwaf", "log_type": "audit", "seq": r["seq"], "actor": r["username"],
                          "action": r["action"], "category": r["category"], "detail": r["detail"], "source_ip": r["ip"], "request_id": r["request_id"],
                          "prev_hash": r["prev_hash"], "hash": r["hash"]}, sort_keys=True, separators=(",", ":"))
        last, n = r, n + 1
    cp = {"checkpoint": True, "app": "shieldwaf", "log_type": "audit", "records": n, "from_seq": int(since_seq) + 1, "head_seq": last["seq"] if last else int(since_seq),
          "head_hash": last["hash"] if last else "", "exported_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
    cp["signature"] = hmac.new(_audit_key(), json.dumps(cp, sort_keys=True, separators=(",", ":")).encode(), hashlib.sha256).hexdigest()
    yield json.dumps(cp, sort_keys=True, separators=(",", ":"))


def verify_export(lines):
    """Check an exported file (list of JSON lines) offline against the key: every record's hash, the links, and the checkpoint signature."""
    recs, cp = [], None
    for ln in lines:
        if not ln.strip():
            continue
        d = json.loads(ln)
        if d.get("checkpoint"):
            cp = d
        else:
            recs.append(d)
    if cp is None:
        return {"ok": False, "reason": "no checkpoint line (the file is cut short)"}
    sig = cp.pop("signature", "")
    if not hmac.compare_digest(sig, hmac.new(_audit_key(), json.dumps(cp, sort_keys=True, separators=(",", ":")).encode(), hashlib.sha256).hexdigest()):
        return {"ok": False, "reason": "the checkpoint signature is wrong"}
    prev = None
    for d in recs:
        full = {"seq": d["seq"], "ts": d["ts"], "username": d["actor"], "action": d["action"], "category": d["category"], "detail": d["detail"], "ip": d["source_ip"],
                "request_id": d["request_id"], "prev_hash": d["prev_hash"]}
        if not hmac.compare_digest(d["hash"], _record_hash(full)):
            return {"ok": False, "reason": f"record #{d['seq']} was changed after it was written", "broken_at": d["seq"]}
        if prev is not None and (d["prev_hash"] != prev[1] or d["seq"] != prev[0] + 1):
            return {"ok": False, "reason": f"the chain is broken at record #{d['seq']}", "broken_at": d["seq"]}
        prev = (d["seq"], d["hash"])
    if recs and (cp["head_seq"] != recs[-1]["seq"] or cp["head_hash"] != recs[-1]["hash"]):
        return {"ok": False, "reason": "the checkpoint does not match the last record"}
    return {"ok": True, "records": len(recs), "head_seq": cp["head_seq"], "head_hash": cp["head_hash"]}


def check_checkpoint(cp):
    """Is the database still consistent with an EARLIER export's checkpoint (cp = its parsed last line)? Detects truncation and rewriting of the tail,
    which the chain alone cannot (a chain cannot prove that records after its head never existed)."""
    seq = int(cp.get("head_seq", 0))
    if seq <= 0:
        return {"ok": True, "reason": "empty checkpoint"}
    r = db().execute("SELECT hash FROM audit WHERE seq=?", (seq,)).fetchone()
    db().commit()
    if not r:
        a_seq, _ = _anchor()
        return {"ok": seq <= a_seq, "reason": "removed by the retention job" if seq <= a_seq else f"record #{seq} from the earlier export no longer exists (truncated)"}
    ok = hmac.compare_digest(r["hash"], cp.get("head_hash", ""))
    return {"ok": ok, "reason": "" if ok else f"record #{seq} differs from the earlier export (rewritten)"}


def audit_purge(before_ts):
    """Retention: remove records older than `before_ts` from the START of the chain and keep an anchor so the rest still verifies. Needs DELETE rights on the
    audit table, which the panel's runtime database role does not have by design (docs/SECURITY_HARDENING.md): it only works with a maintenance connection
    (SHIELD_DB_MAINT_URL) or on SQLite. Returns the number of removed records."""
    with _audit_lock, as_owner():
        con = db()
        row = con.execute("SELECT seq, hash FROM audit WHERE seq IS NOT NULL AND ts<? ORDER BY seq DESC LIMIT 1", (before_ts,)).fetchone()
        con.commit()
        if not row:
            return 0
        cut = int(row["seq"])
        n = con.execute("SELECT COUNT(*) c FROM audit WHERE seq<=?", (cut,)).fetchone()["c"]
        con.execute("DELETE FROM audit WHERE seq<=?", (cut,))
        meta_set("audit_anchor_seq", cut)
        meta_set("audit_anchor_hash", row["hash"])
        con.commit()
        return int(n)




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
