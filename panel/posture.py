"""Security posture page: one place that shows the state of every protection of this installation, each with a verdict (ok / attention / problem) and the reason.
Every section is collected on its own: a failure to read one never hides the others (it shows as 'could not be read')."""
import json
import time

import cluster
import crowdsec
import ratelimit
import store

OK, WARN, ERR, INFO = "ok", "warn", "err", "info"


def _section(title, fn):
    try:
        items = fn()
    except Exception as e:  # noqa: BLE001
        items = [(ERR, "could not be read", type(e).__name__)]
    worst = ERR if any(i[0] == ERR for i in items) else WARN if any(i[0] == WARN for i in items) else OK if any(i[0] == OK for i in items) else INFO
    return {"title": title, "state": worst, "items": [{"state": s, "label": l, "text": t} for s, l, t in items]}


def _ago(ts):
    d = max(0, time.time() - float(ts))
    return f"{int(d // 86400)} d {int(d % 86400 // 3600)} h ago" if d >= 86400 else f"{int(d // 3600)} h {int(d % 3600 // 60)} min ago" if d >= 3600 else f"{int(d // 60)} min ago"


def database():
    out = []
    if not store.PG:
        return [(WARN, "database", "SQLite (a single instance, no high availability): use PostgreSQL in production")]
    con = store.db()
    r = con.execute("SELECT ssl, version FROM pg_stat_ssl WHERE pid=pg_backend_pid()").fetchone()
    out.append((OK, "connection", f"encrypted ({r['version']})") if r and r["ssl"] else (ERR, "connection", "NOT encrypted (set SHIELD_DB_SSLMODE=require)"))
    r = con.execute("SELECT rolsuper, rolcreatedb, rolcreaterole, current_user AS u FROM pg_roles WHERE rolname=current_user").fetchone()
    p = con.execute("SELECT has_table_privilege(current_user,'audit','UPDATE') OR has_table_privilege(current_user,'audit','DELETE') AS w").fetchone()
    risky = r["rolsuper"] or r["rolcreatedb"] or r["rolcreaterole"] or p["w"]
    out.append((WARN, "database role", f"{r['u']} can change or delete audit records or has administrator rights: split the roles (docs/SECURITY_HARDENING.md)") if risky
               else (OK, "database role", f"{r['u']}: data changes only; the audit trail is append-only"))
    out.append((INFO, "schema version", str(store.current_schema_version())))
    try:
        mode = con.execute("SHOW archive_mode").fetchone()
        mode = list(mode.values())[0] if mode else "off"
        out.append((OK, "point-in-time recovery", "WAL archiving is on") if mode == "on" else (INFO, "point-in-time recovery", "off (recovery point = last backup)"))
    except Exception:  # noqa: BLE001
        pass
    con.commit()
    return out


def audit():
    raw = store.meta_get("audit_verify")
    if not raw:
        return [(INFO, "integrity check", "not run yet (runs every 10 minutes)")]
    r = json.loads(raw)
    out = [(OK, "integrity check", f"chain valid, {r.get('records', 0)} records, checked {_ago(r['at'])}") if r.get("ok")
           else (ERR, "integrity check", f"BROKEN at record #{r.get('broken_at')}: {r.get('reason')}")]
    days = int(store.load()["settings"].get("audit_retention_days", 0) or 0)
    out.append((INFO, "retention", f"{days} days" if days else "keep everything"))
    err = store.meta_get("audit_purge_error")
    if err:
        out.append((WARN, "retention job", err))
    return out


def backups():
    con = store.db()
    rows = {r["kind"]: r["t"] for r in con.execute("SELECT kind, MAX(ts) t FROM backup_log GROUP BY kind").fetchall()}
    con.commit()
    out = []
    last = rows.get("backup")
    if not last:
        out.append((WARN, "last backup", "none recorded (apply k8s/backup.yaml)"))
    else:
        out.append((OK if time.time() - float(last) < 36 * 3600 else ERR, "last backup", _ago(last) + (" (older than 36 hours: the nightly job is failing)" if time.time() - float(last) >= 36 * 3600 else "")))
    v = rows.get("verify")
    out.append((WARN, "last restore test", "none recorded (the weekly job proves a backup can be restored)") if not v
               else (OK if time.time() - float(v) < 9 * 86400 else WARN, "last restore test", _ago(v)))
    return out


def cluster_section():
    ns = cluster.nodes()
    alive = [n for n in ns if n["alive"]]
    out = [(OK if len(alive) >= 2 else WARN, "replicas", f"{len(alive)} running" + ("" if len(alive) >= 2 else " (two or more give redundancy)"))]
    versions = {n["version"] for n in alive}
    out.append((OK, "version", ", ".join(sorted(map(str, versions)))) if len(versions) <= 1 else (WARN, "version", "mixed: " + ", ".join(sorted(map(str, versions))) + " (an update is in progress?)"))
    bad = [n["name"] for n in alive if not n["ok"] or not n["engine_ok"]]
    out.append((ERR, "engines", "not healthy: " + ", ".join(bad)) if bad else (OK, "engines", "all healthy and in sync"))
    return out


def ssrf(cfg):
    blocked = [s["host"] for s in cfg["sites"] if s.get("ssrf_blocked")]
    out = [(ERR, "upstreams refused", "no traffic to: " + ", ".join(blocked)) if blocked else (OK, "upstreams", "all pass the network guard")]
    out.append((INFO, "private networks allowed", cfg["settings"].get("upstream_private_allow") or "RFC 1918 / fc00::/7 (default)"))
    out.append((OK, "DNS pinning", "on") if cfg["settings"].get("upstream_pin_dns") else (INFO, "DNS pinning", "off (a name is re-checked every 15 s instead)"))
    return out


def rate_limit(cfg):
    scoped = [s for s in cfg["sites"] if s["rate_limit"]["enabled"]]
    cl = [s for s in scoped if s["rate_limit"].get("scope") == "cluster"]
    out = [(INFO, "sites with a rate limit", f"{len(scoped)} of {len(cfg['sites'])} ({len(cl)} counted across replicas)")]
    st = ratelimit.status()
    if not st["configured"]:
        out.append((WARN if cl else INFO, "Redis", "not configured: limits are per replica" + (" (some sites ask for a cluster-wide limit!)" if cl else "")))
    else:
        out.append((OK if st["ok"] else ERR, "Redis", st["text"]))
        out.append((INFO, "this replica", f"{st.get('allowed', 0)} allowed, {st.get('limited', 0)} limited, {st.get('errors', 0)} errors since start"))
    return out


def bots(cfg):
    c = {}
    for s in cfg["sites"]:
        m = (s.get("bots") or {}).get("mode", "off")
        c[m] = c.get(m, 0) + 1
    on = len(cfg["sites"]) - c.get("off", 0)
    return [(OK if on else INFO, "sites with bot protection", f"{on} of {len(cfg['sites'])} (" + ", ".join(f"{k}: {v}" for k, v in sorted(c.items())) + ")")]


def intel(cfg):
    f, cs = cfg["settings"]["feeds"], cfg["settings"]["crowdsec"]
    out = []
    if f["enabled"]:
        out.append((OK if f["last_ok"] and not f["last_error"] else WARN, "reputation feeds", f"{f['last_count']} networks" + (f", updated {_ago(f['last_ok'])}" if f["last_ok"] else ", not downloaded yet")
                    + (f" - {f['last_error']}" if f["last_error"] else "")))
    else:
        out.append((INFO, "reputation feeds", "off"))
    if cs["enabled"]:
        last = float(store.meta_get("crowdsec_last_ok", 0) or 0)
        out.append((ERR if cs["last_error"] else OK if last and time.time() - last < 300 else WARN, "CrowdSec",
                    f"{cs['last_count']} decisions, last pull {_ago(last)}" if last else "waiting for the first answer"
                    + (f" - {cs['last_error']}" if cs["last_error"] else "")))
    else:
        out.append((INFO, "CrowdSec", "off"))
    return out


def sites_section(cfg):
    modes = {}
    for s in cfg["sites"]:
        modes[s["mode"]] = modes.get(s["mode"], 0) + 1
    out = [(OK if not modes.get("off") and not modes.get("detect") else WARN, "protection mode", ", ".join(f"{k}: {v}" for k, v in sorted(modes.items())) or "no sites yet")]
    notls = [s["host"] for s in cfg["sites"] if not (s["tls"]["enabled"] and s["tls"]["source"] != "none")]
    out.append((WARN, "sites without HTTPS", ", ".join(notls[:6]) + (" ..." if len(notls) > 6 else "")) if notls else (OK, "HTTPS", "every site is served over HTTPS"))
    return out


def accounts(cfg):
    users = cfg["users"]
    admins = [u for u, v in users.items() if v.get("role") == "admin"]
    no2fa = [u for u in admins if not users[u].get("totp_enabled") and not users[u].get("sso")]
    out = [(INFO, "accounts", f"{len(users)} ({len(admins)} administrators)")]
    out.append((WARN, "two-factor", "administrators without it: " + ", ".join(no2fa)) if no2fa and not cfg["settings"].get("oidc", {}).get("enabled") else (OK, "two-factor", "enabled for every administrator or single sign-on in use"))
    return out


def alerts_section(cfg):
    ch = cfg["settings"]["alerts"]["channels"]
    return [(OK, "alert channels", f"{len(ch)} configured") if ch else (WARN, "alert channels", "none: nobody is told when the engine stops or the audit trail breaks")]


def collect(cfg):
    return [_section("Database", database), _section("Audit trail", audit), _section("Backups", backups), _section("Cluster", cluster_section),
            _section("Upstream network guard (SSRF)", lambda: ssrf(cfg)), _section("Rate limiting", lambda: rate_limit(cfg)), _section("Bot protection", lambda: bots(cfg)),
            _section("Threat intelligence", lambda: intel(cfg)), _section("Sites", lambda: sites_section(cfg)), _section("Accounts", lambda: accounts(cfg)),
            _section("Alerting", lambda: alerts_section(cfg))]
