"""Policy approval ("four eyes") and version history for site security policies (module O).

When approval is switched on (Policy page), a change to a site - create, edit, delete - is NOT applied: it becomes a pending change that shows exactly what differs and
how risky it is. A DIFFERENT administrator approves or rejects it; only then is it applied (by the panel, through the normal render / test / reload path). The author can
withdraw it. Every applied version of a site is kept (who proposed it, who approved it, when), and any earlier version can be proposed again ("restore").

* Safety rules: the author cannot approve their own change (unless `allow_self_approve` is switched on, a break-glass option that is audited like everything else);
  a change is bound to the version of the site it was made against and is refused if the site changed since (no silent overwrite of newer work); pending changes expire
  after 14 days; approval cannot be switched on while there is only one administrator and self-approval is off (nobody could ever approve anything).
* What is gated: site create / edit / delete and config import. Not gated: maintenance mode and under-attack mode (emergency switches), user and settings pages.
* Everything here (proposal, approval, rejection, withdrawal, restore, expiry) is written to the tamper-evident audit trail by the caller.
"""
import hashlib
import json
import time

import store

EXPIRE_S = 14 * 86400
MAX_PENDING = 200
MAX_PAYLOAD = 400 * 1024
VOLATILE = ("acme_state", "acme_expires", "acme_error", "ssrf_blocked", "ssrf_seen", "_pinned", "_orig")      # written by background jobs, not by people
# changes that deserve a second look
RISKY = {"mode": "protection mode", "paranoia": "paranoia level", "threshold": "block threshold", "allow_ips": "allowed IP list", "deny_ips": "denied IP list",
         "custom_rules": "custom ModSecurity rules", "exclusions": "rule exclusions", "upstream": "upstream", "upstreams": "upstreams", "methods": "allowed methods",
         "rate_limit.enabled": "rate limit", "tls.enabled": "TLS", "tls.redirect_http": "HTTP to HTTPS redirect", "challenge.enabled": "anti-bot challenge",
         "bots.mode": "bot protection", "block_bots": "scanner blocking", "auth.enabled": "login gate", "geo.mode": "country rules", "openapi.mode": "OpenAPI validation",
         "positive.enabled": "allow-list mode", "maintenance": "maintenance mode"}


def settings(cfg):
    p = cfg["settings"].get("policy") or {}
    return {"approval": bool(p.get("approval")), "allow_self_approve": bool(p.get("allow_self_approve"))}


def enabled(cfg):
    return settings(cfg)["approval"]


def _clean(site):
    out = json.loads(json.dumps(site or {}))
    for k in list(out):
        if k in VOLATILE or k.startswith("_"):
            out.pop(k)
    for k in ("tls", "health"):
        if isinstance(out.get(k), dict):
            for v in VOLATILE + ("down",):
                out[k].pop(v, None)
    return out


def fingerprint(site):
    """Hash of the person-made part of a site (what a change was made against)."""
    return hashlib.sha256(json.dumps(_clean(site), sort_keys=True).encode()).hexdigest()[:20] if site else ""


def _flat(d, prefix=""):
    out = {}
    for k, v in (d or {}).items():
        key = f"{prefix}{k}"
        if isinstance(v, dict):
            out.update(_flat(v, key + "."))
        else:
            out[key] = v
    return out


def diff(old, new):
    """[{field, old, new, risky, label}] between two sites (None = does not exist). Secrets (password hashes of the login gate) are shown as changed, never printed."""
    a, b = _flat(_clean(old)), _flat(_clean(new))
    rows = []
    for k in sorted(set(a) | set(b)):
        if a.get(k) != b.get(k):
            secret = k.startswith("auth.users")
            rows.append({"field": k, "old": "(hidden)" if secret else a.get(k), "new": "(hidden)" if secret else b.get(k), "risky": k in RISKY or k.split(".")[0] in ("custom_rules", "exclusions"),
                         "label": RISKY.get(k, "")})
    return rows


def _cut(v, n=300):
    s = json.dumps(v) if not isinstance(v, str) else v
    return s if len(s) <= n else s[:n] + "..."


def submit(kind, site_id, host, author, old, new):
    """Store a pending change. Returns (id, error)."""
    con = store.db()
    pending = con.execute("SELECT COUNT(*) c FROM policy_changes WHERE status='pending'").fetchone()["c"]
    if pending >= MAX_PENDING:
        con.commit()
        return None, "Too many pending changes: approve or reject some first."
    payload = json.dumps(_clean(new)) if new is not None else ""
    if len(payload) > MAX_PAYLOAD:
        return None, "The change is too large."
    cid = "c" + hashlib.sha256(f"{time.time()}{author}{host}".encode()).hexdigest()[:10]
    rows = diff(old, new) if kind != "delete" else [{"field": "(site)", "old": host, "new": "(deleted)", "risky": True, "label": "site removed"}]
    con.execute("INSERT INTO policy_changes(id, ts, kind, site_id, host, author, status, payload, diff, base) VALUES(?,?,?,?,?,?,?,?,?,?)",
                (cid, time.time(), kind, site_id, host, author, "pending", payload, json.dumps(rows), fingerprint(old)))
    con.commit()
    return cid, None


def expire_old():
    con = store.db()
    con.execute("UPDATE policy_changes SET status='expired', decided_ts=? WHERE status='pending' AND ts<?", (time.time(), time.time() - EXPIRE_S))
    con.commit()


def get(cid):
    r = store.db().execute("SELECT * FROM policy_changes WHERE id=?", (cid,)).fetchone()
    store.db().commit()
    if not r:
        return None
    r = dict(r)
    r["diff"] = json.loads(r.get("diff") or "[]")
    r["new"] = json.loads(r["payload"]) if r.get("payload") else None
    return r


def listing(limit=60):
    expire_old()
    rows = store.db().execute("SELECT * FROM policy_changes ORDER BY ts DESC LIMIT ?", (limit,)).fetchall()
    store.db().commit()
    out = []
    for r in rows:
        r = dict(r)
        r["diff"] = json.loads(r.get("diff") or "[]")
        r["risky"] = any(d["risky"] for d in r["diff"])
        out.append(r)
    return out


def can_decide(cfg, ch, user):
    """(ok, reason): may `user` approve or reject this change?"""
    if ch["status"] != "pending":
        return False, f"This change is already {ch['status']}."
    if user == ch["author"] and not settings(cfg)["allow_self_approve"]:
        return False, "The author cannot approve their own change: another administrator must."
    return True, ""


def stale(cfg, ch):
    """True when the site changed after this change was proposed (the base version differs)."""
    cur = next((s for s in cfg["sites"] if s["id"] == ch["site_id"]), None)
    if ch["kind"] == "create":
        return cur is not None
    return fingerprint(cur) != ch["base"]


def mark(cid, status, user, note=""):
    con = store.db()
    con.execute("UPDATE policy_changes SET status=?, decided_by=?, decided_ts=?, note=? WHERE id=? AND status='pending'", (status, user, time.time(), note[:300], cid))
    con.commit()


def record_version(site, action, author, approver=""):
    """Keep this version of the site (called after it was applied)."""
    con = store.db()
    n = con.execute("SELECT COALESCE(MAX(version), 0) m FROM policy_versions WHERE site_id=?", (site["id"],)).fetchone()["m"]
    con.execute("INSERT INTO policy_versions(site_id, version, ts, action, author, approver, host, data) VALUES(?,?,?,?,?,?,?,?)",
                (site["id"], int(n) + 1, time.time(), action, author, approver, site["host"], json.dumps(_clean(site))))
    con.execute("DELETE FROM policy_versions WHERE site_id=? AND version<=?", (site["id"], int(n) + 1 - 100))          # the last 100 versions of a site
    con.commit()


def merge_volatile(new, cur):
    """A change that was made by people must not wipe what background jobs wrote since (certificate state, SSRF results): copy those fields from the live site."""
    out = json.loads(json.dumps(new))
    for k in VOLATILE:
        if cur and k in cur:
            out[k] = cur[k]
    for k in ("tls", "health"):
        if cur and isinstance(cur.get(k), dict) and isinstance(out.get(k), dict):
            for v in VOLATILE + ("down",):
                if v in cur[k]:
                    out[k][v] = cur[k][v]
    return out


def versions(site_id):
    rows = store.db().execute("SELECT version, ts, action, author, approver, host FROM policy_versions WHERE site_id=? ORDER BY version DESC", (site_id,)).fetchall()
    store.db().commit()
    return [dict(r) for r in rows]


def get_version(site_id, version):
    r = store.db().execute("SELECT * FROM policy_versions WHERE site_id=? AND version=?", (site_id, int(version))).fetchone()
    store.db().commit()
    return (dict(r) | {"site": json.loads(r["data"])}) if r else None


def versions_diff(site_id, a, b):
    va, vb = get_version(site_id, a), get_version(site_id, b)
    return diff(va["site"] if va else None, vb["site"] if vb else None)
