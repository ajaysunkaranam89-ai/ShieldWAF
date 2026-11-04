"""Background workers: tail this replica's nginx/ModSecurity logs into the database, auto-ban noisy IPs, prune old data, refresh feeds.
With several replicas every replica ingests its own logs and watches its own engine; the jobs that must happen once (everything else)
run only on the leader replica (see cluster.py)."""
import ipaddress
import json
import os
import re
import threading
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

import acme
import alerts
import cluster
import netguard
import crsupdate
import engine
import feeds
import security
import store

LOG_DIR = engine.LOG_DIR
_applier = None   # set by app.py: callable(cfg) -> (ok, msg)


def _read_new(path, key, limit=20000):
    """Return new complete lines since the stored offset (handles truncation/rotation)."""
    try:
        size = os.path.getsize(path)
    except OSError:
        return []
    key = f"{key}:{store.NODE}"        # every replica has its own log files and therefore its own read position
    off = int(store.meta_get(key, 0))
    if size < off:
        off = 0
    if size == off:
        return []
    with open(path, "rb") as f:
        f.seek(off)
        data = f.read(8 * 1024 * 1024)
    end = data.rfind(b"\n")
    if end < 0:
        return []
    data = data[: end + 1]
    store.meta_set(key, off + len(data))
    return data.decode("utf-8", "replace").splitlines()[:limit]


def ingest_access():
    rows, counts = [], {}
    for ln in _read_new(os.path.join(LOG_DIR, "access.log"), "off_access"):
        try:
            j = json.loads(ln)
        except ValueError:
            continue
        rows.append((float(j.get("ts", time.time())), j.get("ip", ""), j.get("host", ""), int(j.get("status", 0)), float(j.get("rt", 0))))
        k = f"req_{j.get('status', 0)}"
        counts[k] = counts.get(k, 0) + 1
    if rows:
        con = store.db()
        con.executemany("INSERT INTO access VALUES(?,?,?,?,?)", rows)
        con.commit()
        for k, n in counts.items():
            store.counter_add(k, n)


def _ts(s):
    for fmt in ("%a %b %d %H:%M:%S %Y", "%a %b  %d %H:%M:%S %Y"):
        try:
            return datetime.strptime(s, fmt).timestamp()
        except (ValueError, TypeError):
            pass
    return time.time()


def ingest_audit():
    rows = []
    for ln in _read_new(os.path.join(LOG_DIR, "audit.json"), "off_audit"):
        try:
            t = json.loads(ln)["transaction"]
        except (ValueError, KeyError):
            continue
        req, resp = t.get("request", {}), t.get("response", {})
        status = int(resp.get("http_code", 0) or 0)
        msgs = t.get("messages", []) or []
        main = next((m for m in msgs if not str(m.get("details", {}).get("ruleId", "")).startswith(("949", "959", "980"))), msgs[0] if msgs else {})
        det = main.get("details", {})
        if not msgs:   # blocked by an nginx-level rule (deny list, ban, bot list), not by an OWASP rule
            main = {"message": "Blocked by access control (deny list, ban or bot rule)"}
        score = ""
        for m in msgs:
            if "Anomaly Score Exceeded" in m.get("message", ""):
                score = m["message"].split("(")[-1].rstrip(")")
        host = (req.get("headers", {}) or {}).get("Host", "") or (req.get("headers", {}) or {}).get("host", "")
        rows.append((_ts(t.get("time_stamp", "")), t.get("client_ip", ""), host.split(":")[0], req.get("method", ""), req.get("uri", "")[:500],
                     str(det.get("ruleId", "")), (main.get("message", "") or "")[:300], score, status, 1 if status >= 400 else 0))
    if rows:
        con = store.db()
        con.executemany("INSERT INTO events(ts,ip,host,method,uri,rule_id,msg,score,status,blocked) VALUES(?,?,?,?,?,?,?,?,?,?)", rows)
        con.commit()
        alerts.forward_events([dict(zip(("ts", "ip", "host", "method", "uri", "rule_id", "msg", "score", "status", "blocked"), r), kind="waf_event") for r in rows])
        store.counter_add("blocked_events", sum(r[-1] for r in rows))
        store.counter_add("detected_events", sum(1 - r[-1] for r in rows))


def _never(cfg):
    nets = []
    for x in engine.split_lines(cfg["settings"]["never_ban"]):
        try:
            nets.append(ipaddress.ip_network(x, strict=False))
        except ValueError:
            pass
    return nets


def autoban_tick():
    with store._lock:
        _autoban_locked()


def _autoban_locked():
    cfg = store.load()
    now = time.time()
    changed = False
    keep = [b for b in cfg["bans"] if b["until"] > now]
    if len(keep) != len(cfg["bans"]):
        cfg["bans"], changed = keep, True
    ab = cfg["settings"]["autoban"]
    if ab["enabled"]:
        rows = store.db().execute(
            "SELECT ip, COUNT(*) c FROM access WHERE ts>? AND status IN (403,429) GROUP BY ip HAVING COUNT(*)>=?",
            (now - ab["window_min"] * 60, ab["threshold"])).fetchall()
        never, already = _never(cfg), {b["ip"] for b in cfg["bans"]}
        for r in rows:
            try:
                addr = ipaddress.ip_address(r["ip"])
            except ValueError:
                continue
            if r["ip"] in already or any(addr in n for n in never):
                continue
            cfg["bans"].append({"ip": r["ip"], "until": now + ab["ban_min"] * 60, "manual": False,
                                "reason": f"auto-ban: {r['c']} blocked requests in {ab['window_min']} min"})
            store.audit("system", "auto-ban", f"{r['ip']} ({r['c']} blocks)")
            alerts.notify("auto_ban", f"Auto-ban: {r['ip']}", f"{r['c']} blocked requests in {ab['window_min']} min", key="ban:" + r["ip"])
            changed = True
    if changed and _applier:
        ok, msg = _applier(cfg)
        if ok:
            store.save(cfg)


def prune():
    cfg = store.load()
    cut = time.time() - int(cfg["settings"]["retention_days"]) * 86400
    con = store.db()
    con.execute("DELETE FROM access WHERE ts<?", (cut,))
    con.execute("DELETE FROM events WHERE ts<?", (cut,))
    con.commit()
    engine.rotate_logs()


def _protected_nets(cfg):
    """Networks that must never end up on a block list: the never-ban list and the trusted proxies."""
    nets = []
    for x in engine.split_lines(cfg["settings"]["never_ban"]) + engine.split_lines(cfg["settings"]["trusted_proxies"]):
        try:
            nets.append(ipaddress.ip_network(x, strict=False))
        except ValueError:
            pass
    return nets


def run_feed_refresh():
    """Download the reputation feeds (outside the lock: it can take a while) and apply the result. Returns (ok, count, error)."""
    cfg0 = store.load()
    ok, count, err = feeds.refresh_feeds(cfg0, _protected_nets(cfg0))
    with store._lock:
        cfg = store.load()
        f = cfg["settings"]["feeds"]
        f["last_error"] = err
        if ok:
            f.update(last_ok=time.time(), last_count=count)
            if _applier:
                _applier(cfg)
        store.save(cfg)
    store.audit("system", "threat feeds refreshed" if ok else "threat feed refresh failed", f"{count} networks {err}"[:200])
    if not ok:
        alerts.notify("feeds_failed", "Threat feed refresh failed", err)
    return ok, count, err


def feeds_tick():
    f = store.load()["settings"]["feeds"]
    if not f["enabled"]:
        return
    now = time.time()
    if now - f["last_ok"] > int(f["refresh_hours"]) * 3600 and now - float(store.meta_get("feeds_last_try", 0)) > 900:
        store.meta_set("feeds_last_try", now)
        run_feed_refresh()


def geo_done():
    with store._lock:
        if _applier:
            _applier(store.load())
    store.audit("system", "country data updated", "")


def geo_tick():
    cfg = store.load()
    uses = any(s["geo"]["mode"] != "off" for s in cfg["sites"])
    if not uses:
        return
    st = feeds.geo_status()
    old = (time.time() - float(st.get("updated", 0))) > 7 * 86400
    if (not feeds.geo_ready() or old) and not st["running"] and time.time() - float(store.meta_get("geo_last_try", 0)) > 3600:
        store.meta_set("geo_last_try", time.time())
        feeds.refresh_geo_async(geo_done)


def ddos_tick():
    """Layer-7 flood defence: if a site gets too many requests per second, switch on "under attack" mode for it, then switch off again."""
    with store._lock:
        cfg = store.load()
        d = cfg["settings"]["ddos"]
        now = time.time()
        changed = []
        if d["auto"]:
            win = max(5, int(d["window_s"]))
            counts = {r["host"]: r["c"] for r in store.db().execute(
                "SELECT host, COUNT(*) c FROM access WHERE ts>? GROUP BY host", (now - win,)).fetchall()}
            for s in cfg["sites"]:
                rps = counts.get(s["host"], 0) / win
                if not s["under_attack"] and rps >= int(d["rps_threshold"]):
                    s.update(under_attack=True, ua_until=now + int(d["hold_min"]) * 60)
                    changed.append(f"{s['host']} ON ({rps:.0f} req/s)")
                elif s["under_attack"] and s["ua_until"] and now > s["ua_until"] and rps < int(d["rps_threshold"]) * 0.5:
                    s.update(under_attack=False, ua_until=0)
                    changed.append(f"{s['host']} OFF (calm)")
                elif s["under_attack"] and s["ua_until"] and now > s["ua_until"]:
                    s["ua_until"] = now + 5 * 60       # still under pressure: extend
        else:
            for s in cfg["sites"]:                      # auto mode switched off: end automatic episodes
                if s["under_attack"] and s["ua_until"]:
                    s.update(under_attack=False, ua_until=0)
                    changed.append(f"{s['host']} OFF (auto mode disabled)")
        if changed and _applier:
            ok, msg = _applier(cfg)
            if ok:
                store.save(cfg)
                store.audit("system", "auto under-attack", "; ".join(changed))
                alerts.notify("under_attack", "Under-attack mode changed automatically", "; ".join(changed), severity="warning", force=True)



_mon = {"engine_ok": True, "down_since": 0.0}


def health_tick():
    """Engine watchdog: alert when the engine stops answering for 30 s, and again when it is back."""
    import urllib.request
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{engine.HTTP_PORT}/__shieldwaf_health", timeout=2) as r:  # nosec B310 - fixed loopback URL
            ok = r.status == 200
    except Exception:  # noqa: BLE001
        ok = False
    now = time.time()
    if ok:
        if not _mon["engine_ok"]:
            alerts.notify("engine_recovered", f"Firewall engine is back ({store.NODE})", f"It was down for {int(now - _mon['down_since'])} s.", force=True)
        _mon.update(engine_ok=True, down_since=0.0)
    else:
        if _mon["down_since"] == 0.0:
            _mon["down_since"] = now
        if _mon["engine_ok"] and now - _mon["down_since"] >= 30:
            _mon["engine_ok"] = False
            alerts.notify("engine_down", f"Firewall engine is not answering ({store.NODE})", "No health reply for 30 seconds. Traffic to protected sites is failing on this replica.", force=True)


def spike_tick():
    """Alert when blocked requests in the last minute exceed the configured number."""
    sp = store.load()["settings"]["alerts"]["spike"]
    if not sp["enabled"]:
        return
    n = store.db().execute("SELECT COUNT(*) c FROM access WHERE ts>? AND status IN (403,429)", (time.time() - 60,)).fetchone()["c"]
    if n >= int(sp["blocked_per_min"]):
        top = store.db().execute("SELECT ip, COUNT(*) c FROM access WHERE ts>? AND status IN (403,429) GROUP BY ip ORDER BY c DESC LIMIT 3",
                                 (time.time() - 60,)).fetchall()
        alerts.notify("attack_spike", f"{n} blocked requests in the last minute", "Top sources: " + ", ".join(f"{r['ip']} ({r['c']})" for r in top))


def cert_tick():
    """Daily: warn about certificates that expire within 21 days."""
    if time.time() - float(store.meta_get("cert_check", 0)) < 86400:
        return
    store.meta_set("cert_check", time.time())
    for s in store.load()["sites"]:
        if s["tls"]["enabled"]:
            ci = security.cert_info(security.cert_paths(s)[0])
            if ci and ci["days_left"] is not None and ci["days_left"] < 21:
                alerts.notify("cert_expiring", f"Certificate for {s['host']} expires in {ci['days_left']} days", "Renew it (or check cert-manager).", key="cert:" + s["host"], force=True)



def acme_issue(sid, force=False):
    """Get a certificate for one site with an automatic (ACME) certificate and install it on every replica."""
    cfg = store.load()
    s = next((x for x in cfg["sites"] if x["id"] == sid), None)
    if not s or not (s["tls"]["enabled"] and s["tls"]["source"] == "acme"):
        return
    now = time.time()
    if not force and now - float(store.meta_get(f"acme_try:{sid}", 0)) < acme.RETRY_S:        # authorities rate-limit failures: not more than every 6 hours
        return
    if now - float(store.meta_get(f"acme_busy:{sid}", 0)) < 600:                           # another request for this site is already running
        return
    store.meta_set(f"acme_busy:{sid}", now)
    store.meta_set(f"acme_try:{sid}", now)
    ac, host, err, exp = cfg["settings"]["acme"], s["host"], "", 0
    try:
        chain, key, exp = acme.obtain(host, ac["email"], ac["directory"])
        acme.install(sid, chain, key)
    except Exception as e:  # noqa: BLE001
        err = (str(e) if isinstance(e, acme.AcmeError) else f"{type(e).__name__}: {e}")[:300]
    finally:
        store.meta_set(f"acme_busy:{sid}", 0)
    with store._lock:
        cfg = store.load()
        s = next((x for x in cfg["sites"] if x["id"] == sid), None)
        if not s:
            return
        if err:
            s["tls"].update(acme_state="error", acme_error=err)
        else:
            s["tls"].update(acme_state="issued", acme_error="", acme_expires=exp)
            if _applier:
                _applier(cfg)                       # nginx reloads and starts using the new certificate
        store.save(cfg)
    store.audit("system", "certificate issued" if not err else "certificate request failed", f"{host} {err}"[:200])
    if err:
        alerts.notify("config_failed", f"Certificate request failed: {host}", err, key="acme:" + sid)


def acme_issue_async(sid, force=False):
    threading.Thread(target=acme_issue, args=(sid, force), daemon=True, name="acme-" + sid).start()


def acme_tick():
    """Leader, hourly: request certificates that are missing or expire within 30 days."""
    for s in store.load()["sites"]:
        t = s["tls"]
        if not (t["enabled"] and t["source"] == "acme"):
            continue
        ci = security.cert_info(security.cert_paths(s)[0])
        if t.get("acme_state") != "issued" or not ci or (ci["days_left"] is not None and ci["days_left"] < acme.RENEW_DAYS):
            acme_issue(s["id"])


_hc = {}        # (site id, upstream) -> consecutive good / bad checks (kept by the leader; a new leader starts counting again)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


def _probe(url, path):
    """True when the upstream answers (any status below 500). Redirects are not followed: a 301 is an answer."""
    try:
        with urllib.request.build_opener(_NoRedirect).open(urllib.request.Request(url + path, headers={"User-Agent": "A-Shield-WAF-health"}), timeout=3) as r:  # nosec B310 - upstream already validated (http/https, no metadata addresses)
            return r.status < 500
    except urllib.error.HTTPError as e:
        return e.code < 500
    except Exception:  # noqa: BLE001
        return False


def upstream_health_tick():
    """Leader, every 10 s: probe the upstreams of sites with health checks; two bad checks in a row take one out of rotation, two good ones put it back.
    A change is applied like any configuration change, so every replica follows."""
    cfg = store.load()
    jobs = []
    for s in cfg["sites"]:
        ups = [s["upstream"]] + [u["url"] for u in s.get("upstreams", [])]
        if s.get("health", {}).get("enabled") and s["enabled"] and len(ups) > 1:
            jobs += [(s["id"], u, s["health"]["path"]) for u in ups]
    with ThreadPoolExecutor(max_workers=8) as ex:
        results = list(ex.map(lambda j: _probe(j[1], j[2]), jobs))
    verdict = {}
    for (sid, url, _path), ok in zip(jobs, results):
        st = _hc.setdefault((sid, url), {"ok": 0, "bad": 0})
        st["ok"], st["bad"] = (st["ok"] + 1, 0) if ok else (0, st["bad"] + 1)
        verdict.setdefault(sid, {})[url] = st
    updates = {}
    for s in cfg["sites"]:
        ups = [s["upstream"]] + [u["url"] for u in s.get("upstreams", [])]
        if s["id"] not in verdict:
            if s.get("health", {}).get("down") and not s.get("health", {}).get("enabled"):
                updates[s["id"]] = []                          # checks were switched off: everything back into rotation
            continue
        down = set(s["health"]["down"])
        for url, st in verdict[s["id"]].items():
            if url in down and st["ok"] >= 2:
                down.discard(url)
            elif url not in down and st["bad"] >= 2:
                down.add(url)
        new = [u for u in ups if u in down]
        if new != s["health"]["down"]:
            updates[s["id"]] = new
    if not updates:
        return
    with store._lock:
        cfg = store.load()
        notes = []
        for s in cfg["sites"]:
            if s["id"] in updates and s["health"]["down"] != updates[s["id"]]:
                before = set(s["health"]["down"])
                s["health"]["down"] = updates[s["id"]]
                for u in set(updates[s["id"]]) - before:
                    notes.append(f"{s['host']}: {u} is DOWN (out of rotation)")
                for u in before - set(updates[s["id"]]):
                    notes.append(f"{s['host']}: {u} is back")
        if notes and _applier:
            ok, msg = _applier(cfg)
            if ok:
                store.save(cfg)
                store.audit("system", "upstream health", "; ".join(notes)[:400])
                alerts.notify("upstream_down", "Upstream health changed", "; ".join(notes), severity="warning", force=True)


def ssrf_tick():
    """Leader, every 15 s: resolve every upstream name again. A name that now points at a forbidden address (loopback, link-local, cloud metadata, a private
    range that is not allowed ...) is taken out of use at once on every replica; with DNS pinning a changed answer is applied the same way.
    This closes the gap between 'checked when saved' and 'looked up by nginx for each request' (DNS rebinding) to about the length of this interval."""
    cfg = store.load()
    st = cfg["settings"]
    pin = bool(st.get("upstream_pin_dns"))
    updates = {}
    for s in cfg["sites"]:
        if not s["enabled"]:
            continue
        blocked, seen = [], {}
        for url in [s["upstream"]] + [u["url"] for u in s.get("upstreams", [])]:
            m = re.match(r"^https?://([^/:]+)(?::(\d+))?$", url)
            if not m:
                continue
            err = security.check_upstream(url, st["upstream_allow"], st.get("upstream_private_allow"), log=False)
            if err:
                blocked.append(url)
            elif pin:
                try:
                    seen[url] = sorted(str(a) for a in netguard.resolve(m.group(1)))
                except OSError:
                    seen[url] = []
        if blocked != s.get("ssrf_blocked", []) or (pin and seen != s.get("ssrf_seen", {})) or (not pin and s.get("ssrf_seen")):
            updates[s["id"]] = (blocked, seen if pin else {})
    if not updates:
        return
    with store._lock:
        cfg = store.load()
        notes = []
        for s in cfg["sites"]:
            if s["id"] not in updates:
                continue
            blocked, seen = updates[s["id"]]
            for u in set(blocked) - set(s.get("ssrf_blocked", [])):
                notes.append(f"{s['host']}: {u} now resolves to a forbidden address and was taken out of use")
                netguard.event("upstream-blocked", host=s["host"], url=u)
            for u in set(s.get("ssrf_blocked", [])) - set(blocked):
                notes.append(f"{s['host']}: {u} is acceptable again")
                netguard.event("upstream-cleared", host=s["host"], url=u)
            s["ssrf_blocked"], s["ssrf_seen"] = blocked, seen
        if _applier:
            ok, _msg = _applier(cfg)
            if ok:
                store.save(cfg)
                if notes:
                    store.audit("system", "ssrf upstream check", "; ".join(notes)[:400])
                    alerts.notify("ssrf_blocked", "Upstream address check", "; ".join(notes), severity="critical", force=True)


def audit_tick():
    """Leader, every 10 minutes: move backup / restore events written by the backup jobs into the audit chain, verify the chain (alert if it is broken), and apply
    the retention setting."""
    con = store.db()
    for r in con.execute("SELECT id, ts, kind, detail FROM backup_log WHERE ingested=0 ORDER BY id").fetchall():
        store.audit("backup-job", f"backup-{r['kind']}", f"{r['detail']} (at {time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(float(r['ts'])))} UTC)", "", category="backup")
        con.execute("UPDATE backup_log SET ingested=1 WHERE id=?", (r["id"],))
    con.commit()
    days = int(store.load()["settings"].get("audit_retention_days", 0) or 0)
    if days > 0:
        try:
            removed = store.audit_purge(time.time() - days * 86400)
            if removed:
                store.audit("system", "audit retention", f"{removed} records older than {days} days removed; the chain continues from a stored anchor")
        except Exception as e:  # noqa: BLE001 - the runtime database role may not be allowed to delete (by design)
            store.meta_set("audit_purge_error", f"{type(e).__name__}: {str(e)[:150]}")
    res = store.verify_audit()
    store.meta_set("audit_verify", json.dumps({**res, "at": time.time()}))
    if not res["ok"] and store.meta_get("audit_tamper_alerted") != str(res.get("broken_at")):
        store.meta_set("audit_tamper_alerted", res.get("broken_at"))
        alerts.notify("audit_tamper", "Audit trail integrity check FAILED", f"record #{res.get('broken_at')}: {res.get('reason')}", severity="critical", force=True)
        print(json.dumps({"app": "shieldwaf", "category": "audit", "event": "tamper-detected", "broken_at": res.get("broken_at"), "reason": res.get("reason")}), flush=True)


def _ver(v):
    try:
        return tuple(int(x) for x in v.split("."))
    except ValueError:
        return (0,)


def run_crs_check():
    """Ask GitHub for the latest CRS release. Returns (tag, newer_than_active, error)."""
    err, tag = "", ""
    try:
        tag = crsupdate.latest_tag()
    except Exception as e:  # noqa: BLE001
        err = f"{type(e).__name__}: {e}"[:200]
    with store._lock:
        cfg = store.load()
        c = cfg["settings"]["crs"]
        c["checked_at"], c["error"] = time.time(), err
        newer = False
        if tag:
            c["latest"] = tag
            newer = _ver(tag[1:]) > _ver(crsupdate.version_of(crsupdate.active_dir(cfg)) or "0")
        store.save(cfg)
    if newer and c.get("notified") != tag:
        alerts.notify("rules_update", f"OWASP rule set {tag} is available", "Stage it, canary-test it, then promote it (Rule updates page).", key="crs:" + tag, force=True)
    return tag, newer, err


def run_crs_stage(tag=None):
    """Download + verify + stage a release (never activates it). Returns (ok, message)."""
    try:
        tag = tag or crsupdate.latest_tag()
        ver, sha = crsupdate.stage(tag)
    except Exception as e:  # noqa: BLE001
        with store._lock:
            cfg = store.load()
            cfg["settings"]["crs"]["error"] = f"{type(e).__name__}: {e}"[:200]
            store.save(cfg)
        return False, str(e)
    with store._lock:
        cfg = store.load()
        c = cfg["settings"]["crs"]
        c.update(staged=tag, staged_sha256=sha, staged_at=time.time(), error="", latest=tag)
        ok, msg = _applier(cfg) if _applier else (True, "")
        if ok:
            store.save(cfg)
        else:
            c.update(staged="", staged_sha256="")
            c["error"] = ("the engine refused the new rule set: " + msg)[:200]
            store.save(cfg)
    store.audit("system", "rule set staged" if ok else "rule set staging failed", f"{tag} sha256={sha[:16]}")
    if ok:
        alerts.notify("rules_update", f"OWASP rule set {tag} is staged", "Canary sites now run it in detect-only mode. Review, then promote.", key="crs-staged:" + tag, force=True)
    return ok, msg


def crs_tick():
    c = store.load()["settings"]["crs"]
    if time.time() - c["checked_at"] < 6 * 3600:
        return
    tag, newer, err = run_crs_check()
    cfg = store.load()
    if newer and cfg["settings"]["crs"]["auto_stage"] and cfg["settings"]["crs"]["staged"] != tag:
        run_crs_stage(tag)


def _loop(fn, every):
    while True:
        try:
            fn()
        except Exception as e:  # noqa: BLE001
            print(f"[background] {fn.__name__} error: {e}", flush=True)
        time.sleep(every)


def start(applier):
    global _applier
    _applier = applier
    alerts.start()
    # every replica: its own logs, its own engine, local clean-up. Leader only: everything that must happen once for the whole cluster.
    local = ((ingest_access, 2), (ingest_audit, 2), (prune, 3600), (health_tick, 5))
    once = ((autoban_tick, 15), (feeds_tick, 600), (geo_tick, 600), (ddos_tick, 3), (spike_tick, 20), (cert_tick, 3600), (crs_tick, 900), (acme_tick, 3600), (upstream_health_tick, 10), (ssrf_tick, 15), (audit_tick, 600))
    for fn, every in local + tuple((cluster.leader_only(f), e) for f, e in once):
        threading.Thread(target=_loop, args=(fn, every), daemon=True, name=fn.__name__).start()
