"""Background workers: tail nginx/ModSecurity logs into SQLite, auto-ban noisy IPs, prune old data."""
import ipaddress
import json
import os
import threading
import time
from datetime import datetime

import engine
import feeds
import store

LOG_DIR = engine.LOG_DIR
_applier = None   # set by app.py: callable(cfg) -> (ok, msg)


def _read_new(path, key, limit=20000):
    """Return new complete lines since the stored offset (handles truncation/rotation)."""
    try:
        size = os.path.getsize(path)
    except OSError:
        return []
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
            "SELECT ip, COUNT(*) c FROM access WHERE ts>? AND status IN (403,429) GROUP BY ip HAVING c>=?",
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
    for fn, every in ((ingest_access, 2), (ingest_audit, 2), (autoban_tick, 15), (prune, 3600), (feeds_tick, 600), (geo_tick, 600), (ddos_tick, 3)):
        threading.Thread(target=_loop, args=(fn, every), daemon=True, name=fn.__name__).start()
