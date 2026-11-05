"""Attack and traffic analytics (module P): what is hitting the sites, what the WAF did about it, and how that changes over time.

The data is what the panel already collects: `access` (one row per request: time, client, host, status, time taken) and `events` (one row per rule match: client, host, URI,
rule, message, blocked or not). Both are kept for the retention period of the access log (7 days by default), so ranges up to 7 days are complete; longer ranges show
what exists. Everything is computed by the database (one query per table and view), the page and the CSV export use the same numbers.
"""
import ipaddress
import time

import feeds
import store

RANGES = {"1h": (3600, 300), "24h": (86400, 3600), "7d": (7 * 86400, 6 * 3600), "30d": (30 * 86400, 86400)}      # seconds covered, bucket size in seconds
TOP = 10


def _where(since, host):
    w, a = "ts>=?", [since]
    if host:
        w += " AND host=?"
        a.append(host)
    return w, a


def summary(rng="24h", host="", now=None):
    now = now or time.time()
    rng = rng if rng in RANGES else "24h"
    span, bucket = RANGES[rng]
    since = now - span
    con = store.db()
    w, a = _where(since, host)
    q = lambda sql, args: [dict(r) for r in con.execute(sql, args).fetchall()]            # noqa: E731
    tot = q(f"SELECT COUNT(*) n, SUM(CASE WHEN status=403 THEN 1 ELSE 0 END) b, SUM(CASE WHEN status=429 THEN 1 ELSE 0 END) r, "
            f"SUM(CASE WHEN status>=500 THEN 1 ELSE 0 END) e, AVG(rt) rt FROM access WHERE {w}", a)[0]                   # nosec B608 - w is fixed text, values are bound
    uniq = q(f"SELECT COUNT(DISTINCT ip) n FROM access WHERE {w}", a)[0]["n"]                                         # nosec B608
    n = int(tot["n"] or 0)
    totals = {"requests": n, "blocked": int(tot["b"] or 0), "rate_limited": int(tot["r"] or 0), "server_errors": int(tot["e"] or 0), "unique_clients": int(uniq or 0),
              "avg_ms": round(float(tot["rt"] or 0) * 1000, 1), "block_rate": round(100.0 * (tot["b"] or 0) / n, 2) if n else 0.0}
    b = f"CAST(ts/{int(bucket)} AS INTEGER)"
    series = q(f"SELECT {b} k, COUNT(*) n, SUM(CASE WHEN status=403 THEN 1 ELSE 0 END) blocked, SUM(CASE WHEN status=429 THEN 1 ELSE 0 END) limited "
               f"FROM access WHERE {w} GROUP BY k ORDER BY k", a)                                                       # nosec B608
    by = {int(r["k"]): r for r in series}
    first, last = int(since // bucket), int(now // bucket)
    points = [{"t": k * bucket, "requests": int(by.get(k, {}).get("n") or 0), "blocked": int(by.get(k, {}).get("blocked") or 0), "limited": int(by.get(k, {}).get("limited") or 0)}
              for k in range(first, last + 1)]
    ew, ea = _where(since, host)
    top_hosts = q(f"SELECT host, COUNT(*) n, SUM(CASE WHEN status=403 THEN 1 ELSE 0 END) blocked FROM access WHERE {w} GROUP BY host ORDER BY n DESC LIMIT {TOP}", a)    # nosec B608
    top_rules = q(f"SELECT rule_id, MAX(msg) msg, COUNT(*) n, SUM(blocked) blocked FROM events WHERE {ew} AND rule_id<>'' GROUP BY rule_id ORDER BY n DESC LIMIT {TOP}", ea)   # nosec B608
    top_ips = q(f"SELECT ip, COUNT(*) n, SUM(blocked) blocked, COUNT(DISTINCT rule_id) rules FROM events WHERE {ew} GROUP BY ip ORDER BY n DESC LIMIT {TOP}", ea)               # nosec B608
    top_uris = q(f"SELECT uri, COUNT(*) n, SUM(blocked) blocked FROM events WHERE {ew} GROUP BY uri ORDER BY n DESC LIMIT {TOP}", ea)                                      # nosec B608
    for r in top_ips:
        r["country"] = _country(r["ip"])
    countries = {}
    for r in q(f"SELECT ip, COUNT(*) n FROM events WHERE {ew} GROUP BY ip ORDER BY n DESC LIMIT 500", ea):                                                                  # nosec B608
        c = _country(r["ip"]) or "??"
        countries[c] = countries.get(c, 0) + int(r["n"])
    top_countries = sorted(({"country": c, "n": v} for c, v in countries.items()), key=lambda x: -x["n"])[:TOP]
    ev = q(f"SELECT COUNT(*) n, SUM(blocked) b FROM events WHERE {ew}", ea)[0]
    con.commit()
    return {"range": rng, "host": host, "since": since, "until": now, "bucket": bucket, "totals": totals, "events": {"matches": int(ev["n"] or 0), "blocked": int(ev["b"] or 0)},
            "series": points, "top_hosts": top_hosts, "top_rules": top_rules, "top_ips": top_ips, "top_uris": top_uris, "top_countries": top_countries}


def _country(ip):
    try:
        ipaddress.ip_address(ip)
        return feeds.country_of(ip) or ""
    except Exception:  # noqa: BLE001 - country data may not be loaded
        return ""


def hosts(since=None):
    r = store.db().execute("SELECT DISTINCT host FROM access WHERE ts>=? ORDER BY host", (since or time.time() - 30 * 86400,)).fetchall()
    store.db().commit()
    return [x["host"] for x in r if x["host"]]


def csv_lines(data):
    """The summary as CSV text (sections separated by a blank line)."""
    def esc(v):
        s = str(v if v is not None else "")
        if s[:1] in "=+-@":                       # a spreadsheet must not run a client-chosen URI as a formula
            s = "'" + s
        return '"' + s.replace('"', '""') + '"'
    out = [",".join(esc(x) for x in ("section", "key", "value1", "value2", "value3"))]
    for k, v in data["totals"].items():
        out.append(",".join(esc(x) for x in ("totals", k, v)))
    for p in data["series"]:
        out.append(",".join(esc(x) for x in ("series", time.strftime("%Y-%m-%d %H:%M", time.gmtime(p["t"])) + " UTC", p["requests"], p["blocked"], p["limited"])))
    for name, rows, keys in (("hosts", data["top_hosts"], ("host", "n", "blocked")), ("rules", data["top_rules"], ("rule_id", "n", "msg")),
                             ("clients", data["top_ips"], ("ip", "n", "country")), ("uris", data["top_uris"], ("uri", "n", "blocked")), ("countries", data["top_countries"], ("country", "n"))):
        for r in rows:
            out.append(",".join(esc(x) for x in (name,) + tuple(r.get(k) for k in keys)))
    return "\n".join(out) + "\n"
