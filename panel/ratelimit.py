"""Cluster-wide rate limiting with Redis (module G).

nginx's own limit_req counts per replica: with three replicas a client can send three times the limit. A site with rate_limit.scope = "cluster" is checked
here instead: nginx asks this small server (127.0.0.1 only, inside the same pod) before it passes a request on, and the answer comes from ONE token bucket per
(site, client address) that lives in Redis, so all replicas draw from the same bucket.

  nginx --auth_request--> 127.0.0.1:9101/check  (headers: X-Shield-Site, X-Shield-Rps, X-Shield-Burst, X-Real-IP)
        <-- 204 (allowed) | 403 + X-Shield-RL: limited (nginx turns that into 429 + Retry-After)

* The bucket is updated by one Lua script inside Redis (atomic, uses Redis's own clock, so replicas with different clocks agree).
* Fail-open by default: if Redis is slow or down the request is allowed (and counted as an error) and the replica's own limit_req still applies as a safety net.
  SHIELD_RL_FAIL=closed turns that around (requests are refused while Redis is unavailable).
* IPv6 clients are counted per /64 (one customer usually has a whole /64), IPv4 per address.
* The Redis URL (SHIELD_REDIS_URL, redis:// or rediss://, with the password in it) comes from a secret, never from the GUI or the exported configuration.
"""
import ipaddress
import os
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT = int(os.environ.get("SHIELD_RL_PORT", "9101"))
FAIL_CLOSED = os.environ.get("SHIELD_RL_FAIL", "open").lower() == "closed"
URL = os.environ.get("SHIELD_REDIS_URL", "")

# token bucket: tokens refill at `rate` per second up to `burst`; one request takes one token. Time comes from Redis.
LUA = """
local t = redis.call('TIME')
local now = t[1] * 1000 + math.floor(t[2] / 1000)
local rate = tonumber(ARGV[1])
local burst = tonumber(ARGV[2])
local d = redis.call('HMGET', KEYS[1], 'ts', 'tokens')
local ts = tonumber(d[1])
local tokens = tonumber(d[2])
if ts == nil then ts = now; tokens = burst end
tokens = math.min(burst, tokens + math.max(0, now - ts) * rate / 1000)
local allowed = 0
if tokens >= 1 then tokens = tokens - 1; allowed = 1 end
redis.call('HSET', KEYS[1], 'ts', now, 'tokens', tostring(tokens))
redis.call('PEXPIRE', KEYS[1], math.ceil(burst / rate * 1000) + 2000)
local wait = 0
if allowed == 0 then wait = math.ceil((1 - tokens) / rate * 1000) end
return {allowed, wait}
"""

_lock = threading.Lock()
_client = None
_script = None
_down_until = 0.0            # circuit breaker: after a Redis error the next 2 seconds are answered at once (no waiting on a dead Redis for every request)
stats = {"allowed": 0, "limited": 0, "errors": 0, "last_error": "", "last_ok": 0.0}


def configured():
    return bool(URL)


def _redis():
    global _client, _script
    with _lock:
        if _client is None:
            import redis
            _client = redis.Redis.from_url(URL, socket_connect_timeout=0.25, socket_timeout=0.4, health_check_interval=15, decode_responses=True,
                                           max_connections=64)
            _script = _client.register_script(LUA)
        return _client, _script


def client_key(ip):
    """IPv4: the address. IPv6: the /64. Anything unparsable is counted as itself (never raises)."""
    try:
        a = ipaddress.ip_address(ip.strip())
    except ValueError:
        return ip[:64]
    if isinstance(a, ipaddress.IPv6Address):
        if a.ipv4_mapped:
            return str(a.ipv4_mapped)
        return str(ipaddress.ip_network((a, 64), strict=False).network_address) + "/64"
    return str(a)


def check(site, ip, rps, burst):
    """(allowed, wait_ms, error). `error` is '' when Redis answered."""
    global _down_until
    if time.time() < _down_until:
        return (not FAIL_CLOSED), 0, "CircuitOpen"
    try:
        rps, burst = max(0.1, float(rps)), max(1.0, float(burst) + 1)        # nginx's burst counts requests above the rate: the bucket holds burst + 1
        _c, script = _redis()
        allowed, wait = script(keys=[f"shieldwaf:rl:{site}:{client_key(ip)}"], args=[rps, burst])
        stats["last_ok"] = time.time()
        stats["allowed" if allowed else "limited"] += 1
        return bool(allowed), int(wait), ""
    except Exception as e:  # noqa: BLE001 - a Redis problem must never take the traffic down
        stats["errors"] += 1
        stats["last_error"] = type(e).__name__
        _down_until = time.time() + 2
        return (not FAIL_CLOSED), 0, type(e).__name__


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):          # the engine's own access log is the record of requests
        pass

    def do_GET(self):  # noqa: N802
        if self.path.split("?")[0] == "/health":
            return self._send(200, {"X-Shield-RL": "ok" if _healthy() else "down"})
        if self.path.split("?")[0] != "/check":
            return self._send(404)
        h = self.headers
        site = "".join(ch for ch in (h.get("X-Shield-Site") or "") if ch.isalnum() or ch in "-_")[:40]
        if not site:
            return self._send(400)
        try:
            rps, burst = float(h.get("X-Shield-Rps", "10")), float(h.get("X-Shield-Burst", "20"))
        except ValueError:
            return self._send(400)
        allowed, wait, err = check(site, h.get("X-Real-IP", ""), min(max(rps, 0.1), 100000), min(max(burst, 0), 1000000))
        if allowed:
            return self._send(204, {"X-Shield-RL": "error" if err else "ok"})
        if err:                                           # fail-closed: refused because the limiter cannot check (a plain 403, not "too many requests")
            return self._send(403, {"X-Shield-RL": "error"})
        return self._send(403, {"X-Shield-RL": "limited", "Retry-After": str(max(1, -(-wait // 1000)))})

    def _send(self, code, headers=None):
        self.send_response(code)
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.send_header("Content-Length", "0")
        self.end_headers()


def _healthy():
    try:
        _redis()[0].ping()
        return True
    except Exception:  # noqa: BLE001
        return False


def status():
    """For the GUI and the cluster page."""
    if not configured():
        return {"configured": False, "ok": False, "text": "not configured (rate limits are per replica)"}
    ok = _healthy()
    return {"configured": True, "ok": ok, "text": "Redis reachable" if ok else "Redis NOT reachable: " + (stats["last_error"] or "no answer") +
            (" (requests are refused)" if FAIL_CLOSED else " (requests are allowed; the per-replica limit still applies)"), **{k: stats[k] for k in ("allowed", "limited", "errors")}}


def start():
    """Start the local server once per process (only when Redis is configured)."""
    if not configured():
        return None
    srv = ThreadingHTTPServer(("127.0.0.1", PORT), _Handler)
    srv.daemon_threads = True
    threading.Thread(target=srv.serve_forever, daemon=True, name="ratelimit").start()
    print(f"[shieldwaf] cluster rate limiting: checks on 127.0.0.1:{PORT}, Redis configured", flush=True)
    return srv
