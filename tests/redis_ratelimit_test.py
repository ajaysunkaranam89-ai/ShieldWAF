"""Cluster-wide rate limiting against a REAL Redis and the REAL engine (nginx from the shieldwaf image), driven by tests/redis_ratelimit.sh.
Two nginx instances play two replicas: each has its own limiter (as each pod has) and both share one Redis. The nginx configuration is the one the panel
generates (engine._server). Phase "up": Redis is running. Phase "down": Redis was stopped by the script.
Usage: python3 redis_ratelimit_test.py up|down   (environment: SHIELD_REDIS_URL, run with /panel on the path)"""
import copy
import http.server
import os
import statistics
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request

sys.path.insert(0, "/panel")
import engine  # noqa: E402
import ratelimit  # noqa: E402
import store  # noqa: E402

PHASE = sys.argv[1] if len(sys.argv) > 1 else "up"
TMP = tempfile.mkdtemp()
BACK, A, B, LA, LB = 18090, 18091, 18092, 19101, 19102
RESULTS = []


def check(name, cond, extra=""):
    RESULTS.append(bool(cond))
    print(("PASS  " if cond else "FAIL  ") + name + (f"   [{extra}]" if extra and not cond else ""), flush=True)


class Backend(http.server.BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802
        self.send_response(200)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *a):
        pass


def start_nginx(n, port, limiter_port, scope="cluster"):
    site = copy.deepcopy(store.DEFAULT_SITE)
    site.update(id="s1", host="rl.test", upstream=f"http://127.0.0.1:{BACK}", mode="off", block_bots=False, sec_headers=False)
    site["rate_limit"] = {"enabled": True, "rps": 5, "burst": 10, "scope": scope}
    gen = os.path.join(TMP, f"gen{n}")
    os.makedirs(gen)
    open(os.path.join(gen, "bans.conf"), "w").close()
    engine.HTTP_PORT = port
    ratelimit.PORT = limiter_port
    server = engine._server(site, gen, False, "shared")
    upstream = engine.rl_upstream_block()
    conf = os.path.join(TMP, f"nginx{n}.conf")
    open(conf, "w").write(f"""load_module /etc/nginx/modules/ngx_http_modsecurity_module.so;
worker_processes 1; pid {TMP}/n{n}.pid; error_log {TMP}/err{n}.log warn;
events {{ worker_connections 256; }}
http {{
  access_log off;
{upstream}  map $http_upgrade $connection_upgrade {{ default upgrade; "" close; }}
  limit_conn_zone $binary_remote_addr zone=perip:10m;
  limit_req_zone $binary_remote_addr zone=rl_s1:10m rate=5r/s;       # the replica's own limit stays as a safety net
  client_body_temp_path {TMP}/cb{n}; proxy_temp_path {TMP}/px{n}; fastcgi_temp_path {TMP}/fc{n}; uwsgi_temp_path {TMP}/uw{n}; scgi_temp_path {TMP}/sc{n};
{server}}}
""")
    return subprocess.Popen(["nginx", "-g", "daemon off;", "-c", conf], stderr=subprocess.PIPE)


def get(port, timeout=5):
    t0 = time.time()
    try:
        r = urllib.request.urlopen(f"http://127.0.0.1:{port}/", timeout=timeout)
        return r.status, {}, time.time() - t0
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), time.time() - t0


def wait_up(port):
    for _ in range(50):
        try:
            urllib.request.urlopen(f"http://127.0.0.1:{port}/", timeout=2)
            return True
        except urllib.error.HTTPError:
            return True
        except Exception:  # noqa: BLE001
            time.sleep(0.2)
    return False


srv = http.server.ThreadingHTTPServer(("127.0.0.1", BACK), Backend)
threading.Thread(target=srv.serve_forever, daemon=True).start()

if PHASE == "up":
    print("== token bucket in Redis", flush=True)
    r = ratelimit.status()
    check("the limiter sees Redis", r["configured"] and r["ok"], r)
    ratelimit.PORT = LA
    res = [ratelimit.check("t1", "198.51.100.7", 5, 10)[0] for _ in range(14)]
    check("a burst of 10 plus the first request is allowed, then the 12th is refused (rate 5/s, burst 10)", res[:11] == [True] * 11 and res[11] is False, res)
    wait = ratelimit.check("t1", "198.51.100.7", 5, 10)[1]
    check("a refused request carries a wait time for Retry-After (about 200 ms at 5/s)", 100 <= wait <= 400, wait)
    time.sleep(1.1)
    res = [ratelimit.check("t1", "198.51.100.7", 5, 10)[0] for _ in range(8)]
    check("after one second about 5 requests are allowed again (the bucket refills at the rate)", 4 <= sum(res) <= 7, res)
    check("another client address has its own bucket", ratelimit.check("t1", "198.51.100.8", 5, 10)[0] is True)
    ok1 = [ratelimit.check("t2", "2001:db8:1:2::1", 1, 2)[0] for _ in range(5)]
    ok2 = [ratelimit.check("t2", "2001:db8:1:2:ffff::9", 1, 2)[0] for _ in range(1)]
    check("IPv6 clients are counted per /64 (a second address of the same /64 shares the bucket)", sum(ok1) == 3 and ok2 == [False], (ok1, ok2))
    check("an IPv4-mapped IPv6 address is the same client as the IPv4 address", ratelimit.client_key("::ffff:198.51.100.7") == "198.51.100.7")

    print("== two replicas (nginx + limiter each) sharing one Redis", flush=True)
    ratelimit.PORT = LA
    sa = ratelimit.ThreadingHTTPServer(("127.0.0.1", LA), ratelimit._Handler)
    sb = ratelimit.ThreadingHTTPServer(("127.0.0.1", LB), ratelimit._Handler)
    for s in (sa, sb):
        s.daemon_threads = True
        threading.Thread(target=s.serve_forever, daemon=True).start()
    na, nb = start_nginx("a", A, LA), start_nginx("b", B, LB)
    check("both engines start with the generated configuration", wait_up(A) and wait_up(B), [p.stderr.read().decode()[-400:] for p in (na, nb) if p.poll() is not None])
    time.sleep(2.5)                                                       # let the bucket of this client address refill completely
    out = [get(A if i % 2 == 0 else B) for i in range(40)]
    allowed = sum(1 for s, _h, _t in out if s == 200)
    limited = [(s, h) for s, h, _t in out if s == 429]
    check("alternating over both replicas, the client gets about ONE bucket (11 plus the refill during the test), not one per replica",
          11 <= allowed <= 15, f"allowed {allowed} of 40")
    with_ra = sum(1 for _s, h in limited if h.get("Retry-After"))
    check("refused requests are answered 429; the ones refused by the shared bucket carry Retry-After (the replica's own safety-net limit does not)", len(limited) >= 25 and with_ra >= 8, (len(limited), with_ra))
    got_a = sum(1 for i, (s, _h, _t) in enumerate(out) if s == 200 and i % 2 == 0)
    got_b = sum(1 for i, (s, _h, _t) in enumerate(out) if s == 200 and i % 2 == 1)
    check("both replicas served some of the allowed requests (the bucket is really shared)", got_a >= 3 and got_b >= 3, (got_a, got_b))
    time.sleep(2.5)
    lat = [get(A)[2] for _ in range(10)]
    check("an allowed request costs little time through the limiter (median under 50 ms)", statistics.median(lat) < 0.05, f"{statistics.median(lat) * 1000:.1f} ms")
    nc = start_nginx("c", 18093, 19199)                                  # a replica whose limiter is not running at all
    check("a missing limiter never turns into a 500: the request is allowed (fail-open at the engine)", wait_up(18093) and get(18093)[0] == 200, get(18093)[0])
    for p in (na, nb, nc):
        p.terminate()
    st = ratelimit.status()
    check("the counters are visible (allowed and limited)", st["allowed"] > 0 and st["limited"] > 0, st)

else:
    print("== Redis is down", flush=True)
    ratelimit.PORT = LA
    sa = ratelimit.ThreadingHTTPServer(("127.0.0.1", LA), ratelimit._Handler)
    threading.Thread(target=sa.serve_forever, daemon=True).start()
    na = start_nginx("a", A, LA)
    wait_up(A)
    t0 = time.time()
    out, lat = [], []
    for _ in range(20):                                                  # 4 requests per second: under the replica's own safety-net limit (5/s)
        s, _h, t = get(A)
        out.append(s)
        lat.append(t)
        time.sleep(0.25)
    took = time.time() - t0
    check("with Redis down the traffic keeps flowing (fail-open): all 20 requests are served", out.count(200) == 20, out)
    check("...and no request waits more than 1.5 s for the dead Redis (nginx gives up after 0.4 s, the limiter stops asking for 2 s after an error)", max(lat) < 1.5, f"max {max(lat):.2f}s, median {statistics.median(lat):.2f}s")
    check("the status says Redis is not reachable and what happens meanwhile", (not ratelimit.status()["ok"]) and "allowed" in ratelimit.status()["text"], ratelimit.status())
    check("the errors are counted", ratelimit.stats["errors"] >= 1 and ratelimit.stats["last_error"], ratelimit.stats)
    ratelimit.FAIL_CLOSED = True
    print("direct:", ratelimit.check("x", "198.51.100.9", 5, 10), "closed:", ratelimit.FAIL_CLOSED, flush=True)
    out = [get(A)[0] for _ in range(5)]
    na.terminate()
    na = start_nginx("a2", A + 10, LA)                                  # the configuration is generated again, now in fail-closed mode
    wait_up(A + 10)
    out = [get(A + 10)[0] for _ in range(5)]
    check("with SHIELD_RL_FAIL=closed requests are refused (403) while Redis is down", out.count(200) == 0 and all(s == 403 for s in out), out)
    sd = ratelimit.ThreadingHTTPServer(("127.0.0.1", LA + 50), ratelimit._Handler)
    threading.Thread(target=sd.serve_forever, daemon=True).start()
    nd = start_nginx("d", A + 20, 19999)                                # limiter not running AND fail-closed: also refused
    wait_up(A + 20)
    check("...also when the limiter itself is not running", get(A + 20)[0] == 403, get(A + 20)[0])
    nd.terminate()
    na.terminate()

bad = RESULTS.count(False)
print(f"{len(RESULTS) - bad}/{len(RESULTS)} checks passed in phase {PHASE}")
sys.exit(1 if bad else 0)
