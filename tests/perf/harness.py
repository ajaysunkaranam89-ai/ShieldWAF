"""Performance harness: the REAL engine (nginx + the server blocks the panel generates) in front of a trivial backend, with sites that switch the 2.4 request-path
features on one by one. Runs inside a shieldwaf image (2.3 or 2.4); for 2.3 only the plain site exists. No ModSecurity rules are loaded (sites in mode "off"): the cost
of the OWASP rule set is the same in 2.3 and 2.4 and would hide the differences measured here. Started by tests/perf/perf.sh."""
import copy
import os
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, "/panel")
import engine  # noqa: E402
import store  # noqa: E402

NEW = hasattr(engine, "uses_cluster_rl")
if NEW:
    import ratelimit  # noqa: E402
PORT, BACK = 18101, 18102
TMP = tempfile.mkdtemp()


def site(host, **kw):
    s = copy.deepcopy(store.DEFAULT_SITE)
    s.update(id=host.split(".")[0], host=host, upstream=f"http://127.0.0.1:{BACK}", mode="off", block_bots=False, sec_headers=False)
    s.update(kw)
    return s


BOTS = {"mode": "block", "threshold": 6, "exclude_paths": "", "allow_ua": ""}
CLUSTER = {"enabled": True, "rps": 100000, "burst": 100000, "scope": "cluster"}
REPLICA = {"enabled": True, "rps": 100000, "burst": 100000, "scope": "replica"}
sites = [site("plain.test")]
if NEW:
    sites += [site("bots.test", bots=BOTS), site("rl.test", rate_limit=CLUSTER), site("all.test", bots=BOTS, rate_limit=CLUSTER), site("local.test", rate_limit=REPLICA)]
gen = os.path.join(TMP, "gen")
os.makedirs(gen)
open(os.path.join(gen, "bans.conf"), "w").close()
engine.HTTP_PORT = PORT
servers = "\n".join(engine._server(s, gen, False, "shared") for s in sites)
zones = "".join(f"  limit_req_zone $binary_remote_addr zone=rl_{s['id']}:10m rate={int(s['rate_limit']['rps'])}r/s;\n" for s in sites if s["rate_limit"]["enabled"])
js = f"  js_path {engine.NJS_DIR};\n  js_import challenge from {engine.NJS_DIR}/challenge.js;\n  js_set $chal_need challenge.need;\n"
if NEW:
    js += f"  js_import bots from {engine.NJS_DIR}/bots.js;\n  js_set $bot_score bots.score;\n  js_set $bot_action bots.action;\n"
workers = os.environ.get("WORKERS", "2")
conf = f"""load_module /etc/nginx/modules/ngx_http_modsecurity_module.so;
load_module /etc/nginx/modules/ngx_http_js_module.so;
worker_processes {workers}; pid {TMP}/n.pid; error_log {TMP}/err.log warn;
events {{ worker_connections 4096; }}
http {{
  access_log off;
  client_body_temp_path {TMP}/cb; proxy_temp_path {TMP}/px; fastcgi_temp_path {TMP}/fc; uwsgi_temp_path {TMP}/uw; scgi_temp_path {TMP}/sc;
  map $http_upgrade $connection_upgrade {{ default upgrade; "" close; }}
{js}  limit_conn_zone $binary_remote_addr zone=perip:10m;
  limit_req_zone $binary_remote_addr zone=chal_verify:10m rate=10r/s;
{zones}{servers}
}}
"""
open(os.path.join(TMP, "nginx.conf"), "w").write(conf)
bconf = f"""worker_processes 2; pid {TMP}/b.pid; error_log {TMP}/berr.log warn; events {{ worker_connections 4096; }}
http {{ access_log off; client_body_temp_path {TMP}/bcb; proxy_temp_path {TMP}/bpx; fastcgi_temp_path {TMP}/bfc; uwsgi_temp_path {TMP}/buw; scgi_temp_path {TMP}/bsc;
  server {{ listen {BACK}; location / {{ return 200 "ok"; }} }} }}
"""
open(os.path.join(TMP, "backend.conf"), "w").write(bconf)
if NEW and ratelimit.configured():
    ratelimit.start()
subprocess.Popen(["nginx", "-g", "daemon off;", "-c", os.path.join(TMP, "backend.conf")])
e = subprocess.Popen(["nginx", "-g", "daemon off;", "-c", os.path.join(TMP, "nginx.conf")])
time.sleep(1.5)
print("READY", "new" if NEW else "old", flush=True)
e.wait()
