"""Bot protection (module H) in the REAL engine: the njs scoring (panel/njs/bots.js) runs inside nginx from the shieldwaf image, with the server blocks the panel generates
(engine._server). Skipped when nginx is missing. Cases: what a browser, a script and an attack tool look like, the modes, exclusions and allow-list, the challenge hand-off."""
import copy
import http.server
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "panel"))
import engine  # noqa: E402
import store  # noqa: E402

NGINX = shutil.which("nginx") or ("/usr/sbin/nginx" if os.path.exists("/usr/sbin/nginx") else None)
MODSEC = "/etc/nginx/modules/ngx_http_modsecurity_module.so"
HAVE_ENGINE = bool(NGINX) and os.path.exists(MODSEC) and os.path.isdir("/panel/njs")
PORT, BACK = 18101, 18102

BROWSER = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
           "Accept": "text/html,application/xhtml+xml", "Accept-Language": "en-US,en;q=0.9", "Accept-Encoding": "gzip, deflate, br"}


class Back(http.server.BaseHTTPRequestHandler):
    seen = []

    def do_GET(self):  # noqa: N802
        Back.seen.append(dict(self.headers))
        self.send_response(200)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *a):
        pass


def site(host, **bots):
    s = copy.deepcopy(store.DEFAULT_SITE)
    s.update(id=host.split(".")[0].replace("-", ""), host=host, upstream=f"http://127.0.0.1:{BACK}", mode="off", block_bots=False, sec_headers=False)
    s["bots"] = {"mode": "off", "threshold": 6, "exclude_paths": "", "allow_ua": ""}
    s["bots"].update(bots)
    return s


@unittest.skipUnless(HAVE_ENGINE, "needs nginx + ModSecurity + /panel/njs (run inside the shieldwaf image: tests/unit/run.sh)")
class Bots(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp()
        sites = [site("off.test"), site("detect.test", mode="detect"), site("block.test", mode="block"), site("excl.test", mode="block", exclude_paths="/api/"),
                 site("allow.test", mode="block", allow_ua="monitoring-agent"), site("high.test", mode="block", threshold=12)]
        ch = site("chal.test", mode="challenge")
        ch["challenge"].update(enabled=True, difficulty=3, ttl_hours=1, scope="pages", exclude_paths="")
        nochal = site("nochal.test", mode="challenge")                       # challenge mode without the proof-of-work page falls back to block
        sites += [ch, nochal]
        gen = os.path.join(cls.tmp, "gen")
        os.makedirs(gen)
        open(os.path.join(gen, "bans.conf"), "w").close()
        engine.HTTP_PORT = PORT
        servers = "\n".join(engine._server(s, gen, False, "shared") for s in sites)
        os.makedirs("/data", exist_ok=True)
        try:
            open("/data/challenge.key", "w").write("k" * 32)
        except OSError:
            pass
        conf = os.path.join(cls.tmp, "nginx.conf")
        open(conf, "w").write(f"""load_module {MODSEC};
load_module /etc/nginx/modules/ngx_http_js_module.so;
worker_processes 1; pid {cls.tmp}/n.pid; error_log {cls.tmp}/err.log warn;
events {{ worker_connections 256; }}
http {{
  access_log off;
  client_body_temp_path {cls.tmp}/cb; proxy_temp_path {cls.tmp}/px; fastcgi_temp_path {cls.tmp}/fc; uwsgi_temp_path {cls.tmp}/uw; scgi_temp_path {cls.tmp}/sc;
  map $http_upgrade $connection_upgrade {{ default upgrade; "" close; }}
  js_path {engine.NJS_DIR};
  js_import challenge from {engine.NJS_DIR}/challenge.js;
  js_set $chal_need challenge.need;
  js_import bots from {engine.NJS_DIR}/bots.js;
  js_set $bot_score bots.score;
  js_set $bot_action bots.action;
  limit_conn_zone $binary_remote_addr zone=perip:10m;
  limit_req_zone $binary_remote_addr zone=chal_verify:10m rate=10r/s;
{servers}
}}
""")
        cls.back = http.server.ThreadingHTTPServer(("127.0.0.1", BACK), Back)
        threading.Thread(target=cls.back.serve_forever, daemon=True).start()
        cls.nginx = subprocess.Popen([NGINX, "-g", "daemon off;", "-c", conf], stderr=subprocess.PIPE)
        for _ in range(50):
            try:
                urllib.request.urlopen(urllib.request.Request(f"http://127.0.0.1:{PORT}/", headers={"Host": "off.test"}), timeout=2)
                break
            except urllib.error.HTTPError:
                break
            except Exception:  # noqa: BLE001
                time.sleep(0.2)
        else:
            raise RuntimeError("nginx did not start: " + (cls.nginx.stderr.read().decode()[-500:] if cls.nginx.poll() is not None else "no answer"))

    @classmethod
    def tearDownClass(cls):
        cls.nginx.terminate()
        cls.back.shutdown()

    def get(self, host, path="/", headers=None):
        h = dict(headers or {})
        h["Host"] = host
        req = urllib.request.Request(f"http://127.0.0.1:{PORT}{path}", headers=h)
        try:
            r = urllib.request.urlopen(req, timeout=5)
            return r.status, r.read().decode()
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode()

    def test_a_normal_browser_is_never_a_bot(self):
        self.assertEqual(self.get("block.test", headers=BROWSER)[0], 200)

    def test_attack_tools_score_high_and_are_blocked(self):
        for ua in ("sqlmap/1.7", "Nikto/2.5", "nuclei - Open-source project", "feroxbuster/2.10"):
            with self.subTest(ua=ua):
                self.assertEqual(self.get("block.test", headers={"User-Agent": ua, "Accept": "*/*"})[0], 403)

    def test_a_script_without_a_user_agent_is_blocked_but_not_when_judging_is_off(self):
        self.assertEqual(self.get("block.test", headers={"User-Agent": ""})[0], 403)
        self.assertEqual(self.get("off.test", headers={"User-Agent": ""})[0], 200)

    def test_automation_libraries_reach_the_threshold_only_together_with_other_signs(self):
        # an API client: automation UA alone = 4 points, below the threshold of 6 (machine clients keep working by default)
        self.assertEqual(self.get("block.test", headers={"User-Agent": "python-requests/2.31", "Accept": "application/json"})[0], 200)
        # a "browser" that sends no Accept-Language and no Accept-Encoding and no Accept = 5; with an automation word in its user agent it is over the line
        self.assertEqual(self.get("block.test", headers={"User-Agent": "Mozilla/5.0 (X11) HeadlessChrome/120.0"})[0], 403)

    def test_a_browser_user_agent_without_browser_headers_is_blocked_at_the_default_threshold(self):
        h = {"User-Agent": BROWSER["User-Agent"], "Accept": "*/*"}                 # no Accept-Language (2) + no Accept-Encoding (1): 3 -> allowed
        self.assertEqual(self.get("block.test", headers=h)[0], 200)
        h = {"User-Agent": "Mozilla/5.0 (compatible; HeadlessChrome/120.0)", "Accept": "*/*"}   # headless (4) + the missing headers (3) = 7
        self.assertEqual(self.get("block.test", headers=h)[0], 403)

    def test_detect_mode_never_blocks_and_tells_the_application_the_score(self):
        Back.seen.clear()
        self.assertEqual(self.get("detect.test", headers={"User-Agent": "sqlmap/1.7"})[0], 200)
        self.assertEqual(Back.seen[-1].get("X-Shield-Bot-Score"), "10")

    def test_a_client_cannot_fake_the_score_header(self):
        Back.seen.clear()
        self.get("block.test", headers={**BROWSER, "X-Shield-Bot-Score": "0"})
        self.assertEqual(Back.seen[-1].get("X-Shield-Bot-Score"), "0")                        # the real score of a browser is 0 ...
        self.get("off.test", headers={**BROWSER, "X-Shield-Bot-Score": "99"})
        self.assertIn(Back.seen[-1].get("X-Shield-Bot-Score"), (None, ""))                  # ... and with the feature off the client's value is removed

    def test_excluded_paths_and_allowed_user_agents_are_not_judged(self):
        self.assertEqual(self.get("excl.test", "/page", {"User-Agent": "sqlmap/1.7"})[0], 403)
        self.assertEqual(self.get("excl.test", "/api/items", {"User-Agent": "sqlmap/1.7"})[0], 200)
        self.assertEqual(self.get("allow.test", "/", {"User-Agent": "Monitoring-Agent/1.0 sqlmap"})[0], 200)

    def test_the_threshold_is_per_site(self):
        self.assertEqual(self.get("high.test", headers={"User-Agent": "Mozilla/5.0 (compatible; HeadlessChrome/120.0)", "Accept": "*/*"})[0], 200)      # 7 < 12
        self.assertEqual(self.get("high.test", headers={"User-Agent": "sqlmap/1.7"})[0], 200)         # 10 < 12: this site tolerates tools until they add more signs

    def test_challenge_mode_sends_a_suspect_to_the_proof_of_work_page(self):
        code, body = self.get("chal.test", "/", {"User-Agent": "Mozilla/5.0 (compatible; HeadlessChrome/120.0)", "Accept": "*/*"})
        self.assertEqual(code, 200)
        self.assertNotEqual(body, "ok")
        api = {**BROWSER, "Accept": "application/json"}
        self.assertEqual(self.get("chal.test", "/", api)[1], "ok")                             # scope "pages": a normal API client with a score of 0 is not asked

    def test_challenge_mode_without_the_challenge_feature_falls_back_to_block(self):
        self.assertEqual(self.get("nochal.test", "/", {"User-Agent": "sqlmap/1.7"})[0], 403)


if __name__ == "__main__":
    unittest.main()
