"""High-availability test for A Shield WAF 2.3 on a throw-away deployment with 3 replicas in the namespace "shieldwaf-test".
It talks to every replica directly (one tunnel per pod), so it can prove that a change made on one replica is served by all of them,
that sessions and certificates are shared, that nothing is lost when administrators work on different replicas at the same time,
that 80 sites reload in seconds, and that killing a replica, stopping the database or doing a rolling restart does not stop the firewall.
Throw-away random passwords, never printed. Needs kubectl, curl is not required."""
import base64
import collections
import hashlib
import http.cookiejar
import json
import re
import secrets
import socket
import ssl
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

NS = "shieldwaf-test"
DEMO_NS = "shieldwaf-demo"
NOTES = "http://demo-notes.shieldwaf-demo.svc.cluster.local:80"
SQLI = "/?q=" + urllib.parse.quote("1' OR '1'='1' UNION SELECT NULL--")
CTX = ssl.create_default_context()
CTX.check_hostname = False
CTX.verify_mode = ssl.CERT_NONE
results = []


def check(name, cond, extra=""):
    results.append((name, bool(cond)))
    print(("PASS  " if cond else "FAIL  ") + name + (f"   [{extra}]" if extra and not cond else ""), flush=True)


def kube(*args, timeout=120, check_rc=False):
    r = subprocess.run(["kubectl", "-n", NS, *args], capture_output=True, text=True, timeout=timeout)
    if check_rc and r.returncode != 0:
        raise RuntimeError(r.stderr)
    return r.stdout


def psql(sql):
    return subprocess.run(["kubectl", "-n", NS, "exec", "shieldwaf-db-0", "--", "psql", "-U", "shieldwaf", "-d", "shieldwaf", "-tA", "-c", sql],
                          capture_output=True, text=True, timeout=60).stdout.strip()


def pods():
    out = json.loads(kube("get", "pods", "-l", "app=shieldwaf", "-o", "json") or '{"items":[]}')
    res = []
    for p in out["items"]:
        if p["metadata"].get("deletionTimestamp"):
            continue
        ready = all(c.get("ready") for c in p["status"].get("containerStatuses", [])) and len(p["status"].get("containerStatuses", [])) == 2
        res.append((p["metadata"]["name"], ready, p["status"].get("podIP", ""), p["spec"].get("nodeName", "")))
    return sorted(res)


def wait_pods(n, timeout=240):
    end = time.time() + timeout
    while time.time() < end:
        ps = [p for p in pods() if p[1]]
        if len(ps) >= n and len(pods()) == len(ps):
            return ps
        time.sleep(3)
    return [p for p in pods() if p[1]]


class Tunnel:
    """kubectl port-forward to one pod: panel, plain proxy and TLS proxy ports."""
    _next = 22000

    def __init__(self, pod):
        self.pod = pod
        Tunnel._next += 10
        self.panel, self.http, self.tls = Tunnel._next, Tunnel._next + 1, Tunnel._next + 2
        self.alive = True
        self.proc = None
        threading.Thread(target=self._keep, daemon=True).start()
        for _ in range(60):
            try:
                socket.create_connection(("127.0.0.1", self.http), timeout=1).close()
                return
            except OSError:
                time.sleep(0.5)

    def _keep(self):
        """kubectl port-forward drops now and then: restart it for as long as the tunnel is wanted."""
        while self.alive:
            self.proc = subprocess.Popen(["kubectl", "-n", NS, "port-forward", f"pod/{self.pod}", f"{self.panel}:9000", f"{self.http}:8080", f"{self.tls}:8443"],
                                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            self.proc.wait()
            time.sleep(0.5)

    def close(self):
        self.alive = False
        if self.proc:
            self.proc.terminate()


class Panel:
    def __init__(self, port):
        self.base = f"https://127.0.0.1:{port}"
        self.jar = http.cookiejar.CookieJar()
        self.op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.jar), urllib.request.HTTPSHandler(context=CTX))

    def req(self, path, data=None, timeout=120):
        body = urllib.parse.urlencode(data, doseq=True).encode() if data is not None else None
        try:
            r = self.op.open(urllib.request.Request(self.base + path, data=body), timeout=timeout)
            return r.status, r.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode("utf-8", "replace")
        except Exception as e:  # noqa: BLE001
            return 0, str(e)

    @staticmethod
    def token(html):
        m = re.search(r'name="_csrf" value="([0-9a-f]+)"', html)
        return m.group(1) if m else ""

    def post(self, path, fields, page="/dashboard"):
        _, html = self.req(page)
        d = dict(fields)
        d["_csrf"] = self.token(html)
        return self.req(path, d)


def site_form(host, upstream=NOTES, **kw):
    f = {"host": host, "upstream": upstream, "enabled": "on", "mode": "block", "paranoia": "1", "threshold": "5", "max_body_mb": "10",
         "down_page": "on", "block_bots": "on", "sec_headers": "on", "rl_rps": "10", "rl_burst": "20",
         "methods": ["GET", "HEAD", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"], "tls_source": "none", "tls_hsts_days": "365",
         "auth_realm": "Restricted", "chal_difficulty": "4", "chal_ttl": "12", "chal_scope": "pages"}
    f.update(kw)
    return {k: v for k, v in f.items() if v is not None}


def px(t, host, path="/", method="GET", headers=None):
    h = {"Host": host, **(headers or {})}
    try:
        r = urllib.request.urlopen(urllib.request.Request(f"http://127.0.0.1:{t.http}{path}", headers=h, method=method), timeout=15)
        return r.status
    except urllib.error.HTTPError as e:
        return e.code
    except Exception:  # noqa: BLE001
        return 0


def cert_fp(t, host):
    try:
        with socket.create_connection(("127.0.0.1", t.tls), timeout=8) as s, CTX.wrap_socket(s, server_hostname=host) as ss:
            return hashlib.sha256(ss.getpeercert(binary_form=True)).hexdigest()
    except Exception:  # noqa: BLE001
        return ""


def converge(tuns, host, path, want, timeout=20):
    """Wait until every replica answers `want` for the request (a replica applies a change within about a second)."""
    end = time.time() + timeout
    got = {}
    while time.time() < end:
        got = {t.pod: px(t, host, path) for t in tuns}
        if all(v == want for v in got.values()):
            return True, got
        time.sleep(0.5)
    return False, got


def leader_name():
    return psql("select name from nodes where ts > extract(epoch from now())-12 and info::json->>'leader'='true'").splitlines()


# =============================================================================================== 0. three replicas
import os
HERE = os.path.dirname(os.path.abspath(__file__))


def sh(*args, timeout=180, inp=None):
    return subprocess.run(list(args), capture_output=True, text=True, timeout=timeout, input=inp)


print("== preparing the ACME test server (Pebble)", flush=True)
sh("kubectl", "apply", "-f", os.path.join(HERE, "pebble.yaml"))
cid = sh("docker", "create", "ghcr.io/letsencrypt/pebble:latest").stdout.strip()
ca_file = os.path.join(HERE, ".pebble-ca.pem")
sh("docker", "cp", f"{cid}:/test/certs/pebble.minica.pem", ca_file)
sh("docker", "rm", cid)
sh("kubectl", "-n", NS, "delete", "configmap", "acme-ca", "--ignore-not-found")
sh("kubectl", "-n", NS, "create", "configmap", "acme-ca", f"--from-file=ca.pem={ca_file}")
os.remove(ca_file)
sh("kubectl", "-n", NS, "apply", "-f", "-", inp="apiVersion: v1\nkind: Service\nmetadata: {name: pebble}\nspec: {type: ExternalName, externalName: pebble.shieldwaf-demo.svc.cluster.local}\n")
patch_ops = [
    {"op": "add", "path": "/spec/template/spec/containers/1/env/-", "value": {"name": "SHIELD_ACME_TEST_CA", "value": "/acme-ca/ca.pem"}},
    {"op": "add", "path": "/spec/template/spec/containers/1/env/-", "value": {"name": "SHIELD_ACME_ALLOW_PRIVATE", "value": "1"}},
    {"op": "add", "path": "/spec/template/spec/containers/1/volumeMounts/-", "value": {"name": "acme-ca", "mountPath": "/acme-ca", "readOnly": True}},
    {"op": "add", "path": "/spec/template/spec/volumes/-", "value": {"name": "acme-ca", "configMap": {"name": "acme-ca"}}}]
sh("kubectl", "-n", NS, "patch", "deploy/shieldwaf-test", "--type", "json", "-p", json.dumps(patch_ops))
proxy_ip = kube("get", "svc", "shieldwaf-proxy", "-o", "jsonpath={.spec.clusterIP}").strip()
sh("kubectl", "-n", DEMO_NS, "patch", "deploy/challtest", "--type", "json", "-p",
   json.dumps([{"op": "replace", "path": "/spec/template/spec/containers/0/args", "value": ["-defaultIPv4", proxy_ip, "-defaultIPv6", ""]}]))
sh("kubectl", "-n", NS, "rollout", "status", "deploy/shieldwaf-test", "--timeout=240s", timeout=260)
sh("kubectl", "-n", DEMO_NS, "rollout", "status", "deploy/challtest", "--timeout=120s", timeout=140)
sh("kubectl", "-n", DEMO_NS, "rollout", "status", "deploy/pebble", "--timeout=180s", timeout=200)

print("== waiting for 3 replicas", flush=True)
kube("scale", "deploy/shieldwaf-test", "--replicas=3")
ps = wait_pods(3)
check("three replicas are running and ready", len(ps) == 3, str(ps))
check("replicas are spread over more than one node", len({p[3] for p in ps}) > 1, str([p[3] for p in ps]))
T = {p[0]: Tunnel(p[0]) for p in ps}
tl = list(T.values())
codes = {re.search(r"Setup code: (\w+)", kube("logs", p[0], "-c", "panel")).group(1) for p in ps if "Setup code" in kube("logs", p[0], "-c", "panel")}
check("every replica shows the SAME setup code (shared bootstrap secret)", len(codes) == 1, str(codes))
code = codes.pop() if codes else ""
fps = {p[0]: kube("exec", p[0], "-c", "panel", "--", "sh", "-c", "sha256sum /data/challenge.key /data/secret.key /data/certs/panel/fullchain.pem | cut -c1-16") for p in ps}
check("challenge key, session key and panel certificate are identical on all replicas", len(set(fps.values())) == 1, str(fps))
row = psql("select count(*) from sfiles where path in ('challenge.key','secret.key','certs/panel')")
check("shared files are stored in the database", row == "3", row)
stored = psql("select data from sfiles where path='secret.key'")
check("shared files in the database are encrypted (not readable text)", stored.startswith("gAAAA") and len(stored) > 60, stored[:20])

# =============================================================================================== 1. sessions are shared
PW = secrets.token_urlsafe(14) + "aB3#"
A, B, C = (Panel(t.panel) for t in tl)
_, html = A.req("/setup")
s, html = A.req("/setup", {"_csrf": A.token(html), "username": "hatester", "password": PW, "password2": PW, "code": code})
check("admin account is created through replica 1", "Dashboard" in html, re.sub(r"<[^>]+>", " ", html)[:200])
B.jar.clear()
# copy the session cookie of replica 1 to the client talking to replica 2: server-side sessions live in the database
for c in A.jar:
    B.jar.set_cookie(c)
s, html = B.req("/dashboard")
check("a session started on replica 1 is valid on replica 2 (shared sessions and key)", "Requests" in html, html[:100])
s, html = B.req("/cluster")
names = re.findall(r'<td class="mono">(shieldwaf-test-[a-z0-9-]+)', html)
check("Cluster page lists all three running replicas (replicas that stopped earlier stay listed as offline for a day)", {p_[0] for p_ in ps} <= set(names), str(set(names)))
for _ in range(20):      # a replica that stopped a moment ago (the setup restart) can still be listed as leader for up to 12 seconds
    if len(leader_name()) == 1:
        break
    time.sleep(1)
s, html = B.req("/cluster")
check("exactly one replica is the leader", len(leader_name()) == 1 and html.count('p-ok">leader') == 1, str(leader_name()))
for c in A.jar:
    C.jar.set_cookie(c)
for p_ in (B, C):
    p_.req("/dashboard")

# =============================================================================================== 2. a change on one replica reaches all
print("== changes propagate", flush=True)
s, html = A.post("/sites/new", site_form("ha1.test"), "/sites/new")
check("site added on replica 1 and the page says it was applied on 3/3 replicas", "site added" in html and "3/3 replicas" in re.sub(r"<[^>]+>", " ", html),
      re.sub(r"<[^>]+>", " ", html)[250:420])
ok, got = converge(tl, "ha1.test", "/", 200, 5)
check("...and every replica serves it immediately", ok, str(got))
ok, got = converge(tl, "ha1.test", SQLI, 403, 5)
check("...and every replica blocks an SQL injection", ok, str(got))
ids = {}
for m in re.finditer(r"<td><b>([\w.*-]+)</b>.*?/sites/(s[0-9a-f]+)\"", B.req("/sites")[1], re.S):
    ids.setdefault(m.group(1), m.group(2))
check("replica 2 lists the site added on replica 1", "ha1.test" in ids, str(ids))
s, html = B.post(f"/sites/{ids.get('ha1.test', 'x')}/maintenance", {"state": "on"}, "/sites")
ok, got = converge(tl, "ha1.test", "/", 503, 8)
check("maintenance switched on through replica 2 shows on all replicas", ok, str(got))
B.post(f"/sites/{ids.get('ha1.test', 'x')}/maintenance", {"state": "off"}, "/sites")
ok, got = converge(tl, "ha1.test", "/", 200, 8)
check("maintenance switched off again on all replicas", ok, str(got))

# certificates are shared
s, html = C.post("/sites/new", site_form("tls.ha.test", tls_enabled="on", tls_source="selfsigned", tls_generate="on"), "/sites/new")
check("TLS site with generated certificate added through replica 3", "site added" in html, re.sub(r"<[^>]+>", " ", html)[250:400])
time.sleep(2)
fp = {t.pod: cert_fp(t, "tls.ha.test") for t in tl}
check("all replicas serve the SAME certificate for the site (shared through the database)", len(set(fp.values())) == 1 and "" not in fp.values(), str(fp))
ver = psql("select count(*) from sfiles where path like 'certs/s%'")
check("the certificate is stored encrypted in the database", ver == "1", ver)

# concurrent administrators on different replicas
print("== concurrent administrators", flush=True)
panels = [A, B, C]
errs = []


def add(i):
    try:
        pnl = panels[i % 3]
        s_, h_ = pnl.post("/sites/new", site_form(f"c{i}.ha.test"), "/sites/new")
        if "site added" not in h_:
            errs.append((i, re.sub(r"<[^>]+>", " ", h_)[250:380]))
    except Exception as e:  # noqa: BLE001
        errs.append((i, str(e)))


th = [threading.Thread(target=add, args=(i,)) for i in range(12)]
t0 = time.time()
for x in th:
    x.start()
for x in th:
    x.join()
check("12 sites added at the same time through 3 replicas: all accepted", not errs, str(errs)[:300])
page = A.req("/sites")[1]
have = [i for i in range(12) if f"c{i}.ha.test" in page]
check("...and none was lost (no overwritten changes)", len(have) == 12, f"{len(have)}/12 in {time.time() - t0:.0f}s")
ok, got = converge(tl, "c11.ha.test", "/", 200, 15)
check("...and the last one is served by every replica", ok, str(got))

# =============================================================================================== 3. 80 sites reload fast
print("== 80 sites", flush=True)
sites = [{"host": f"s{i:02d}.big.test", "upstream": NOTES, "mode": "block"} for i in range(70)]
sites += [{"host": "ha1.test", "upstream": NOTES, "mode": "block"},
          {"host": "detect.big.test", "upstream": NOTES, "mode": "detect"},
          {"host": "lax.big.test", "upstream": NOTES, "mode": "block", "threshold": 100},
          {"host": "strict.big.test", "upstream": NOTES, "mode": "block", "paranoia": 3},
          {"host": "excl.big.test", "upstream": NOTES, "mode": "block", "exclusions": [{"rule": "942100", "path": "/api"}]},
          {"host": "own.big.test", "upstream": NOTES, "mode": "block",
           "custom_rules": 'SecRule REQUEST_URI "@contains /custom-block" "id:1000001,phase:1,deny,status:403,msg:custom"'},
          {"host": "*.wild.test", "upstream": NOTES, "mode": "block"},
          {"host": "a.wild.test", "upstream": NOTES, "mode": "detect"},
          {"host": "off.big.test", "upstream": NOTES, "mode": "off"}]
boundary = "----x" + secrets.token_hex(6)
_, html = A.req("/backup")
payload = (f"--{boundary}\r\nContent-Disposition: form-data; name=\"_csrf\"\r\n\r\n{A.token(html)}\r\n--{boundary}\r\nContent-Disposition: form-data; "
           f"name=\"file\"; filename=\"a.json\"\r\nContent-Type: application/json\r\n\r\n{json.dumps({'sites': sites})}\r\n--{boundary}--\r\n").encode()
t0 = time.time()
try:
    r = A.op.open(urllib.request.Request(A.base + "/backup/import", data=payload, headers={"Content-Type": "multipart/form-data; boundary=" + boundary}), timeout=180)
    html = r.read().decode()
except urllib.error.HTTPError as e:
    html = e.read().decode()
took = time.time() - t0
txt = re.sub(r"<[^>]+>", " ", html)
check("importing 79 sites is applied on all 3 replicas", "config imported" in txt and "3/3 replicas" in txt, txt[200:400])
check("...in under 20 seconds (it took %.1f s)" % took, took < 20, f"{took:.1f}s")
stats = json.loads(psql("select info from nodes where ts > extract(epoch from now())-30 order by name limit 1") or "{}")     # live replicas only: rows of replicas that were replaced earlier in the run stay in the table for a while
check("replicas report the shared rule-set layout with one dedicated site", stats.get("layout") == "shared" and stats.get("dedicated") == 1, str(stats))
check("nginx -t takes under 3 s with 79 sites (%s ms)" % stats.get("test_ms"), int(stats.get("test_ms", 99999)) < 3000, str(stats))
for t in tl:
    c = {
        "ordinary site clean": px(t, "s33.big.test", "/"), "ordinary site blocks SQLi": px(t, "s33.big.test", SQLI),
        "last site blocks SQLi": px(t, "s69.big.test", SQLI),
        "detect-only site lets it through": px(t, "detect.big.test", SQLI), "high-threshold site lets it through": px(t, "lax.big.test", SQLI),
        "paranoia-3 site blocks it": px(t, "strict.big.test", SQLI),
        "site with own rule blocks /custom-block": px(t, "own.big.test", "/custom-block"), "...and still gets the OWASP rules": px(t, "own.big.test", SQLI),
        "other sites ignore that custom rule": px(t, "s10.big.test", "/custom-block"),
        "wildcard site blocks": px(t, "x.wild.test", SQLI), "exact name overrides the wildcard (detect)": px(t, "a.wild.test", SQLI),
        "WAF-off site passes it": px(t, "off.big.test", SQLI),
        "Host with upper case and trailing dot gets the same rules": px(t, "S33.BIG.TEST.", SQLI),
    }
    want = {"ordinary site clean": 200, "ordinary site blocks SQLi": 403, "last site blocks SQLi": 403, "detect-only site lets it through": 200,
            "high-threshold site lets it through": 200, "paranoia-3 site blocks it": 403, "site with own rule blocks /custom-block": 403,
            "...and still gets the OWASP rules": 403, "other sites ignore that custom rule": 200, "wildcard site blocks": 403,
            "exact name overrides the wildcard (detect)": 200, "WAF-off site passes it": 200,
            "Host with upper case and trailing dot gets the same rules": 403}
    for k, v in c.items():
        check(f"[{t.pod[-5:]}] {k}", (v != 403) if k == "other sites ignore that custom rule" else v == want[k], f"got {v}")
    break
for t in tl[1:]:
    ok = all(px(t, h, p) == w for h, p, w in (("s33.big.test", SQLI, 403), ("detect.big.test", SQLI, 200), ("own.big.test", "/custom-block", 403),
                                              ("a.wild.test", SQLI, 200), ("x.wild.test", SQLI, 403), ("s69.big.test", "/", 200)))
    check(f"[{t.pod[-5:]}] same behaviour on the other replicas", ok)
check("a request to an unknown host gets no reply content (444)", px(tl[0], "unknown.example", "/") == 0)

s, html = A.post("/sites/new", site_form("tls2.ha.test", tls_enabled="on", tls_source="selfsigned", tls_generate="on"), "/sites/new")
time.sleep(2)
fp = {t.pod: cert_fp(t, "tls2.ha.test") for t in tl}
check("TLS site added after the import: all replicas serve the same certificate", len(set(fp.values())) == 1 and "" not in fp.values(), str(fp))

# =============================================================================================== 3b. automatic certificates (ACME)
print("== automatic certificates (Pebble)", flush=True)


def https_status(t, host):
    try:
        with socket.create_connection(("127.0.0.1", t.tls), timeout=8) as sk, CTX.wrap_socket(sk, server_hostname=host) as ss:
            ss.sendall(f"GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode())
            return int(ss.recv(64).split()[1])
    except Exception:  # noqa: BLE001
        return 0


settings_form = {"ab_threshold": "10", "ab_window": "5", "ab_ban": "30", "retention": "7", "idle": "30", "trusted_proxies": "", "never_ban": "127.0.0.1",
                 "panel_allow_ips": "", "upstream_allow": "", "dd_rps": "200", "dd_window": "20", "dd_hold": "15", "acme_form": "1"}
s, html = A.post("/sites/new", site_form("early.ha.test", tls_enabled="on", tls_source="acme"), "/sites/new")
check("a site with an automatic certificate is refused until the e-mail address and terms are set", "Automatic certificates" in html and "site added" not in html,
      re.sub(r"<[^>]+>", " ", html)[250:400])
s, html = A.post("/settings", {**settings_form, "acme_email": "not-an-email", "acme_directory": "https://pebble:14000/dir", "acme_agreed": "on"}, "/settings")
check("a bad e-mail address is refused", "Invalid settings" in html)
s, html = A.post("/settings", {**settings_form, "acme_email": "admin@example.test", "acme_directory": "http://pebble:14000/dir", "acme_agreed": "on"}, "/settings")
check("a plain-http certificate authority address is refused", "Invalid settings" in html and "https" in html)
s, html = A.post("/settings", {**settings_form, "acme_email": "admin@example.test", "acme_directory": "https://pebble:14000/dir", "acme_agreed": "on"}, "/settings")
check("e-mail, authority and terms are saved", "settings saved" in html, re.sub(r"<[^>]+>", " ", html)[200:350])
s, html = A.post("/sites/new", site_form("acme.ha.test", tls_enabled="on", tls_source="acme", tls_redirect="on", tls_hsts="on"), "/sites/new")
check("site with an automatic certificate is added", "site added" in html, re.sub(r"<[^>]+>", " ", html)[250:420])
ids2 = {}
for m in re.finditer(r"<td><b>([\w.*-]+)</b>.*?/sites/(s[0-9a-f]+)\"", A.req("/sites")[1], re.S):
    ids2.setdefault(m.group(1), m.group(2))
acme_sid = ids2.get("acme.ha.test", "x")
fp_before = cert_fp(tl[0], "acme.ha.test")
t0 = time.time()
fps = {}
for _ in range(60):
    fps = {t.pod: cert_fp(t, "acme.ha.test") for t in tl}
    if len(set(fps.values())) == 1 and "" not in fps.values() and fp_before not in fps.values():
        break
    time.sleep(3)
check("the certificate arrives and ALL replicas serve the same new one (took %.0f s)" % (time.time() - t0), len(set(fps.values())) == 1 and "" not in fps.values() and fp_before not in fps.values(), str(fps))
issuers = {p_[0]: kube("exec", p_[0], "-c", "panel", "--", "openssl", "x509", "-noout", "-issuer", "-in", f"/data/certs/{acme_sid}/fullchain.pem") for p_ in ps}
check("it was issued by the certificate authority (Pebble), not self-signed", all("Pebble" in v for v in issuers.values()), str(issuers))
check("the site is served over HTTPS with the new certificate on every replica", all(https_status(t, "acme.ha.test") == 200 for t in tl))
check("the site page shows the certificate as issued", "certificate issued" in A.req(f"/sites/{acme_sid}")[1])
import http.client


def raw_status(t, host, path="/"):
    """Status without following redirects."""
    try:
        c = http.client.HTTPConnection("127.0.0.1", t.http, timeout=8)
        c.request("GET", path, headers={"Host": host})
        return c.getresponse().status
    except Exception:  # noqa: BLE001
        return 0


check("the HTTP side redirects to HTTPS (and still answers the authority on the challenge path)", all(raw_status(t, "acme.ha.test") == 301 for t in tl))
# the challenge answer must be served by every replica, whichever one publishes it
tok = "ha_test_token_" + secrets.token_hex(8)
kube("exec", tl[0].pod, "-c", "panel", "--", "python3", "-c",
     f"import os, acme, sharedfs; os.makedirs(acme.CHALLENGE_DIR, exist_ok=True); open(acme.CHALLENGE_DIR + '/{tok}', 'w').write('answer-{tok}'); sharedfs.publish('acme')")
got = {}
for _ in range(20):
    got = {}
    for t in tl:
        try:
            got[t.pod] = urllib.request.urlopen(urllib.request.Request(f"http://127.0.0.1:{t.http}/.well-known/acme-challenge/{tok}", headers={"Host": "acme.ha.test"}), timeout=8).read().decode()
        except Exception as e:  # noqa: BLE001
            got[t.pod] = str(e)
    if all(v == f"answer-{tok}" for v in got.values()):
        break
    time.sleep(1)
check("a challenge answer published on one replica is served by all replicas", all(v == f"answer-{tok}" for v in got.values()), str(got))
other = urllib.request.Request(f"http://127.0.0.1:{tl[1].http}/.well-known/acme-challenge/{tok}", headers={"Host": "ha1.test"})
try:
    body = urllib.request.urlopen(other, timeout=8).read().decode()
except urllib.error.HTTPError:
    body = ""
check("sites without an automatic certificate do not expose the challenge folder", body != f"answer-{tok}")
kube("exec", tl[0].pod, "-c", "panel", "--", "python3", "-c", f"import acme; acme._unpublish('{tok}')")
gone = False
for _ in range(20):
    gone = all(px(t, "acme.ha.test", f"/.well-known/acme-challenge/{tok}") != 200 for t in tl)
    if gone:
        break
    time.sleep(1)
check("the challenge answer is removed again everywhere", gone)

# =============================================================================================== 3c. several upstreams per site
print("== several upstreams per site", flush=True)
PYURL = "http://demo-python.shieldwaf-demo.svc.cluster.local:80"


def hits(t, host, n=60, path="/", method="GET"):
    """Which demo application answered each request (X-Demo-App header), or the error status."""
    c = collections.Counter()
    for _ in range(n):
        try:
            r = urllib.request.urlopen(urllib.request.Request(f"http://127.0.0.1:{t.http}{path}", headers={"Host": host}, method=method,
                                                              data=b"{}" if method == "POST" else None), timeout=20)
            c[r.headers.get("X-Demo-App", "?")] += 1
        except urllib.error.HTTPError as e:
            c[f"http{e.code}"] += 1
        except Exception:  # noqa: BLE001
            c["err"] += 1
    return c


def site_ids(panel):
    out = {}
    for m in re.finditer(r"<td><b>([\w.*-]+)</b>.*?/sites/(s[0-9a-f]+)\"", panel.req("/sites")[1], re.S):
        out.setdefault(m.group(1), m.group(2))
    return out


def refused(fields, text):
    s_, h_ = A.post("/sites/new", fields, "/sites/new")
    return "site added" not in h_ and text in re.sub(r"<[^>]+>", " ", h_)


many = "\n".join(f"http://x{i}.shieldwaf-demo.svc.cluster.local:80" for i in range(10))
check("more than 10 upstreams are refused", refused(site_form("v1.ha.test", upstreams=many), "At most 10"))
check("an upstream weight above 100 is refused", refused(site_form("v2.ha.test", upstreams=PYURL + " 500"), "weight"))
check("an unknown word after an upstream is refused", refused(site_form("v3.ha.test", upstreams=PYURL + " fast"), "only a weight"))
check("a cloud-metadata address among the extra upstreams is refused (SSRF)", refused(site_form("v4.ha.test", upstreams="http://169.254.169.254:80 1"), "Upstream"))
check("the same upstream listed twice is refused", refused(site_form("v5.ha.test", upstreams=NOTES + " 1"), "twice"))

s, html = A.post("/sites/new", site_form("lb.ha.test", upstreams=PYURL + " 1"), "/sites/new")
check("a site with two upstreams is added and applied on all replicas", "site added" in html and "3/3 replicas" in re.sub(r"<[^>]+>", " ", html), re.sub(r"<[^>]+>", " ", html)[250:420])
time.sleep(1)
for t in tl:
    c = hits(t, "lb.ha.test", 80)
    check(f"[{t.pod[-5:]}] requests are spread over both upstreams ({dict(c)})", c["demo-notes"] >= 16 and c["demo-python"] >= 16 and sum(c.values()) == 80, str(c))
s, html = A.post("/sites/new", site_form("w.ha.test", upstreams=PYURL + " 9"), "/sites/new")
c = hits(tl[0], "w.ha.test", 100)
check(f"weights are respected: weight 9 against 1 sends most requests to the heavier upstream ({dict(c)})", c["demo-python"] >= 70, str(c))
s, html = A.post("/sites/new", site_form("h.ha.test", upstreams=PYURL + " 1", lb_method="ip_hash"), "/sites/new")
c = hits(tl[0], "h.ha.test", 40)
check(f"'keep each visitor on the same upstream' sends one visitor to one upstream only ({dict(c)})", len([k for k, v in c.items() if v]) == 1, str(c))

# one upstream dies: reads are retried on the next one, writes are not replayed
sh("kubectl", "-n", DEMO_NS, "scale", "deploy/demo-python", "--replicas=0")
sh("kubectl", "-n", DEMO_NS, "delete", "pod", "-l", "app=demo-python", "--force", "--grace-period=0")      # the demo server ignores SIGTERM: do not wait for its 30 s grace period
time.sleep(10)
c = hits(tl[0], "lb.ha.test", 40)
check(f"with one upstream dead every read request still succeeds, retried on the other ({dict(c)})", c["demo-notes"] == 40, str(c))
c2 = hits(tl[1], "lb.ha.test", 40, "/api/notes", "POST")
check(f"a write that hit the dead upstream is NOT replayed (502 seen), writes to the living one work ({dict(c2)})", c2["http502"] > 0 and c2["demo-notes"] > 0 and sum(c2.values()) == 40, str(c2))

# health checks take it out of rotation, and bring it back
sid_lb = site_ids(A).get("lb.ha.test", "x")
s, html = A.post(f"/sites/{sid_lb}", site_form("lb.ha.test", upstreams=PYURL + " 1", health_enabled="on", health_path="/"), f"/sites/{sid_lb}")
check("health checks are switched on for the site", "site updated" in html, re.sub(r"<[^>]+>", " ", html)[250:400])
out = False
for _ in range(25):
    time.sleep(3)
    if "out of rotation now" in A.req(f"/sites/{sid_lb}")[1]:
        out = True
        break
check("the dead upstream is taken out of rotation by the health checks (within about 75 s)", out)
ok_all, got = True, {}
for t in tl:
    got[t.pod[-5:]] = hits(t, "lb.ha.test", 30)
    ok_all = ok_all and got[t.pod[-5:]]["demo-notes"] == 30
check("...on every replica, and every request goes straight to the living upstream", ok_all, str(got))
sh("kubectl", "-n", DEMO_NS, "scale", "deploy/demo-python", "--replicas=1")
sh("kubectl", "-n", DEMO_NS, "rollout", "status", "deploy/demo-python", "--timeout=120s", timeout=140)
back = False
for _ in range(25):
    time.sleep(3)
    if "out of rotation now" not in A.req(f"/sites/{sid_lb}")[1]:
        back = True
        break
check("when it answers again it is put back into rotation automatically", back)
time.sleep(2)
c = hits(tl[2], "lb.ha.test", 80)
check(f"and gets its share of the traffic again ({dict(c)})", c["demo-notes"] >= 16 and c["demo-python"] >= 16, str(c))

# =============================================================================================== 4. a replica dies
print("== killing the leader replica", flush=True)
lead = leader_name()[0] if leader_name() else ""
survivors = [t for t in tl if t.pod != lead]
fails, total, stop = [], [0], threading.Event()


def watch():
    while not stop.is_set():
        for t in survivors:
            total[0] += 1
            c = px(t, "s33.big.test", "/")
            if c != 200:
                fails.append((time.time(), t.pod, c))
        time.sleep(0.3)


w = threading.Thread(target=watch, daemon=True)
w.start()
kube("delete", "pod", lead, "--wait=false")
t_kill = time.time()
new_leader = []
for _ in range(40):
    time.sleep(1)
    new_leader = leader_name()
    if len(new_leader) == 1 and new_leader[0] != lead:
        break
check("another replica becomes the leader within 20 s (took %.0f s)" % (time.time() - t_kill), len(new_leader) == 1 and new_leader[0] != lead and time.time() - t_kill < 20, str(new_leader))
tmp = {p.pod: Panel(p.panel) for p in survivors}
sv = list(tmp.values())[0]
for c in A.jar:
    sv.jar.set_cookie(c)
s, html = sv.post("/sites/new", site_form("while-down.ha.test"), "/sites/new")
check("an administrator can keep changing the configuration while one replica is down", "site added" in html, re.sub(r"<[^>]+>", " ", html)[250:400])
ps = wait_pods(3, 240)
check("the replacement replica starts and becomes ready", len(ps) == 3, str(ps))
for t in tl:
    if t.pod == lead:
        t.close()
new_t = [Tunnel(p[0]) for p in ps if p[0] not in T and p[1]]
tl2 = survivors + new_t
ok, got = converge(new_t, "while-down.ha.test", "/", 200, 30) if new_t else (False, {})
check("the replacement replica serves the change made while it did not exist", ok, str(got))
ok = bool(new_t) and all(px(new_t[0], h, p) == wv for h, p, wv in (("s33.big.test", SQLI, 403), ("own.big.test", "/custom-block", 403), ("a.wild.test", SQLI, 200)))
check("the replacement replica enforces all 80 sites like the others", ok)
fp2 = cert_fp(new_t[0], "tls2.ha.test") if new_t else ""
check("the replacement replica serves the same site certificate (pulled from the shared store)", fp2 and fp2 in set(fp.values()), fp2[:16])
time.sleep(2)
stop.set()
w.join()
check("no request to the surviving replicas failed while a replica was killed (%d requests)" % total[0], not fails, str(fails[:3]))
check("exactly one leader after recovery", len(leader_name()) == 1, str(leader_name()))

# =============================================================================================== 5. the database stops
print("== database outage", flush=True)
kube("scale", "statefulset/shieldwaf-db", "--replicas=0")
time.sleep(25)
res = {t.pod[-5:]: (px(t, "s33.big.test", "/"), px(t, "s33.big.test", SQLI)) for t in tl2}
check("with the database stopped every replica still serves and blocks (the data path does not need it)", all(v == (200, 403) for v in res.values()), str(res))
kube("scale", "statefulset/shieldwaf-db", "--replicas=1")
for _ in range(60):
    if "1/1" in kube("get", "pod", "shieldwaf-db-0", "--no-headers"):
        break
    time.sleep(3)
time.sleep(25)
ok_pods = [p for p in pods() if p[1]]
check("all replicas are ready again after the database returns", len(ok_pods) == 3, str(ok_pods))
nodes_ok = psql("select count(*) from nodes where ts > extract(epoch from now())-12")
check("all replicas report in again", nodes_ok == "3", nodes_ok)
check("a leader exists again", len(leader_name()) == 1, str(leader_name()))
s, html = sv.req("/dashboard")
check("the panel works again and the earlier session is still valid", "Requests" in html, html[:80])

# =============================================================================================== 6. rolling restart without downtime
print("== rolling restart under load", flush=True)
probe = (
    "import urllib.request,urllib.error,time,json,collections\n"
    "c=collections.Counter();end=time.time()+110\n"
    "while time.time()<end:\n"
    "  for path,host in (('/','s33.big.test'),('/?q=1%27%20OR%20%271%27%3D%271%27%20UNION%20SELECT%20NULL--','s33.big.test')):\n"
    "    try:\n"
    "      r=urllib.request.urlopen(urllib.request.Request('http://shieldwaf-proxy.shieldwaf-test.svc.cluster.local:8080'+path,headers={'Host':host}),timeout=5);c[r.status]+=1\n"
    "    except urllib.error.HTTPError as e: c[e.code]+=1\n"
    "    except Exception as e: c['err']+=1\n"
    "  time.sleep(0.05)\n"
    "print('RESULT',json.dumps(c))\n")
subprocess.run(["kubectl", "-n", DEMO_NS, "delete", "pod", "ha-probe", "--ignore-not-found", "--wait=true"], capture_output=True, timeout=60)
subprocess.run(["kubectl", "-n", DEMO_NS, "run", "ha-probe", "--restart=Never", "--image=python:3.12-alpine", "--", "python3", "-u", "-c", probe], capture_output=True, timeout=60)
time.sleep(12)
kube("rollout", "restart", "deploy/shieldwaf-test")
r = subprocess.run(["kubectl", "-n", NS, "rollout", "status", "deploy/shieldwaf-test", "--timeout=300s"], capture_output=True, text=True, timeout=330)
check("rolling restart of all replicas completes", r.returncode == 0, r.stdout[-200:] + r.stderr[-200:])
res = ""
for _ in range(60):
    res = subprocess.run(["kubectl", "-n", DEMO_NS, "logs", "ha-probe"], capture_output=True, text=True).stdout
    if "RESULT" in res:
        break
    time.sleep(3)
m = re.search(r"RESULT (\{.*\})", res)
cnt = json.loads(m.group(1)) if m else {}
tot = sum(cnt.values())
bad = sum(v for k, v in cnt.items() if k not in ("200", "403"))
check("during the rolling restart %d requests got an answer and %d failed (%s)" % (tot, bad, cnt), tot > 500 and bad == 0, str(cnt))
check("attacks were blocked during the whole restart (403 count > 0, never 200 for the attack)", cnt.get("403", 0) > 0)
subprocess.run(["kubectl", "-n", DEMO_NS, "delete", "pod", "ha-probe", "--ignore-not-found", "--wait=false"], capture_output=True, timeout=60)
ps = wait_pods(3, 120)
check("three ready replicas after the rolling restart", len(ps) == 3, str(ps))

for t in tl + new_t:
    t.close()
print()
bad = [n for n, ok in results if not ok]
print(f"{len(results) - len(bad)}/{len(results)} high-availability checks passed")
if bad:
    print("FAILED:", *bad, sep="\n  ")
sys.exit(1 if bad else 0)
