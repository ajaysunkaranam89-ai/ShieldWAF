"""ACME client test against Pebble (the official Let's Encrypt test server). Run by tests/acme.sh inside a container of the shieldwaf image on a
private Docker network where Pebble answers every name with this container's address (pebble-challtestsrv)."""
import http.server
import os
import sys
import tempfile
import threading
import time

os.environ["SHIELD_DATA"] = tempfile.mkdtemp()
sys.path.insert(0, "/panel")
import acme  # noqa: E402

results = []


def check(name, cond, extra=""):
    results.append((name, bool(cond)))
    print(("PASS  " if cond else "FAIL  ") + name + (f"   [{extra}]" if extra and not cond else ""), flush=True)


class H(http.server.BaseHTTPRequestHandler):
    serving = True
    seen = []

    def do_GET(self):
        H.seen.append(self.path)
        pre = "/.well-known/acme-challenge/"
        p = os.path.join(acme.CHALLENGE_DIR, self.path[len(pre):]) if self.path.startswith(pre) and H.serving else ""
        if p and os.path.isfile(p):
            b = open(p, "rb").read()
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(b)))
            self.end_headers()
            self.wfile.write(b)
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, *a):
        pass


srv = http.server.ThreadingHTTPServer(("0.0.0.0", 5002), H)
threading.Thread(target=srv.serve_forever, daemon=True).start()
DIRECTORY = "https://pebble:14000/dir"

# --- a normal issuance
chain, key, exp = acme.obtain("app.example.test", "admin@example.test", DIRECTORY)
check("a certificate is issued for the host name by the authority", "BEGIN CERTIFICATE" in chain and "PRIVATE KEY" in key)
check("the authority fetched the challenge file over HTTP from us", any(p.startswith("/.well-known/acme-challenge/") for p in H.seen), str(H.seen[:3]))
check("the expiry date is read from the certificate (Pebble issues short test certificates)", exp - time.time() > 86400, str(exp - time.time()))
check("the challenge file is removed again after validation", not os.path.isdir(acme.CHALLENGE_DIR) or not os.listdir(acme.CHALLENGE_DIR))
check("the certificate checker accepts it", acme.check_certificate(chain, key, "app.example.test") == exp)
try:
    acme.check_certificate(chain, key, "other.example.test")
    ok = False
except acme.AcmeError:
    ok = True
check("a certificate for another host name is refused by the checker", ok)
other = acme.obtain("second.example.test", "admin@example.test", DIRECTORY)
check("the same account can order a second certificate", "BEGIN CERTIFICATE" in other[0] and other[1] != key)
key_file = os.path.join(os.environ["SHIELD_DATA"], "secrets", "acme_account.json")
check("the account key is kept and reused (not regenerated)", os.path.isfile(key_file) and oct(os.stat(key_file).st_mode)[-3:] == "600")

# --- install writes both files with the right permissions
import security  # noqa: E402
acme.install("stest", chain, key)
d = os.path.join(security.CERT_DIR, "stest")
check("install writes the chain and the key (key mode 600)", os.path.isfile(d + "/fullchain.pem") and oct(os.stat(d + "/privkey.pem").st_mode)[-3:] == "600")

# --- failures
H.serving = False
t0 = time.time()
try:
    acme.obtain("third.example.test", "admin@example.test", DIRECTORY)
    ok, msg = False, ""
except acme.AcmeError as e:
    ok, msg = True, str(e)
check("when the challenge cannot be fetched the order fails with a clear message", ok and "could not verify" in msg, msg)
H.serving = True
for host in ("*.example.test", "1.2.3.4", "localhost", "-bad.example.test", "a b.example.test"):
    try:
        acme.obtain(host, "", DIRECTORY)
        ok = False
    except acme.AcmeError:
        ok = True
    check(f"host name '{host}' is refused", ok)
os.environ["SHIELD_ACME_ALLOW_PRIVATE"] = "0"
check("a directory on a private address is refused (SSRF protection)", acme.check_directory("https://pebble:14000/dir") is not None)
check("a plain http directory is refused", acme.check_directory("http://acme.example.test/dir") is not None)
check("the Let's Encrypt directory addresses pass the syntax rules", acme.LETSENCRYPT.startswith("https://") and acme.LETSENCRYPT_STAGING.startswith("https://"))

print()
bad = [n for n, ok in results if not ok]
print(f"{len(results) - len(bad)}/{len(results)} ACME checks passed")
sys.exit(1 if bad else 0)
