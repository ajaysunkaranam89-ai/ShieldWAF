"""Checks for the upgrade / rollback test (tests/upgrade.sh) on the throw-away namespace "shieldwaf-test": data created on 2.3 must survive every step.
Usage: python3 upgrade_test.py seed | activity | check <label> [--version 2.3|2.4] [--restricted]
State (admin password, site names, audit row count) is kept in tests/.upg-state.json."""
import http.cookiejar
import json
import os
import re
import secrets
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

NS = "shieldwaf-test"
PANEL, PROXY = "https://127.0.0.1:19000", "http://127.0.0.1:18088"
STATE = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".upg-state.json")
NOTES = "http://demo-notes.shieldwaf-demo.svc.cluster.local:80"
PY = "http://demo-python.shieldwaf-demo.svc.cluster.local:80"
CTX = ssl.create_default_context()
CTX.check_hostname = False
CTX.verify_mode = ssl.CERT_NONE
RESULTS = []


def check(name, cond, extra=""):
    RESULTS.append(bool(cond))
    print(("PASS  " if cond else "FAIL  ") + name + (f"   [{str(extra)[:300]}]" if extra and not cond else ""), flush=True)


class Panel:
    def __init__(self):
        self.op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()), urllib.request.HTTPSHandler(context=CTX))

    def req(self, path, data=None):
        body = urllib.parse.urlencode(data, doseq=True).encode() if data is not None else None
        try:
            r = self.op.open(urllib.request.Request(PANEL + path, data=body), timeout=60)
            return r.status, r.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode("utf-8", "replace")

    @staticmethod
    def token(html):
        m = re.search(r'name="_csrf" value="([0-9a-f]+)"', html)
        return m.group(1) if m else ""

    def post(self, path, fields, page):
        _, html = self.req(page)
        return self.req(path, {**fields, "_csrf": self.token(html)})

    def login(self, user, pw):
        _, html = self.req("/login")
        return self.req("/login", {"_csrf": self.token(html), "username": user, "password": pw})


def psql(sql):
    r = subprocess.run(["kubectl", "-n", NS, "exec", "shieldwaf-db-0", "--", "psql", "-U", "shieldwaf", "-d", "shieldwaf", "-tAc", sql], capture_output=True, text=True)
    return r.stdout.strip()


def proxy(host):
    for _ in range(6):
        try:
            r = urllib.request.urlopen(urllib.request.Request(PROXY + "/", headers={"Host": host}), timeout=20)
            return r.status
        except urllib.error.HTTPError as e:
            return e.code
        except Exception:  # noqa: BLE001
            time.sleep(2)
    return 0


def site_form(host, upstream):
    return {"host": host, "upstream": upstream, "enabled": "on", "mode": "block", "paranoia": "1", "threshold": "5", "max_body_mb": "10", "down_page": "on",
            "block_bots": "on", "sec_headers": "on", "rl_rps": "10", "rl_burst": "20", "methods": ["GET", "HEAD", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"],
            "tls_source": "none", "tls_hsts_days": "365", "auth_realm": "Restricted", "chal_difficulty": "4", "chal_ttl": "12", "chal_scope": "pages"}


def load():
    return json.load(open(STATE))


def save(st):
    json.dump(st, open(STATE, "w"))


def failed_logins(n=2):
    p = Panel()
    for i in range(n):
        _, html = p.req("/login")
        p.req("/login", {"_csrf": p.token(html), "username": "nobody", "password": "wrong-%d" % i})


def seed():
    p = Panel()
    logs = subprocess.run(["kubectl", "-n", NS, "logs", "deploy/shieldwaf-test", "-c", "panel"], capture_output=True, text=True).stdout
    code = re.search(r"Setup code: (\w+)", logs).group(1)
    pw = "Up-" + secrets.token_hex(8) + "-Zz9!"
    _, html = p.req("/setup")
    _, html = p.req("/setup", {"_csrf": p.token(html), "code": code, "username": "upgrader", "password": pw, "password2": pw})
    check("(2.3) the administrator account is created", "Dashboard" in html, re.sub(r"<[^>]+>", " ", html)[:200])
    hosts = {"up1.shield.test": NOTES, "up2.shield.test": PY}
    for h, up in hosts.items():
        _, html = p.post("/sites/new", site_form(h, up), "/sites/new")
    time.sleep(8)
    for h in hosts:
        check(f"(2.3) site {h} is created and served", proxy(h) == 200, proxy(h))
    failed_logins(3)
    time.sleep(1)
    st = {"pw": pw, "hosts": list(hosts), "audit": int(psql("select count(*) from audit") or 0)}
    save(st)
    check("(2.3) the audit trail has entries before the upgrade", st["audit"] >= 3, st)


def verify(label, version, restricted):
    st = load()
    p = Panel()
    s, html = p.login("upgrader", st["pw"])
    check(f"({label}) the administrator signs in with the same password", "Dashboard" in html, re.sub(r"<[^>]+>", " ", html)[:200])
    _, sites = p.req("/sites")
    check(f"({label}) both sites are still configured", all(h in sites for h in st["hosts"]))
    time.sleep(3)
    check(f"({label}) both sites are served through the engine", all(proxy(h) == 200 for h in st["hosts"]), [proxy(h) for h in st["hosts"]])
    now = int(psql("select count(*) from audit") or 0)
    check(f"({label}) no audit record was lost ({st['audit']} before, {now} now)", now >= st["audit"], now)
    s, cl = p.req("/cluster")
    versions = set((psql("select string_agg(distinct version, ',') from nodes where ts > extract(epoch from now())-45") or "").split(","))
    check(f"({label}) every running replica reports version {version} (rows of replaced pods are ignored) and the cluster page opens", s == 200 and versions == {version}, versions)
    s, au = p.req("/audit")
    check(f"({label}) the audit page opens", s == 200 and "audit" in au.lower(), s)
    if version == "2.4":
        _, au = p.post("/audit/verify", {}, "/audit")
        check(f"({label}) audit verification: the chain is valid, older records included", "no change detected" in au, re.sub(r"<[^>]+>", " ", au)[:300])
        s, po = p.req("/posture")
        check(f"({label}) the security posture page opens", s == 200 and "Security posture" in po, s)
    Panel().login("upgrader", st["pw"])                                   # a successful sign-in is audited (failed ones can be swallowed by the login lockout of this test)
    time.sleep(1)
    after = int(psql("select count(*) from audit") or 0)
    check(f"({label}) a new audit record is written after the step ({now} -> {after})", after >= now + 1, after)
    if restricted:
        users = psql("select string_agg(distinct usename, ',') from pg_stat_activity where application_name like 'shieldwaf-panel%'")
        check(f"({label}) the panel connects as the restricted role (found: {users})", users == "shieldwaf_app", users)
        denied = subprocess.run(["kubectl", "-n", NS, "exec", "shieldwaf-db-0", "--", "sh", "-c",
                                 "PGPASSWORD=$(cat /dev/null) psql -U shieldwaf -d shieldwaf -tAc \"set role shieldwaf_app; delete from audit where seq=-1\" 2>&1"], capture_output=True, text=True).stdout
        check(f"({label}) the restricted role may not delete from the audit trail", "permission denied" in denied, denied)
    st["audit"] = after
    save(st)


if __name__ == "__main__":
    cmd = sys.argv[1]
    if cmd == "seed":
        seed()
    elif cmd == "activity":
        failed_logins(2)
    else:
        verify(sys.argv[2], "2.3" if "2.3" in sys.argv else "2.4", "--restricted" in sys.argv)
    bad = RESULTS.count(False)
    print(f"{len(RESULTS) - bad}/{len(RESULTS)} checks passed")
    sys.exit(1 if bad else 0)
