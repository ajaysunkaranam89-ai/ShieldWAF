"""Single sign-on test: acts like a browser against the panel (https://panel:9000) and a real identity provider (Dex, https://dex:5556/dex).
Run by tests/sso.sh inside a container on the test network. Also checks the ID token verifier with forged tokens."""
import base64
import hashlib
import http.cookiejar
import json
import os
import re
import ssl
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request

os.environ["SHIELD_DATA"] = tempfile.mkdtemp()
sys.path.insert(0, "/panel")
PANEL = "https://panel:9000"
CTX = ssl.create_default_context()
CTX.check_hostname = False
CTX.verify_mode = ssl.CERT_NONE
results = []


def check(name, cond, extra=""):
    results.append((name, bool(cond)))
    print(("PASS  " if cond else "FAIL  ") + name + (f"   [{extra}]" if extra and not cond else ""), flush=True)


class Callback(Exception):
    def __init__(self, url):
        self.url = url


class Stop(urllib.request.HTTPRedirectHandler):
    """Follow redirects like a browser, but stop when the identity provider sends us back to the panel."""
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if "/sso/callback" in newurl:
            raise Callback(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def browser(stop=True):
    jar = http.cookiejar.CookieJar()
    handlers = [urllib.request.HTTPCookieProcessor(jar), urllib.request.HTTPSHandler(context=CTX)] + ([Stop()] if stop else [])
    return urllib.request.build_opener(*handlers), jar


def get(op, url, data=None):
    body = urllib.parse.urlencode(data).encode() if data is not None else None
    try:
        r = op.open(urllib.request.Request(url, data=body), timeout=30)
        return r.status, r.read().decode("utf-8", "replace"), r.geturl()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace"), url


def sso_start(op):
    """Click the SSO button and sign in at Dex; returns the callback URL Dex sends the browser to (or None) and the Dex page."""
    try:
        s, html, _ = get(op, PANEL + "/sso/login")
    except Callback as cb:
        return cb.url, ""
    return None, html


def dex_login(op, email, password):
    cb, html = sso_start(op)
    if cb:
        return cb
    m = re.search(r'<form[^>]*action="([^"]+)"', html)
    if not m:
        return None
    action = urllib.parse.urljoin("https://dex:5556/dex/auth/local/login", m.group(1).replace("&amp;", "&"))
    try:
        get(op, action, {"login": email, "password": password})
    except Callback as cb:
        return cb.url
    return None


def finish(cb_url, jar):
    """The browser follows the identity provider's redirect back to the panel, carrying the cookies it has."""
    op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar), urllib.request.HTTPSHandler(context=CTX))
    return get(op, cb_url) + (op,)


PW = "correct-horse-Battery-9"
# ------------------------------------------------------------------------------------------------ the login page
op, jar = browser()
s, html, _ = get(op, PANEL + "/login")
check("the login page offers the single sign-on button", "/sso/login" in html and "Sign in with SSO" in html)
check("the password form is still there (emergency access)", 'name="password"' in html)

# ------------------------------------------------------------------------------------------------ a normal sign-in: alice is an administrator
op, jar = browser()
cb = dex_login(op, "alice@example.test", "password")
check("the identity provider signs alice in and sends the browser back with a code and a state", bool(cb) and "code=" in cb and "state=" in cb, str(cb)[:100])
binder = [c for c in jar if c.name == "__Host-sso"]
check("the panel set a short-lived, Secure, HttpOnly, SameSite=Lax binding cookie", bool(binder) and binder[0].secure and binder[0].has_nonstandard_attr("HttpOnly")
      and str(binder[0].get_nonstandard_attr("SameSite")).lower() == "lax", str([(c.name, c.secure, c._rest) for c in jar]))
s, page, final, session_op = finish(cb, jar)
check("alice is signed in to the panel (dashboard)", "Dashboards" in page or "Requests" in page, page[:100])
s, users, _ = get(session_op, PANEL + "/users")
check("alice got the administrator role (she can open the user list)", s == 200 and "alice@example.test" in users, users[:100])

# replaying the same callback (same code, same state) must fail
s, page2, _, _ = finish(cb, jar)
check("replaying the callback with the same code and state is refused", "Single sign-on failed" in page2 or "Sign in" in page2 and "Requests" not in page2, page2[:100])

# ------------------------------------------------------------------------------------------------ bob: allowed domain, default role viewer
op, jar = browser()
cb = dex_login(op, "bob@example.test", "password")
s, page, final, bob_op = finish(cb, jar)
check("bob (allowed domain) is signed in", "Requests" in page or "Dashboards" in page, page[:100])
s, _, _ = get(bob_op, PANEL + "/users")
check("bob is only a viewer: the user list is forbidden (403)", s == 403, str(s))
s, _, _ = get(bob_op, PANEL + "/audit")
check("...and so is the audit trail", s == 403, str(s))

# ------------------------------------------------------------------------------------------------ carol: valid account at the provider, not allowed here
op, jar = browser()
cb = dex_login(op, "carol@other.test", "password")
s, page, final, carol_op = finish(cb, jar)
check("carol (a valid account, but not an allowed domain) is refused", "not allowed to sign in" in page, re.sub(r"<[^>]+>", " ", page)[:200])
s, _, url = get(carol_op, PANEL + "/dashboard")
check("...and has no session", "/login" in url)

# ------------------------------------------------------------------------------------------------ attacks on the callback
op, jar = browser()
cb = dex_login(op, "alice@example.test", "password")
other, ojar = browser(stop=False)
s, page, _ = get(other, cb)
check("a callback opened in a browser without the binding cookie is refused", "Single sign-on failed" in page and "Requests" not in page, re.sub(r"<[^>]+>", " ", page)[:200])
op, jar = browser()
cb = dex_login(op, "alice@example.test", "password")
opB, jarB = browser()
sso_start(opB)                                  # another visitor starts their own sign-in: they get their OWN binding cookie
s, page, _, _ = finish(cb, jarB)
check("a code and state stolen into another browser (different binding cookie) is refused", "another browser" in page, re.sub(r"<[^>]+>", " ", page)[:200])
op, jar = browser()
cb = dex_login(op, "alice@example.test", "password")
bad = cb.split("state=")[0] + "state=" + "A" * 43
s, page, _, _ = finish(bad, jar)
check("a callback with a forged state is refused", "Single sign-on failed" in page, re.sub(r"<[^>]+>", " ", page)[:200])
s, page, _ = get(browser(stop=False)[0], PANEL + "/sso/callback")
check("a callback with nothing in it is refused", "Single sign-on failed" in page)
s, page, _ = get(browser(stop=False)[0], PANEL + "/sso/callback?error=access_denied")
check("an error reported by the provider is shown, nobody is signed in", "Single sign-on failed" in page and "Requests" not in page)
s, page, url = get(browser(stop=False)[0], PANEL + "/dashboards")
check("...a visitor without a session is sent to the login page", "/login" in url)

# ------------------------------------------------------------------------------------------------ local login still works, SSO users have no password
op, jar = browser(stop=False)
s, html, _ = get(op, PANEL + "/login")
token = re.search(r'name="_csrf" value="([0-9a-f]+)"', html).group(1)
s, page, _ = get(op, PANEL + "/login", {"_csrf": token, "username": "localadmin", "password": PW})
check("the local administrator can still sign in with a password", "Requests" in page or "Dashboards" in page, page[:100])
s, audit, _ = get(op, PANEL + "/audit")
check("the audit trail records the sso logins with the role", "sso as admin" in audit and "sso as viewer" in audit)
check("the audit trail records the refusals", "sso-login-failed" in audit and "not allowed to sign in" in audit)
op2, _ = browser(stop=False)
s, html, _ = get(op2, PANEL + "/login")
token = re.search(r'name="_csrf" value="([0-9a-f]+)"', html).group(1)
s, page, _ = get(op2, PANEL + "/login", {"_csrf": token, "username": "alice@example.test", "password": ""})
check("an SSO user cannot sign in with an empty or any password", "Wrong username or password" in page)

# ------------------------------------------------------------------------------------------------ the ID token verifier, with forged tokens
import oidc  # noqa: E402
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa, utils  # noqa: E402

ISS, CID, NONCE = "https://idp.example", "client-1", "n-123"
key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
nums = key.public_key().public_numbers()
JWK = {"kty": "RSA", "kid": "k1", "n": oidc._b64e(nums.n.to_bytes(256, "big")), "e": oidc._b64e(nums.e.to_bytes(3, "big"))}
ekey = ec.generate_private_key(ec.SECP256R1())
en = ekey.public_key().public_numbers()
EJWK = {"kty": "EC", "crv": "P-256", "kid": "e1", "x": oidc._b64e(en.x.to_bytes(32, "big")), "y": oidc._b64e(en.y.to_bytes(32, "big"))}


def make(claims=None, alg="RS256", signer=key, kid="k1", tamper=False):
    now = int(time.time())
    c = {"iss": ISS, "aud": CID, "sub": "u1", "exp": now + 300, "iat": now, "nonce": NONCE, "email": "x@example.test", "email_verified": True}
    c.update(claims or {})
    h64 = oidc._b64e(json.dumps({"alg": alg, "kid": kid, "typ": "JWT"}).encode())
    p64 = oidc._b64e(json.dumps(c).encode())
    si = f"{h64}.{p64}".encode()
    if alg == "none":
        sig = b""
    elif alg == "HS256":
        import hmac
        sig = hmac.new(b"anything", si, hashlib.sha256).digest()
    elif alg == "ES256":
        r, s_ = utils.decode_dss_signature(signer.sign(si, ec.ECDSA(hashes.SHA256())))
        sig = r.to_bytes(32, "big") + s_.to_bytes(32, "big")
    else:
        sig = signer.sign(si, padding.PKCS1v15(), hashes.SHA256())
    if tamper:
        p64 = oidc._b64e(json.dumps({**c, "email": "admin@example.test"}).encode())
    return f"{h64}.{p64}.{oidc._b64e(sig)}"


def verify(tok, **kw):
    try:
        oidc.verify_id_token(tok, lambda force: {"k1": JWK, "e1": EJWK}, kw.get("iss", ISS), kw.get("cid", CID), kw.get("nonce", NONCE), kw.get("verified", True))
        return None
    except oidc.OidcError as e:
        return str(e)


check("a correct RS256 token is accepted", verify(make()) is None)
check("a correct ES256 token is accepted", verify(make(alg="ES256", signer=ekey, kid="e1")) is None)
check("an unsigned token (alg none) is refused", "algorithm" in (verify(make(alg="none")) or ""))
check("an HMAC token (algorithm confusion) is refused", "algorithm" in (verify(make(alg="HS256")) or ""))
check("a token signed with a different key is refused", "signature" in (verify(make(signer=rsa.generate_private_key(public_exponent=65537, key_size=2048))) or ""))
check("a token whose content was changed after signing is refused", "signature" in (verify(make(tamper=True)) or ""))
check("a token for another application (audience) is refused", "not meant" in (verify(make({"aud": "other-app"})) or ""))
check("a token from another issuer is refused", "someone else" in (verify(make({"iss": "https://evil.example"})) or ""))
check("an expired token is refused", "expired" in (verify(make({"exp": int(time.time()) - 3600})) or ""))
check("a token with the wrong nonce (replayed from another login) is refused", "login attempt" in (verify(make({"nonce": "other"})) or ""))
check("an unverified e-mail address is refused", "verified" in (verify(make({"email_verified": False})) or ""))
check("...unless the administrator turned that check off", verify(make({"email_verified": False}), verified=False) is None)
check("a token without a subject is refused", "subject" in (verify(make({"sub": ""})) or ""))
check("two audiences without matching azp are refused", "not meant" in (verify(make({"aud": [CID, "x"]})) or ""))
check("garbage is refused", "malformed" in (verify("not.a.token.at.all") or "") or "malformed" in (verify("abc") or ""))

sso = {"enabled": True, "issuer": "https://dex", "client_id": "c", "redirect_base": "https://panel:9000", "scopes": "openid", "allowed_domains": "example.test",
       "allowed_emails": "", "admin_emails": "", "admin_groups": "ops", "default_role": "viewer", "require_verified_email": True}
try:
    oidc.decide(sso, {"email": "e@evil.test"})
    check("policy: a domain that is not allowed is refused", False)
except oidc.OidcError:
    check("policy: a domain that is not allowed is refused", True)
check("policy: an allowed domain gets the default role", oidc.decide(sso, {"email": "A@Example.test"}) == ("a@example.test", "viewer"))
check("policy: a member of an administrator group becomes administrator", oidc.decide(sso, {"email": "a@example.test", "groups": ["Ops"]})[1] == "admin")
try:
    oidc.decide(sso, {"email": "x@example.test.evil.com"})
    check("policy: a look-alike domain (example.test.evil.com) is refused", False)
except oidc.OidcError:
    check("policy: a look-alike domain (example.test.evil.com) is refused", True)
os.environ["SHIELD_OIDC_ALLOW_PRIVATE"] = "0"
check("an identity provider on a private address is refused (SSRF)", oidc.check_url("https://127.0.0.1/") is not None and oidc.check_url("https://169.254.169.254/") is not None)
check("an identity provider over plain http is refused", oidc.check_url("http://idp.example.com/") is not None)
check("settings validation: nobody may sign in unless somebody is listed", oidc.validate_settings({**sso, "allowed_domains": "", "issuer": "https://login.microsoftonline.com/x"}) is not None)

print()
bad = [n for n, ok in results if not ok]
print(f"{len(results) - len(bad)}/{len(results)} single sign-on checks passed")
if bad:
    print("FAILED:", *bad, sep="\n  ")
sys.exit(1 if bad else 0)
