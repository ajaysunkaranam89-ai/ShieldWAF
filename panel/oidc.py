"""Single sign-on with OpenID Connect (authorization code flow with PKCE): Microsoft Entra ID, Google, Okta, Keycloak, Dex, Authentik ...

What is checked, and why it is written this way:
  * The identity provider's address must be https and, outside tests, resolve to public addresses only (no request into the cluster).
  * Everything the provider returns is verified, never trusted: the discovery document must name the same issuer, the ID token signature must
    verify against the provider's published keys (RS256 or ES256 only: "none" and HMAC algorithms are refused), and issuer, audience,
    expiry, nonce and (optionally) a verified e-mail address must all be right.
  * state, nonce and the PKCE verifier are random, stored server-side, bound to the browser that started the login by a cookie, and used once.
  * Who may sign in and with which role is decided HERE (allowed e-mail domains / addresses, administrator list, default role), not by the provider.
Test hooks (operator environment only): SHIELD_OIDC_TEST_CA = extra trusted CA file, SHIELD_OIDC_ALLOW_PRIVATE=1."""
import base64
import hashlib
import json
import os
import re
import secrets
import socket
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa, utils

import netguard
import sharedfs
import store

SECRET_FILE = os.path.join(store.DATA, "secrets", "oidc.json")
SECRET_UNIT = "secrets/oidc.json"  # nosec B105 - a file name, not a password
PENDING_TTL = 600
LEEWAY = 60
ALGS = ("RS256", "ES256")
EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+\-]{1,64}@[A-Za-z0-9.\-]{1,200}\.[A-Za-z]{2,}$")
_cache = {"disc": {}, "jwks": {}}


class OidcError(Exception):
    pass


def _b64d(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _b64e(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _public(ip_text):
    return netguard.classify(ip_text) == "public"


def check_url(url, what="address"):
    """Return an error string or None: https, and a public host (unless the operator allowed private addresses for a test)."""
    u = urllib.parse.urlparse(url or "")
    if u.scheme != "https" or not u.hostname or u.username or u.fragment:
        return f"The {what} must be an https:// address."
    if os.environ.get("SHIELD_OIDC_ALLOW_PRIVATE") == "1":
        return None
    try:
        for info in socket.getaddrinfo(u.hostname, u.port or 443, proto=socket.IPPROTO_TCP):
            if not _public(info[4][0]):
                return f"The {what} resolves to a private or reserved address (refused)."
    except OSError:
        return f"The {what} host name does not resolve."
    return None


def _ctx():
    ca = os.environ.get("SHIELD_OIDC_TEST_CA")
    return ssl.create_default_context(cafile=ca) if ca else ssl.create_default_context()


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


def _http(url, data=None, headers=None, what="identity provider"):
    err = check_url(url, what)
    if err:
        raise OidcError(err)
    req = urllib.request.Request(url, data=data, headers={"User-Agent": "A-Shield-WAF/2.3", **(headers or {})})
    opener = urllib.request.build_opener(_NoRedirect, urllib.request.HTTPSHandler(context=_ctx()))
    try:
        with opener.open(req, timeout=15) as r:  # nosec B310 - https only and checked above
            return r.status, r.read(2 * 1024 * 1024)
    except urllib.error.HTTPError as e:
        return e.code, e.read(65536)
    except OSError as e:
        raise OidcError(f"cannot reach the {what}: {type(e).__name__}") from e


# ----------------------------------------------------------------------------------------------------- configuration
def load_secret():
    try:
        with open(SECRET_FILE) as f:
            return json.load(f).get("client_secret", "")
    except (OSError, ValueError):
        return ""


def save_secret(value):
    os.makedirs(os.path.dirname(SECRET_FILE), mode=0o700, exist_ok=True)
    tmp = SECRET_FILE + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump({"client_secret": value}, f)
    os.replace(tmp, SECRET_FILE)
    sharedfs.publish(SECRET_UNIT)


def split(text):
    return [x.strip().lower() for x in re.split(r"[\s,;]+", text or "") if x.strip()]


def validate_settings(sso):
    """Return an error string or None for the settings form."""
    if not sso["enabled"]:
        return None
    err = check_url(sso["issuer"], "identity provider address (issuer)")
    if err:
        return err
    if not re.fullmatch(r"[A-Za-z0-9._~:@\-]{1,200}", sso["client_id"] or ""):
        return "Enter the client ID of this application as registered at the identity provider."
    err = check_url(sso["redirect_base"], "panel address")
    if err or urllib.parse.urlparse(sso["redirect_base"]).path not in ("", "/"):
        return err or "The panel address must be like https://waf-admin.example.com (no path)."
    if sso["default_role"] not in ("viewer", "admin"):
        return "Invalid default role."
    for d in split(sso["allowed_domains"]):
        if not re.fullmatch(r"[a-z0-9.\-]{3,200}", d) or "." not in d:
            return f"'{d}' is not a valid e-mail domain."
    for e in split(sso["allowed_emails"]) + split(sso["admin_emails"]):
        if not EMAIL_RE.match(e):
            return f"'{e}' is not a valid e-mail address."
    if not split(sso["allowed_domains"]) and not split(sso["allowed_emails"]) and not split(sso["admin_emails"]):
        return "Say who may sign in: allowed e-mail domains and/or addresses (nobody is allowed by default)."
    return None


def redirect_uri(sso):
    return sso["redirect_base"].rstrip("/") + "/sso/callback"


def discovery(issuer):
    hit = _cache["disc"].get(issuer)
    if hit and time.time() - hit[0] < 600:
        return hit[1]
    status, body = _http(issuer.rstrip("/") + "/.well-known/openid-configuration")
    if status != 200:
        raise OidcError(f"the identity provider's configuration could not be read (HTTP {status})")
    doc = json.loads(body)
    if doc.get("issuer", "").rstrip("/") != issuer.rstrip("/"):
        raise OidcError("the identity provider names a different issuer than the one configured (refused)")
    for k in ("authorization_endpoint", "token_endpoint", "jwks_uri"):
        if check_url(doc.get(k, ""), k):
            raise OidcError(f"the provider's {k} is not a safe https address")
    _cache["disc"][issuer] = (time.time(), doc)
    return doc


def _jwks(uri, force=False):
    hit = _cache["jwks"].get(uri)
    if hit and not force and time.time() - hit[0] < 600:
        return hit[1]
    status, body = _http(uri)
    if status != 200:
        raise OidcError("the identity provider's signing keys could not be read")
    keys = {k.get("kid", ""): k for k in json.loads(body).get("keys", [])}
    _cache["jwks"][uri] = (time.time(), keys)
    return keys


# ----------------------------------------------------------------------------------------------------- the ID token
def _verify_signature(alg, jwk, signing_input, sig):
    if alg == "RS256" and jwk.get("kty") == "RSA":
        pub = rsa.RSAPublicNumbers(int.from_bytes(_b64d(jwk["e"]), "big"), int.from_bytes(_b64d(jwk["n"]), "big")).public_key()
        pub.verify(sig, signing_input, padding.PKCS1v15(), hashes.SHA256())
    elif alg == "ES256" and jwk.get("kty") == "EC" and jwk.get("crv") == "P-256":
        pub = ec.EllipticCurvePublicNumbers(int.from_bytes(_b64d(jwk["x"]), "big"), int.from_bytes(_b64d(jwk["y"]), "big"), ec.SECP256R1()).public_key()
        if len(sig) != 64:
            raise ValueError("bad signature length")
        pub.verify(utils.encode_dss_signature(int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big")), signing_input, ec.ECDSA(hashes.SHA256()))
    else:
        raise ValueError("key does not match the algorithm")


def verify_id_token(token, jwks_loader, issuer, client_id, nonce, need_verified_email=True, now=None):
    """Return the claims of a valid ID token or raise OidcError. `jwks_loader(force)` returns {kid: jwk}."""
    now = now or time.time()
    try:
        h64, p64, s64 = token.split(".")
        header, claims, sig = json.loads(_b64d(h64)), json.loads(_b64d(p64)), _b64d(s64)
    except (ValueError, TypeError) as e:
        raise OidcError("the ID token is malformed") from e
    alg = header.get("alg")
    if alg not in ALGS:
        raise OidcError(f"the ID token uses a signature algorithm that is not accepted ({str(alg)[:20]})")
    signing_input = f"{h64}.{p64}".encode()
    ok = False
    for force in (False, True):                  # an unknown key id may mean the provider rotated its keys: reload once
        keys = jwks_loader(force)
        jwk = keys.get(header.get("kid", "")) or (next(iter(keys.values())) if len(keys) == 1 and not header.get("kid") else None)
        if jwk:
            try:
                _verify_signature(alg, jwk, signing_input, sig)
                ok = True
            except Exception:  # noqa: BLE001 - InvalidSignature, ValueError, KeyError ...
                ok = False
            break
    if not ok:
        raise OidcError("the ID token signature is not valid")
    if str(claims.get("iss", "")).rstrip("/") != issuer.rstrip("/"):
        raise OidcError("the ID token was issued by someone else")
    aud = claims.get("aud")
    auds = aud if isinstance(aud, list) else [aud]
    if client_id not in auds or (len(auds) > 1 and claims.get("azp") != client_id):
        raise OidcError("the ID token is not meant for this application")
    exp, iat = claims.get("exp"), claims.get("iat", now)
    if not isinstance(exp, (int, float)) or exp < now - LEEWAY:
        raise OidcError("the ID token has expired")
    if not isinstance(iat, (int, float)) or iat > now + LEEWAY * 5:
        raise OidcError("the ID token is dated in the future")
    if not nonce or not secrets.compare_digest(str(claims.get("nonce", "")), nonce):
        raise OidcError("the ID token does not belong to this login attempt")
    if not claims.get("sub"):
        raise OidcError("the ID token has no subject")
    if need_verified_email and claims.get("email_verified") is not True:
        raise OidcError("the identity provider has not verified your e-mail address")
    return claims


# ----------------------------------------------------------------------------------------------------- the login flow
def begin(sso):
    """Start a login: returns (url to send the browser to, binder cookie value). The state is kept server-side."""
    doc = discovery(sso["issuer"])
    state, nonce, verifier, binder = (secrets.token_urlsafe(32) for _ in range(4))
    challenge = _b64e(hashlib.sha256(verifier.encode()).digest())
    con = store.db()
    con.execute("DELETE FROM sso_pending WHERE created<?", (time.time() - PENDING_TTL,))
    con.execute("INSERT INTO sso_pending(state,nonce,verifier,binder,created) VALUES(?,?,?,?,?)",
                (state, nonce, verifier, hashlib.sha256(binder.encode()).hexdigest(), time.time()))
    con.commit()
    q = {"response_type": "code", "client_id": sso["client_id"], "redirect_uri": redirect_uri(sso), "scope": sso["scopes"] or "openid email profile",
         "state": state, "nonce": nonce, "code_challenge": challenge, "code_challenge_method": "S256"}
    return doc["authorization_endpoint"] + ("&" if "?" in doc["authorization_endpoint"] else "?") + urllib.parse.urlencode(q), binder


def finish(sso, code, state, binder):
    """Complete a login: returns the verified claims. Raises OidcError for anything wrong (the message is safe to show)."""
    if not state or not code or not binder or len(state) > 100 or len(code) > 2000:
        raise OidcError("the sign-in response is incomplete")
    con = store.db()
    row = con.execute("SELECT * FROM sso_pending WHERE state=?", (state,)).fetchone()
    con.execute("DELETE FROM sso_pending WHERE state=?", (state,))             # single use, whatever happens next
    con.commit()
    if not row or time.time() - float(row["created"]) > PENDING_TTL:
        raise OidcError("the sign-in attempt is unknown or too old: start again")
    if not secrets.compare_digest(row["binder"], hashlib.sha256(binder.encode()).hexdigest()):
        raise OidcError("the sign-in attempt was started in another browser")
    doc = discovery(sso["issuer"])
    form = {"grant_type": "authorization_code", "code": code, "redirect_uri": redirect_uri(sso), "client_id": sso["client_id"], "code_verifier": row["verifier"]}
    headers, secret = {"Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json"}, load_secret()
    if secret:
        headers["Authorization"] = "Basic " + base64.b64encode(f"{urllib.parse.quote(sso['client_id'], safe='')}:{urllib.parse.quote(secret, safe='')}".encode()).decode()
    status, body = _http(doc["token_endpoint"], urllib.parse.urlencode(form).encode(), headers)
    try:
        tok = json.loads(body)
    except ValueError as e:
        raise OidcError("the identity provider's answer could not be understood") from e
    if status != 200 or "id_token" not in tok:
        raise OidcError("the identity provider refused the sign-in (" + str(tok.get("error", status))[:60] + ")")
    return verify_id_token(tok["id_token"], lambda force: _jwks(doc["jwks_uri"], force), sso["issuer"], sso["client_id"], row["nonce"],
                           bool(sso.get("require_verified_email", True)))


def decide(sso, claims):
    """Who may sign in and as what: returns (username, role) or raises OidcError. The provider only proves who the person is."""
    email = str(claims.get("email", "")).strip().lower()
    if not EMAIL_RE.match(email):
        raise OidcError("the identity provider did not send a usable e-mail address")
    domain = email.rsplit("@", 1)[1]
    admins, allowed = split(sso["admin_emails"]), split(sso["allowed_emails"])
    groups = {str(g).lower() for g in (claims.get("groups") or []) if isinstance(g, str)}
    if not (email in admins or email in allowed or domain in split(sso["allowed_domains"])):
        raise OidcError(f"{email} is not allowed to sign in to this panel")
    role = "admin" if (email in admins or groups & set(split(sso.get("admin_groups", "")))) else sso["default_role"]
    return email, role
