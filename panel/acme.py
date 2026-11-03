"""Automatic HTTPS certificates (ACME, RFC 8555) with the HTTP-01 challenge: Let's Encrypt and any other ACME certificate authority.

How it works: the panel registers an account (a key that is created once and shared by all replicas), orders a certificate for the site's
host name, publishes the challenge answer as a small file that every replica serves at /.well-known/acme-challenge/<token> on port 80,
asks the authority to check it, generates a new private key and a signing request, downloads the certificate, verifies it, and installs it
for the site. The leader replica renews it automatically 30 days before it expires.

Safety: the directory URL must be https and every authority URL must be on the same host; outside of tests the host must resolve to public
addresses only (no request into the cluster); the issued certificate is checked (right name, valid now, matches our key) before use;
failures are retried at most every 6 hours per site (authorities rate-limit failed validations). Needs a public host name that reaches this
firewall on port 80, and does not support wildcard names (those need DNS-01).
Test hooks (operator environment only, never settings): SHIELD_ACME_TEST_CA = extra trusted CA file, SHIELD_ACME_ALLOW_PRIVATE=1."""
import base64
import hashlib
import json
import os
import re
import socket
import ssl
import time
import urllib.error
import urllib.request
from urllib.parse import urlparse

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.x509.oid import NameOID

import sharedfs
import store

LETSENCRYPT = "https://acme-v02.api.letsencrypt.org/directory"
LETSENCRYPT_STAGING = "https://acme-staging-v02.api.letsencrypt.org/directory"
CHALLENGE_DIR = os.path.join(store.DATA, "acme")
ACCOUNT_UNIT = "secrets/acme_account.json"
ACCOUNT_FILE = os.path.join(store.DATA, "secrets", "acme_account.json")
HOST_RE = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$")
TOKEN_RE = re.compile(r"^[A-Za-z0-9_-]{16,128}$")
RENEW_DAYS = 30
RETRY_S = 6 * 3600


class AcmeError(Exception):
    pass


def _b64(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _public(ip_text):
    import ipaddress
    ip = ipaddress.ip_address(ip_text)
    return not (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast or ip.is_unspecified)


def check_directory(url):
    """Return an error string or None."""
    u = urlparse(url or "")
    if u.scheme != "https" or not u.hostname or u.username or u.fragment:
        return "The ACME directory must be an https:// address."
    if os.environ.get("SHIELD_ACME_ALLOW_PRIVATE") == "1":
        return None
    try:
        for info in socket.getaddrinfo(u.hostname, u.port or 443, proto=socket.IPPROTO_TCP):
            if not _public(info[4][0]):
                return "The ACME directory resolves to a private or reserved address (refused)."
    except OSError:
        return "The ACME directory host name does not resolve."
    return None


def valid_host(host):
    return bool(HOST_RE.match(host or "")) and not host.startswith("*") and not re.fullmatch(r"[0-9.]+", host)


# ---------------------------------------------------------------------------------------------------- the protocol
class Client:
    def __init__(self, directory_url, account_key):
        err = check_directory(directory_url)
        if err:
            raise AcmeError(err)
        self.dir_url = directory_url
        self.host = urlparse(directory_url).hostname
        self.key = account_key
        ca = os.environ.get("SHIELD_ACME_TEST_CA")
        self.ctx = ssl.create_default_context(cafile=ca) if ca else ssl.create_default_context()
        self.nonce = None
        self.kid = None
        self.dir = json.loads(self._http(directory_url)[2])
        for k in ("newNonce", "newAccount", "newOrder"):
            if k not in self.dir:
                raise AcmeError("not an ACME directory (missing " + k + ")")

    # -- plumbing
    def _http(self, url, data=None, headers=None, method=None):
        u = urlparse(url)
        if u.scheme != "https" or u.hostname != self.host:
            raise AcmeError("the authority sent an address outside its own host (refused): " + url[:80])
        req = urllib.request.Request(url, data=data, headers={"User-Agent": "A-Shield-WAF/2.3", **(headers or {})}, method=method)
        try:
            with urllib.request.urlopen(req, timeout=30, context=self.ctx) as r:  # nosec B310 - https only, host pinned to the directory host
                return r.status, dict(r.headers), r.read(2 * 1024 * 1024)
        except urllib.error.HTTPError as e:
            return e.code, dict(e.headers), e.read(65536)

    def _jwk(self):
        n = self.key.public_key().public_numbers()
        return {"crv": "P-256", "kty": "EC", "x": _b64(n.x.to_bytes(32, "big")), "y": _b64(n.y.to_bytes(32, "big"))}

    def thumbprint(self):
        return _b64(hashlib.sha256(json.dumps(self._jwk(), sort_keys=True, separators=(",", ":")).encode()).digest())

    def _new_nonce(self):
        _, h, _ = self._http(self.dir["newNonce"], method="HEAD")
        self.nonce = {k.lower(): v for k, v in h.items()}["replay-nonce"]

    def post(self, url, payload, retries=3):
        """Signed request. payload None = POST-as-GET. Returns (status, headers, parsed body or raw bytes)."""
        for attempt in range(retries):
            if not self.nonce:
                self._new_nonce()
            prot = {"alg": "ES256", "nonce": self.nonce, "url": url}
            prot.update({"kid": self.kid} if self.kid else {"jwk": self._jwk()})
            p64 = _b64(json.dumps(prot).encode())
            pl64 = "" if payload is None else _b64(json.dumps(payload).encode())
            r, s = utils.decode_dss_signature(self.key.sign(f"{p64}.{pl64}".encode(), ec.ECDSA(hashes.SHA256())))
            body = json.dumps({"protected": p64, "payload": pl64, "signature": _b64(r.to_bytes(32, "big") + s.to_bytes(32, "big"))}).encode()
            status, headers, raw = self._http(url, body, {"Content-Type": "application/jose+json"}, "POST")
            hl = {k.lower(): v for k, v in headers.items()}
            self.nonce = hl.get("replay-nonce")
            if status == 400 and b"badNonce" in raw and attempt < retries - 1:
                self.nonce = None
                continue
            try:
                parsed = json.loads(raw) if raw[:1] in (b"{", b"[") else raw
            except ValueError:
                parsed = raw
            if status >= 400:
                detail = parsed.get("detail") if isinstance(parsed, dict) else ""
                raise AcmeError(f"the certificate authority refused the request ({status}): {str(detail)[:300]}")
            return status, hl, parsed
        raise AcmeError("could not get a valid nonce from the certificate authority")

    def register(self, email):
        payload = {"termsOfServiceAgreed": True}
        if email:
            payload["contact"] = ["mailto:" + email]
        _, h, _ = self.post(self.dir["newAccount"], payload)
        self.kid = h["location"]

    # -- one certificate
    def issue(self, host, publish, unpublish, wait_s=4, timeout_s=120):
        """Order, prove control by HTTP-01 and finalize. Returns (certificate chain PEM, private key PEM)."""
        _, h, order = self.post(self.dir["newOrder"], {"identifiers": [{"type": "dns", "value": host}]})
        order_url = h["location"]
        for authz_url in order["authorizations"]:
            _, _, authz = self.post(authz_url, None)
            if authz.get("status") == "valid":
                continue
            ch = next((c for c in authz.get("challenges", []) if c.get("type") == "http-01"), None)
            if not ch or not TOKEN_RE.match(ch.get("token", "")):
                raise AcmeError("the authority did not offer a usable HTTP-01 challenge")
            token = ch["token"]
            publish(token, f"{token}.{self.thumbprint()}")
            try:
                time.sleep(wait_s)                      # let every replica receive and serve the answer file
                self.post(ch["url"], {})
                end = time.time() + timeout_s
                while True:
                    time.sleep(2)
                    _, _, authz = self.post(authz_url, None)
                    if authz.get("status") == "valid":
                        break
                    if authz.get("status") in ("invalid", "deactivated", "expired", "revoked") or time.time() > end:
                        err = (ch.get("error") or authz.get("challenges", [{}])[0].get("error") or {}).get("detail", "") if authz.get("status") != "valid" else ""
                        for c in authz.get("challenges", []):
                            if c.get("error"):
                                err = c["error"].get("detail", err)
                        raise AcmeError("the authority could not verify the host name over HTTP: " + (err or "timed out")[:300])
            finally:
                unpublish(token)
        key = ec.generate_private_key(ec.SECP256R1())
        csr = (x509.CertificateSigningRequestBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, host)]))
               .add_extension(x509.SubjectAlternativeName([x509.DNSName(host)]), critical=False).sign(key, hashes.SHA256()))
        self.post(order["finalize"], {"csr": _b64(csr.public_bytes(serialization.Encoding.DER))})
        end = time.time() + timeout_s
        while True:
            _, _, order = self.post(order_url, None)
            if order.get("status") == "valid" and order.get("certificate"):
                break
            if order.get("status") == "invalid" or time.time() > end:
                raise AcmeError("the certificate order did not complete (" + str(order.get("status")) + ")")
            time.sleep(2)
        _, _, chain = self.post(order["certificate"], None)
        chain_pem = chain.decode() if isinstance(chain, bytes) else str(chain)
        key_pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode()
        check_certificate(chain_pem, key_pem, host)
        return chain_pem, key_pem


def check_certificate(chain_pem, key_pem, host):
    """Do not trust the download blindly: right name, valid now, belongs to our key."""
    leaf = x509.load_pem_x509_certificate(chain_pem.encode())
    names = leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName)
    if host not in names:
        raise AcmeError("the issued certificate is not for " + host)
    now = time.time()
    if not (leaf.not_valid_before_utc.timestamp() - 300 <= now <= leaf.not_valid_after_utc.timestamp()):
        raise AcmeError("the issued certificate is not valid now")
    key = serialization.load_pem_private_key(key_pem.encode(), None)
    pub = lambda k: k.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)  # noqa: E731
    if pub(key.public_key()) != pub(leaf.public_key()):
        raise AcmeError("the issued certificate does not match the private key")
    return leaf.not_valid_after_utc.timestamp()


# ---------------------------------------------------------------------------------------------------- the panel's side
def _account_key():
    """One account key for the whole cluster, created once and shared (encrypted) with every replica."""
    def make():
        os.makedirs(os.path.dirname(ACCOUNT_FILE), mode=0o700, exist_ok=True)
        pem = ec.generate_private_key(ec.SECP256R1()).private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode()
        fd = os.open(ACCOUNT_FILE, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            json.dump({"key_pem": pem}, f)
    sharedfs.ensure(ACCOUNT_UNIT, make)
    with open(ACCOUNT_FILE) as f:
        return serialization.load_pem_private_key(json.load(f)["key_pem"].encode(), None)


def _publish(token, keyauth):
    os.makedirs(CHALLENGE_DIR, mode=0o755, exist_ok=True)
    tmp = os.path.join(CHALLENGE_DIR, f".{token}.tmp")
    with open(tmp, "w") as f:
        f.write(keyauth)
    os.replace(tmp, os.path.join(CHALLENGE_DIR, token))
    sharedfs.publish("acme")


def _unpublish(token):
    try:
        os.remove(os.path.join(CHALLENGE_DIR, token))
    except OSError:
        pass
    if sharedfs.present("acme"):
        sharedfs.publish("acme")
    else:
        sharedfs.forget("acme")


def obtain(host, email, directory):
    """Get a new certificate for `host`. Returns (chain PEM, key PEM, expires epoch). Raises AcmeError."""
    if not valid_host(host):
        raise AcmeError("Let's Encrypt needs a public host name like app.example.com (no wildcard, no IP address).")
    client = Client(directory, _account_key())
    client.register(email)
    chain, key = client.issue(host, _publish, _unpublish)
    return chain, key, check_certificate(chain, key, host)


def install(site_id, chain_pem, key_pem):
    """Write the certificate where nginx reads it and share it with the other replicas."""
    import security
    d = os.path.join(security.CERT_DIR, site_id)
    os.makedirs(d, mode=0o700, exist_ok=True)
    for name, text, mode in (("fullchain.pem", chain_pem, 0o644), ("privkey.pem", key_pem, 0o600)):
        tmp = os.path.join(d, "." + name)
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
        with os.fdopen(fd, "w") as f:
            f.write(text.strip() + "\n")
        os.replace(tmp, os.path.join(d, name))
    sharedfs.publish(f"certs/{site_id}")
