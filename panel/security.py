"""Security helpers: TOTP 2FA, strong password hashing for the site login gate, SSRF-safe upstream validation, certificates."""
import base64
import hashlib
import hmac
import ipaddress
import os
import re
import secrets
import struct
import subprocess
import time
from urllib.parse import quote, urlparse

import sharedfs
import store

# ----------------------------------------------------------------------------------------------- TOTP (RFC 6238)


def totp_new_secret():
    return base64.b32encode(secrets.token_bytes(20)).decode().rstrip("=")


def _hotp(secret, counter):
    key = base64.b32decode(secret + "=" * (-len(secret) % 8))
    mac = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    off = mac[-1] & 0x0F
    return "%06d" % ((struct.unpack(">I", mac[off:off + 4])[0] & 0x7FFFFFFF) % 1_000_000)


def totp_verify(secret, code, last_step=0):
    """Return the matching time step (int) or 0. Accepts +-1 step of clock drift; a step can only be used once."""
    code = re.sub(r"\s", "", code or "")
    if not re.fullmatch(r"\d{6}", code):
        return 0
    now = int(time.time() // 30)
    for step in (now, now - 1, now + 1):
        if step > last_step and hmac.compare_digest(_hotp(secret, step), code):
            return step
    return 0


def totp_uri(user, secret):
    return f"otpauth://totp/{quote('A Shield WAF')}:{quote(user)}?secret={secret}&issuer={quote('A Shield WAF')}&algorithm=SHA1&digits=6&period=30"


def new_recovery_codes(n=8):
    codes = [secrets.token_hex(5) for _ in range(n)]
    return codes, [hashlib.sha256(c.encode()).hexdigest() for c in codes]


# ----------------------------------------------------------------------------------------- passwords for the site gate
def crypt_hash(password):
    """SHA-512 crypt ($6$) via the openssl binary (password goes through stdin, never the command line)."""
    r = subprocess.run(["/usr/bin/openssl", "passwd", "-6", "-stdin"], input=password, capture_output=True, text=True, timeout=15)
    h = r.stdout.strip()
    if r.returncode != 0 or not h.startswith("$6$"):
        raise RuntimeError("password hashing failed")
    return h


# -------------------------------------------------------------------------------------------------- upstream (SSRF)
_BLOCKED_NETS = [ipaddress.ip_network(n) for n in (
    "127.0.0.0/8", "0.0.0.0/8", "169.254.0.0/16", "100.100.100.200/32", "::1/128", "fe80::/10", "fd00:ec2::/32")]
_BLOCKED_NAMES = ("localhost", "metadata.google.internal", "metadata", "instance-data")


def check_upstream(url, allow_suffixes=""):
    """Return an error string or None. Blocks loopback, link-local and cloud-metadata targets so the WAF cannot be
    pointed at itself, at its own admin panel or at the instance metadata service."""
    u = urlparse(url)
    host = (u.hostname or "").lower().rstrip(".")
    if not host:
        return "Upstream has no host name."
    if u.port is not None and not (1 <= u.port <= 65535):
        return "Upstream port out of range."
    if host in _BLOCKED_NAMES or host.endswith(".localhost"):
        return "Upstream host is not allowed (loopback / metadata name)."
    try:
        ip = ipaddress.ip_address(host)
        if any(ip in n for n in _BLOCKED_NETS):
            return "Upstream address is not allowed (loopback, link-local or cloud-metadata range)."
    except ValueError:
        pass
    suffixes = [x.strip().lower() for x in re.split(r"[\s,]+", allow_suffixes or "") if x.strip()]
    if suffixes and not any(host == s or host.endswith("." + s.lstrip(".")) for s in suffixes):
        return "Upstream host is not in the allowed list (Settings, 'Allowed upstream suffixes')."
    return None


# --------------------------------------------------------------------------------------------------- certificates
CERT_DIR = os.path.join(store.DATA, "certs")


def _run(cmd, **kw):
    return subprocess.run(cmd, capture_output=True, text=True, timeout=30, **kw)


def cert_paths(site):
    """(cert_file, key_file) for a site according to its TLS settings, or (None, None)."""
    t = site["tls"]
    if t["source"] in ("uploaded", "selfsigned", "acme"):
        d = os.path.join(CERT_DIR, site["id"])
        return os.path.join(d, "fullchain.pem"), os.path.join(d, "privkey.pem")
    if t["source"] == "mounted" and re.fullmatch(r"[a-z0-9][a-z0-9.-]{0,62}", t.get("mounted_name", "")):
        d = f"/certs/{t['mounted_name']}"
        return os.path.join(d, "tls.crt"), os.path.join(d, "tls.key")
    return None, None


def cert_info(cert_file):
    """Subject / expiry of a certificate file, or None."""
    if not cert_file or not os.path.exists(cert_file):
        return None
    r = _run(["/usr/bin/openssl", "x509", "-noout", "-subject", "-enddate", "-in", cert_file])
    if r.returncode != 0:
        return None
    info = dict(l.split("=", 1) for l in r.stdout.strip().splitlines() if "=" in l)
    try:
        end = time.mktime(time.strptime(info["notAfter"].replace("  ", " "), "%b %d %H:%M:%S %Y %Z"))
    except (KeyError, ValueError):
        end = 0
    return {"subject": info.get("subject", "").strip(), "expires": end, "days_left": int((end - time.time()) // 86400) if end else None}


def _pubkey_of_cert(path):
    return _run(["/usr/bin/openssl", "x509", "-noout", "-pubkey", "-in", path]).stdout


def _pubkey_of_key(path):
    return _run(["/usr/bin/openssl", "pkey", "-pubout", "-in", path]).stdout


def install_pair(site_id, cert_pem, key_pem):
    """Validate a PEM cert chain + private key and store them (key mode 0600). Returns an error string or None."""
    if len(cert_pem) > 60000 or len(key_pem) > 20000:
        return "Certificate or key file is too large."
    if "BEGIN CERTIFICATE" not in cert_pem or "PRIVATE KEY" not in key_pem:
        return "Paste a PEM certificate chain and a PEM private key."
    if "ENCRYPTED" in key_pem:
        return "The private key must not be password-protected."
    d = os.path.join(CERT_DIR, site_id)
    os.makedirs(d, mode=0o700, exist_ok=True)
    tmp_c, tmp_k = os.path.join(d, ".c.pem"), os.path.join(d, ".k.pem")
    try:
        with open(tmp_c, "w") as f:
            f.write(cert_pem.strip() + "\n")
        fd = os.open(tmp_k, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(key_pem.strip() + "\n")
        a, b = _pubkey_of_cert(tmp_c), _pubkey_of_key(tmp_k)
        if not a or not b:
            return "Could not read the certificate or the key (wrong format?)."
        if a != b:
            return "The private key does not match the certificate."
        os.replace(tmp_c, os.path.join(d, "fullchain.pem"))
        os.replace(tmp_k, os.path.join(d, "privkey.pem"))
        sharedfs.publish(f"certs/{site_id}")        # every replica needs the certificate
        return None
    finally:
        for t in (tmp_c, tmp_k):
            if os.path.exists(t):
                os.remove(t)


def make_selfsigned(site_id, host, days=365):
    """Generate an ECDSA P-256 self-signed certificate for `host` (lab/testing; use a real CA certificate in production)."""
    d = os.path.join(CERT_DIR, site_id)
    os.makedirs(d, mode=0o700, exist_ok=True)
    san = f"DNS:{host.lstrip('*.')}" + (f",DNS:{host}" if host.startswith("*.") else "")
    key, crt = os.path.join(d, "privkey.pem"), os.path.join(d, "fullchain.pem")
    fd = os.open(key, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    os.close(fd)
    r = _run(["/usr/bin/openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes", "-days", str(days),
              "-subj", f"/CN={host.lstrip('*.')}", "-addext", f"subjectAltName={san}", "-keyout", key, "-out", crt])
    os.chmod(key, 0o600)
    if r.returncode == 0:
        sharedfs.publish(f"certs/{site_id}")
    return None if r.returncode == 0 else "openssl failed: " + r.stderr[-200:]


def ensure_default_cert(name="default", cn="shieldwaf.local"):
    """Self-signed certificate for the default TLS server / the admin panel (replace it by mounting your own)."""
    d = os.path.join(CERT_DIR, name)
    if os.path.exists(os.path.join(d, "fullchain.pem")):
        return d
    os.makedirs(d, mode=0o700, exist_ok=True)
    key, crt = os.path.join(d, "privkey.pem"), os.path.join(d, "fullchain.pem")
    fd = os.open(key, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    os.close(fd)
    _run(["/usr/bin/openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes", "-days", "825",
          "-subj", f"/CN={cn}", "-addext", f"subjectAltName=DNS:{cn},DNS:localhost,IP:127.0.0.1", "-keyout", key, "-out", crt])
    os.chmod(key, 0o600)
    return d
