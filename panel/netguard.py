"""Network guard: one place that decides whether the panel (or the firewall engine, on behalf of a site) may talk to an address.

Why it exists: an upstream, a feed, a webhook or an identity provider that points at loopback, the cloud metadata service or the cluster's internal
network turns the WAF into a door into that network (SSRF). Checking the text of a URL is not enough: a public DNS name can resolve to 127.0.0.1,
a numeric host can be written as 0177.0.0.1 or 2130706433, an IPv6 address can wrap an IPv4 one (::ffff:169.254.169.254, 64:ff9b::7f00:1, 2002:7f00:1::),
and the answer can change between the check and the use (DNS rebinding). So: resolve, classify EVERY address, refuse the whole name if any address is bad,
re-check on a timer, and validate each redirect hop.

Classes (see classify()): "public", "private" (RFC 1918, unique-local fc00::/7, CGNAT 100.64/10: allowed only through an explicit allowlist),
and never-allowed: "loopback", "link-local", "metadata", "unspecified", "multicast", "reserved"."""
import ipaddress
import json
import re
import socket
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

# Cloud metadata services (the link-local ones are also caught by "link-local"; listed so the reason is named)
METADATA = {ipaddress.ip_address(a) for a in ("169.254.169.254", "169.254.170.2", "fd00:ec2::254", "100.100.100.200", "192.0.0.192", "168.63.129.16")}
NEVER = ("loopback", "link-local", "metadata", "unspecified", "multicast", "reserved")
BLOCKED_NAMES = {"localhost", "metadata", "instance-data", "metadata.google.internal"}
DEFAULT_PRIVATE_ALLOW = "10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 fc00::/7"     # what 2.3 accepted implicitly: tighten to your pod/service ranges
_NAT64 = ipaddress.ip_network("64:ff9b::/96")
_6TO4 = ipaddress.ip_network("2002::/16")
_CGNAT = ipaddress.ip_network("100.64.0.0/10")
_TEREDO = ipaddress.ip_network("2001::/32")


def unwrap(ip):
    """The IPv4 address hidden inside an IPv6 one (mapped, NAT64, 6to4), or the address itself."""
    if isinstance(ip, ipaddress.IPv6Address):
        if ip.ipv4_mapped is not None:
            return ip.ipv4_mapped
        if ip in _NAT64:
            return ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF)
        if ip in _6TO4:
            return ipaddress.IPv4Address((int(ip) >> 80) & 0xFFFFFFFF)
        if ip in _TEREDO:
            return ipaddress.IPv4Address((~int(ip)) & 0xFFFFFFFF)       # Teredo stores the client address inverted in the last 32 bits
        if ip.is_site_local:
            return ip
    return ip


def classify(ip):
    """One of: public, private, loopback, link-local, metadata, unspecified, multicast, reserved."""
    if isinstance(ip, str):
        ip = ipaddress.ip_address(ip)
    ip = unwrap(ip)
    if ip in METADATA:
        return "metadata"
    if ip.is_unspecified:
        return "unspecified"
    if ip.is_loopback:
        return "loopback"
    if ip.is_link_local:
        return "link-local"
    if ip.is_multicast:
        return "multicast"
    if isinstance(ip, ipaddress.IPv4Address) and ip in _CGNAT:
        return "private"
    if ip.is_private and not ip.is_reserved:
        return "private"
    if ip.is_reserved or (isinstance(ip, ipaddress.IPv6Address) and (ip.is_site_local or ip in _TEREDO)):
        return "reserved"
    if ip.is_private:
        return "private"
    return "public"


_NUMERIC = re.compile(r"^(?:0x[0-9a-f]+|[0-9]+)(?:\.(?:0x[0-9a-f]+|[0-9]+)){0,3}$", re.I)


def literal_ip(host):
    """If `host` is an IP address in ANY form the C library accepts (dotted decimal, octal 0177.0.0.1, hex 0x7f.1, one decimal number, IPv6), return it, else None."""
    host = host.strip("[]")
    try:
        return ipaddress.ip_address(host)
    except ValueError:
        pass
    if _NUMERIC.match(host):
        try:
            return ipaddress.IPv4Address(socket.inet_aton(host))
        except OSError:
            return None
    return None


def parse_networks(text):
    out = []
    for x in re.split(r"[\s,;]+", text or ""):
        if x.strip():
            out.append(ipaddress.ip_network(x.strip(), strict=False))      # ValueError for junk: the settings form reports it
    return out


def _getaddrinfo(host, port):          # a separate function so tests can replace DNS
    return socket.getaddrinfo(host, port or 0, proto=socket.IPPROTO_TCP)


def resolve(host, port=None):
    """All addresses a name resolves to (IPv4 and IPv6), as ip_address objects. Raises OSError when it does not resolve."""
    lit = literal_ip(host)
    if lit is not None:
        return [lit]
    return sorted({ipaddress.ip_address(i[4][0].split("%")[0]) for i in _getaddrinfo(host, port)}, key=str)


def judge(addresses, private_allow=None):
    """Return (ok, reason). Every address must be acceptable: one bad answer refuses the whole name (a name that sometimes resolves to
    the metadata service is a name that will)."""
    nets = parse_networks(DEFAULT_PRIVATE_ALLOW if private_allow is None else private_allow)
    for ip in addresses:
        c = classify(ip)
        if c in NEVER:
            return False, f"{ip} is a {c} address"
        if c == "private" and not any(unwrap(ip) in n for n in nets if n.version == unwrap(ip).version):
            return False, f"{ip} is a private address that is not on the allowed list"
    return True, ""


def check_host(host, port=None, private_allow=None, allow_unresolved=True):
    """Return (error or None, addresses). The one entry point for 'may we connect to this host name or address'."""
    host = (host or "").strip().lower().rstrip(".")
    if not host:
        return "no host name", []
    if host in BLOCKED_NAMES or host.endswith(".localhost"):
        return "that host name is not allowed (loopback / metadata name)", []
    try:
        addrs = resolve(host, port)
    except (OSError, UnicodeError):
        return (None, []) if allow_unresolved else ("the host name does not resolve", [])
    ok, why = judge(addrs, private_allow)
    return (None if ok else why), addrs


def check_url(url, schemes=("http", "https"), private_allow=None, allow_unresolved=True):
    """Return an error string or None for a whole URL (scheme, port, credentials in the URL, then check_host)."""
    try:
        u = urllib.parse.urlparse(url or "")
        port = u.port
    except ValueError:
        return "the address is not a valid URL"
    if u.scheme not in schemes or not u.hostname:
        return "the address must be " + " or ".join(s + "://" for s in schemes)
    if u.username or u.password:
        return "credentials inside the address are not allowed"
    if port is not None and not 1 <= port <= 65535:
        return "port out of range"
    err, _ = check_host(u.hostname, port or (443 if u.scheme == "https" else 80), private_allow, allow_unresolved)
    return err


# ------------------------------------------------------------------------------------------------------ events
def event(kind, **fields):
    """One JSON line on stdout (collected by the cluster's log pipeline and by Wazuh) plus the audit trail. Never raises."""
    rec = {"ts": round(time.time(), 3), "app": "shieldwaf", "category": "ssrf", "event": kind, **{k: str(v)[:300] for k, v in fields.items()}}
    try:
        print(json.dumps(rec, separators=(",", ":")), file=sys.stdout, flush=True)
        import store
        store.audit("system", f"ssrf-{kind}", json.dumps({k: v for k, v in rec.items() if k not in ("ts", "app", "category", "event")})[:480], fields.get("ip", ""))
    except Exception:  # noqa: BLE001 - logging must never break the caller
        pass


# ------------------------------------------------------------------------------------------------------ outbound requests
class _Hop(urllib.request.HTTPRedirectHandler):
    """Follow at most 3 redirects, and check every destination with the same rules as the first address."""
    max_redirections = 3

    def __init__(self, check):
        self._check = check

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        err = self._check(newurl)
        if err:
            raise urllib.error.URLError(f"redirect to {newurl[:80]} refused: {err}")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def safe_open(req, timeout=15, check=None, schemes=("https",), private_allow="", context=None):
    """urlopen that validates the first address AND every redirect hop. `check(url)` returns an error string or None (default: public https only)."""
    chk = check or (lambda u: check_url(u, schemes, private_allow, allow_unresolved=False))
    url = req.full_url if hasattr(req, "full_url") else str(req)
    err = chk(url)
    if err:
        raise urllib.error.URLError(f"{url[:80]} refused: {err}")
    handlers = [_Hop(chk)] + ([urllib.request.HTTPSHandler(context=context)] if context else [])
    return urllib.request.build_opener(*handlers).open(req, timeout=timeout)  # nosec B310 - validated above, and per redirect hop
