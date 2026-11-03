"""Threat intelligence that is NOT pattern matching: IP reputation feeds and country data.

* Reputation feeds (Spamhaus DROP, FireHOL level 1, or your own https list) are downloaded, validated and turned into an nginx `geo`
  table, so an address on a list is refused before any rule runs. Private / reserved / very broad ranges are always dropped so a bad
  list can never lock out your own network, and addresses in the "never ban" list are removed.
* Country data comes from the five regional internet registries (RIPE, ARIN, APNIC, LACNIC, AFRINIC): free public allocation files,
  no account or licence key. It gives the registered country of an address block (not the physical location of a user).
Downloads use HTTPS with certificate verification, a size cap and a timeout; a failed refresh keeps the previous data."""
import ipaddress
import os
import socket
import threading
import time
import urllib.request
from urllib.parse import urlparse

import sharedfs
import store

FEED_DIR = os.path.join(store.DATA, "feeds")
GEO_DIR = os.path.join(store.DATA, "geo")
RIR_URLS = {
    "ripencc": "https://ftp.ripe.net/pub/stats/ripencc/delegated-ripencc-extended-latest",
    "arin": "https://ftp.arin.net/pub/stats/arin/delegated-arin-extended-latest",
    "apnic": "https://ftp.apnic.net/stats/apnic/delegated-apnic-extended-latest",
    "lacnic": "https://ftp.lacnic.net/pub/stats/lacnic/delegated-lacnic-extended-latest",
    "afrinic": "https://ftp.afrinic.net/pub/stats/afrinic/delegated-afrinic-extended-latest",
}
MAX_FEED_BYTES = 8 * 1024 * 1024
MAX_RIR_BYTES = 80 * 1024 * 1024
MAX_ENTRIES = 150000
_state = {"geo_running": False, "geo_error": ""}
_state_lock = threading.Lock()


# ---------------------------------------------------------------------------------------------- safe fetching
def _public_ip(ip):
    return not (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved or ip.is_unspecified)


def check_url(url):
    """Return an error string or None. https only, and the host must resolve to public addresses only (no SSRF into the cluster)."""
    u = urlparse(url)
    if u.scheme != "https" or not u.hostname:
        return "Feed URL must start with https://"
    try:
        infos = socket.getaddrinfo(u.hostname, u.port or 443, proto=socket.IPPROTO_TCP)
    except OSError:
        return "Feed host name does not resolve."
    for info in infos:
        if not _public_ip(ipaddress.ip_address(info[4][0])):
            return "Feed host resolves to a private or reserved address (refused)."
    return None


def _fetch_lines(url, cap):
    err = check_url(url)
    if err:
        raise ValueError(err)
    if not url.startswith("https://"):                      # defence in depth: check_url() already enforces this
        raise ValueError("only https:// feeds are allowed")
    req = urllib.request.Request(url, headers={"User-Agent": "A-Shield-WAF/2.1 (+threat-feed-refresh)"})
    with urllib.request.urlopen(req, timeout=40) as r:      # nosec B310 - scheme is https only, host checked to be public
        total = 0
        for raw in r:
            total += len(raw)
            if total > cap:
                raise ValueError("download larger than the allowed size")
            yield raw.decode("utf-8", "replace")


# ---------------------------------------------------------------------------------------------- reputation feeds
def _parse_feed_line(line):
    line = line.strip()
    if not line or line[0] in "#;":
        return None
    tok = line.split(";")[0].split()[0]
    try:
        return ipaddress.ip_network(tok, strict=False)
    except ValueError:
        return None


def _acceptable(net):
    """Drop anything that could hurt legitimate users: private/reserved space, and prefixes so short they cover huge parts of the internet."""
    if not _public_ip(net.network_address) or not _public_ip(net.broadcast_address):
        return False
    return net.prefixlen >= (8 if net.version == 4 else 19)


def refresh_feeds(cfg, never_nets):
    """Download all enabled sources. Returns (ok, count, error). On error the old list stays in place."""
    nets, errors = [], []
    for src in cfg["settings"]["feeds"]["sources"]:
        if not src.get("on"):
            continue
        try:
            for line in _fetch_lines(src["url"], MAX_FEED_BYTES):
                n = _parse_feed_line(line)
                if n is not None and _acceptable(n):
                    nets.append(n)
        except Exception as e:  # noqa: BLE001
            errors.append(f"{src['name']}: {e}")
    if errors and not nets:
        return False, 0, "; ".join(errors)[:300]
    v4 = [n for n in nets if n.version == 4]
    v6 = [n for n in nets if n.version == 6]
    merged = list(ipaddress.collapse_addresses(v4)) + list(ipaddress.collapse_addresses(v6))
    merged = [n for n in merged if not any(n.overlaps(x) for x in never_nets)][:MAX_ENTRIES]
    os.makedirs(FEED_DIR, exist_ok=True)
    tmp = os.path.join(FEED_DIR, ".feed.tmp")
    with open(tmp, "w") as f:
        f.write("".join(f"  {n} 1;\n" for n in merged))
    os.replace(tmp, os.path.join(FEED_DIR, "feed.geo"))
    sharedfs.publish("feeds/feed.geo")          # the other replicas pick it up
    return True, len(merged), "; ".join(errors)[:300]


def feed_file():
    p = os.path.join(FEED_DIR, "feed.geo")
    return p if os.path.exists(p) else None


def is_listed(ip_text):
    """For the GUI lookup tool: is this address on the loaded reputation list?"""
    try:
        ip = ipaddress.ip_address(ip_text.strip())
    except ValueError:
        return None
    p = feed_file()
    if not p:
        return False
    with open(p) as f:
        for line in f:
            try:
                if ip in ipaddress.ip_network(line.split()[0], strict=False):
                    return line.split()[0]
            except (ValueError, IndexError):
                continue
    return False


# ---------------------------------------------------------------------------------------------- country data (RIR files)
def geo_ready():
    return os.path.exists(os.path.join(GEO_DIR, "meta.txt"))


def geo_status():
    meta = {}
    p = os.path.join(GEO_DIR, "meta.txt")
    if os.path.exists(p):
        for line in open(p):
            if "=" in line:
                k, v = line.strip().split("=", 1)
                meta[k] = v
    with _state_lock:
        meta["running"] = _state["geo_running"]
        meta["error"] = _state["geo_error"]
    return meta


def _build_geo():
    os.makedirs(GEO_DIR, exist_ok=True)
    per_cc = {}
    for rir, url in RIR_URLS.items():
        for line in _fetch_lines(url, MAX_RIR_BYTES):
            p = line.strip().split("|")
            if len(p) < 7 or p[1] in ("*", "") or p[2] not in ("ipv4", "ipv6") or p[6] not in ("allocated", "assigned"):
                continue
            cc = p[1].upper()
            try:
                if p[2] == "ipv4":
                    start = ipaddress.IPv4Address(p[3])
                    last = ipaddress.IPv4Address(int(start) + int(p[4]) - 1)
                    nets = ipaddress.summarize_address_range(start, last)
                else:
                    nets = [ipaddress.IPv6Network(f"{p[3]}/{int(p[4])}", strict=False)]
            except (ValueError, ipaddress.AddressValueError):
                continue
            per_cc.setdefault(cc, []).extend(nets)
    if len(per_cc) < 50:
        raise ValueError("registry data looks incomplete; keeping the previous data")
    for cc, nets in per_cc.items():
        tmp = os.path.join(GEO_DIR, f".{cc}.tmp")
        with open(tmp, "w") as f:
            f.write("".join(f"{n}\n" for n in nets))
        os.replace(tmp, os.path.join(GEO_DIR, f"{cc}.cidr"))
    with open(os.path.join(GEO_DIR, "meta.txt"), "w") as f:
        f.write(f"updated={int(time.time())}\ncountries={len(per_cc)}\nblocks={sum(len(v) for v in per_cc.values())}\n")
    sharedfs.publish("geo")                       # the other replicas pick it up


def refresh_geo_async(on_done=None):
    """Download the registry files in a background thread (takes about a minute). Returns False if one is already running."""
    with _state_lock:
        if _state["geo_running"]:
            return False
        _state["geo_running"], _state["geo_error"] = True, ""

    def run():
        try:
            _build_geo()
            if on_done:
                on_done()
        except Exception as e:  # noqa: BLE001
            with _state_lock:
                _state["geo_error"] = str(e)[:300]
        finally:
            with _state_lock:
                _state["geo_running"] = False
    threading.Thread(target=run, daemon=True, name="geo-refresh").start()
    return True


def country_geo_lines(countries):
    """nginx geo lines for the given country codes (only those are loaded: keeps nginx small and reloads fast)."""
    out = []
    for cc in sorted(set(countries)):
        p = os.path.join(GEO_DIR, f"{cc}.cidr")
        if os.path.exists(p):
            out.extend(f"  {l.strip()} {cc};\n" for l in open(p) if l.strip())
    return "".join(out)


def country_of(ip_text):
    """Registered country of an address (for the GUI lookup tool), or None."""
    try:
        ip = ipaddress.ip_address(ip_text.strip())
    except ValueError:
        return None
    if not geo_ready():
        return None
    for name in os.listdir(GEO_DIR):
        if not name.endswith(".cidr"):
            continue
        for l in open(os.path.join(GEO_DIR, name)):
            try:
                if ip in ipaddress.ip_network(l.strip(), strict=False):
                    return name[:-5]
            except ValueError:
                continue
    return None
