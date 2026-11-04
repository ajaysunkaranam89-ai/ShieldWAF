"""CrowdSec bouncer (module I): the panel pulls the blocklist of a CrowdSec Local API (LAPI) and refuses those addresses at the engine, together with the other
threat-intelligence feeds (feeds.rebuild merges them into one list, the engine's `$shield_feed` check refuses listed addresses before any rule runs).

* Standard bouncer protocol: GET <lapi>/v1/decisions/stream?startup=true|false with the header X-Api-Key (a key made with `cscli bouncers add shieldwaf`).
  The first call returns the complete list, later calls only what is new or deleted. Only decisions of type "ban" for an address or a range are used.
* Only the leader pulls (once per 30 s), the result is shared with all replicas through the database like every other feed file.
* The key is a secret: it lives in the panel-only folder (secrets/crowdsec.json, mode 0600, copied to the other replicas encrypted), never in the exported
  configuration and never shown again in the GUI.
* The LAPI is normally inside your network, so private addresses are allowed here (same private allowlist as for upstreams); loopback, link-local and metadata
  addresses are never allowed. Public https addresses work as well.
* Safety: anything that could lock out real users is dropped (private ranges, prefixes shorter than /8 for IPv4, /19 for IPv6), the protected networks and the
  networks of the administrators (never_ban) are never listed, and a decision expires locally when its duration is over even if the LAPI is unreachable.
* Not done: reporting what the WAF blocks back to CrowdSec (signals); a CrowdSec "captcha" decision is not mapped to the challenge.
"""
import ipaddress
import json
import os
import re
import threading
import time
import urllib.error
import urllib.request

import feeds
import netguard
import sharedfs
import store

STATE = os.path.join(feeds.FEED_DIR, "crowdsec.json")
SECRET = os.path.join(store.PRIVATE, "secrets", "crowdsec.json")
_lock = threading.Lock()
MAX_DECISIONS = 100000
FULL_REFRESH_S = 3600
DUR = re.compile(r"(?:(\d+)h)?(?:(\d+)m)?(?:(\d+(?:\.\d+)?)s)?")


def duration_seconds(text):
    """'3h59m12.5s' -> seconds (CrowdSec prints Go durations). Unparsable or empty -> 4 h, the CrowdSec default for a ban."""
    m = DUR.fullmatch((text or "").strip())
    if not m or not any(m.groups()):
        return 4 * 3600
    h, mi, s = (float(g) if g else 0.0 for g in m.groups())
    return max(1, int(h * 3600 + mi * 60 + s))


def set_key(key):
    key = (key or "").strip()
    os.makedirs(os.path.dirname(SECRET), mode=0o700, exist_ok=True)
    fd = os.open(SECRET, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump({"key": key}, f)
    sharedfs.publish("secrets/crowdsec.json")


def get_key():
    try:
        with open(SECRET) as f:
            return json.load(f).get("key", "")
    except (OSError, ValueError):
        return ""


def _load():
    try:
        with open(STATE) as f:
            return json.load(f)
    except (OSError, ValueError):
        return {"decisions": {}, "full_at": 0, "last": 0}


def _save(st):
    os.makedirs(feeds.FEED_DIR, exist_ok=True)
    tmp = STATE + ".tmp"
    with open(tmp, "w") as f:
        json.dump(st, f)
    os.replace(tmp, STATE)


def entries():
    """The networks of the live (not yet expired) decisions."""
    now, out = time.time(), []
    for value, exp in _load()["decisions"].items():
        if exp > now:
            try:
                out.append(ipaddress.ip_network(value, strict=False))
            except ValueError:
                pass
    return out


def _decision_net(d):
    if (d.get("type") or "ban").lower() != "ban":
        return None
    scope = (d.get("scope") or "").lower()
    if scope not in ("ip", "range"):
        return None
    try:
        net = ipaddress.ip_network(str(d.get("value", "")).strip(), strict=False)
    except ValueError:
        return None
    return net if feeds._acceptable(net) else None


def pull(cfg, never_nets=()):
    """One call to the LAPI. Returns (ok, count, error)."""
    cs = cfg["settings"]["crowdsec"]
    url, key = (cs.get("url") or "").rstrip("/"), get_key()
    if not url or not key:
        return False, 0, "the CrowdSec address or key is not set"
    private = cfg["settings"].get("upstream_private_allow") or netguard.DEFAULT_PRIVATE_ALLOW
    with _lock:
        st = _load()
        now = time.time()
        full = now - st.get("full_at", 0) > FULL_REFRESH_S or not st["decisions"]
        try:
            req = urllib.request.Request(f"{url}/v1/decisions/stream?startup={'true' if full else 'false'}&scopes=Ip,Range",
                                         headers={"X-Api-Key": key, "User-Agent": "A-Shield-WAF/2.4 (crowdsec-bouncer)", "Accept": "application/json"})
            with netguard.safe_open(req, timeout=15, schemes=("http", "https"), private_allow=private, check=lambda u: netguard.check_url(
                    u, ("http", "https"), private, allow_unresolved=False)) as r:
                body = r.read(20 * 1024 * 1024 + 1)
            if len(body) > 20 * 1024 * 1024:
                raise ValueError("the answer is larger than the allowed size")
            data = json.loads(body.decode("utf-8", "replace") or "{}")
        except urllib.error.HTTPError as e:
            return False, len(st["decisions"]), f"the CrowdSec server answered HTTP {e.code}" + (" (wrong or revoked key?)" if e.code in (401, 403) else "")
        except Exception as e:  # noqa: BLE001 - the old list stays in place
            return False, len(st["decisions"]), f"{type(e).__name__}: {str(e)[:160]}"
        dec = {} if full else dict(st["decisions"])
        for d in data.get("new") or []:
            net = _decision_net(d)
            if net is not None and not any(net.overlaps(x) for x in never_nets):
                dec[str(net)] = now + duration_seconds(d.get("duration"))
        for d in data.get("deleted") or []:
            net = _decision_net({**d, "type": "ban"})
            if net is not None:
                dec.pop(str(net), None)
        dec = {k: v for k, v in dec.items() if v > now}
        if len(dec) > MAX_DECISIONS:
            dec = dict(sorted(dec.items(), key=lambda kv: -kv[1])[:MAX_DECISIONS])
        st.update(decisions=dec, last=now, **({"full_at": now} if full else {}))
        _save(st)
        return True, len(dec), ""
