"""Alerting and SIEM export.

Channels: webhook (Slack, Microsoft Teams, Discord or generic JSON), email (SMTP), syslog (RFC 5424 JSON or CEF, UDP or TCP) and an
HTTP event collector (Splunk HEC, Elastic, any JSON endpoint). Alerts are rate-limited per event (cooldown) and delivered by a
background worker with retries; every delivery is recorded. Secrets (webhook URLs that contain tokens, SMTP password, collector tokens)
live only in /data/secrets/<channel>.json (mode 0600) and are never shown again in the GUI or written to exports.
Channel targets may be private/cluster addresses (internal SIEM, internal SMTP relay) but never loopback, link-local or cloud metadata."""
import ipaddress
import json
import os
import queue
import re
import smtplib
import socket
import ssl
import threading
import time
import urllib.request
from email.message import EmailMessage
from urllib.parse import urlparse

import netguard
import sharedfs
import store

SECRET_DIR = os.path.join(store.DATA, "secrets")
SEVERITY = {"info": 0, "warning": 1, "critical": 2}
EVENTS = {   # key: (label, default severity)
    "engine_down": ("The firewall engine stopped answering", "critical"),
    "engine_recovered": ("The firewall engine is back", "info"),
    "config_failed": ("A configuration change was refused by the engine", "warning"),
    "under_attack": ("Under-attack mode switched on or off", "warning"),
    "attack_spike": ("Many blocked requests in a short time", "warning"),
    "auto_ban": ("An address was banned automatically", "info"),
    "upstream_down": ("An upstream of a site went down or came back", "warning"),
    "ssrf_blocked": ("An upstream resolved to a forbidden address (possible SSRF / DNS rebinding)", "critical"),
    "login_lockout": ("Admin login locked out after repeated failures", "warning"),
    "admin_change": ("Administrator, role, password or 2FA change", "warning"),
    "cert_expiring": ("A certificate expires soon", "warning"),
    "feeds_failed": ("Threat feed refresh failed", "info"),
    "rules_update": ("A new OWASP rule set is available or was promoted", "info"),
    "test": ("Test message", "info"),
}
_q = queue.Queue(maxsize=500)
_last = {}
_lock = threading.Lock()


# ---------------------------------------------------------------------------------------------- secrets
def _secret_path(cid):
    return os.path.join(SECRET_DIR, f"{cid}.json")


def load_secret(cid):
    try:
        with open(_secret_path(cid)) as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def save_secret(cid, data):
    os.makedirs(SECRET_DIR, mode=0o700, exist_ok=True)
    tmp = _secret_path(cid) + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(data, f)
    os.replace(tmp, _secret_path(cid))
    sharedfs.publish(f"secrets/{cid}.json")


def delete_secret(cid):
    try:
        os.remove(_secret_path(cid))
    except OSError:
        pass
    sharedfs.forget(f"secrets/{cid}.json")


# ---------------------------------------------------------------------------------------------- target safety
def check_target(host):
    """Return an error string or None. Private addresses are allowed (internal SIEM / SMTP); loopback, link-local, metadata, unspecified and reserved ones are not,
    in any spelling and also when a public name resolves to them."""
    err, _ = netguard.check_host(host, None, "0.0.0.0/0 ::/0", allow_unresolved=False)
    return None if not err else ("Target host name does not resolve." if "resolve" in err else f"Target is refused: {err}.")


def check_url(url):
    u = urlparse(url)
    if u.scheme not in ("https", "http") or not u.hostname:
        return "URL must start with https:// (or http:// for an internal collector)."
    return check_target(u.hostname)


# ---------------------------------------------------------------------------------------------- formatting
def _cef_escape(s):
    return str(s).replace("\\", "\\\\").replace("|", "\\|").replace("=", "\\=").replace("\n", " ")


def format_syslog(ch, ev):
    ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ev["ts"]))
    host = os.environ.get("HOSTNAME", "shieldwaf")
    sev = {"info": 6, "warning": 4, "critical": 2}.get(ev["severity"], 6)
    pri = 8 * 16 + sev                        # facility local0
    if ch.get("format") == "cef":
        body = (f"CEF:0|AShieldWAF|WAF|2.3|{_cef_escape(ev['event'])}|{_cef_escape(ev['title'])}|{ {'info': 3, 'warning': 6, 'critical': 9}[ev['severity']] }|"
                f"msg={_cef_escape(ev['detail'])} rt={int(ev['ts'] * 1000)}")
    else:
        body = json.dumps(ev, separators=(",", ":"))
    return f"<{pri}>1 {ts} {host} ashieldwaf - {ev['event']} - {body}"


def format_webhook(ch, ev):
    text = f"[{ev['severity'].upper()}] {ev['title']}\n{ev['detail']}" if ev["detail"] else f"[{ev['severity'].upper()}] {ev['title']}"
    kind = ch.get("kind", "generic")
    if kind == "slack":
        return {"text": text}
    if kind == "discord":
        return {"content": text[:1900]}
    if kind == "teams":
        return {"@type": "MessageCard", "@context": "https://schema.org/extensions", "summary": ev["title"], "title": ev["title"], "text": ev["detail"] or ev["title"]}
    return ev


# ---------------------------------------------------------------------------------------------- delivery
def _post_json(url, payload, headers=None, timeout=15):
    req = urllib.request.Request(url, data=json.dumps(payload).encode(), method="POST",
                                 headers={"Content-Type": "application/json", "User-Agent": "A-Shield-WAF/2.3", **(headers or {})})
    # validated again now (DNS may have changed since the channel was saved) and at every redirect hop
    with netguard.safe_open(req, timeout=timeout, schemes=("http", "https"), private_allow="0.0.0.0/0 ::/0") as r:
        r.read(2048)
        if r.status >= 300:
            raise ValueError(f"HTTP {r.status}")


def _send_email(ch, sec, ev):
    msg = EmailMessage()
    msg["Subject"] = f"[A Shield WAF][{ev['severity']}] {ev['title']}"[:200]
    msg["From"], msg["To"] = ch["from"], ", ".join(ch["to"])
    msg.set_content(f"{ev['title']}\n\n{ev['detail']}\n\nEvent: {ev['event']}\nTime: {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime(ev['ts']))}\n")
    ctx = ssl.create_default_context()
    if ch["tls"] == "ssl":
        s = smtplib.SMTP_SSL(ch["host"], int(ch["port"]), timeout=20, context=ctx)
    else:
        s = smtplib.SMTP(ch["host"], int(ch["port"]), timeout=20)
        if ch["tls"] == "starttls":
            s.starttls(context=ctx)
    try:
        if ch.get("user") and sec.get("password"):
            s.login(ch["user"], sec["password"])
        s.send_message(msg)
    finally:
        s.quit()


def _send_syslog(ch, ev):
    line = format_syslog(ch, ev).encode("utf-8", "replace")[:8000]
    if ch.get("proto") == "tcp":
        with socket.create_connection((ch["host"], int(ch["port"])), timeout=10) as s:
            s.sendall(line + b"\n")
    else:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.sendto(line, (ch["host"], int(ch["port"])))


def deliver(ch, ev):
    """Send one event through one channel. Raises on failure."""
    sec = load_secret(ch["id"])
    t = ch["type"]
    if t == "webhook":
        _post_json(sec["url"], format_webhook(ch, ev))
    elif t == "collector":
        h = {"Authorization": sec["auth"]} if sec.get("auth") else {}
        _post_json(sec["url"], ev, h)
    elif t == "email":
        _send_email(ch, sec, ev)
    elif t == "syslog":
        _send_syslog(ch, ev)
    else:
        raise ValueError("unknown channel type")


def _log(ch, ev, ok, err=""):
    con = store.db()
    con.execute("INSERT INTO alert_log VALUES(?,?,?,?,?,?)", (time.time(), ch["name"], ev["event"], ev["title"][:120], 1 if ok else 0, err[:200]))
    con.execute("DELETE FROM alert_log WHERE ts < ?", (time.time() - 14 * 86400,))
    con.commit()


def _worker():
    while True:
        ch, ev = _q.get()
        err = ""
        for attempt in range(3):
            try:
                deliver(ch, ev)
                err = ""
                break
            except Exception as e:  # noqa: BLE001
                err = f"{type(e).__name__}: {e}"
                time.sleep(2 * (attempt + 1))
        try:
            _log(ch, ev, not err, err)
        except Exception:  # noqa: BLE001
            pass


def start():
    threading.Thread(target=_worker, daemon=True, name="alert-worker").start()


def notify(event, title, detail="", severity=None, key=None, force=False):
    """Queue an alert for every enabled channel that wants this event/severity. Safe to call from anywhere; never raises."""
    try:
        cfg = store.load()["settings"]["alerts"]
        label, default_sev = EVENTS.get(event, (event, "info"))
        severity = severity or default_sev
        if not force and not cfg["events"].get(event, True):
            return
        now = time.time()
        k = key or event
        with _lock:
            if not force and now - _last.get(k, 0) < int(cfg["cooldown_s"]):
                return
            _last[k] = now
        ev = {"ts": now, "event": event, "severity": severity, "title": title, "detail": detail[:900], "source": "a-shield-waf"}
        for ch in cfg["channels"]:
            if ch.get("enabled") and SEVERITY[severity] >= SEVERITY[ch.get("min_severity", "info")]:
                try:
                    _q.put_nowait((ch, ev))
                except queue.Full:
                    pass
    except Exception:  # noqa: BLE001
        pass


def forward_events(rows):
    """SIEM export: send security events (and audit lines) to channels that asked for forwarding. rows = list of dicts."""
    try:
        chans = [c for c in store.load()["settings"]["alerts"]["channels"] if c.get("enabled") and c.get("forward") and c["type"] in ("syslog", "collector")]
        if not chans or not rows:
            return
        for r in rows[:200]:
            ev = {"ts": r["ts"], "event": r.get("kind", "waf_event"), "severity": "warning" if r.get("blocked") else "info",
                  "title": r.get("msg") or "WAF event", "source": "a-shield-waf",
                  "detail": f"{r.get('ip', '')} {r.get('host', '')} {r.get('method', '')} {r.get('uri', '')} rule={r.get('rule_id', '')} status={r.get('status', '')}"[:900]}
            for ch in chans:
                try:
                    _q.put_nowait((ch, ev))
                except queue.Full:
                    return
    except Exception:  # noqa: BLE001
        pass
