"""ShieldWAF control panel (Flask, served over HTTPS only).

Security model: first-run setup with a one-time code, salted password hash, server-side revocable sessions with idle timeout,
TOTP two-factor login with recovery codes, lockout after failed logins, optional IP allow-list for the panel, CSRF tokens on every
POST, strict CSP (no inline scripts), upstream (SSRF) validation, validated config import, audit trail with client IPs."""
import hashlib
import ipaddress
import json
import os
import re
import secrets
import threading
import time
import urllib.request
from datetime import datetime

from flask import Flask, Response, abort, flash, jsonify, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

import background
import engine
import feeds
import pages
import security
import store

VERSION = "2.1"
app = Flask(__name__)
store.init_db()

# --- secrets -----------------------------------------------------------------------------------
os.makedirs(store.DATA, exist_ok=True)
_sk = os.path.join(store.DATA, "secret.key")
if not os.path.exists(_sk):
    fd = os.open(_sk, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(secrets.token_hex(32))
app.secret_key = open(_sk).read().strip()
app.config.update(SESSION_COOKIE_NAME="__Host-shieldwaf", SESSION_COOKIE_SECURE=True, SESSION_COOKIE_HTTPONLY=True,
                  SESSION_COOKIE_SAMESITE="Strict", MAX_CONTENT_LENGTH=2 * 1024 * 1024)
ABS_SESSION = 8 * 3600
_bc = os.path.join(store.DATA, "bootstrap.code")


def bootstrap_code():
    """One-time code shown ONLY in the panel container log; needed to create the first admin account."""
    if not os.path.exists(_bc):
        fd = os.open(_bc, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(secrets.token_hex(4))
    return open(_bc).read().strip()


if not store.load()["users"]:
    print(f"[shieldwaf] FIRST RUN: open the panel (https) and create the admin account. Setup code: {bootstrap_code()}", flush=True)

# --- helpers -----------------------------------------------------------------------------------
HOST_RE = re.compile(r"^(\*\.)?[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?$")
UP_RE = re.compile(r"^https?://[a-zA-Z0-9.-]+(:\d{1,5})?$")
PATH_RE = re.compile(r"^/[A-Za-z0-9._~/\-]*$")
USER_RE = re.compile(r"^[A-Za-z0-9_.-]{3,32}$")
HASH_RE = re.compile(r"^\$6\$[./A-Za-z0-9$]{8,200}$")
ALL_METHODS = ["GET", "HEAD", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"]
_dummy_hash = generate_password_hash(secrets.token_hex(8))


def csrf():
    if "csrf" not in session:
        session["csrf"] = secrets.token_hex(16)
    return session["csrf"]


app.jinja_env.globals["csrf"] = csrf
app.jinja_env.globals["VERSION"] = VERSION
app.jinja_env.filters["ts"] = lambda t: datetime.fromtimestamp(float(t)).strftime("%Y-%m-%d %H:%M:%S")


def _nets(text):
    out = []
    for x in engine.split_lines(text):
        try:
            out.append(ipaddress.ip_network(x, strict=False))
        except ValueError:
            pass
    return out


def client_ip():
    """Client address; X-Forwarded-For is honoured only when the direct peer is a configured trusted proxy."""
    peer = request.remote_addr or ""
    xff = request.headers.get("X-Forwarded-For", "")
    if xff:
        trusted = _nets(store.load()["settings"]["trusted_proxies"])
        try:
            if any(ipaddress.ip_address(peer) in n for n in trusted):
                for hop in reversed([h.strip() for h in xff.split(",")]):
                    if not any(ipaddress.ip_address(hop) in n for n in trusted):
                        return hop
        except ValueError:
            pass
    return peer


def password_error(pw, user=""):
    if len(pw) < 12:
        return "Password must be at least 12 characters."
    if user and user.lower() in pw.lower():
        return "Password must not contain the username."
    if sum(bool(re.search(p, pw)) for p in (r"[a-z]", r"[A-Z]", r"\d", r"[^A-Za-z0-9]")) < 3:
        return "Use at least three of: lower case, upper case, digits, symbols."
    return None


# --- sessions ----------------------------------------------------------------------------------
def start_session(user):
    for k in list(session.keys()):
        session.pop(k)
    sid = secrets.token_urlsafe(32)
    now = time.time()
    store.db().execute("INSERT INTO sessions VALUES(?,?,?,?,?)", (sid, user, now, now, client_ip()))
    store.db().commit()
    session["sid"], session["user"], session["csrf"] = sid, user, secrets.token_hex(16)
    session.permanent = True


def end_session(all_for_user=None, keep=None):
    con = store.db()
    if all_for_user:
        con.execute("DELETE FROM sessions WHERE user=? AND sid!=?", (all_for_user, keep or ""))
    elif session.get("sid"):
        con.execute("DELETE FROM sessions WHERE sid=?", (session["sid"],))
    con.commit()


def session_valid():
    sid = session.get("sid")
    if not sid:
        return False
    row = store.db().execute("SELECT * FROM sessions WHERE sid=?", (sid,)).fetchone()
    now = time.time()
    idle = int(store.load()["settings"]["session_idle_min"]) * 60
    if not row or row["user"] != session.get("user") or now - row["last"] > idle or now - row["created"] > ABS_SESSION:
        if row:
            end_session()
        return False
    if now - row["last"] > 60:
        store.db().execute("UPDATE sessions SET last=? WHERE sid=?", (now, sid))
        store.db().commit()
    return True


@app.before_request
def _guard():
    ip = client_ip()
    if request.path != "/healthz":
        allow = _nets(store.load()["settings"]["panel_allow_ips"])
        if allow:
            try:
                if not any(ipaddress.ip_address(ip) in n for n in allow):
                    abort(403)
            except ValueError:
                abort(403)
    if request.method == "POST":
        if not session.get("csrf") or not secrets.compare_digest(request.form.get("_csrf", ""), session.get("csrf", "")):
            abort(400, "bad CSRF token")
    open_paths = ("/login", "/setup", "/healthz", "/metrics", "/static/")
    if not request.path.startswith(open_paths) and not session_valid():
        session.clear()
        return redirect(url_for("login"))
    if session.get("user") and not request.path.startswith(open_paths):
        u = store.load()["users"].get(me(), {})
        if (u.get("role", "admin") == "viewer"
                and (request.endpoint not in VIEWER_OK or (request.method == "POST" and request.endpoint not in POST_OK_FOR_VIEWER))):
            abort(403)
        if u.get("must_change") and request.endpoint not in ("settings", "password", "logout"):
            flash("Please choose your own password before continuing.", "err")
            return redirect(url_for("settings"))


@app.after_request
def _headers(r):
    r.headers["X-Frame-Options"] = "DENY"
    r.headers["X-Content-Type-Options"] = "nosniff"
    r.headers["Referrer-Policy"] = "no-referrer"
    if request.path.startswith("/static/"):
        r.headers["Cache-Control"] = "public, max-age=3600"        # logo, css, js: nothing sensitive
    else:
        r.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        r.headers["Pragma"] = "no-cache"
    r.headers["Cross-Origin-Embedder-Policy"] = "require-corp"
    r.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    r.headers["Cross-Origin-Opener-Policy"] = "same-origin"
    r.headers["Cross-Origin-Resource-Policy"] = "same-origin"
    r.headers["Permissions-Policy"] = "geolocation=(), camera=(), microphone=(), payment=()"
    r.headers["Content-Security-Policy"] = ("default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
                                            "connect-src 'self'; form-action 'self'; frame-src about:; frame-ancestors 'none'; base-uri 'none'")
    return r


def me():
    return session.get("user", "?")


VIEWER_OK = {"dashboard", "index", "sites", "site_edit", "pages_view", "logs", "bans", "intel", "settings", "security_view", "logout", "password", "static", "healthz"}
POST_OK_FOR_VIEWER = {"logout", "password", "security_view"}


def role():
    return store.load()["users"].get(me(), {}).get("role", "admin")


@app.context_processor
def _ctx():
    return {"is_admin": session.get("user") is not None and role() == "admin"}


def apply_cfg(cfg, action, detail=""):
    """Render+test+reload with the new config; only persist it if the engine accepts it."""
    ok, msg = engine.render(cfg)
    if ok:
        store.save(cfg)
        store.audit(me(), action, detail, client_ip())
        flash(f"{action}: {msg}", "ok")
    else:
        flash(f"NOT applied (old config kept). {msg}", "err")
    return ok


def site_by_id(cfg, sid):
    return next((s for s in cfg["sites"] if s["id"] == sid), None)


def validate_site(s, cfg):
    """Full validation of a site dict (used for form input AND imported files). Returns an error string or None."""
    if not HOST_RE.match(s["host"]):
        return "Host name looks invalid (example: app.example.com or *.example.com)."
    if not UP_RE.match(s["upstream"]):
        return "Upstream must look like http://service.namespace.svc.cluster.local:80 (no path)."
    err = security.check_upstream(s["upstream"], cfg["settings"]["upstream_allow"])
    if err:
        return err
    if any(x["host"] == s["host"] and x["id"] != s["id"] for x in cfg["sites"]):
        return "Another site already uses this host name."
    if not (1 <= int(s["paranoia"]) <= 4 and 1 <= int(s["threshold"]) <= 100 and 1 <= int(s["max_body_mb"]) <= 1024):
        return "A number is out of range (paranoia 1-4, threshold 1-100, body 1-1024 MB)."
    rl = s["rate_limit"]
    if not (1 <= int(rl["rps"]) <= 10000 and 0 <= int(rl["burst"]) <= 100000):
        return "Rate limit out of range."
    if s["mode"] not in ("block", "detect", "off"):
        return "Invalid mode."
    try:
        engine.clean_ips(s["allow_ips"])
        engine.clean_ips(s["deny_ips"])
    except ValueError as e:
        return f"Bad IP/CIDR in allow/deny list: {e}"
    for ex in s["exclusions"]:
        if not re.fullmatch(r"\d{1,7}", str(ex.get("rule", ""))) or (ex.get("path") and not PATH_RE.match(ex["path"])):
            return "Bad rule exclusion."
    if len(s["custom_rules"]) > 8000 or re.search(r"(?im)^\s*Include", s["custom_rules"]):
        return "Custom rules: max 8000 characters and no Include directive."
    if len(s["page_maint"]) > 100000 or len(s["page_down"]) > 100000:
        return "Custom page too large (max 100 KB)."
    ms = s["methods"].split()
    if not ms or any(m not in ALL_METHODS for m in ms):
        return "Allowed methods must be from: " + " ".join(ALL_METHODS)
    t = s["tls"]
    if t["source"] not in ("none", "uploaded", "selfsigned", "mounted") or not (1 <= int(t["hsts_days"]) <= 730):
        return "Invalid TLS settings."
    if t["enabled"] and t["source"] == "none":
        return "TLS is enabled: choose a certificate source (upload, self-signed or mounted)."
    if t["redirect_port"] and not re.fullmatch(r"\d{2,5}", str(t["redirect_port"])):
        return "Redirect port must be a number."
    if t["source"] == "mounted" and not re.fullmatch(r"[a-z0-9][a-z0-9.-]{0,62}", t.get("mounted_name", "")):
        return "Mounted certificate name must be lower-case letters, digits, dots or dashes."
    a = s["auth"]
    if len(a["realm"]) > 60 or any(not USER_RE.match(u) or not HASH_RE.match(h) for u, h in a["users"].items()):
        return "Invalid login-gate settings."
    c = s["challenge"]
    if not (3 <= int(c["difficulty"]) <= 6 and 1 <= int(c["ttl_hours"]) <= 720) or c["scope"] not in ("pages", "all"):
        return "Challenge: difficulty 3-6, lifetime 1-720 hours, scope pages or all."
    if any(not PATH_RE.match(p) for p in engine.split_lines(c["exclude_paths"])):
        return "Challenge exclude paths must be URL paths like /api/ ."
    ps = s["positive"]
    if any(not re.fullmatch(r"=?/[A-Za-z0-9._~/\-]*", x) for x in engine.split_lines(ps["paths"])):
        return "Allowed paths must look like /api/ (prefix) or =/ (exact)."
    if ps["enabled"] and not engine.split_lines(ps["paths"]):
        return "Positive security model: list at least one allowed path (for example =/ and /api/)."
    if not (64 <= int(ps["max_url"]) <= 8000) or any(not re.fullmatch(r"[a-z0-9.+/-]+", t.lower()) for t in engine.split_lines(ps["content_types"])):
        return "Positive model: URL length 64-8000, content types like application/json."
    g = s["geo"]
    codes = engine.split_lines(g["countries"].upper())
    if g["mode"] not in ("off", "deny", "allow") or any(not re.fullmatch(r"[A-Z]{2}", c2) for c2 in codes):
        return "Country rules: use two-letter codes such as IN US CN."
    if g["mode"] != "off" and not codes:
        return "Country rules: enter at least one country code."
    return None


def parse_site(form, cfg, existing=None):
    """Build a site dict from the form and validate it. Returns (site, error_or_None)."""
    s = json.loads(json.dumps(existing or store.DEFAULT_SITE))
    try:
        ex = []
        for ln in form.get("exclusions", "").splitlines():
            p = ln.split()
            if not p:
                continue
            if len(p) > 2:
                return s, f"Bad exclusion line '{ln}'. Use: RULEID  or  RULEID /path"
            ex.append({"rule": p[0], "path": p[1] if len(p) == 2 else ""})
        auth_users = dict(s["auth"]["users"])
        for u in form.getlist("auth_remove"):
            auth_users.pop(u, None)
        nu, npw = form.get("auth_user_new", "").strip(), form.get("auth_pass_new", "")
        if nu or npw:
            if not USER_RE.match(nu):
                return s, "Login gate user name: 3-32 letters, digits, . _ -"
            if len(npw) < 10:
                return s, "Login gate password must be at least 10 characters."
            auth_users[nu] = security.crypt_hash(npw)
        s.update({
            "host": form.get("host", "").strip().lower(), "upstream": form.get("upstream", "").strip().rstrip("/"),
            "enabled": bool(form.get("enabled")), "mode": form.get("mode", "block"), "paranoia": int(form.get("paranoia", 1)),
            "threshold": int(form.get("threshold", 5)), "maintenance": bool(form.get("maintenance")), "down_page": bool(form.get("down_page")),
            "rate_limit": {"enabled": bool(form.get("rl_enabled")), "rps": int(form.get("rl_rps", 10)), "burst": int(form.get("rl_burst", 20))},
            "allow_ips": engine.split_lines(form.get("allow_ips", "")), "deny_ips": engine.split_lines(form.get("deny_ips", "")),
            "block_bots": bool(form.get("block_bots")), "sec_headers": bool(form.get("sec_headers")),
            "max_body_mb": int(form.get("max_body_mb", 10)), "methods": " ".join(m for m in form.getlist("methods") if m in ALL_METHODS),
            "tls": {"enabled": bool(form.get("tls_enabled")), "source": form.get("tls_source", "none"),
                    "redirect_http": bool(form.get("tls_redirect")), "redirect_port": form.get("tls_redirect_port", "").strip(),
                    "hsts": bool(form.get("tls_hsts")), "hsts_days": int(form.get("tls_hsts_days", 365) or 365),
                    "mounted_name": form.get("tls_mounted_name", "").strip().lower()},
            "auth": {"enabled": bool(form.get("auth_enabled")), "realm": form.get("auth_realm", "Restricted").strip(), "users": auth_users},
            "challenge": {"enabled": bool(form.get("chal_enabled")), "difficulty": int(form.get("chal_difficulty", 4)),
                          "ttl_hours": int(form.get("chal_ttl", 12)), "scope": form.get("chal_scope", "pages"),
                          "exclude_paths": form.get("chal_exclude", "")},
            "positive": {"enabled": bool(form.get("pos_enabled")), "paths": form.get("pos_paths", ""),
                         "content_types": form.get("pos_types", ""), "max_url": int(form.get("pos_max_url", 2048) or 2048)},
            "geo": {"mode": form.get("geo_mode", "off"), "countries": " ".join(engine.split_lines(form.get("geo_countries", "").upper()))},
            "exclusions": ex, "custom_rules": form.get("custom_rules", ""),
            "page_maint": form.get("page_maint", ""), "page_down": form.get("page_down", ""),
        })
        s["allow_ips"], s["deny_ips"] = engine.clean_ips(s["allow_ips"]), engine.clean_ips(s["deny_ips"])
    except ValueError:
        return s, "A number or IP address in the form is not valid."
    return s, validate_site(s, cfg)


def handle_certs(s, form):
    """Install an uploaded certificate or generate a self-signed one when requested. Returns an error string or None."""
    t = s["tls"]
    if not t["enabled"]:
        return None
    if t["source"] == "selfsigned" and (form.get("tls_generate") or not os.path.exists(security.cert_paths(s)[0])):
        return security.make_selfsigned(s["id"], s["host"])
    if t["source"] == "uploaded" and (form.get("cert_pem", "").strip() or form.get("key_pem", "").strip()):
        return security.install_pair(s["id"], form.get("cert_pem", ""), form.get("key_pem", ""))
    if t["source"] == "uploaded" and not os.path.exists(security.cert_paths(s)[0]):
        return "Paste a certificate chain and a private key (PEM) for this site."
    return None


def engine_up():
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{engine.HTTP_PORT}/__shieldwaf_health", timeout=1) as r:  # nosec B310 - fixed loopback URL
            return r.status == 200
    except Exception:  # noqa: BLE001
        return False


# --- auth --------------------------------------------------------------------------------------
def _locked(user, ip):
    cut = time.time() - 900
    con = store.db()
    by_user = con.execute("SELECT COUNT(*) c FROM login_fail WHERE ts>? AND user=?", (cut, user)).fetchone()["c"]
    by_ip = con.execute("SELECT COUNT(*) c FROM login_fail WHERE ts>? AND ip=?", (cut, ip)).fetchone()["c"]
    return by_user >= 5 or by_ip >= 15


def _fail(user, ip, why="login-failed"):
    store.db().execute("INSERT INTO login_fail VALUES(?,?,?)", (time.time(), user[:64], ip))
    store.db().commit()
    store.audit(user[:64] or "?", why, "", ip)


@app.route("/setup", methods=["GET", "POST"])
def setup():
    cfg = store.load()
    if cfg["users"]:
        return redirect(url_for("login"))
    if request.method == "POST":
        user, pw, pw2 = request.form.get("username", "").strip(), request.form.get("password", ""), request.form.get("password2", "")
        code = request.form.get("code", "").strip()
        if not secrets.compare_digest(code, bootstrap_code()):
            flash("Wrong setup code. Read it from the panel container log.", "err")
        elif not USER_RE.match(user):
            flash("Username: 3-32 letters, digits, . _ -", "err")
        elif pw != pw2:
            flash("The two passwords differ.", "err")
        elif password_error(pw, user):
            flash(password_error(pw, user), "err")
        else:
            cfg["users"][user] = {"hash": generate_password_hash(pw), "created": time.time(), "totp_secret": "", "totp_enabled": False,
                                  "totp_last": 0, "recovery": [], "role": "admin", "must_change": False}
            store.save(cfg)
            store.audit(user, "setup", "admin account created", client_ip())
            engine.render(cfg)
            start_session(user)
            flash("Admin account created. Please enable two-factor login (menu: Security).", "ok")
            return redirect(url_for("dashboard"))
    return render_template("setup.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    cfg = store.load()
    if not cfg["users"]:
        return redirect(url_for("setup"))
    if request.method == "POST":
        ip, name = client_ip(), request.form.get("username", "").strip()
        if _locked(name, ip):
            flash("Too many failed attempts. Try again in 15 minutes.", "err")
            return render_template("login.html"), 429
        u = cfg["users"].get(name)
        ok = check_password_hash(u["hash"] if u else _dummy_hash, request.form.get("password", "")) and u is not None
        if not ok:
            _fail(name, ip)
            flash("Wrong username or password.", "err")
            return render_template("login.html"), 401
        if u.get("totp_enabled"):
            for k in list(session.keys()):
                session.pop(k)
            session["pre_user"], session["pre_ts"], session["csrf"] = name, time.time(), secrets.token_hex(16)
            return redirect(url_for("login_2fa"))
        start_session(name)
        store.audit(name, "login", "", ip)
        return redirect(url_for("dashboard"))
    return render_template("login.html")


@app.route("/login/2fa", methods=["GET", "POST"])
def login_2fa():
    name = session.get("pre_user")
    if not name or time.time() - session.get("pre_ts", 0) > 300:
        session.clear()
        return redirect(url_for("login"))
    if request.method == "POST":
        ip = client_ip()
        if _locked(name, ip):
            flash("Too many failed attempts. Try again in 15 minutes.", "err")
            return render_template("login_2fa.html"), 429
        cfg = store.load()
        u = cfg["users"].get(name)
        code = request.form.get("code", "").strip()
        step = security.totp_verify(u["totp_secret"], code, u.get("totp_last", 0)) if u else 0
        used_recovery = False
        if not step and u:
            h = hashlib.sha256(re.sub(r"[\s-]", "", code).lower().encode()).hexdigest()
            if h in u.get("recovery", []):
                u["recovery"].remove(h)
                used_recovery = True
        if step or used_recovery:
            if step:
                u["totp_last"] = step
            store.save(cfg)
            start_session(name)
            store.audit(name, "login", "2fa recovery code used" if used_recovery else "2fa", ip)
            return redirect(url_for("dashboard"))
        _fail(name, ip, "2fa-failed")
        flash("Wrong code.", "err")
    return render_template("login_2fa.html")


@app.route("/logout", methods=["POST"])
def logout():
    store.audit(me(), "logout", "", client_ip())
    end_session()
    session.clear()
    return redirect(url_for("login"))


@app.route("/healthz")
def healthz():
    return "ok\n"


# --- two-factor settings -----------------------------------------------------------------------
@app.route("/security", methods=["GET", "POST"])
def security_view():
    with store._lock:
        cfg = store.load()
        u = cfg["users"][me()]
        if request.method == "POST":
            act = request.form.get("act")
            if act == "start":
                session["totp_pending"] = security.totp_new_secret()
            elif act == "enable":
                sec = session.get("totp_pending")
                step = security.totp_verify(sec, request.form.get("code", "")) if sec else 0
                if not step:
                    flash("That code is not valid. Check the time on your phone and try again.", "err")
                else:
                    codes, hashes = security.new_recovery_codes()
                    u.update({"totp_secret": sec, "totp_enabled": True, "totp_last": step, "recovery": hashes})
                    store.save(cfg)
                    store.audit(me(), "2fa enabled", "", client_ip())
                    session.pop("totp_pending", None)
                    return render_template("recovery.html", codes=codes)
            elif act == "disable":
                step = security.totp_verify(u["totp_secret"], request.form.get("code", ""), u.get("totp_last", 0))
                if check_password_hash(u["hash"], request.form.get("password", "")) and step:
                    u.update({"totp_secret": "", "totp_enabled": False, "recovery": []})
                    store.save(cfg)
                    store.audit(me(), "2fa disabled", "", client_ip())
                    flash("Two-factor login disabled.", "ok")
                else:
                    flash("Password or code is wrong.", "err")
            return redirect(url_for("security_view"))
        pend = session.get("totp_pending")
        return render_template("security.html", enabled=u.get("totp_enabled"), pending=pend,
                               uri=security.totp_uri(me(), pend) if pend else "", left=len(u.get("recovery", [])))


# --- dashboard ---------------------------------------------------------------------------------
@app.route("/")
def index():
    return redirect(url_for("dashboard"))


@app.route("/dashboard")
def dashboard():
    cfg = store.load()
    con, now = store.db(), time.time()
    since = now - 86400
    q = lambda sql, *a: con.execute(sql, a).fetchall()  # noqa: E731
    total = q("SELECT COUNT(*) c FROM access WHERE ts>?", since)[0]["c"]
    waf = q("SELECT COUNT(*) c FROM access WHERE ts>? AND status=403", since)[0]["c"]
    rl = q("SELECT COUNT(*) c FROM access WHERE ts>? AND status=429", since)[0]["c"]
    err = q("SELECT COUNT(*) c FROM access WHERE ts>? AND status>=500", since)[0]["c"]
    hours = {int(r["h"]): (r["t"], r["b"]) for r in q(
        "SELECT CAST(ts/3600 AS INT) h, COUNT(*) t, SUM(status IN (403,429)) b FROM access WHERE ts>? GROUP BY h", since)}
    cur = int(now // 3600)
    series = [(datetime.fromtimestamp((cur - i) * 3600).strftime("%H:00"),) + tuple(hours.get(cur - i, (0, 0))) for i in range(23, -1, -1)]
    peak = max([s[1] for s in series] + [1])
    warn = []
    if not cfg["users"].get(me(), {}).get("totp_enabled"):
        warn.append("Two-factor login is not enabled for your account. Enable it under Security.")
    fd = cfg["settings"]["feeds"]
    if fd["enabled"] and not fd["last_ok"]:
        warn.append("Threat feeds are enabled but have not been downloaded yet (Threat intel page: Refresh now).")
    for s in cfg["sites"]:
        ci = security.cert_info(security.cert_paths(s)[0]) if s["tls"]["enabled"] else None
        if ci and ci["days_left"] is not None and ci["days_left"] < 30:
            warn.append(f"Certificate for {s['host']} expires in {ci['days_left']} days.")
        if s["tls"]["enabled"] is False and not s["tls"]["redirect_http"]:
            pass
    return render_template(
        "dashboard.html", cfg=cfg, total=total, waf=waf, rl=rl, err=err, series=series, peak=peak, warn=warn,
        top_rules=q("SELECT rule_id, msg, COUNT(*) c FROM events WHERE blocked=1 AND rule_id!='' AND ts>? GROUP BY rule_id ORDER BY c DESC LIMIT 8", since),
        top_ips=q("SELECT ip, COUNT(*) c FROM access WHERE ts>? AND status IN (403,429) GROUP BY ip ORDER BY c DESC LIMIT 8", since),
        recent=q("SELECT * FROM events ORDER BY ts DESC LIMIT 10"),
        under=sum(1 for s in cfg["sites"] if s["under_attack"]), maint=sum(1 for s in cfg["sites"] if s["maintenance"]), bans=sum(1 for b in cfg["bans"] if b["until"] > now), up=engine_up())


# --- sites -------------------------------------------------------------------------------------
@app.route("/sites")
def sites():
    return render_template("sites.html", cfg=store.load(), now=time.time())


def _form(s, new, cfg):
    cp = security.cert_paths(s)[0] if s["tls"]["enabled"] else None
    return render_template("site_form.html", s=s, new=new, pages=pages, cinfo=security.cert_info(cp), all_methods=ALL_METHODS)


@app.route("/sites/new", methods=["GET", "POST"])
def site_new():
    with store._lock:
        cfg = store.load()
        if request.method == "POST":
            s, err = parse_site(request.form, cfg)
            if not err:
                s["id"] = "s" + secrets.token_hex(3)
                err = handle_certs(s, request.form)
            if err:
                flash(err, "err")
                return _form(s, True, cfg)
            cfg["sites"].append(s)
            if apply_cfg(cfg, "site added", s["host"]):
                return redirect(url_for("sites"))
            return _form(s, True, cfg)
        s = json.loads(json.dumps(store.DEFAULT_SITE))
        s["upstream"] = "http://service.namespace.svc.cluster.local:80"
        s["methods"] = "GET HEAD POST PUT DELETE PATCH OPTIONS"
        return _form(s, True, cfg)


@app.route("/sites/<sid>", methods=["GET", "POST"])
def site_edit(sid):
    with store._lock:
        cfg = store.load()
        cur = site_by_id(cfg, sid) or abort(404)
        if request.method == "POST":
            s, err = parse_site(request.form, cfg, cur)
            if not err:
                err = handle_certs(s, request.form)
            if err:
                flash(err, "err")
                return _form(s, False, cfg)
            cfg["sites"] = [s if x["id"] == sid else x for x in cfg["sites"]]
            if apply_cfg(cfg, "site updated", s["host"]):
                return redirect(url_for("sites"))
            return _form(s, False, cfg)
        return _form(cur, False, cfg)


@app.route("/sites/<sid>/delete", methods=["POST"])
def site_delete(sid):
    with store._lock:
        cfg = store.load()
        s = site_by_id(cfg, sid) or abort(404)
        cfg["sites"] = [x for x in cfg["sites"] if x["id"] != sid]
        if apply_cfg(cfg, "site deleted", s["host"]):
            import shutil
            shutil.rmtree(os.path.join(security.CERT_DIR, sid), ignore_errors=True)
    return redirect(url_for("sites"))


@app.route("/sites/<sid>/maintenance", methods=["POST"])
def site_maintenance(sid):
    """One-click maintenance switch. sid='all' switches every site. Form field 'state' = on|off."""
    on = request.form.get("state") == "on"
    with store._lock:
        cfg = store.load()
        targets = cfg["sites"] if sid == "all" else [site_by_id(cfg, sid) or abort(404)]
        for s in targets:
            s["maintenance"] = on
        apply_cfg(cfg, f"maintenance {'ON' if on else 'OFF'}", ", ".join(s["host"] for s in targets))
    return redirect(url_for("sites"))


@app.route("/sites/<sid>/under-attack", methods=["POST"])
def site_under_attack(sid):
    """Emergency switch: every visitor must pass the anti-bot challenge and a rate limit applies. sid='all' for every site."""
    on = request.form.get("state") == "on"
    with store._lock:
        cfg = store.load()
        targets = cfg["sites"] if sid == "all" else [site_by_id(cfg, sid) or abort(404)]
        for s in targets:
            s["under_attack"], s["ua_until"] = on, 0
        apply_cfg(cfg, f"under-attack mode {'ON' if on else 'OFF'}", ", ".join(s["host"] for s in targets))
    return redirect(url_for("sites"))


# --- pages -------------------------------------------------------------------------------------
@app.route("/pages", methods=["GET", "POST"])
def pages_view():
    with store._lock:
        cfg = store.load()
        if request.method == "POST":
            m, d = request.form.get("maintenance", ""), request.form.get("down", "")
            if len(m) > 100000 or len(d) > 100000:
                flash("Page too large (max 100 KB).", "err")
            else:
                if request.form.get("reset") == "maintenance":
                    m = ""
                if request.form.get("reset") == "down":
                    d = ""
                cfg["pages"] = {"maintenance": m, "down": d}
                apply_cfg(cfg, "global pages saved")
                return redirect(url_for("pages_view"))
        return render_template("pages.html", cfg=cfg, dm=pages.DEFAULT_MAINTENANCE, dd=pages.DEFAULT_DOWN)


# --- threat intelligence (reputation feeds, country data) --------------------------------------
@app.route("/intel", methods=["GET", "POST"])
def intel():
    with store._lock:
        cfg = store.load()
        f = cfg["settings"]["feeds"]
        if request.method == "POST":
            act = request.form.get("act")
            if act == "settings":
                try:
                    hrs = int(request.form.get("refresh_hours", 6))
                    if not 1 <= hrs <= 168:
                        raise ValueError("range")
                except ValueError:
                    flash("Refresh interval: 1-168 hours.", "err")
                    return redirect(url_for("intel"))
                f["enabled"], f["refresh_hours"] = bool(request.form.get("enabled")), hrs
                for i, src in enumerate(f["sources"]):
                    src["on"] = bool(request.form.get(f"src_{i}"))
                apply_cfg(cfg, "threat feed settings saved")
            elif act == "add":
                name, url = request.form.get("name", "").strip()[:60], request.form.get("url", "").strip()
                err = feeds.check_url(url) if name and url else "Enter a name and an https URL."
                if err or len(f["sources"]) >= 10:
                    flash(err or "At most 10 feeds.", "err")
                else:
                    f["sources"].append({"name": name, "url": url, "on": True})
                    store.save(cfg)
                    store.audit(me(), "feed added", url[:150], client_ip())
                    flash("Feed added. Press Refresh now to download it.", "ok")
            elif act == "remove":
                try:
                    del f["sources"][int(request.form.get("idx", -1))]
                    store.save(cfg)
                    store.audit(me(), "feed removed", "", client_ip())
                except (ValueError, IndexError):
                    pass
            elif act == "refresh":
                threading.Thread(target=background.run_feed_refresh, daemon=True).start()
                flash("Refresh started; reload this page in a few seconds.", "ok")
            elif act == "geo":
                flash("Country data download started (about a minute)." if feeds.refresh_geo_async(background.geo_done) else "A download is already running.", "ok")
            return redirect(url_for("intel"))
        ip = request.args.get("ip", "").strip()
        look = None
        if ip:
            look = {"ip": ip, "feed": feeds.is_listed(ip), "country": feeds.country_of(ip)}
        return render_template("intel.html", f=f, geo=feeds.geo_status(), look=look, now=time.time())


# --- logs / bans -------------------------------------------------------------------------------
@app.route("/logs")
def logs():
    host, qtxt, only = request.args.get("host", ""), request.args.get("q", ""), request.args.get("only", "blocked")
    sql, args = "SELECT * FROM events WHERE 1=1", []
    if host:
        sql += " AND host=?"
        args.append(host)
    if qtxt:
        sql += " AND (uri LIKE ? OR msg LIKE ? OR ip LIKE ? OR rule_id LIKE ?)"
        args += [f"%{qtxt}%"] * 4
    if only == "blocked":
        sql += " AND blocked=1"
    elif only == "detected":
        sql += " AND blocked=0"
    rows = store.db().execute(sql + " ORDER BY ts DESC LIMIT 300", args).fetchall()
    return render_template("logs.html", rows=rows, cfg=store.load(), host=host, q=qtxt, only=only)


@app.route("/bans", methods=["GET", "POST"])
def bans():
    with store._lock:
        cfg = store.load()
        now = time.time()
        if request.method == "POST":
            act = request.form.get("act")
            ip = request.form.get("ip", "").strip()
            try:
                net = engine.clean_ips([ip])[0] if ip else None
            except ValueError:
                net = None
            if not net:
                flash("Enter a valid IP or CIDR.", "err")
            elif act == "add":
                try:
                    mins = max(1, min(int(request.form.get("minutes", 60) or 60), 525600))
                except ValueError:
                    mins = 60
                cfg["bans"] = [b for b in cfg["bans"] if b["ip"] != net] + [
                    {"ip": net, "until": now + mins * 60, "manual": True, "reason": request.form.get("reason", "manual")[:100]}]
                apply_cfg(cfg, "ban added", net)
            elif act == "remove":
                cfg["bans"] = [b for b in cfg["bans"] if b["ip"] != net]
                apply_cfg(cfg, "ban removed", net)
            return redirect(url_for("bans"))
        return render_template("bans.html", bans=[b for b in cfg["bans"] if b["until"] > now], now=now)


# --- settings / audit / backup -----------------------------------------------------------------
@app.route("/settings", methods=["GET", "POST"])
def settings():
    with store._lock:
        cfg = store.load()
        st = cfg["settings"]
        if request.method == "POST":
            try:
                ab = {"enabled": bool(request.form.get("ab_enabled")), "threshold": int(request.form["ab_threshold"]),
                      "window_min": int(request.form["ab_window"]), "ban_min": int(request.form["ab_ban"])}
                if not (1 <= ab["threshold"] <= 10000 and 1 <= ab["window_min"] <= 1440 and 1 <= ab["ban_min"] <= 525600):
                    raise ValueError("auto-ban values out of range")
                ret = int(request.form["retention"])
                idle = int(request.form["idle"])
                if not (1 <= ret <= 365 and 5 <= idle <= 480):
                    raise ValueError("retention 1-365 days, idle 5-480 minutes")
                tp, nb = request.form.get("trusted_proxies", ""), request.form.get("never_ban", "")
                pa, ua = request.form.get("panel_allow_ips", ""), request.form.get("upstream_allow", "")
                for v in (tp, nb, pa):
                    engine.clean_ips(engine.split_lines(v))
                if pa.strip():     # never lock the admin out: the current address must be allowed
                    if not any(ipaddress.ip_address(client_ip()) in n for n in _nets(pa)):
                        raise ValueError(f"your current address {client_ip()} would be locked out")
                for h in engine.split_lines(ua):
                    if not re.fullmatch(r"[a-z0-9][a-z0-9.-]*", h.lower()):
                        raise ValueError("allowed upstream suffixes must look like svc.cluster.local")
            except (ValueError, KeyError) as e:
                flash(f"Invalid settings: {e}", "err")
                return redirect(url_for("settings"))
            dd = {"auto": bool(request.form.get("dd_auto")), "rps_threshold": int(request.form["dd_rps"]),
                  "window_s": int(request.form["dd_window"]), "hold_min": int(request.form["dd_hold"])}
            if not (10 <= dd["rps_threshold"] <= 100000 and 5 <= dd["window_s"] <= 300 and 1 <= dd["hold_min"] <= 1440):
                raise ValueError("flood defence values out of range")
            st.update({"autoban": ab, "retention_days": ret, "trusted_proxies": tp, "never_ban": nb, "panel_allow_ips": pa,
                       "upstream_allow": ua, "session_idle_min": idle, "ddos": dd})
            apply_cfg(cfg, "settings saved")
            return redirect(url_for("settings"))
        return render_template("settings.html", st=st, users=list(cfg["users"]))


@app.route("/settings/metrics-token", methods=["POST"])
def metrics_token():
    with store._lock:
        cfg = store.load()
        cfg["settings"]["metrics_token"] = secrets.token_urlsafe(32)
        store.save(cfg)
        store.audit(me(), "metrics token regenerated", "", client_ip())
        flash("New metrics token: " + cfg["settings"]["metrics_token"] + "  (shown once; update your Prometheus scrape config)", "ok")
    return redirect(url_for("settings"))


@app.route("/password", methods=["POST"])
def password():
    with store._lock:
        cfg = store.load()
        u = cfg["users"].get(me())
        new = request.form.get("new", "")
        if not u or not check_password_hash(u["hash"], request.form.get("old", "")):
            flash("Current password is wrong.", "err")
        elif new != request.form.get("new2", ""):
            flash("The two new passwords differ.", "err")
        elif password_error(new, me()):
            flash(password_error(new, me()), "err")
        else:
            u["hash"] = generate_password_hash(new)
            u["must_change"] = False
            store.save(cfg)
            end_session(all_for_user=me(), keep=session.get("sid"))   # sign out every other session
            store.audit(me(), "password changed", "other sessions signed out", client_ip())
            flash("Password changed. All other sessions were signed out.", "ok")
    return redirect(url_for("settings"))



# --- users and roles ---------------------------------------------------------------------------
def _admins(cfg):
    return [n for n, u in cfg["users"].items() if u.get("role", "admin") == "admin"]


@app.route("/users", methods=["GET", "POST"])
def users():
    if role() != "admin":
        abort(403)
    with store._lock:
        cfg = store.load()
        if request.method == "POST":
            act, name = request.form.get("act"), request.form.get("name", "").strip()
            if act == "add":
                pw, r = request.form.get("password", ""), request.form.get("role", "viewer")
                if not USER_RE.match(name) or name in cfg["users"]:
                    flash("User name: 3-32 letters, digits, . _ - and not already used.", "err")
                elif r not in ("admin", "viewer"):
                    flash("Role must be admin or viewer.", "err")
                elif password_error(pw, name):
                    flash(password_error(pw, name), "err")
                else:
                    cfg["users"][name] = {"hash": generate_password_hash(pw), "created": time.time(), "totp_secret": "", "totp_enabled": False,
                                          "totp_last": 0, "recovery": [], "role": r, "must_change": True}
                    store.save(cfg)
                    store.audit(me(), "user added", f"{name} ({r})", client_ip())
                    flash(f"User {name} created. They must choose a new password at first login.", "ok")
            elif name in cfg["users"]:
                u = cfg["users"][name]
                if act == "delete":
                    if name == me() or (u.get("role") == "admin" and len(_admins(cfg)) <= 1):
                        flash("You cannot delete yourself or the last administrator.", "err")
                    else:
                        del cfg["users"][name]
                        store.save(cfg)
                        store.db().execute("DELETE FROM sessions WHERE user=?", (name,))
                        store.db().commit()
                        store.audit(me(), "user deleted", name, client_ip())
                        flash(f"User {name} deleted.", "ok")
                elif act == "role":
                    r = request.form.get("role", "viewer")
                    if r not in ("admin", "viewer") or (u.get("role") == "admin" and r != "admin" and len(_admins(cfg)) <= 1):
                        flash("There must always be at least one administrator.", "err")
                    else:
                        u["role"] = r
                        store.save(cfg)
                        store.audit(me(), "role changed", f"{name} -> {r}", client_ip())
                        flash(f"{name} is now {r}.", "ok")
                elif act == "reset2fa":
                    u.update({"totp_secret": "", "totp_enabled": False, "recovery": []})
                    store.save(cfg)
                    store.audit(me(), "2fa reset", name, client_ip())
                    flash(f"Two-factor login reset for {name}.", "ok")
                elif act == "signout":
                    store.db().execute("DELETE FROM sessions WHERE user=?", (name,))
                    store.db().commit()
                    store.audit(me(), "sessions revoked", name, client_ip())
                    flash(f"All sessions of {name} were signed out.", "ok")
            return redirect(url_for("users"))
        return render_template("users.html", users=cfg["users"], me=me())

@app.route("/audit")
def audit_view():
    if role() != "admin":
        abort(403)
    return render_template("audit.html", rows=store.db().execute("SELECT * FROM audit ORDER BY ts DESC LIMIT 300").fetchall())


@app.route("/backup")
def backup():
    return render_template("backup.html")


@app.route("/backup/export")
def backup_export():
    cfg = store.load()
    sites = []
    for s in cfg["sites"]:
        s = json.loads(json.dumps(s))
        s["auth"]["users"] = {}                          # gate password hashes are not exported
        sites.append(s)
    out = {"version": VERSION, "settings": {k: v for k, v in cfg["settings"].items() if k != "metrics_token"}, "sites": sites, "pages": cfg["pages"]}
    store.audit(me(), "backup exported", "", client_ip())
    return Response(json.dumps(out, indent=1), mimetype="application/json",
                    headers={"Content-Disposition": "attachment; filename=shieldwaf-config.json"})


@app.route("/backup/import", methods=["POST"])
def backup_import():
    f = request.files.get("file")
    try:
        data = json.loads(f.read().decode("utf-8"))
        if not (isinstance(data.get("sites"), list) and len(data["sites"]) <= 500):
            raise ValueError("not an export file")
    except Exception:  # noqa: BLE001
        flash("Not a valid ShieldWAF export file.", "err")
        return redirect(url_for("backup"))
    with store._lock:
        cfg = store.load()
        new_sites = []
        for raw in data["sites"]:
            s = json.loads(json.dumps(store.DEFAULT_SITE))
            for k in s:
                if k in raw and isinstance(raw[k], type(s[k])):
                    s[k] = raw[k]
            for k in ("rate_limit", "tls", "auth", "challenge", "positive", "geo"):   # nested dicts: merge onto defaults
                if isinstance(raw.get(k), dict):
                    s[k] = {**store.DEFAULT_SITE[k], **{kk: vv for kk, vv in raw[k].items() if kk in store.DEFAULT_SITE[k]}}
            s["auth"]["users"] = {}
            s["under_attack"], s["ua_until"] = False, 0
            s["id"] = "s" + secrets.token_hex(3)
            s["tls"]["enabled"] = s["tls"]["enabled"] and s["tls"]["source"] == "mounted"   # uploaded keys are never exported
            cfg_probe = {"settings": cfg["settings"], "sites": new_sites}
            err = validate_site(s, cfg_probe)
            if err:
                flash(f"Import refused ({s['host'] or '?'}): {err}", "err")
                return redirect(url_for("backup"))
            new_sites.append(s)
        cfg["sites"] = new_sites
        if isinstance(data.get("pages"), dict):
            cfg["pages"] = {"maintenance": str(data["pages"].get("maintenance", ""))[:100000], "down": str(data["pages"].get("down", ""))[:100000]}
        apply_cfg(cfg, "config imported", f"{len(new_sites)} sites")
    return redirect(url_for("sites"))


@app.route("/apply", methods=["POST"])
def apply_now():
    with store._lock:
        apply_cfg(store.load(), "re-applied")
    return redirect(url_for("sites"))


# --- metrics / api -----------------------------------------------------------------------------
@app.route("/metrics")
def metrics():
    cfg = store.load()
    tok = cfg["settings"]["metrics_token"]
    got = request.headers.get("Authorization", "")
    if not tok or not secrets.compare_digest(got, "Bearer " + tok):
        abort(401)
    con = store.db()
    lines = ["# TYPE shieldwaf_requests_total counter"]
    for r in con.execute("SELECT k,v FROM counters WHERE k LIKE 'req_%' ORDER BY k"):
        lines.append(f'shieldwaf_requests_total{{status="{r["k"][4:]}"}} {r["v"]}')
    ev = {r["k"]: r["v"] for r in con.execute("SELECT k,v FROM counters WHERE k IN ('blocked_events','detected_events')")}
    lines += ["# TYPE shieldwaf_waf_events_total counter",
              f'shieldwaf_waf_events_total{{action="blocked"}} {ev.get("blocked_events", 0)}',
              f'shieldwaf_waf_events_total{{action="detected"}} {ev.get("detected_events", 0)}',
              "# TYPE shieldwaf_sites gauge", f"shieldwaf_sites {len(cfg['sites'])}",
              "# TYPE shieldwaf_sites_in_maintenance gauge", f"shieldwaf_sites_in_maintenance {sum(1 for s in cfg['sites'] if s['maintenance'])}",
              "# TYPE shieldwaf_sites_under_attack gauge", f"shieldwaf_sites_under_attack {sum(1 for s in cfg['sites'] if s['under_attack'])}",
              "# TYPE shieldwaf_threat_feed_networks gauge", f"shieldwaf_threat_feed_networks {cfg['settings']['feeds']['last_count']}",
              "# TYPE shieldwaf_active_bans gauge", f"shieldwaf_active_bans {sum(1 for b in cfg['bans'] if b['until'] > time.time())}",
              "# TYPE shieldwaf_engine_up gauge", f"shieldwaf_engine_up {1 if engine_up() else 0}"]
    return Response("\n".join(lines) + "\n", mimetype="text/plain")


@app.route("/api/status")
def api_status():
    cfg = store.load()
    return jsonify(engine_up=engine_up(), sites=[{"host": s["host"], "mode": s["mode"], "maintenance": s["maintenance"]} for s in cfg["sites"]])


def _start():
    cfg = store.load()
    if not cfg["settings"].get("metrics_token"):
        cfg["settings"]["metrics_token"] = secrets.token_urlsafe(32)
        store.save(cfg)
    ok, msg = engine.render(cfg)
    print(f"[shieldwaf] initial render: {ok} {msg}", flush=True)
    background.start(lambda c: engine.render(c))


_start()
