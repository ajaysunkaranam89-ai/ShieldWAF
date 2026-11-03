"""ShieldWAF control panel (Flask). Edits the config, renders nginx+ModSecurity, shows logs/dashboard, manages bans & pages."""
import ipaddress
import json
import os
import re
import secrets
import time
import urllib.request
from datetime import datetime

from flask import Flask, Response, abort, flash, jsonify, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

import background
import engine
import pages
import store

VERSION = "1.0"
app = Flask(__name__)
store.init_db()

# --- secrets -----------------------------------------------------------------------------------
os.makedirs(store.DATA, exist_ok=True)
_sk = os.path.join(store.DATA, "secret.key")
if not os.path.exists(_sk):
    with open(_sk, "w") as f:
        f.write(secrets.token_hex(32))
    os.chmod(_sk, 0o600)
app.secret_key = open(_sk).read().strip()
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax", PERMANENT_SESSION_LIFETIME=8 * 3600,
                  MAX_CONTENT_LENGTH=8 * 1024 * 1024)

_bc = os.path.join(store.DATA, "bootstrap.code")


def bootstrap_code():
    """One-time code shown ONLY in the panel container log; needed to create the first admin account."""
    if not os.path.exists(_bc):
        with open(_bc, "w") as f:
            f.write(secrets.token_hex(4))
        os.chmod(_bc, 0o600)
    return open(_bc).read().strip()


if not store.load()["users"]:
    print(f"[shieldwaf] FIRST RUN: open the panel and create the admin account. Setup code: {bootstrap_code()}", flush=True)

# --- helpers -----------------------------------------------------------------------------------
HOST_RE = re.compile(r"^(\*\.)?[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?$")
UP_RE = re.compile(r"^https?://[a-zA-Z0-9.-]+(:\d{1,5})?$")
PATH_RE = re.compile(r"^/[A-Za-z0-9._~/\-]*$")
_login_fail = {}


def csrf():
    if "csrf" not in session:
        session["csrf"] = secrets.token_hex(16)
    return session["csrf"]


app.jinja_env.globals["csrf"] = csrf
app.jinja_env.globals["VERSION"] = VERSION
app.jinja_env.filters["ts"] = lambda t: datetime.fromtimestamp(float(t)).strftime("%Y-%m-%d %H:%M:%S")


@app.before_request
def _guard():
    if request.method == "POST":
        if not session.get("csrf") or request.form.get("_csrf") != session.get("csrf"):
            abort(400, "bad CSRF token")
    open_paths = ("/login", "/setup", "/healthz", "/static/", "/metrics")
    if not request.path.startswith(open_paths) and not session.get("user"):
        return redirect(url_for("login"))


@app.after_request
def _headers(r):
    r.headers["X-Frame-Options"] = "SAMEORIGIN"
    r.headers["X-Content-Type-Options"] = "nosniff"
    r.headers["Referrer-Policy"] = "same-origin"
    r.headers["Cache-Control"] = "no-store"
    r.headers["Content-Security-Policy"] = "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; frame-src 'self' about:; img-src 'self' data:"
    return r


def me():
    return session.get("user", "?")


def apply_cfg(cfg, action, detail=""):
    """Render+test+reload with the new config; only persist it if the engine accepts it."""
    ok, msg = engine.render(cfg)
    if ok:
        store.save(cfg)
        store.audit(me(), action, detail)
        flash(f"{action}: {msg}", "ok")
    else:
        flash(f"NOT applied (old config kept). nginx said: {msg}", "err")
    return ok


def site_by_id(cfg, sid):
    return next((s for s in cfg["sites"] if s["id"] == sid), None)


def parse_site(form, cfg, existing=None):
    """Validate the site form. Returns (site_dict, error_or_None)."""
    s = json.loads(json.dumps(existing or store.DEFAULT_SITE))
    host = form.get("host", "").strip().lower()
    up = form.get("upstream", "").strip().rstrip("/")
    if not HOST_RE.match(host):
        return s, "Host name looks invalid (example: app.example.com or *.example.com)."
    if not UP_RE.match(up):
        return s, "Upstream must look like http://service.namespace.svc.cluster.local:80 (no path)."
    if any(x["host"] == host and x["id"] != s["id"] for x in cfg["sites"]):
        return s, "Another site already uses this host name."
    try:
        paranoia = int(form.get("paranoia", 1))
        threshold = int(form.get("threshold", 5))
        body = int(form.get("max_body_mb", 10))
        rps = int(form.get("rl_rps", 10))
        burst = int(form.get("rl_burst", 20))
        assert 1 <= paranoia <= 4 and 1 <= threshold <= 100 and 1 <= body <= 1024 and 1 <= rps <= 10000 and 0 <= burst <= 100000
    except (ValueError, AssertionError):
        return s, "A number is out of range (paranoia 1-4, threshold 1-100, body 1-1024 MB, rate 1-10000/s)."
    mode = form.get("mode", "block")
    if mode not in ("block", "detect", "off"):
        return s, "Invalid mode."
    try:
        allow = engine.clean_ips(engine.split_lines(form.get("allow_ips", "")))
        deny = engine.clean_ips(engine.split_lines(form.get("deny_ips", "")))
    except ValueError as e:
        return s, f"Bad IP/CIDR in allow/deny list: {e}"
    ex = []
    for ln in form.get("exclusions", "").splitlines():
        p = ln.split()
        if not p:
            continue
        if not re.fullmatch(r"\d{1,7}", p[0]) or len(p) > 2 or (len(p) == 2 and not PATH_RE.match(p[1])):
            return s, f"Bad exclusion line '{ln}'. Use: RULEID  or  RULEID /path"
        ex.append({"rule": p[0], "path": p[1] if len(p) == 2 else ""})
    custom = form.get("custom_rules", "")
    if len(custom) > 8000 or re.search(r"(?im)^\s*Include", custom):
        return s, "Custom rules: max 8000 characters and no Include directive."
    for k in ("page_maint", "page_down"):
        if len(form.get(k, "")) > 100000:
            return s, "Custom page too large (max 100 KB)."
    s.update({"host": host, "upstream": up, "enabled": bool(form.get("enabled")), "mode": mode, "paranoia": paranoia,
              "threshold": threshold, "maintenance": bool(form.get("maintenance")), "down_page": bool(form.get("down_page")),
              "rate_limit": {"enabled": bool(form.get("rl_enabled")), "rps": rps, "burst": burst},
              "allow_ips": allow, "deny_ips": deny, "block_bots": bool(form.get("block_bots")),
              "sec_headers": bool(form.get("sec_headers")), "max_body_mb": body, "exclusions": ex, "custom_rules": custom,
              "page_maint": form.get("page_maint", ""), "page_down": form.get("page_down", "")})
    return s, None


def engine_up():
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{engine.LISTEN_PORT}/__shieldwaf_health", timeout=1) as r:
            return r.status == 200
    except Exception:  # noqa: BLE001
        return False


# --- auth --------------------------------------------------------------------------------------
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
        elif not re.fullmatch(r"[A-Za-z0-9_.-]{3,32}", user):
            flash("Username: 3-32 letters, digits, . _ -", "err")
        elif len(pw) < 12 or pw != pw2:
            flash("Password must be at least 12 characters and typed twice identically.", "err")
        else:
            cfg["users"][user] = {"hash": generate_password_hash(pw), "created": time.time()}
            store.save(cfg)
            store.audit(user, "setup", "admin account created")
            ok, msg = engine.render(cfg)
            session.clear()
            session["user"] = user
            session.permanent = True
            flash("Admin account created. Welcome!", "ok")
            return redirect(url_for("dashboard"))
    return render_template("setup.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    cfg = store.load()
    if not cfg["users"]:
        return redirect(url_for("setup"))
    if request.method == "POST":
        ip = request.remote_addr
        recent = [t for t in _login_fail.get(ip, []) if t > time.time() - 600]
        if len(recent) >= 5:
            flash("Too many failed logins. Wait 10 minutes.", "err")
            return render_template("login.html"), 429
        u = cfg["users"].get(request.form.get("username", "").strip())
        if u and check_password_hash(u["hash"], request.form.get("password", "")):
            session.clear()
            session["user"] = request.form["username"].strip()
            session.permanent = True
            store.audit(session["user"], "login", ip)
            return redirect(url_for("dashboard"))
        recent.append(time.time())
        _login_fail[ip] = recent
        store.audit("?", "login-failed", ip)
        flash("Wrong username or password.", "err")
    return render_template("login.html")


@app.route("/logout", methods=["POST"])
def logout():
    store.audit(me(), "logout")
    session.clear()
    return redirect(url_for("login"))


@app.route("/healthz")
def healthz():
    return "ok\n"


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
    return render_template(
        "dashboard.html", cfg=cfg, total=total, waf=waf, rl=rl, err=err, series=series, peak=peak,
        top_rules=q("SELECT rule_id, msg, COUNT(*) c FROM events WHERE blocked=1 AND rule_id!='' AND ts>? GROUP BY rule_id ORDER BY c DESC LIMIT 8", since),
        top_ips=q("SELECT ip, COUNT(*) c FROM access WHERE ts>? AND status IN (403,429) GROUP BY ip ORDER BY c DESC LIMIT 8", since),
        recent=q("SELECT * FROM events ORDER BY ts DESC LIMIT 10"),
        maint=sum(1 for s in cfg["sites"] if s["maintenance"]), bans=sum(1 for b in cfg["bans"] if b["until"] > now),
        up=engine_up())


# --- sites -------------------------------------------------------------------------------------
@app.route("/sites")
def sites():
    return render_template("sites.html", cfg=store.load(), now=time.time())


@app.route("/sites/new", methods=["GET", "POST"])
def site_new():
    with store._lock:
        cfg = store.load()
        if request.method == "POST":
            s, err = parse_site(request.form, cfg)
            if err:
                flash(err, "err")
                return render_template("site_form.html", s=s, new=True, pages=pages)
            s["id"] = "s" + secrets.token_hex(3)
            cfg["sites"].append(s)
            if apply_cfg(cfg, "site added", s["host"]):
                return redirect(url_for("sites"))
            return render_template("site_form.html", s=s, new=True, pages=pages)
        s = json.loads(json.dumps(store.DEFAULT_SITE))
        s["upstream"] = "http://service.namespace.svc.cluster.local:80"
        return render_template("site_form.html", s=s, new=True, pages=pages)


@app.route("/sites/<sid>", methods=["GET", "POST"])
def site_edit(sid):
    with store._lock:
        cfg = store.load()
        cur = site_by_id(cfg, sid) or abort(404)
        if request.method == "POST":
            s, err = parse_site(request.form, cfg, cur)
            if err:
                flash(err, "err")
                return render_template("site_form.html", s=s, new=False, pages=pages)
            cfg["sites"] = [s if x["id"] == sid else x for x in cfg["sites"]]
            if apply_cfg(cfg, "site updated", s["host"]):
                return redirect(url_for("sites"))
            return render_template("site_form.html", s=s, new=False, pages=pages)
        return render_template("site_form.html", s=cur, new=False, pages=pages)


@app.route("/sites/<sid>/delete", methods=["POST"])
def site_delete(sid):
    with store._lock:
        cfg = store.load()
        s = site_by_id(cfg, sid) or abort(404)
        cfg["sites"] = [x for x in cfg["sites"] if x["id"] != sid]
        apply_cfg(cfg, "site deleted", s["host"])
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
    return redirect(request.referrer or url_for("sites"))


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
                mins = max(1, min(int(request.form.get("minutes", 60) or 60), 525600))
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
                assert 1 <= ab["threshold"] <= 10000 and 1 <= ab["window_min"] <= 1440 and 1 <= ab["ban_min"] <= 525600
                ret = int(request.form["retention"])
                assert 1 <= ret <= 365
                tp = request.form.get("trusted_proxies", "")
                nb = request.form.get("never_ban", "")
                engine.clean_ips(engine.split_lines(tp))
                engine.clean_ips(engine.split_lines(nb))
            except (ValueError, KeyError, AssertionError) as e:
                flash(f"Invalid settings: {e}", "err")
                return redirect(url_for("settings"))
            st.update({"autoban": ab, "retention_days": ret, "trusted_proxies": tp, "never_ban": nb})
            apply_cfg(cfg, "settings saved")
            return redirect(url_for("settings"))
        return render_template("settings.html", st=st, users=list(cfg["users"]))


@app.route("/password", methods=["POST"])
def password():
    with store._lock:
        cfg = store.load()
        u = cfg["users"].get(me())
        new = request.form.get("new", "")
        if not u or not check_password_hash(u["hash"], request.form.get("old", "")):
            flash("Current password is wrong.", "err")
        elif len(new) < 12 or new != request.form.get("new2", ""):
            flash("New password: at least 12 characters, typed twice identically.", "err")
        else:
            u["hash"] = generate_password_hash(new)
            store.save(cfg)
            store.audit(me(), "password changed")
            flash("Password changed.", "ok")
    return redirect(url_for("settings"))


@app.route("/audit")
def audit_view():
    return render_template("audit.html", rows=store.db().execute("SELECT * FROM audit ORDER BY ts DESC LIMIT 300").fetchall())


@app.route("/backup")
def backup():
    return render_template("backup.html")


@app.route("/backup/export")
def backup_export():
    cfg = store.load()
    out = {"version": VERSION, "settings": cfg["settings"], "sites": cfg["sites"], "pages": cfg["pages"]}   # no users, no bans
    store.audit(me(), "backup exported")
    return Response(json.dumps(out, indent=1), mimetype="application/json",
                    headers={"Content-Disposition": "attachment; filename=shieldwaf-config.json"})


@app.route("/backup/import", methods=["POST"])
def backup_import():
    f = request.files.get("file")
    try:
        data = json.loads(f.read().decode("utf-8"))
        assert isinstance(data.get("sites"), list)
    except Exception:  # noqa: BLE001
        flash("Not a valid ShieldWAF export file.", "err")
        return redirect(url_for("backup"))
    with store._lock:
        cfg = store.load()
        cfg["sites"], cfg["pages"] = data["sites"], data.get("pages", cfg["pages"])
        cfg["settings"].update(data.get("settings", {}))
        for s in cfg["sites"]:
            for k, v in store.DEFAULT_SITE.items():
                s.setdefault(k, json.loads(json.dumps(v)))
            s["id"] = s.get("id") or "s" + secrets.token_hex(3)
        apply_cfg(cfg, "config imported", f"{len(cfg['sites'])} sites")
    return redirect(url_for("sites"))


@app.route("/apply", methods=["POST"])
def apply_now():
    with store._lock:
        apply_cfg(store.load(), "re-applied")
    return redirect(request.referrer or url_for("dashboard"))


# --- metrics / api -----------------------------------------------------------------------------
@app.route("/metrics")
def metrics():
    cfg = store.load()
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
              "# TYPE shieldwaf_active_bans gauge", f"shieldwaf_active_bans {sum(1 for b in cfg['bans'] if b['until'] > time.time())}",
              "# TYPE shieldwaf_engine_up gauge", f"shieldwaf_engine_up {1 if engine_up() else 0}"]
    return Response("\n".join(lines) + "\n", mimetype="text/plain")


@app.route("/api/status")
def api_status():
    cfg = store.load()
    return jsonify(engine_up=engine_up(), sites=[{"host": s["host"], "mode": s["mode"], "maintenance": s["maintenance"]} for s in cfg["sites"]])


def _start():
    cfg = store.load()
    ok, msg = engine.render(cfg)
    print(f"[shieldwaf] initial render: {ok} {msg}", flush=True)
    background.start(lambda c: engine.render(c))


_start()
