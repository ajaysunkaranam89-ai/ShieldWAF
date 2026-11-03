"""Render nginx + ModSecurity config from the ShieldWAF config, test it, hand it to the engine container, verify the reload.

Hardening baseline (all sites): TLS 1.2+ only, strict timeouts and header limits, method allow-list, unknown host names get no
reply (444), spoofable X-Forwarded-For is replaced by the real client IP, request ids, Server header removed.
Reload handshake: the panel swaps the `current` link and writes reload.request; the engine container (separate, no shared
process namespace) tests+reloads nginx and answers in reload.status; on failure the panel rolls back to the previous generation."""
import ipaddress
import json
import os
import re
import shutil
import subprocess
import time

import feeds
import pages
import security
import store

DATA = store.DATA
RENDER_DIR = os.path.join(DATA, "rendered")
LOG_DIR = os.path.join(DATA, "logs")
HTTP_PORT = int(os.environ.get("SHIELD_PROXY_PORT", "8080"))
TLS_PORT = int(os.environ.get("SHIELD_TLS_PORT", "8443"))
LISTEN_PORT = HTTP_PORT            # kept for the health probe in app.py
MODSEC_DIR = "/etc/modsecurity.d"
NJS_DIR = "/panel/njs"

SCANNERS = "sqlmap|nikto|nmap|masscan|acunetix|nessus|openvas|dirbuster|gobuster|wpscan|havij|zgrab|nuclei|jaeles|whatweb|w3af|netsparker"
METHOD_RE = re.compile(r"^[A-Z]{3,10}$")


def _dns_servers():
    try:
        with open("/etc/resolv.conf") as f:
            ns = [ln.split()[1] for ln in f if ln.startswith("nameserver") and ":" not in ln.split()[1]]
        return " ".join(ns) or "127.0.0.11"
    except OSError:
        return "127.0.0.11"


def clean_ips(items):
    out = []
    for it in items:
        it = it.strip()
        if not it:
            continue
        out.append(str(ipaddress.ip_network(it, strict=False)) if "/" in it else str(ipaddress.ip_address(it)))
    return out


def split_lines(text):
    return [x.strip() for x in re.split(r"[\s,]+", text or "") if x.strip()]


def effective(site):
    """The configuration actually rendered: "under attack" forces the anti-bot challenge for everyone plus a rate limit."""
    s = json.loads(json.dumps(site))
    if s.get("under_attack"):
        ch = s["challenge"]
        ch.update(enabled=True, scope="all", difficulty=max(int(ch["difficulty"]), 4), ttl_hours=min(int(ch["ttl_hours"]), 6))
        if not s["rate_limit"]["enabled"]:
            s["rate_limit"].update(enabled=True, rps=20, burst=40)
    return s


def _modsec_site(site, gen):
    mode = {"block": "On", "detect": "DetectionOnly"}.get(site["mode"], "Off")
    body = int(site["max_body_mb"]) * 1024 * 1024
    lines = [
        f"SecRuleEngine {mode}", "SecRequestBodyAccess On", f"SecRequestBodyLimit {body}", "SecRequestBodyNoFilesLimit 262144",
        "SecRequestBodyLimitAction Reject", "SecRequestBodyJsonDepthLimit 512", "SecArgumentsLimit 1000",
        "SecPcreMatchLimit 100000", "SecPcreMatchLimitRecursion 100000", "SecResponseBodyAccess Off",
        "SecTmpDir /tmp", "SecDataDir /tmp", "SecAuditEngine RelevantOnly", 'SecAuditLogRelevantStatus "^(?:5|4(?!04))"',
        "SecAuditLogParts ABIJDEFHZ", "SecAuditLogType Serial", f"SecAuditLog {LOG_DIR}/audit.json", "SecAuditLogFormat JSON",
        "SecArgumentSeparator &", "SecCookieFormat 0", f"SecUnicodeMapFile {MODSEC_DIR}/unicode.mapping 20127", "SecStatusEngine Off",
        'SecRule REQUEST_HEADERS:Content-Type "^(?:application(?:/soap\\+|/)|text/)xml" "id:200000,phase:1,t:none,t:lowercase,pass,nolog,ctl:requestBodyProcessor=XML"',
        'SecRule REQUEST_HEADERS:Content-Type "^application/json" "id:200001,phase:1,t:none,t:lowercase,pass,nolog,ctl:requestBodyProcessor=JSON"',
        'SecRule REQUEST_HEADERS:Content-Type "^application/[a-z0-9.-]+[+]json" "id:200006,phase:1,t:none,t:lowercase,pass,nolog,ctl:requestBodyProcessor=JSON"',
        'SecRule REQBODY_ERROR "!@eq 0" "id:200002,phase:2,t:none,log,deny,status:400,msg:\'Failed to parse request body.\',severity:2"',
        f'SecAction "id:900000,phase:1,pass,nolog,t:none,setvar:tx.blocking_paranoia_level={int(site["paranoia"])}"',
        f'SecAction "id:900110,phase:1,pass,nolog,t:none,setvar:tx.inbound_anomaly_score_threshold={int(site["threshold"])},setvar:tx.outbound_anomaly_score_threshold=4"',
    ]
    uid = 100000
    for ex in site["exclusions"]:
        if ex.get("path"):
            uid += 1
            lines.append(f'SecRule REQUEST_URI "@beginsWith {ex["path"]}" "id:{uid},phase:1,pass,nolog,ctl:ruleRemoveById={ex["rule"]}"')
    if site["custom_rules"].strip():
        lines += ["# ---- custom rules (admin supplied) ----", site["custom_rules"].strip()]
    lines += [f"Include {MODSEC_DIR}/owasp-crs/crs-setup.conf", f"Include {MODSEC_DIR}/owasp-crs/rules/*.conf"]
    for ex in site["exclusions"]:
        if not ex.get("path"):
            lines.append(f"SecRuleRemoveById {ex['rule']}")
    return "\n".join(lines) + "\n"


def _common(site, gen, feed_on):
    """Directives shared by the HTTP and HTTPS server of a site (access control, headers, WAF, maintenance / proxy)."""
    sid = site["id"]
    pdir = f"{gen}/pages/{sid}"
    L = [f"  client_max_body_size {int(site['max_body_mb'])}m;", "  limit_conn perip 300;", f"  include {gen}/bans.conf;"]
    if feed_on:
        L.append("  if ($shield_feed) { return 403; }")                 # listed on a threat-intelligence feed
    g = site["geo"]
    cc = [c for c in split_lines(g["countries"].upper()) if re.fullmatch(r"[A-Z]{2}", c)]
    if g["mode"] == "deny" and cc:
        L.append(f'  if ($shield_cc ~ "^({"|".join(cc)})$") {{ return 403; }}')
    elif g["mode"] == "allow" and cc:
        L.append(f'  if ($shield_cc !~ "^({"|".join(cc + ["LAN"])})$") {{ return 403; }}')
    for ip in clean_ips(site["deny_ips"]):
        L.append(f"  deny {ip};")
    allow = clean_ips(site["allow_ips"])
    if allow:
        L += [f"  allow {a};" for a in allow] + ["  deny all;"]
    methods = [m for m in site["methods"].split() if METHOD_RE.match(m)] or ["GET", "HEAD", "POST"]
    L.append(f'  if ($request_method !~ "^({"|".join(methods)})$") {{ return 405; }}')
    pos = site["positive"]
    if pos["enabled"]:
        prefixes = [p for p in split_lines(pos["paths"]) if re.fullmatch(r"=?/[A-Za-z0-9._~/\-]*", p)]
        if prefixes:
            alts = [("^" + re.escape(p[1:]) + "$") if p.startswith("=") else ("^" + re.escape(p)) for p in prefixes] + ["^/__shield/"]
            L.append(f'  if ($uri !~ "{"|".join(alts)}") {{ return 403; }}')
        if 64 <= int(pos["max_url"]) <= 8000:
            L.append(f'  if ($request_uri ~ "^.{{{int(pos["max_url"]) + 1},}}") {{ return 414; }}')
        if split_lines(pos["content_types"]):
            L.append(f"  if ($shield_ct_{site['id']} = 0) {{ return 415; }}")
    if site["sec_headers"]:
        L += ['  add_header X-Frame-Options "SAMEORIGIN" always;', '  add_header X-Content-Type-Options "nosniff" always;',
              '  add_header Referrer-Policy "strict-origin-when-cross-origin" always;',
              '  add_header Permissions-Policy "geolocation=(), camera=(), microphone=()" always;']
    if site["block_bots"]:
        L.append(f'  if ($http_user_agent ~* "({SCANNERS})") {{ return 403; }}')
    if site["mode"] == "off":
        L.append("  modsecurity off;")
    else:
        L += ["  modsecurity on;", f"  modsecurity_rules_file {gen}/ms-{sid}.conf;"]
    ch = site["challenge"]
    if ch["enabled"]:
        excl = " ".join(p for p in split_lines(ch["exclude_paths"]) if re.fullmatch(r"/[A-Za-z0-9._~/\-]*", p))
        L += [f"  set $chal_diff {int(ch['difficulty'])};", f"  set $chal_ttl {int(ch['ttl_hours']) * 3600};",
              f"  set $chal_scope {'all' if ch['scope'] == 'all' else 'pages'};", f'  set $chal_excl "{excl}";',
              "  location = /__shield/page { internal; modsecurity off; js_content challenge.page; }",
              "  location = /__shield/verify { modsecurity off; limit_req zone=chal_verify burst=10 nodelay; js_content challenge.verify; }"]
    if site["maintenance"]:
        L += ["  error_page 503 /__shield_maintenance.html;",
              f"  location = /__shield_maintenance.html {{ internal; root {pdir}; add_header Retry-After 1800 always; add_header Cache-Control no-store always; }}",
              "  location / { return 503; }"]
        return L
    if site["down_page"]:
        L += ["  error_page 502 503 504 /__shield_down.html;",
              f"  location = /__shield_down.html {{ internal; root {pdir}; add_header Retry-After 30 always; add_header Cache-Control no-store always; }}"]
    loc = ["  location / {"]
    if ch["enabled"]:
        loc.append("    if ($chal_need = 1) { rewrite ^ /__shield/page last; }")
    if site["auth"]["enabled"] and site["auth"]["users"]:
        realm = re.sub(r'[^A-Za-z0-9 ._-]', "", site["auth"]["realm"])[:60] or "Restricted"
        loc += [f'    auth_basic "{realm}";', f"    auth_basic_user_file {gen}/htpasswd-{sid};"]
    loc += [f'    set $up "{site["upstream"]}";', "    proxy_pass $up;", "    proxy_http_version 1.1;", "    proxy_ssl_server_name on;",
            "    proxy_set_header Host $host;", "    proxy_set_header X-Real-IP $remote_addr;",
            "    proxy_set_header X-Forwarded-For $remote_addr;",          # never trust a client-supplied chain
            "    proxy_set_header X-Forwarded-Host $host;", "    proxy_set_header X-Forwarded-Proto $scheme;",
            "    proxy_set_header X-Request-ID $request_id;", '    proxy_set_header Proxy "";',
            "    proxy_set_header Upgrade $http_upgrade;", "    proxy_set_header Connection $connection_upgrade;",
            "    proxy_connect_timeout 5s;", "    proxy_read_timeout 60s;", "    proxy_send_timeout 60s;", "    proxy_hide_header X-Powered-By;"]
    if site["rate_limit"]["enabled"]:
        loc += [f"    limit_req zone=rl_{sid} burst={int(site['rate_limit']['burst'])} nodelay;", "    limit_req_status 429;"]
    loc.append("  }")
    return L + loc


def _server(site, gen, feed_on):
    host, t = site["host"], site["tls"]
    body = "\n".join(_common(site, gen, feed_on))
    if not (t["enabled"] and t["source"] != "none"):
        return f"server {{\n  listen {HTTP_PORT};\n  server_name {host};\n{body}\n}}\n"
    cert, key = security.cert_paths(site)
    if not cert or not os.path.exists(cert) or not os.path.exists(key):
        raise ValueError(f"TLS is enabled for {host} but its certificate is missing")
    ssl = [f"  ssl_certificate {cert};", f"  ssl_certificate_key {key};"]
    if t["hsts"]:
        ssl.append(f'  add_header Strict-Transport-Security "max-age={int(t["hsts_days"]) * 86400}; includeSubDomains" always;')
    https_listen = [f"  listen {TLS_PORT} ssl;", "  http2 on;"]
    if t["redirect_http"]:
        port = f":{t['redirect_port']}" if t["redirect_port"] and t["redirect_port"] != "443" else ""
        redir = (f"server {{\n  listen {HTTP_PORT};\n  server_name {host};\n  include {gen}/bans.conf;\n"
                 f"  location / {{ return 301 https://$host{port}$request_uri; }}\n}}\n")
    else:
        redir = ""
        https_listen.append(f"  listen {HTTP_PORT};")
    return redir + f"server {{\n" + "\n".join(https_listen) + f"\n  server_name {host};\n" + "\n".join(ssl) + f"\n{body}\n}}\n"


def render(cfg):
    """Write a new generation, test it with `nginx -t`, switch `current`, wait for the engine to confirm. Returns (ok, message)."""
    for d in (LOG_DIR, RENDER_DIR, "/tmp/nx"):      # nosec B108 - /tmp is the pod's private emptyDir, not a shared host directory
        os.makedirs(d, exist_ok=True)
    gen = os.path.join(RENDER_DIR, f"gen-{int(time.time() * 1000)}")
    os.makedirs(gen)
    try:
        st = cfg["settings"]
        now = time.time()
        with open(f"{gen}/bans.conf", "w") as f:
            f.write("".join(f"deny {b['ip']};\n" for b in cfg["bans"] if b["until"] > now))
        real_ip = ""
        tp = clean_ips(split_lines(st["trusted_proxies"]))
        if tp:
            real_ip = "  real_ip_header X-Forwarded-For;\n  real_ip_recursive on;\n" + "".join(f"  set_real_ip_from {c};\n" for c in tp)
        sites = [effective(s) for s in cfg["sites"] if s["enabled"]]
        feed_src = feeds.feed_file() if st["feeds"]["enabled"] else None
        feed_on = bool(feed_src)
        if feed_on:
            shutil.copy(feed_src, f"{gen}/feeds.geo")
        need_cc = sorted({c for s in sites if s["geo"]["mode"] != "off"
                          for c in split_lines(s["geo"]["countries"].upper()) if re.fullmatch(r"[A-Z]{2}", c)})
        if need_cc and not feeds.geo_ready():
            raise ValueError("country data has not been downloaded yet (Threat intelligence page: Update country data)")
        lan = "".join(f"  {n} LAN;\n" for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "100.64.0.0/10", "fc00::/7", "::1/128"))
        with open(f"{gen}/countries.geo", "w") as f:
            f.write(lan + feeds.country_geo_lines(need_cc))
        ct_maps = ""
        for s in sites:
            types = [t.lower() for t in split_lines(s["positive"]["content_types"]) if re.fullmatch(r"[a-z0-9.+/-]+", t.lower())]
            if s["positive"]["enabled"] and types:
                alt = "|".join(re.escape(t) for t in types)
                ct_maps += f'  map $http_content_type $shield_ct_{s["id"]} {{ default 0; "" 1; "~*^(?:{alt})(?:;|$)" 1; }}\n'
        zones = "".join(f"  limit_req_zone $binary_remote_addr zone=rl_{s['id']}:10m rate={int(s['rate_limit']['rps'])}r/s;\n"
                        for s in sites if s["rate_limit"]["enabled"])
        servers = ""
        for s in sites:
            pd = f"{gen}/pages/{s['id']}"
            os.makedirs(pd)
            m = s["page_maint"] or cfg["pages"]["maintenance"] or pages.DEFAULT_MAINTENANCE
            d = s["page_down"] or cfg["pages"]["down"] or pages.DEFAULT_DOWN
            for name, html in (("__shield_maintenance.html", m), ("__shield_down.html", d)):
                with open(f"{pd}/{name}", "w", encoding="utf-8") as f:
                    f.write(pages.fill(html, s["host"]))
            if s["mode"] != "off":
                with open(f"{gen}/ms-{s['id']}.conf", "w") as f:
                    f.write(_modsec_site(s, gen))
            if s["auth"]["enabled"] and s["auth"]["users"]:
                with open(f"{gen}/htpasswd-{s['id']}", "w") as f:
                    f.write("".join(f"{u}:{h}\n" for u, h in s["auth"]["users"].items()))
                os.chmod(f"{gen}/htpasswd-{s['id']}", 0o640)
            servers += _server(s, gen, feed_on)
        any_tls = any(s["tls"]["enabled"] and s["tls"]["source"] != "none" for s in sites)
        default_tls = (f"  server {{ listen {TLS_PORT} ssl default_server; ssl_reject_handshake on; }}\n" if any_tls else "")
        conf = f"""load_module /etc/nginx/modules/ngx_http_modsecurity_module.so;
load_module /etc/nginx/modules/ngx_http_js_module.so;
load_module /etc/nginx/modules/ngx_http_headers_more_filter_module.so;
worker_processes 2;
pid /tmp/nginx.pid;
error_log /dev/stderr warn;
events {{ worker_connections 2048; }}
http {{
  include /etc/nginx/mime.types;
  default_type application/octet-stream;
  server_tokens off;
  more_clear_headers Server;
  client_body_temp_path /tmp/nx/cb; proxy_temp_path /tmp/nx/pt; fastcgi_temp_path /tmp/nx/fc; uwsgi_temp_path /tmp/nx/uw; scgi_temp_path /tmp/nx/sc;
  client_header_timeout 10s; client_body_timeout 15s; send_timeout 15s; keepalive_timeout 30s; keepalive_requests 200;
  reset_timedout_connection on;
  client_header_buffer_size 2k; large_client_header_buffers 4 8k;
  ssl_protocols TLSv1.2 TLSv1.3;
  ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305;
  ssl_prefer_server_ciphers off; ssl_session_tickets off; ssl_session_cache shared:SSL:10m; ssl_session_timeout 1h;
  log_format shield escape=json '{{"ts":$msec,"ip":"$remote_addr","host":"$host","method":"$request_method","uri":"$request_uri","status":$status,"rt":$request_time,"ua":"$http_user_agent"}}';
  access_log {LOG_DIR}/access.log shield;
  resolver {_dns_servers()} valid=10s ipv6=off;
  map $http_upgrade $connection_upgrade {{ default upgrade; '' close; }}
  js_import challenge from {NJS_DIR}/challenge.js;
  js_set $chal_need challenge.need;
  limit_conn_zone $binary_remote_addr zone=perip:10m;
  limit_req_zone $binary_remote_addr zone=chal_verify:10m rate=10r/s;
  geo $shield_feed {{ default 0;{(chr(10) + "    include " + gen + "/feeds.geo;") if feed_on else ""} }}
  geo $shield_cc {{ default ""; include {gen}/countries.geo; }}
{ct_maps}{real_ip}{zones}
  server {{
    listen {HTTP_PORT} default_server;
    server_name _;
    access_log off;
    location = /__shieldwaf_health {{ return 200 "ok {os.path.basename(gen)}\\n"; }}
    location / {{ return 444; }}
  }}
{default_tls}{servers}}}
"""
        with open(f"{gen}/nginx.conf", "w") as f:
            f.write(conf)
        r = subprocess.run(["/usr/sbin/nginx", "-t", "-c", f"{gen}/nginx.conf"], capture_output=True, text=True, timeout=120)
        if r.returncode != 0:
            shutil.rmtree(gen, ignore_errors=True)
            return False, (r.stderr or r.stdout).strip()[-1500:]
        return _activate(gen)
    except Exception as e:  # noqa: BLE001
        shutil.rmtree(gen, ignore_errors=True)
        return False, f"render error: {e}"


def _swap(target):
    link, tmp = os.path.join(RENDER_DIR, "current"), os.path.join(RENDER_DIR, ".current-tmp")
    if os.path.lexists(tmp):
        os.remove(tmp)
    os.symlink(target, tmp)
    os.replace(tmp, link)


def engine_alive():
    try:
        return time.time() - os.path.getmtime(os.path.join(RENDER_DIR, "engine.alive")) < 5
    except OSError:
        return False


def _activate(gen):
    link = os.path.join(RENDER_DIR, "current")
    prev = os.path.realpath(link) if os.path.islink(link) else None
    status = os.path.join(RENDER_DIR, "reload.status")
    if os.path.exists(status):
        os.remove(status)
    _swap(gen)
    if not engine_alive():
        _prune()
        return True, "applied (the engine is not running yet; it will start with this config)"
    request_reload()
    for _ in range(300):                                  # up to 30 s: every site loads the whole rule set on reload
        time.sleep(0.1)
        try:
            with open(status) as f:
                g, res = f.read().strip().split("|")[:2]
        except (OSError, ValueError):
            continue
        if g == gen:
            if res == "ok":
                _prune()
                return True, "applied and reloaded"
            if prev:
                _swap(prev)
            return False, "the engine refused the new configuration (it keeps running the previous one)"
    if prev:
        _swap(prev)
    return False, "no answer from the engine within 30 s; previous configuration restored"


def request_reload():
    with open(os.path.join(RENDER_DIR, "reload.request"), "w") as f:
        f.write(str(time.time()))


def reload_nginx():
    request_reload()
    return True


def _prune(keep=5):
    gens = sorted(d for d in os.listdir(RENDER_DIR) if d.startswith("gen-"))
    cur = os.path.realpath(os.path.join(RENDER_DIR, "current"))
    for d in gens[:-keep]:
        if os.path.join(RENDER_DIR, d) != cur:
            shutil.rmtree(os.path.join(RENDER_DIR, d), ignore_errors=True)


def rotate_logs(max_mb=50):
    """Rotate big logs: rename, then ask the engine to reload so nginx/ModSecurity reopen their files."""
    rotated = False
    for name in ("access.log", "audit.json"):
        p = os.path.join(LOG_DIR, name)
        if os.path.exists(p) and os.path.getsize(p) > max_mb * 1024 * 1024:
            os.replace(p, p + ".1")
            rotated = True
    if rotated:
        request_reload()
    return rotated
