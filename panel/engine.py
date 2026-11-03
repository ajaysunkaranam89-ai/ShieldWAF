"""Render nginx + ModSecurity config from the ShieldWAF config, test it, and hot-reload nginx (or keep the old config)."""
import ipaddress
import os
import re
import shutil
import signal
import subprocess
import time

import pages
import store

DATA = store.DATA
RENDER_DIR = os.path.join(DATA, "rendered")
LOG_DIR = os.path.join(DATA, "logs")
LISTEN_PORT = int(os.environ.get("SHIELD_PROXY_PORT", "8080"))
MODSEC_DIR = "/etc/modsecurity.d"

SCANNERS = "sqlmap|nikto|nmap|masscan|acunetix|nessus|openvas|dirbuster|gobuster|wpscan|havij|zgrab|nuclei|jaeles|whatweb|w3af|netsparker"


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


def _modsec_site(site, gen):
    mode = {"block": "On", "detect": "DetectionOnly"}.get(site["mode"], "Off")
    body = int(site["max_body_mb"]) * 1024 * 1024
    lines = [
        f"SecRuleEngine {mode}",
        "SecRequestBodyAccess On",
        f"SecRequestBodyLimit {body}",
        "SecRequestBodyNoFilesLimit 262144",
        "SecRequestBodyLimitAction Reject",
        "SecRequestBodyJsonDepthLimit 512",
        "SecArgumentsLimit 1000",
        "SecPcreMatchLimit 100000",
        "SecPcreMatchLimitRecursion 100000",
        "SecResponseBodyAccess Off",
        "SecTmpDir /tmp",
        "SecDataDir /tmp",
        "SecAuditEngine RelevantOnly",
        'SecAuditLogRelevantStatus "^(?:5|4(?!04))"',
        "SecAuditLogParts ABIJDEFHZ",
        "SecAuditLogType Serial",
        f"SecAuditLog {LOG_DIR}/audit.json",
        "SecAuditLogFormat JSON",
        "SecArgumentSeparator &",
        "SecCookieFormat 0",
        f"SecUnicodeMapFile {MODSEC_DIR}/unicode.mapping 20127",
        "SecStatusEngine Off",
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
        lines.append("# ---- custom rules (admin supplied) ----")
        lines.append(site["custom_rules"].strip())
    lines += [f"Include {MODSEC_DIR}/owasp-crs/crs-setup.conf", f"Include {MODSEC_DIR}/owasp-crs/rules/*.conf"]
    for ex in site["exclusions"]:
        if not ex.get("path"):
            lines.append(f"SecRuleRemoveById {ex['rule']}")
    return "\n".join(lines) + "\n"


def _server(site, gen, cfg):
    sid, host = site["id"], site["host"]
    pdir = f"{gen}/pages/{sid}"
    up = site["upstream"]
    L = [f"server {{", f"  listen {LISTEN_PORT};", f"  server_name {host};",
         f"  client_max_body_size {int(site['max_body_mb'])}m;"]
    # bans first, then per-site deny / allow lists
    L.append(f"  include {gen}/bans.conf;")
    for ip in clean_ips(site["deny_ips"]):
        L.append(f"  deny {ip};")
    allow = clean_ips(site["allow_ips"])
    if allow:
        L += [f"  allow {a};" for a in allow] + ["  deny all;"]
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
    if site["maintenance"]:
        L += ["  error_page 503 /__shield_maintenance.html;",
              f"  location = /__shield_maintenance.html {{ internal; root {pdir}; add_header Retry-After 1800 always; add_header Cache-Control no-store always; }}",
              "  location / { return 503; }"]
    else:
        if site["down_page"]:
            L += ["  error_page 502 503 504 /__shield_down.html;",
                  f"  location = /__shield_down.html {{ internal; root {pdir}; add_header Retry-After 30 always; add_header Cache-Control no-store always; }}"]
        loc = ["  location / {", f'    set $up "{up}";', "    proxy_pass $up;", "    proxy_http_version 1.1;",
               "    proxy_set_header Host $host;", "    proxy_set_header X-Real-IP $remote_addr;",
               "    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;", "    proxy_set_header X-Forwarded-Proto $scheme;",
               "    proxy_set_header Upgrade $http_upgrade;", "    proxy_set_header Connection $connection_upgrade;",
               "    proxy_connect_timeout 5s;", "    proxy_read_timeout 60s;", "    proxy_send_timeout 60s;",
               "    proxy_hide_header X-Powered-By;"]
        if site["rate_limit"]["enabled"]:
            loc += [f"    limit_req zone=rl_{sid} burst={int(site['rate_limit']['burst'])} nodelay;", "    limit_req_status 429;"]
        loc.append("  }")
        L += loc
    L.append("}")
    return "\n".join(L) + "\n"


def render(cfg):
    """Write a new generation, test it with `nginx -t`; on success swap `current` and HUP nginx. Returns (ok, message)."""
    os.makedirs(LOG_DIR, exist_ok=True)
    os.makedirs(RENDER_DIR, exist_ok=True)
    os.makedirs("/tmp/nx", exist_ok=True)      # nginx -t needs its temp dir to exist
    gen =os.path.join(RENDER_DIR, f"gen-{int(time.time() * 1000)}")
    os.makedirs(gen)
    try:
        st = cfg["settings"]
        now = time.time()
        bans = [b for b in cfg["bans"] if b["until"] > now]
        with open(f"{gen}/bans.conf", "w") as f:
            f.write("".join(f"deny {b['ip']};\n" for b in bans))
        real_ip = ""
        tp = clean_ips(split_lines(st["trusted_proxies"]))
        if tp:
            real_ip = "  real_ip_header X-Forwarded-For;\n  real_ip_recursive on;\n" + "".join(f"  set_real_ip_from {c};\n" for c in tp)
        zones = "".join(f"  limit_req_zone $binary_remote_addr zone=rl_{s['id']}:10m rate={int(s['rate_limit']['rps'])}r/s;\n"
                        for s in cfg["sites"] if s["enabled"] and s["rate_limit"]["enabled"])
        servers = ""
        for s in cfg["sites"]:
            if not s["enabled"]:
                continue
            pd = f"{gen}/pages/{s['id']}"
            os.makedirs(pd)
            m = s["page_maint"] or cfg["pages"]["maintenance"] or pages.DEFAULT_MAINTENANCE
            d = s["page_down"] or cfg["pages"]["down"] or pages.DEFAULT_DOWN
            with open(f"{pd}/__shield_maintenance.html", "w", encoding="utf-8") as f:
                f.write(pages.fill(m, s["host"]))
            with open(f"{pd}/__shield_down.html", "w", encoding="utf-8") as f:
                f.write(pages.fill(d, s["host"]))
            if s["mode"] != "off":
                with open(f"{gen}/ms-{s['id']}.conf", "w") as f:
                    f.write(_modsec_site(s, gen))
            servers += _server(s, gen, cfg)
        conf = f"""load_module /etc/nginx/modules/ngx_http_modsecurity_module.so;
worker_processes 2;
pid /tmp/nginx.pid;
error_log /dev/stderr warn;
events {{ worker_connections 2048; }}
http {{
  include /etc/nginx/mime.types;
  default_type application/octet-stream;
  server_tokens off;
  client_body_temp_path /tmp/nx/cb; proxy_temp_path /tmp/nx/pt; fastcgi_temp_path /tmp/nx/fc; uwsgi_temp_path /tmp/nx/uw; scgi_temp_path /tmp/nx/sc;
  log_format shield escape=json '{{"ts":$msec,"ip":"$remote_addr","host":"$host","method":"$request_method","uri":"$request_uri","status":$status,"rt":$request_time,"ua":"$http_user_agent"}}';
  access_log {LOG_DIR}/access.log shield;
  resolver {_dns_servers()} valid=10s ipv6=off;
  map $http_upgrade $connection_upgrade {{ default upgrade; '' close; }}
{real_ip}{zones}
  server {{
    listen {LISTEN_PORT} default_server;
    server_name _;
    access_log off;
    location = /__shieldwaf_health {{ return 200 "ok\\n"; }}
    location / {{ default_type text/plain; return 404 "ShieldWAF: no site is configured for this host name\\n"; }}
  }}
{servers}}}
"""
        with open(f"{gen}/nginx.conf", "w") as f:
            f.write(conf)
        r = subprocess.run(["nginx", "-t", "-c", f"{gen}/nginx.conf"], capture_output=True, text=True, timeout=120)
        if r.returncode != 0:
            shutil.rmtree(gen, ignore_errors=True)
            return False, (r.stderr or r.stdout).strip()[-1500:]
        link, tmp = os.path.join(RENDER_DIR, "current"), os.path.join(RENDER_DIR, ".current-tmp")
        if os.path.lexists(tmp):
            os.remove(tmp)
        os.symlink(gen, tmp)
        os.replace(tmp, link)
        reloaded = reload_nginx()
        _prune()
        return True, "applied and reloaded" if reloaded else "applied (engine not running yet; it will start with this config)"
    except Exception as e:  # noqa: BLE001
        shutil.rmtree(gen, ignore_errors=True)
        return False, f"render error: {e}"


def _prune(keep=5):
    gens = sorted(d for d in os.listdir(RENDER_DIR) if d.startswith("gen-"))
    cur = os.path.realpath(os.path.join(RENDER_DIR, "current"))
    for d in gens[:-keep]:
        if os.path.join(RENDER_DIR, d) != cur:
            shutil.rmtree(os.path.join(RENDER_DIR, d), ignore_errors=True)


def nginx_master_pid():
    for p in os.listdir("/proc"):
        if not p.isdigit():
            continue
        try:
            with open(f"/proc/{p}/cmdline", "rb") as f:
                cmd = f.read().replace(b"\0", b" ")
        except OSError:
            continue
        if cmd.startswith(b"nginx: master process"):
            return int(p)
    return None


def reload_nginx():
    pid = nginx_master_pid()
    if not pid:
        return False
    os.kill(pid, signal.SIGHUP)
    return True


def rotate_logs(max_mb=50):
    """Rotate big logs: rename, then HUP so nginx/ModSecurity reopen their files."""
    rotated = False
    for name in ("access.log", "audit.json"):
        p = os.path.join(LOG_DIR, name)
        if os.path.exists(p) and os.path.getsize(p) > max_mb * 1024 * 1024:
            os.replace(p, p + ".1")
            rotated = True
    if rotated:
        reload_nginx()
    return rotated
