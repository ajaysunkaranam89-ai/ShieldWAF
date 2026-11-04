"""Render nginx + ModSecurity config from the ShieldWAF config, test it, hand it to the engine container, verify the reload.

Hardening baseline (all sites): TLS 1.2+ only, strict timeouts and header limits, method allow-list, unknown host names get no
reply (444), spoofable X-Forwarded-For is replaced by the real client IP, request ids, Server header removed.
Reload handshake: the panel swaps the `current` link and writes reload.request; the engine container (separate, no shared
process namespace) tests+reloads nginx and answers in reload.status; on failure the panel rolls back to the previous generation.

Reload speed: the OWASP rule set is parsed ONCE (ms-shared.conf at http level) and every site inherits it; the per-site settings (mode, paranoia,
threshold, exclusions) are chosen per request by the Host header inside that one rule set. Only sites with their own custom or OpenAPI rules get a
small dedicated file that nginx-ModSecurity merges onto the shared rules without parsing them again. While a canary rule set is being tested the
old layout (one full rule set per site) is used, because two versions of the rules cannot be merged."""
import hashlib
import ipaddress
import json
import os
import re
import shutil
import subprocess
import threading
import time

import crsupdate
import feeds
import openapi
import pages
import ratelimit
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

SHARED_RULES = os.environ.get("SHIELD_SHARED_RULES", "1") != "0"      # 0 = always use one full rule set per site (slow, for troubleshooting)
RENDER_LOCK = threading.RLock()
LAST = {}              # {"key": (config hash, shared-files version), "stats": {...}} of the last successful render
SHARED_BASE_ID = 5000000

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


def _modsec_site(site, gen, crs_dir=crsupdate.BAKED, canary=False):
    mode = {"block": "On", "detect": "DetectionOnly"}.get(site["mode"], "Off")
    if canary:
        mode = "DetectionOnly" if mode != "Off" else "Off"      # a canary rule set must never block anyone
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
    oa = site["openapi"]
    if oa["mode"] != "off" and oa["spec"].strip():
        lines.append(openapi.compile_rules(oa["spec"], oa["mode"], oa["strict"], oa["unknown_paths"], max_body_kb=oa.get("max_body_kb", 1024), max_depth=oa.get("max_depth", 10))[0])
    lines += [f"Include {crs_dir}/crs-setup.conf", f"Include {crs_dir}/rules/*.conf"]
    for ex in site["exclusions"]:
        if not ex.get("path"):
            lines.append(f"SecRuleRemoveById {ex['rule']}")
    return "\n".join(lines) + "\n"


def _dedicated(site):
    """Sites with their own custom or OpenAPI rules cannot share the rule set's per-host dispatch."""
    oa = site["openapi"]
    return bool(site["custom_rules"].strip()) or (oa["mode"] != "off" and bool(oa["spec"].strip()))


def _core(host):
    h = host.lower()
    return r"(?:[^.:/]+\.)+" + re.escape(h[2:]) if h.startswith("*.") else re.escape(h)


def _host_rx(cores):
    """Regex for a Host header (case-insensitive via t:lowercase), tolerant of a port and of a trailing dot."""
    return "^(?:" + "|".join(cores) + r")\.?(?::[0-9]+)?$"


def _more_specific(site, others):
    """Other sites whose host names nginx would pick before this wildcard site (they must not receive its settings)."""
    h = site["host"].lower()
    if not h.startswith("*."):
        return []
    suf = "." + h[2:]
    out = []
    for o in others:
        oh = o["host"].lower()
        if oh != h and (oh[2:] if oh.startswith("*.") else oh).endswith(suf):
            out.append(o)
    return out


def _scoped(uid, conds, actions):
    """A (chained) SecRule that runs `actions` when every condition holds: conds = [(variable, operator, transformations)]."""
    out = []
    for i, (var, op, tr) in enumerate(conds):
        last = i == len(conds) - 1
        acts = ([f"id:{uid}", "phase:1", "pass", "nolog"] if i == 0 else []) + [tr] + ([] if last else ["chain"]) + ([actions] if last else [])
        out.append(("  " if i else "") + f'SecRule {var} "{op}" "{",".join(acts)}"')
    return out


def _modsec_base(body_bytes):
    return [
        "SecRuleEngine On", "SecRequestBodyAccess On", f"SecRequestBodyLimit {body_bytes}", "SecRequestBodyNoFilesLimit 262144",
        "SecRequestBodyLimitAction Reject", "SecRequestBodyJsonDepthLimit 512", "SecArgumentsLimit 1000",
        "SecPcreMatchLimit 100000", "SecPcreMatchLimitRecursion 100000", "SecResponseBodyAccess Off",
        "SecTmpDir /tmp", "SecDataDir /tmp", "SecAuditEngine RelevantOnly", 'SecAuditLogRelevantStatus "^(?:5|4(?!04))"',
        "SecAuditLogParts ABIJDEFHZ", "SecAuditLogType Serial", f"SecAuditLog {LOG_DIR}/audit.json", "SecAuditLogFormat JSON",
        "SecArgumentSeparator &", "SecCookieFormat 0", f"SecUnicodeMapFile {MODSEC_DIR}/unicode.mapping 20127", "SecStatusEngine Off",
        'SecRule REQUEST_HEADERS:Content-Type "^(?:application(?:/soap\\+|/)|text/)xml" "id:200000,phase:1,t:none,t:lowercase,pass,nolog,ctl:requestBodyProcessor=XML"',
        'SecRule REQUEST_HEADERS:Content-Type "^application/json" "id:200001,phase:1,t:none,t:lowercase,pass,nolog,ctl:requestBodyProcessor=JSON"',
        'SecRule REQUEST_HEADERS:Content-Type "^application/[a-z0-9.-]+[+]json" "id:200006,phase:1,t:none,t:lowercase,pass,nolog,ctl:requestBodyProcessor=JSON"',
        'SecRule REQBODY_ERROR "!@eq 0" "id:200002,phase:2,t:none,log,deny,status:400,msg:\'Failed to parse request body.\',severity:2"',
    ]


def _modsec_shared(shared, all_sites, crs_dir):
    """The one rule set every ordinary site inherits: base settings, per-host settings, then the OWASP rules (parsed once)."""
    body = max(int(s["max_body_mb"]) for s in all_sites if s["mode"] != "off") * 1024 * 1024
    lines = _modsec_base(body)
    lines.append("# ---- per-site settings, chosen by the Host header (they must run before the OWASP rules read them) ----")
    uid = SHARED_BASE_ID
    ordered = sorted(shared, key=lambda s: (not s["host"].startswith("*."), len(s["host"])))      # wildcards first: an exact name overrides them
    for s in ordered:
        rx = _host_rx([_core(s["host"])])
        specific = _more_specific(s, shared)
        neg = _host_rx([_core(o["host"]) for o in specific]) if specific else ""
        base = [("REQUEST_HEADERS:Host", f"@rx {rx}", "t:none,t:lowercase")]
        if neg:
            base.append(("REQUEST_HEADERS:Host", f"!@rx {neg}", "t:none,t:lowercase"))
        sets = [f"setvar:tx.blocking_paranoia_level={int(s['paranoia'])}", f"setvar:tx.inbound_anomaly_score_threshold={int(s['threshold'])}",
                "setvar:tx.outbound_anomaly_score_threshold=4"]
        if s["mode"] == "detect":
            sets.append("ctl:ruleEngine=DetectionOnly")
        uid += 1
        lines += _scoped(uid, base, ",".join(sets))
        for ex in s["exclusions"]:
            uid += 1
            conds = base + ([("REQUEST_URI", f"@beginsWith {ex['path']}", "t:none")] if ex.get("path") else [])
            lines += _scoped(uid, conds, f"ctl:ruleRemoveById={ex['rule']}")
    # fail closed: a request that matches none of the sites above (for example an absolute-URI request line with a different Host header)
    # is judged with the strictest values of all sites, never with weaker defaults
    maxpl = max([int(s["paranoia"]) for s in shared] or [1])
    minthr = min([int(s["threshold"]) for s in shared] or [5])
    lines.append(f'SecRule &TX:BLOCKING_PARANOIA_LEVEL "@eq 0" "id:{SHARED_BASE_ID + 90000},phase:1,pass,nolog,t:none,setvar:tx.blocking_paranoia_level={maxpl}"')
    lines.append(f'SecRule &TX:INBOUND_ANOMALY_SCORE_THRESHOLD "@eq 0" "id:{SHARED_BASE_ID + 90001},phase:1,pass,nolog,t:none,setvar:tx.inbound_anomaly_score_threshold={minthr}"')
    lines += [f"Include {crs_dir}/crs-setup.conf", f"Include {crs_dir}/rules/*.conf"]
    return "\n".join(lines) + "\n"


def _modsec_dedicated(site):
    """Rules of one site that has its own custom/OpenAPI rules. nginx-ModSecurity merges the shared OWASP rules in after these (no second parse)."""
    mode = {"block": "On", "detect": "DetectionOnly"}.get(site["mode"], "Off")
    lines = [f"SecRuleEngine {mode}",
             f'SecAction "id:900000,phase:1,pass,nolog,t:none,setvar:tx.blocking_paranoia_level={int(site["paranoia"])}"',
             f'SecAction "id:900110,phase:1,pass,nolog,t:none,setvar:tx.inbound_anomaly_score_threshold={int(site["threshold"])},setvar:tx.outbound_anomaly_score_threshold=4"']
    uid = 100000
    for ex in site["exclusions"]:
        uid += 1
        cond = f'REQUEST_URI "@beginsWith {ex["path"]}"' if ex.get("path") else 'REQUEST_URI "@unconditionalMatch"'
        lines.append(f'SecRule {cond} "id:{uid},phase:1,pass,nolog,ctl:ruleRemoveById={ex["rule"]}"')
    if site["custom_rules"].strip():
        lines += ["# ---- custom rules (admin supplied) ----", site["custom_rules"].strip()]
    oa = site["openapi"]
    if oa["mode"] != "off" and oa["spec"].strip():
        lines.append(openapi.compile_rules(oa["spec"], oa["mode"], oa["strict"], oa["unknown_paths"], max_body_kb=oa.get("max_body_kb", 1024), max_depth=oa.get("max_depth", 10))[0])
    return "\n".join(lines) + "\n"


ACME_LOCATION = "location ^~ /.well-known/acme-challenge/ { alias " + os.path.join(DATA, "acme") + "/; default_type text/plain; modsecurity off; }"


def _pin_url(url, ip):
    u = re.match(r"^(https?)://[^/:]+(:\d+)?$", url)
    if not u:
        return None
    host = f"[{ip}]" if ip.version == 6 else str(ip)
    return f"{u.group(1)}://{host}{u.group(2) or ''}"


def _pin_sites(sites, st):
    """DNS pinning: resolve every upstream now, keep only addresses that pass the network guard, and let nginx connect to those addresses."""
    import netguard
    for s in sites:
        pinned = {}
        for url in [s["upstream"]] + [u["url"] for u in s.get("upstreams", [])]:
            m = re.match(r"^https?://([^/:]+)(?::(\d+))?$", url)
            if not m:
                continue
            err, addrs = netguard.check_host(m.group(1), int(m.group(2)) if m.group(2) else None, st.get("upstream_private_allow"))
            pinned[url] = [t for t in (_pin_url(url, netguard.unwrap(a)) for a in addrs) if t] if not err else []
        s["_pinned"] = pinned


def balancing(site):
    """Upstreams to spread requests over, in order: healthy primaries; backups only when no primary is healthy; everything if all are marked down
    (better to try than to refuse). Upstreams the SSRF check refused are never used. With DNS pinning (site["_pinned"]) every upstream is replaced by the
    addresses the panel validated. Returns [] when nothing may be used. Entries: {"url", "weight", "backup", "_orig"}."""
    base = [{"url": site["upstream"], "weight": 1, "backup": False}] + [dict(u) for u in site.get("upstreams", [])]
    bad, down, pinned = set(site.get("ssrf_blocked", [])), set(site.get("health", {}).get("down", [])), site.get("_pinned")
    ups = []
    for u in base:
        if u["url"] in bad:
            continue
        urls = [u["url"]] if pinned is None else pinned.get(u["url"], [])
        for t in urls:
            ups.append({**u, "url": t, "weight": max(1, int(u["weight"]) // max(1, len(urls))), "_orig": u["url"]})
    if not ups:
        return []
    for pool in ([x for x in ups if not x["backup"] and x["_orig"] not in down], [x for x in ups if x["backup"] and x["_orig"] not in down], ups):
        if pool:
            return pool
    return ups


def _proxy_opts(site):
    return PROXY_OPTS + (["    proxy_ssl_name $host;"] if site.get("_pinned") is not None else [])      # pinned upstream is an address: send the visitor's host name as SNI


def _lb_conf(site):
    """http-level nginx directives that pick an upstream per request (variables are resolved at request time, so an upstream that does not
    exist yet never stops nginx from starting): split_clients = weighted choice, map = 'the next upstream' used when the first one fails."""
    pool = balancing(site)
    if len(pool) < 2:
        return ""
    sid, total = site["id"], sum(int(u["weight"]) for u in pool)
    key = "${remote_addr}" if site.get("lb_method") == "ip_hash" else "${request_id}"
    rows, acc = [], 0.0
    for u in pool[:-1]:
        pct = round(100.0 * int(u["weight"]) / total, 2)
        acc += pct
        rows.append(f'    {pct:.2f}% "{u["url"]}";')
    rows.append(f'    * "{pool[-1]["url"]}";')
    nxt = [f'    "{pool[i]["url"]}" "{pool[(i + 1) % len(pool)]["url"]}";' for i in range(len(pool))]
    return (f'  split_clients "{key}" $up_{sid} {{\n' + "\n".join(rows) + "\n  }\n"
            f'  map $up_{sid} $upnext_{sid} {{\n    default "{pool[0]["url"]}";\n' + "\n".join(nxt) + "\n  }\n")


PROXY_OPTS = ["    proxy_http_version 1.1;", "    proxy_ssl_server_name on;",
              "    proxy_set_header Host $host;", "    proxy_set_header X-Real-IP $remote_addr;",
              "    proxy_set_header X-Forwarded-For $remote_addr;",          # never trust a client-supplied chain
              "    proxy_set_header X-Forwarded-Host $host;", "    proxy_set_header X-Forwarded-Proto $scheme;",
              "    proxy_set_header X-Request-ID $request_id;", '    proxy_set_header Proxy "";',
              "    proxy_set_header Upgrade $http_upgrade;", "    proxy_set_header Connection $connection_upgrade;",
              "    proxy_connect_timeout 5s;", "    proxy_read_timeout 60s;", "    proxy_send_timeout 60s;", "    proxy_hide_header X-Powered-By;"]


def _common(site, gen, feed_on, layout="legacy"):
    """Directives shared by the HTTP and HTTPS server of a site (access control, headers, WAF, maintenance / proxy)."""
    sid = site["id"]
    pdir = f"{gen}/pages/{sid}"
    L = [f"  client_max_body_size {int(site['max_body_mb'])}m;", "  limit_conn perip 300;", f"  include {gen}/bans.conf;"]
    if site["tls"]["source"] == "acme":
        L.append("  " + ACME_LOCATION)               # the certificate authority fetches its answer here (any replica can answer)
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
    elif layout == "legacy" or _dedicated(site):
        L += ["  modsecurity on;", f"  modsecurity_rules_file {gen}/ms-{sid}.conf;"]
    # layout "shared": nothing here, the server inherits the rule set loaded once at http level
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
    cluster_rl = uses_cluster_rl(site)
    pool0 = balancing(site)
    if not pool0:                                  # every upstream was refused (SSRF check): answer 502 instead of connecting anywhere
        return L + ["  location / { return 502; }"]
    lb = len(pool0) > 1
    if lb:      # several upstreams: when nginx itself cannot get an answer (refused, timed out), a read request is retried once on the next upstream
        L.append(f"  error_page 502 503 504 = @retry_{sid};")
    elif site["down_page"]:
        L.append("  error_page 502 503 504 /__shield_down.html;")
    if site["down_page"]:
        L.append(f"  location = /__shield_down.html {{ internal; root {pdir}; add_header Retry-After 30 always; add_header Cache-Control no-store always; }}")
    loc = ["  location / {"]
    if cluster_rl:
        loc += [f"    auth_request /__shield/rl_{sid};", f"    auth_request_set $shield_rl $upstream_http_x_shield_rl;", f"    error_page 403 = @rl_{sid};"]
    if ch["enabled"]:
        loc.append("    if ($chal_need = 1) { rewrite ^ /__shield/page last; }")
    if site["auth"]["enabled"] and site["auth"]["users"]:
        realm = re.sub(r'[^A-Za-z0-9 ._-]', "", site["auth"]["realm"])[:60] or "Restricted"
        loc += [f'    auth_basic "{realm}";', f"    auth_basic_user_file {gen}/htpasswd-{sid};"]
    up = f"$up_{sid}" if lb else f'"{balancing(site)[0]["url"]}"'
    loc += [f"    set $up {up};", "    proxy_pass $up;"] + _proxy_opts(site)
    if site["rate_limit"]["enabled"]:
        loc += [f"    limit_req zone=rl_{sid} burst={int(site['rate_limit']['burst'])} nodelay;", "    limit_req_status 429;"]
    loc.append("  }")
    if cluster_rl:
        loc += rl_cluster_locations(site)
    if lb:
        retry = [f"  location @retry_{sid} {{", '    if ($request_method !~ "^(GET|HEAD|OPTIONS)$") { return 502; }',      # never replay a write
                 f"    set $up $upnext_{sid};", "    proxy_pass $up;"] + _proxy_opts(site)
        # the retry location must not inherit "error_page ... = @retry" (that would loop): it shows the down page, or a plain 502 without one
        retry.append("    error_page 502 503 504 " + ("/__shield_down.html;" if site["down_page"] else "/__shield_gw;"))
        loc += retry + ["  }"]
        if not site["down_page"]:
            loc.append('  location = /__shield_gw { internal; return 502 "Bad gateway"; }')
    return L + loc


def uses_cluster_rl(site):
    """True when this site's rate limit is counted cluster-wide in Redis (needs SHIELD_REDIS_URL; without it the per-replica limit is used)."""
    rl = site["rate_limit"]
    return bool(rl["enabled"] and rl.get("scope") == "cluster" and ratelimit.configured())


def rl_cluster_locations(site):
    """The internal locations for a cluster-wide rate limit: the check against the local limiter (any failure of it means 'allowed': fail-open is decided
    inside the limiter, nginx must never answer 500 because the limiter is restarting) and the 429 answer."""
    sid, rl = site["id"], site["rate_limit"]
    return [f"  location = /__shield/rl_{sid} {{",
            "    internal; modsecurity off;",
            f"    proxy_pass http://127.0.0.1:{ratelimit.PORT}/check;",
            '    proxy_http_version 1.1; proxy_set_header Connection ""; proxy_pass_request_body off; proxy_set_header Content-Length "";',
            "    proxy_set_header X-Real-IP $remote_addr;",
            f"    proxy_set_header X-Shield-Site {sid}; proxy_set_header X-Shield-Rps {int(rl['rps'])}; proxy_set_header X-Shield-Burst {int(rl['burst'])};",
            "    proxy_connect_timeout 200ms; proxy_read_timeout 400ms; proxy_intercept_errors on;",
            f"    error_page 500 502 503 504 ={'403' if ratelimit.FAIL_CLOSED else '204'} /__shield/rl_ok_{sid};",
            "  }",
            f"  location = /__shield/rl_ok_{sid} {{ internal; return {'403' if ratelimit.FAIL_CLOSED else '204'}; }}",
            f"  location @rl_{sid} {{",
            '    if ($shield_rl = "limited") { add_header Retry-After 1 always; return 429; }',
            "    return 403;",
            "  }"]


def _server(site, gen, feed_on, layout="legacy"):
    host, t = site["host"], site["tls"]
    body = "\n".join(_common(site, gen, feed_on, layout))
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
        acme_loc = ("  " + ACME_LOCATION + "\n") if t["source"] == "acme" else ""
        redir = (f"server {{\n  listen {HTTP_PORT};\n  server_name {host};\n  include {gen}/bans.conf;\n{acme_loc}"
                 f"  location / {{ return 301 https://$host{port}$request_uri; }}\n}}\n")
    else:
        redir = ""
        https_listen.append(f"  listen {HTTP_PORT};")
    return redir + f"server {{\n" + "\n".join(https_listen) + f"\n  server_name {host};\n" + "\n".join(ssl) + f"\n{body}\n}}\n"


def render(cfg, files_ver=None):
    """Write a new generation, test it with `nginx -t`, switch `current`, wait for the engine to confirm. Returns (ok, message).
    One render at a time per replica; the result is remembered in LAST so an unchanged configuration is not applied twice."""
    with RENDER_LOCK:
        if files_ver is None:
            try:
                files_ver = store.state_version()[1]
            except Exception:  # noqa: BLE001
                files_ver = 0
        key = (hashlib.sha1(json.dumps(cfg, sort_keys=True).encode()).hexdigest(), files_ver)  # nosec B324 - change detection only
        t0 = time.time()
        ok, msg, stats = _render(cfg)
        if ok:
            stats.update(total_ms=int((time.time() - t0) * 1000), at=time.time())
            LAST.update(key=key, stats=stats)
        return ok, msg


def _render(cfg):
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
        if st.get("upstream_pin_dns"):
            _pin_sites(sites, st)
        crs_active, crs_staged = crsupdate.active_dir(cfg), crsupdate.staged_dir(cfg)
        crs_note = ""
        if not os.path.isdir(crs_active):
            # An upgrade from 2.2 (or a replica that has not received the shared copy yet): the promoted rule set lived on the old data volume.
            # Fetch the same release again (checked download from github.com, then shared with the other replicas); if that is not possible
            # keep protecting with the rule set built into the image rather than refusing to start.
            tag = cfg["settings"]["crs"]["active"]
            try:
                crsupdate.stage(tag)
            except Exception as e:  # noqa: BLE001
                crs_note = f"rule set {tag} is not available here ({type(e).__name__}); using the built-in rule set"
                print(f"[shieldwaf] {crs_note}", flush=True)
            if os.path.isdir(crs_active):
                crs_note = f"rule set {tag} was downloaded again"
            elif os.path.isdir(crsupdate.BAKED):
                crs_active = crsupdate.BAKED
            else:
                raise ValueError("the active OWASP rule set directory is missing")
        protected = [s for s in sites if s["mode"] != "off"]
        canary = crs_staged is not None and any(s["crs_channel"] == "canary" for s in protected)
        layout = "shared" if (SHARED_RULES and not canary) else "legacy"
        t_render = time.time()
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
        lb_conf = "".join(_lb_conf(s) for s in sites)
        for s in sites:
            pd = f"{gen}/pages/{s['id']}"
            os.makedirs(pd)
            m = s["page_maint"] or cfg["pages"]["maintenance"] or pages.DEFAULT_MAINTENANCE
            d = s["page_down"] or cfg["pages"]["down"] or pages.DEFAULT_DOWN
            for name, html in (("__shield_maintenance.html", m), ("__shield_down.html", d)):
                with open(f"{pd}/{name}", "w", encoding="utf-8") as f:
                    f.write(pages.fill(html, s["host"]))
            if s["mode"] != "off":
                is_canary = s["crs_channel"] == "canary" and crs_staged is not None
                if layout == "legacy":
                    with open(f"{gen}/ms-{s['id']}.conf", "w") as f:
                        f.write(_modsec_site(s, gen, crs_staged if is_canary else crs_active, is_canary))
                elif _dedicated(s):
                    with open(f"{gen}/ms-{s['id']}.conf", "w") as f:
                        f.write(_modsec_dedicated(s))
            if s["auth"]["enabled"] and s["auth"]["users"]:
                with open(f"{gen}/htpasswd-{s['id']}", "w") as f:
                    f.write("".join(f"{u}:{h}\n" for u, h in s["auth"]["users"].items()))
                os.chmod(f"{gen}/htpasswd-{s['id']}", 0o640)
            servers += _server(s, gen, feed_on, layout)
        shared_on = layout == "shared" and bool(protected)
        if shared_on:
            with open(f"{gen}/ms-shared.conf", "w") as f:
                f.write(_modsec_shared([s for s in protected if not _dedicated(s)], sites, crs_active))
        modsec_http = f"  modsecurity on;\n  modsecurity_rules_file {gen}/ms-shared.conf;\n" if shared_on else ""
        any_tls = any(s["tls"]["enabled"] and s["tls"]["source"] != "none" for s in sites)
        default_tls = (f"  server {{ listen {TLS_PORT} ssl default_server; ssl_reject_handshake on; modsecurity off; }}\n" if any_tls else "")
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
  map_hash_bucket_size 256;                  # upstream addresses are used as map keys (failover to the next upstream)
  map $http_upgrade $connection_upgrade {{ default upgrade; '' close; }}
  js_import challenge from {NJS_DIR}/challenge.js;
  js_set $chal_need challenge.need;
  limit_conn_zone $binary_remote_addr zone=perip:10m;
  limit_req_zone $binary_remote_addr zone=chal_verify:10m rate=10r/s;
  geo $shield_feed {{ default 0;{(chr(10) + "    include " + gen + "/feeds.geo;") if feed_on else ""} }}
  geo $shield_cc {{ default ""; include {gen}/countries.geo; }}
{modsec_http}{ct_maps}{real_ip}{zones}{lb_conf}
  server {{
    listen {HTTP_PORT} default_server;
    server_name _;
    access_log off;
    modsecurity off;
    location = /__shieldwaf_health {{ return 200 "ok {os.path.basename(gen)}\\n"; }}
    location / {{ return 444; }}
  }}
{default_tls}{servers}}}
"""
        with open(f"{gen}/nginx.conf", "w") as f:
            f.write(conf)
        t_test = time.time()
        r = subprocess.run(["/usr/sbin/nginx", "-t", "-c", f"{gen}/nginx.conf"], capture_output=True, text=True, timeout=max(120, 3 * len(sites)))
        if r.returncode != 0:
            shutil.rmtree(gen, ignore_errors=True)
            return False, (r.stderr or r.stdout).strip()[-1500:], {}
        wait_s = 30 if layout == "shared" else int(max(30, 5 + 1.5 * len(protected)))      # one full rule set per site is slow to load
        with open(f"{gen}/.tested", "w") as f:           # the engine does not test the same file a second time
            f.write("ok")
        with open(f"{gen}/.wait", "w") as f:
            f.write(str(wait_s))
        t_act = time.time()
        ok, msg = _activate(gen, wait_s)
        return ok, msg, {"note": crs_note, "layout": layout, "sites": len(sites), "dedicated": sum(1 for s in protected if _dedicated(s)),
                         "write_ms": int((t_test - t_render) * 1000), "test_ms": int((t_act - t_test) * 1000),
                         "reload_ms": int((time.time() - t_act) * 1000)}
    except Exception as e:  # noqa: BLE001
        shutil.rmtree(gen, ignore_errors=True)
        return False, f"render error: {e}", {}


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


def _activate(gen, wait_s=30):
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
    for _ in range(int(wait_s * 10)):                     # the engine confirms once the new generation answers
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
    return False, f"no answer from the engine within {wait_s} s; previous configuration restored"


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
