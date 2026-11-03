# User guide

Everything is done in the web panel (https://localhost:9000 through `kubectl port-forward`, see `INSTALL.md`). Menu names below match the panel.

## Daily routine (5 minutes)
1. **Dashboard:** warnings at the top (two-factor off, certificate expiring, rule update staged), blocked requests, top rules and addresses.
2. **Attack log:** what was blocked or detected, and by which OWASP rule.
3. **Alerts:** make sure a channel is configured so nobody has to watch the dashboard.

## Sites (the heart of the product)
A *site* maps a host name to an application inside the cluster. **Sites, + Add site**, or **Edit** an existing one.

| Setting | What it does | Advice |
|---|---|---|
| Host name / Upstream | the name users type, and the in-cluster address of the application | the upstream must not be loopback or a cloud-metadata address |
| WAF mode | **block** refuses attacks, **detect only** logs them, **off** disables the rules | new application: detect first, tune, then block |
| Paranoia level 1-4 | higher = stricter = more false positives | stay at 1 until you have tuned |
| Rule exclusions | switch off one OWASP rule, everywhere or for one path (`942100` or `942100 /api/upload`) | use the rule id from the Attack log |
| Allowed methods | other methods get HTTP 405 | tick only what the application uses |
| Rate limit | requests per second per address, then HTTP 429 | protects logins and APIs |
| Allow-list / Deny-list | addresses that may / may never connect | an allow-list blocks everyone else |

### Maintenance mode (planned updates)
**Sites**, press **Turn on** in the *Maintenance* column (or **Maintenance ON (all)**). Visitors see a maintenance page (HTTP 503); your
application keeps running so you can update it. Edit the page under **Pages**. Press **Turn off** when done. Takes effect within seconds.

### Service-down page
If the application stops, visitors see a friendly page that reloads itself every 10 seconds and sends them back when it is up again. No setup needed; edit it under **Pages**.

### HTTPS (TLS)
In the site's **TLS / HTTPS** section tick *Serve this site over HTTPS* and choose where the certificate comes from:
- **upload certificate + key:** paste a PEM chain and a PEM private key (not password protected). The key is never shown again.
- **self-signed:** for testing only (browsers will warn).
- **mounted secret:** a certificate that cert-manager keeps renewed (see `CLOUD.md`). Recommended in production.
HSTS and an HTTP to HTTPS redirect are options. TLS 1.2 and 1.3 only.

### Anti-bot challenge
Tick *Require the challenge*. Browsers solve a small puzzle once (a second or less) and receive a signed pass; scripts that cannot run JavaScript are stopped.
*Applies to* **browser page loads** keeps APIs untouched; **every request** is strict (list API paths under *Paths that never get the challenge*).

### Login gate
Tick *Require login* and add users (10+ character passwords). Visitors must sign in before reaching the site. Use it over HTTPS.

### Positive security model
Instead of looking for bad patterns, list what is allowed: paths (`=/` exact home page, `/api/` everything under it), request content types, and the longest URL.
Everything else is refused. **Test it first** on a copy of the site; a path you forgot returns 403.

### OpenAPI validation
Paste your API description (OpenAPI 3, JSON, up to 1 MB) and choose **detect** or **enforce**. Requests with unknown paths, methods, query parameters or
JSON fields, missing required fields, wrong types, bad enum values, out-of-range numbers or over-long strings are refused. After saving, expand
*What is enforced* to see exactly what was understood. Not enforced: `oneOf / anyOf / allOf`, formats, patterns. Convert YAML to JSON first.

### Country rules
First press **Update country data** on **Threat intel**. Then in the site choose *block these countries* or *allow only these countries* and list two-letter codes (`CN RU`, `IN US`).
It uses the *registered* country of an address block, not a user's physical location.

## Threat intel
- **IP reputation feeds:** known botnet / hijacked networks are refused before any rule runs. Refreshed automatically; add your own https list; look up any address.
- Private networks and your "never ban" addresses are never blocked by a list.

## Under attack
If a site is flooded press **Under attack ON** (or enable the automatic mode in **Settings, Flood defence**): everyone must pass the challenge and a rate limit applies.
This stops application-layer floods. It cannot stop network-level floods: see [`DDOS.md`](DDOS.md).

## IP bans and auto-ban
**IP bans** lists manual and automatic bans. **Settings, Automatic banning**: an address blocked too often is banned for a while. Put your own admin address under *Never ban*.

## Alerts and SIEM export
**Alerts, Add a channel:** Slack / Teams / Discord / generic webhook, email (SMTP), syslog (JSON or CEF), or an HTTP collector (Splunk HEC, Elastic). Press **Test** on each.
Tick *Also send every blocked / detected request* on syslog or collector channels to feed your SIEM. Choose which events alert, and how often the same alert may repeat.
Webhook addresses, SMTP passwords and tokens are secrets: stored in protected files and never shown again.

## OWASP rule updates
**Rule updates** shows the active, staged and latest versions. **Download and stage the latest** (or let it stage automatically): sites on the *canary* channel
(Site settings, WAF section) run the new rules in detect-only mode, so you can compare. When satisfied tick the confirmation and **Promote to all sites**; **Roll back** returns to the previous set.
Updates are never switched on without an administrator.

## Users, roles and two-factor login
- **Users:** add administrators (full control) and **viewers** (read-only dashboard, sites, attack log). New users must choose their own password at first login.
- **Security (2FA):** scan or type the key into any authenticator app, confirm a code, **save the 8 recovery codes** (shown once).
- **Settings, Admin panel access:** restrict which addresses may open the panel at all.

## Monitoring
Prometheus can scrape `https://shieldwaf-panel.shieldwaf.svc:9000/metrics` with the header `Authorization: Bearer <token>` (create the token under **Settings, Metrics token**).
Useful alerts: `shieldwaf_engine_up == 0`, a jump in `shieldwaf_requests_total{status="403"}`, `shieldwaf_sites_under_attack > 0`.

## If you are locked out
Anyone with `kubectl exec` rights on the cluster can recover (they already control the pod):
```bash
kubectl exec -n shieldwaf deploy/shieldwaf -c panel -- python3 /panel/tools.py reset-panel-allow     # clears the panel address allow-list
kubectl exec -n shieldwaf deploy/shieldwaf -c panel -- python3 /panel/tools.py reset-2fa <user>       # turns off 2FA for a user
echo "NewStrongPassword123!" | kubectl exec -i -n shieldwaf deploy/shieldwaf -c panel -- python3 /panel/tools.py set-password <user>
```
