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

### Several upstreams (load balancing and failover)
In the site form, **Basics**, add more backends under *More upstreams*, one per line: an address and an optional weight (1-100), or the word `backup` for a backend that is used only when all the others are down.
```
http://app-2.my-namespace.svc.cluster.local:80 3
http://spare.my-namespace.svc.cluster.local:80 backup
```
- **Balancing:** *spread requests* picks a backend for every request, in proportion to the weights. *Keep each visitor on the same upstream* picks by the visitor's address, so a visitor stays on one backend (useful for apps that keep session data in memory).
- **Failover without any setting:** if nginx cannot reach the backend it chose (refused or timed out), a read request (GET, HEAD, OPTIONS) is retried once on the next backend. **Writes (POST, PUT, ...) are never replayed**, so a request is not executed twice; they get the usual "service is down" answer instead.
- **Health checks (recommended):** tick *Check all upstreams every 10 seconds*. The leader replica asks every backend for the health path (default `/`); two failed checks in a row (an answer of 500 or higher, or no answer) take it out of rotation, two good ones put it back. The site list and the site page show which are out; an alert is sent (event "An upstream of a site went down or came back"). If every backend is marked down they are all tried anyway (better than refusing). Checks run from the leader replica's point of view.
- Backend addresses are looked up again for every request, so a replaced Kubernetes service is found without a reload. All the usual checks apply to every backend (no loopback or cloud-metadata addresses, the allowed-suffix list in Settings).

### Maintenance mode (planned updates)
**Sites**, press **Turn on** in the *Maintenance* column (or **Maintenance ON (all)**). Visitors see a maintenance page (HTTP 503); your
application keeps running so you can update it. Edit the page under **Pages**. Press **Turn off** when done. Takes effect within seconds.

### Service-down page
If the application stops, visitors see a friendly page that reloads itself every 10 seconds and sends them back when it is up again. No setup needed; edit it under **Pages**.

### HTTPS (TLS)
In the site's **TLS / HTTPS** section tick *Serve this site over HTTPS* and choose where the certificate comes from:
- **upload certificate + key:** paste a PEM chain and a PEM private key (not password protected). The key is never shown again.
- **self-signed:** for testing only (browsers will warn).
- **Let's Encrypt (automatic, free):** the firewall gets the certificate by itself and renews it 30 days before it expires. See "Automatic certificates" below.
- **mounted secret:** a certificate that cert-manager keeps renewed (see `CLOUD.md`). Recommended for wildcard names and when you already run cert-manager.
HSTS and an HTTP to HTTPS redirect are options. TLS 1.2 and 1.3 only.

### Automatic certificates (Let's Encrypt)
1. Go to **Settings, Automatic HTTPS certificates**. Enter a contact e-mail address (the authority warns you there if a renewal ever fails), choose **Let's Encrypt (production)**, tick the box to accept the authority's agreement, and save.
   Tip: first try **Let's Encrypt staging** with one site (its certificates are not trusted by browsers, but the limits are generous).
2. In the site, tick *Serve this site over HTTPS*, choose certificate source **Let's Encrypt (automatic, free)**, and save. A temporary self-signed certificate is used for the first seconds, then the real one replaces it; the site page shows *certificate issued*. Use **Get / renew the certificate now** to retry.
3. Renewal is automatic: the leader replica checks every hour and renews 30 days before expiry. If a renewal fails you get an alert (if you set up alert channels) and the page shows the reason.

What you need: the host name must be **public** (a real DNS name that points to this firewall) and **port 80 must reach the firewall from the internet** (the authority checks `http://your-host/.well-known/acme-challenge/...`; the firewall answers that on any replica).
What does not work: wildcard names (`*.example.com`) and IP addresses (use cert-manager or an upload for those), and sites that block the authority: a **country rule**, an **IP allow-list** or a **login gate** in front of the challenge address can make the check fail (the authority validates from several places in the world). Failed checks are retried at most every 6 hours because authorities limit failures.
The certificate and its private key are shared between the replicas, encrypted, through the database.

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

## Single sign-on (company accounts)
Instead of (or next to) passwords, people can sign in with their company account through **OpenID Connect**.
1. **At your identity provider** (Microsoft Entra ID, Google Workspace, Okta, Keycloak, Authentik ...) register a new *web application / OIDC client*. The redirect address is your panel's public address plus `/sso/callback`, for example `https://waf-admin.example.com/sso/callback`. Note the **client ID**, the **client secret** and the **issuer address** (the address that serves `/.well-known/openid-configuration`; for Entra ID it is `https://login.microsoftonline.com/<tenant-id>/v2.0`).
2. **In the panel:** Settings, *Single sign-on*: tick *Enable*, enter the issuer address, the panel's public address, the client ID and secret, and **who may sign in**: allowed e-mail domains and/or addresses. Nobody is allowed until you list somebody. Name your administrators (e-mail addresses, or group names if your provider sends a `groups` claim). Everyone else becomes a **read-only viewer** (or an administrator if you choose so; think twice). Save: the panel checks that it can reach the provider.
3. The login page now shows a button. The first sign-in creates the user (name = e-mail address); the role is re-evaluated at every sign-in, so removing someone from the administrator list or group takes effect at their next login. Remove a person completely under **Users**.
**Good to know:** the password login stays available (it is your way in if the provider is down; keep a strong local administrator with two-factor login). Two-factor login for SSO users is whatever your identity provider enforces. The provider must give a **verified** e-mail address (you can relax this in the settings, but it is safer not to). If the provider ever sends a different subject for the same e-mail address, the sign-in is refused until an administrator removes the user (protection against a re-used address). Sign-in attempts and refusals are in the **Audit trail**.

## Users, roles and two-factor login
- **Users:** add administrators (full control) and **viewers** (read-only dashboard, sites, attack log). New users must choose their own password at first login.
- **Security (2FA):** scan or type the key into any authenticator app, confirm a code, **save the 8 recovery codes** (shown once).
- **Settings, Admin panel access:** restrict which addresses may open the panel at all.

## Dashboards (Grafana-style)
Open **Dashboards** for the charts you know from Grafana, built into the panel (no extra software, no JavaScript library; read-only viewers can open it too).
Choose the **time range** (1 h, 6 h, 24 h, 7 d) and the **refresh** interval (off, 10 s, 30 s, 60 s) at the top right.
- **Tiles:** requests, blocked by the WAF (403), rate limited (429), server errors (5xx), blocked share, average response time, each with a small trend line.
- **Requests by status:** stacked columns; green is normal traffic, red blocked, orange rate-limited, purple server errors. Hover a column for the exact numbers.
- **Attacks caught by the OWASP rules:** blocked versus *detected only* (sites in detect-only mode).
- **Busiest sites, most triggered OWASP rules, top blocked addresses, HTTP status codes:** the bars show the top eight for the chosen period. Many hits of one rule on a normal page usually mean a false positive to tune (Sites, rule exclusions).
- **Replicas:** the state of every replica (details on the Cluster page).
The numbers come from the access and attack logs in the database, so all replicas appear together. The longest range is limited by the log retention (Settings, default 7 days).

## Cluster (replicas)
The **Cluster** page shows every replica of the firewall: whether it is online, whether its engine is running, which configuration version it has applied, and which one is the **leader**
(the replica that runs the once-only jobs). After every change the green message tells you on how many replicas the change is already live, for example *applied and reloaded; applied on 3/3 replicas*.
If a replica needs longer, the message names it and the Cluster page shows its progress. The card on the right shows how long the last reload took on the replica you are connected to; with the
default *one shared OWASP rule set* layout this stays in the range of a second even for many sites. Scale up or down with `kubectl scale deploy/shieldwaf -n shieldwaf --replicas=N`.

## Monitoring
The built-in **Dashboards** page shows the same kind of charts you know from Grafana (time range and auto-refresh in the top bar); this section is for external monitoring.
Prometheus can scrape `https://shieldwaf-panel.shieldwaf.svc:9000/metrics` with the header `Authorization: Bearer <token>` (create the token under **Settings, Metrics token**).
Useful alerts: `shieldwaf_engine_up == 0`, a jump in `shieldwaf_requests_total{status="403"}`, `shieldwaf_sites_under_attack > 0`.

## If you are locked out
Anyone with `kubectl exec` rights on the cluster can recover (they already control the pod):
```bash
kubectl exec -n shieldwaf deploy/shieldwaf -c panel -- python3 /panel/tools.py reset-panel-allow     # clears the panel address allow-list
kubectl exec -n shieldwaf deploy/shieldwaf -c panel -- python3 /panel/tools.py reset-2fa <user>       # turns off 2FA for a user
echo "NewStrongPassword123!" | kubectl exec -i -n shieldwaf deploy/shieldwaf -c panel -- python3 /panel/tools.py set-password <user>
```
