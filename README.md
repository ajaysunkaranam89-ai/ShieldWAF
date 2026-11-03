<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/logo-full.svg">
    <img src="docs/logo-full-light.svg" alt="A Shield WAF" width="560">
  </picture>
</p>

# A Shield WAF

An open-source **web application firewall with a web GUI**, built for Kubernetes and for the cloud. It combines proven free components
into one product:

- **Engine:** nginx + **ModSecurity v3** + the **OWASP Core Rule Set**, with TLS termination and an anti-bot challenge.
- **Control panel (GUI):** HTTPS-only web app: sites, TLS certificates, maintenance switch, page editor, login gate, rate limits,
  IP lists, auto-ban, attack log, dashboard, two-factor login, audit trail, backup, Prometheus metrics.
- **One pod, two containers**, hardened (non-root, read-only filesystem, no capabilities, network policy). About 230 MB RAM with four sites.

Free and open source. Built and tested on the kind cluster `mycluster`; cloud guide in [`docs/CLOUD.md`](docs/CLOUD.md).
No secrets are stored in this repo: the admin account is created in your browser on first start.

> **Read [`SECURITY.md`](SECURITY.md) before production use.** It lists what is protected, what is *not*, and what you must do.
> This product has not had an independent security audit.

![Dashboard](docs/images/gui-dashboard.png)

## Features

| Area | What you get |
|---|---|
| **Attack blocking** | OWASP CRS 4: SQL injection, XSS, path traversal, file inclusion, command injection, Log4Shell, scanner detection, protocol attacks; JSON bodies inspected |
| **Per-site WAF mode** | `block`, `detect only` (log, never block: ideal for tuning) or `off`; paranoia level 1-4, anomaly threshold |
| **False-positive tuning** | rule exclusions (global or per URL path), custom ModSecurity rules |
| **TLS / HTTPS** | TLS 1.2/1.3 only, certificate upload, self-signed generation, **mounted cert-manager secrets**, HSTS, HTTP to HTTPS redirect, HTTP/2 |
| **Anti-bot challenge** | proof-of-work page for browsers; signed pass bound to client IP + browser; scope "pages" or "all"; path exclusions |
| **Login gate** | require user name + password in front of any site (users managed in the GUI, hashes only) |
| **Maintenance mode** | one-click switch per site or all sites; the app keeps running; colourful editable page |
| **Automatic service-down page** | friendly page when the app is unreachable; reloads itself and the app returns by itself |
| **Positive security model** | per site: only the listed paths, content types and URL length are accepted; everything else is refused, whatever it contains (not pattern based) |
| **IP reputation feeds** | Spamhaus DROP + FireHOL level 1 (or your own https lists), refreshed automatically; private/reserved ranges never loaded |
| **Country rules** | per site allow/deny by registered country (free regional-registry data, no licence key) |
| **Flood defence** | one-click **under-attack mode** (challenge for everyone + rate limit) and **automatic escalation** when a site exceeds a request-rate threshold ([`docs/DDOS.md`](docs/DDOS.md)) |
| **Alerts + SIEM export** | webhooks (Slack, Teams, Discord, generic), email, syslog (RFC 5424 JSON / CEF), HTTP collector (Splunk HEC, Elastic); alerts for engine down, attack spikes, auto-bans, under-attack, lockouts, admin changes, certificate expiry; every blocked request can be forwarded to your SIEM; secrets never shown again |
| **OWASP rule updates** | new releases detected and staged automatically, tried in **detect-only canary** sites, then promoted with one click, with rollback; nothing goes live without approval |
| **OpenAPI validation** | upload your OpenAPI 3 document: unknown paths / methods / parameters / JSON fields, missing required fields, wrong types, enums, ranges and lengths are refused (or logged in detect mode) |
| **PostgreSQL** | configuration, attack log, sessions and audit trail live in PostgreSQL (in-cluster, hardened) or in your managed PostgreSQL |
| **Users and roles** | several administrators and read-only **viewers**; forced password change for new users; reset 2FA / revoke sessions |
| **Rate limiting, IP control** | per-IP rate limit, per-site allow/deny lists, manual bans, **auto-ban** (like fail2ban), method allow-list |
| **Hardening** | unknown hosts get no reply, no server version, strict timeouts/header limits, real client IP only from trusted proxies, security headers |
| **Cloud safety** | upstream SSRF protection (no loopback / cloud-metadata targets), optional allowed-suffix list for upstreams |
| **Admin security** | HTTPS only, **TOTP two-factor login** + recovery codes, lockouts, revocable sessions with idle timeout, CSRF, strict CSP, panel IP allow-list, audit trail with IPs |
| **Visibility** | dashboard, searchable attack log with OWASP rule ids, Prometheus `/metrics` (bearer token) |
| **Safe operations** | every change is tested (`nginx -t`) and confirmed live before it counts; automatic rollback; config export/import (re-validated, no secrets) |

## Quick start

```bash
# 0. create the database secret (random password, kept only in the cluster, never in git)
sh scripts/create-db-secret.sh            # Windows: .\scripts\create-db-secret.ps1

# 1. build the image and load it into kind (for a real cluster push it to your registry, see docs/CLOUD.md)
docker build -t shieldwaf:2.2 .
docker build -t shieldwaf-db:16 db
kind load docker-image shieldwaf:2.2 shieldwaf-db:16 --name mycluster

# 2. deploy
kubectl apply -f k8s/shieldwaf.yaml
kubectl get pods -n shieldwaf                  # 2/2 Running
```

### First start: create the admin account
```bash
kubectl port-forward -n shieldwaf svc/shieldwaf-panel 9000:9000
kubectl logs -n shieldwaf deploy/shieldwaf -c panel          # find the line "Setup code: ..."
```
Open **https://localhost:9000** (the certificate is self-signed at first: accept the warning, or mount your own),
enter the setup code, then **choose your own admin name and a strong password**. Then open **Security (2FA)** and enable two-factor login.

### Add the two apps (Sites, then + Add site)
| Host name | Upstream |
|---|---|
| `notes.waf.local` | `http://notes-app.notes.svc.cluster.local:80` |
| `python.waf.local` | `http://python-app-service.python-app.svc.cluster.local:80` |

### Reach the protected apps
```bash
kubectl port-forward -n shieldwaf svc/shieldwaf-proxy 8088:8080 8443:8443
```
Add `127.0.0.1  notes.waf.local  python.waf.local` to your hosts file (Administrator) and open `http://notes.waf.local:8088`.
For other PCs add `--address 0.0.0.0` and open the firewall port. In the cloud use a LoadBalancer service (see `docs/CLOUD.md`).

## The GUI

| Screen | Use |
|---|---|
| **Dashboard** | requests, blocks, rate limits, 5xx, hourly chart, top rules and IPs, warnings (2FA off, certificate expiring) |
| **Sites** | add/edit/delete; **TLS, anti-bot, login gate, methods, rate limit, WAF tuning**; **Maintenance ON/OFF** per site or for all |
| **Pages** | edit the maintenance and service-down pages with live preview |
| **Attack log** | filter by site, text, blocked / detected; OWASP rule id and score |
| **IP bans** | manual and automatic bans |
| **Threat intel** | reputation feeds, country data, address lookup |
| **Users** | administrators and viewers (admin only) |
| **Alerts** | channels, which events alert, SIEM export, delivery log (admin) |
| **Rule updates** | stage, canary-test, promote and roll back OWASP rule sets (admin) |
| **Settings** | panel allow-list, idle timeout, upstream restrictions, flood defence, auto-ban, trusted proxies, metrics token, password |
| **Security (2FA)** | enable/disable two-factor login |
| **Audit trail** | who did what, from which IP |
| **Backup** | export/import sites, settings and pages |

![Sites](docs/images/gui-sites.png)
![Site settings: TLS, WAF, anti-bot, login gate](docs/images/gui-site_tls.png)
![Attack log](docs/images/gui-logs.png)
![Positive security model, country rules, challenge, login gate](docs/images/gui-site_policy.png)
![Alerts and SIEM export](docs/images/gui-alerts.png)
![OWASP rule-set updates](docs/images/gui-rules.png)
![OpenAPI validation, canary rules, positive model](docs/images/gui-site_openapi.png)
![Threat intelligence](docs/images/gui-intel.png)
![Users and roles](docs/images/gui-users.png)
![Flood defence and settings](docs/images/gui-settings.png)
![Two-factor login](docs/images/gui-security.png)
![Sign in](docs/images/gui-login.png)

## How it works

```
 client --Host: notes.waf.local--> [engine: nginx + ModSecurity + OWASP CRS (+ TLS, challenge)] --> notes-app / python-app-service
                                          ^ reload, confirmed by a handshake file
                                   [panel: renders nginx + rule files into /data/rendered/gen-N, tests them, swaps "current"]
                                          | tails access.log / audit.json into SQLite -> dashboard, attack log, auto-ban
```
The two containers share only the `/data` volume: the panel writes a new generation and a `reload.request`; the engine tests and
reloads nginx, waits until the new generation answers, and reports in `reload.status`. If it fails the panel restores the previous generation.

## Test results (kind, notes app + python app as upstreams)
An automated suite of **185 checks** (all passing on the final build, on a real cluster with a real PostgreSQL) covers: setup and password policy, wrong-code and weak-password refusal, login lockout, TOTP login with
recovery codes and replay refusal, session revocation after logout and after a password change, CSP/HSTS/cookie flags, metrics token,
panel allow-list lock-out protection, SSRF refusal (loopback, metadata address and names, allowed-suffix list), import validation,
13 attack types blocked, unknown-host drop, header-size and method limits, spoofed `X-Forwarded-For`, TLS (1.1 refused, 1.3 works,
unknown-host handshake refused, HSTS, redirect), certificate upload (mismatched key refused, key never shown), login gate, anti-bot
challenge (correct work, wrong work, forged seed, forged cookie, other browser, scope pages/all, exclusions), maintenance, service-down
page, rate limiting, auto-ban, backup contents and audit trail, the positive security model, live reputation feeds, country rules (real address blocks), under-attack mode and its automatic escalation under a real flood, and the admin / viewer roles, alert delivery through every channel type to a test receiver (webhook, syslog UDP/TCP, CEF, HTTP collector with a secret header, SMTP), SIEM forwarding of a blocked attack, OpenAPI enforcement (missing / unknown / over-long fields, undocumented methods and paths), the complete OWASP rule-set cycle with a **real GitHub download** (check, stage, canary in detect-only, promote, rollback), and persistence in PostgreSQL across a panel restart. Static analysis (Bandit), manifest and image scans (Trivy: 0 high/critical) and an OWASP ZAP baseline (0 failures) are in [`docs/SECURITY-REVIEW.md`](docs/SECURITY-REVIEW.md). See [`SECURITY.md`](SECURITY.md) for the design and the limits.

## Limits (honest list)
- **No independent audit.** A documented self-review is in [`docs/SECURITY-REVIEW.md`](docs/SECURITY-REVIEW.md); get a third-party test before relying on it for high-value systems.
- **Detection is partly pattern-based** (OWASP rules). The positive model, reputation feeds, country rules, challenge and flood defence add protection that does not depend on patterns, but keep your applications patched.
- **No volumetric DDoS protection** (impossible inside a cluster); application-layer floods are handled; see [`docs/DDOS.md`](docs/DDOS.md) for what to put in front.
- Single panel/engine replica (no high availability; the database is PostgreSQL, ready for a managed, replicated service); reload time grows with the number of sites (about half a second each); certificates are renewed by cert-manager, not by this product.
Details in `SECURITY.md`.

## Comparison with SafeLine and BunkerWeb
See [`COMPARISON.md`](COMPARISON.md).

## Files
| Path | Purpose |
|---|---|
| `Dockerfile`, `engine-entrypoint.sh`, `panel-entrypoint.sh` | the single image: engine and panel |
| `panel/` | control panel (Flask app, renderer, security helpers, workers, templates, anti-bot challenge in `njs/`) |
| `k8s/shieldwaf.yaml` | hardened namespace, volume, pod, PostgreSQL StatefulSet, services, network policies |
| `db/Dockerfile` | the PostgreSQL image (official, pinned, OS fixes, unused `gosu` removed) |
| `scripts/create-db-secret.*` | creates the database secret in the cluster (random password) |
| `SECURITY.md` | security design, limits, operator duties |
| `docs/SECURITY-REVIEW.md` | self-review: scans, scanner baseline, findings and fixes |
| `docs/CLOUD.md` | running it in the cloud |
| `docs/DDOS.md` | denial-of-service defence: what the WAF does, what must sit in front |
| `.github/workflows/security.yml` | CI: Bandit, Trivy (config + image), hadolint |
| `docs/` | logo and GUI screenshots |
