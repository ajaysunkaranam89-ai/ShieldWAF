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
| **Rate limiting, IP control** | per-IP rate limit, per-site allow/deny lists, manual bans, **auto-ban** (like fail2ban), method allow-list |
| **Hardening** | unknown hosts get no reply, no server version, strict timeouts/header limits, real client IP only from trusted proxies, security headers |
| **Cloud safety** | upstream SSRF protection (no loopback / cloud-metadata targets), optional allowed-suffix list for upstreams |
| **Admin security** | HTTPS only, **TOTP two-factor login** + recovery codes, lockouts, revocable sessions with idle timeout, CSRF, strict CSP, panel IP allow-list, audit trail with IPs |
| **Visibility** | dashboard, searchable attack log with OWASP rule ids, Prometheus `/metrics` (bearer token) |
| **Safe operations** | every change is tested (`nginx -t`) and confirmed live before it counts; automatic rollback; config export/import (re-validated, no secrets) |

## Quick start

```bash
# 1. build the image and load it into kind (for a real cluster push it to your registry, see docs/CLOUD.md)
docker build -t shieldwaf:2.0 .
kind load docker-image shieldwaf:2.0 --name mycluster

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
| **Settings** | panel allow-list, idle timeout, upstream restrictions, auto-ban, trusted proxies, metrics token, password |
| **Security (2FA)** | enable/disable two-factor login |
| **Audit trail** | who did what, from which IP |
| **Backup** | export/import sites, settings and pages |

![Sites](docs/images/gui-sites.png)
![Site settings: TLS, WAF, anti-bot, login gate](docs/images/gui-site_tls.png)
![Attack log](docs/images/gui-logs.png)
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
An automated suite of **88 checks** covers: setup and password policy, wrong-code and weak-password refusal, login lockout, TOTP login with
recovery codes and replay refusal, session revocation after logout and after a password change, CSP/HSTS/cookie flags, metrics token,
panel allow-list lock-out protection, SSRF refusal (loopback, metadata address and names, allowed-suffix list), import validation,
13 attack types blocked, unknown-host drop, header-size and method limits, spoofed `X-Forwarded-For`, TLS (1.1 refused, 1.3 works,
unknown-host handshake refused, HSTS, redirect), certificate upload (mismatched key refused, key never shown), login gate, anti-bot
challenge (correct work, wrong work, forged seed, forged cookie, other browser, scope pages/all, exclusions), maintenance, service-down
page, rate limiting, auto-ban, backup contents and audit trail. See [`SECURITY.md`](SECURITY.md) for the design and the limits.

## Limits (honest list)
Not independently audited; OWASP rules are pattern-based (a determined attacker may bypass them; keep apps patched); no volumetric
DDoS protection; single admin account and single replica; reload time grows with the number of sites (about half a second each);
certificates are renewed by cert-manager, not by this product. Details in `SECURITY.md`.

## Comparison with SafeLine and BunkerWeb
See [`COMPARISON.md`](COMPARISON.md).

## Files
| Path | Purpose |
|---|---|
| `Dockerfile`, `engine-entrypoint.sh`, `panel-entrypoint.sh` | the single image: engine and panel |
| `panel/` | control panel (Flask app, renderer, security helpers, workers, templates, anti-bot challenge in `njs/`) |
| `k8s/shieldwaf.yaml` | hardened namespace, volume, pod, services, network policies |
| `SECURITY.md` | security design, limits, operator duties |
| `docs/CLOUD.md` | running it in the cloud |
| `docs/` | logo and GUI screenshots |
