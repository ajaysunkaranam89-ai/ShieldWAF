# A Shield WAF vs SafeLine vs BunkerWeb (free editions)

**How to read this.** *A Shield WAF* and *BunkerWeb* were installed and tested on this cluster. *SafeLine* was installed on this cluster
too, but its Kubernetes port never accepted a site (its detector answered `401 without valid token`), so its column is based on the
console menus seen during that attempt (Statistics, Applications, Attacks, Allow & Deny, HTTP Flood, Anti-Bot, Auth, Settings) and on
public documentation. Items marked **(?)** are not verified here. A Shield WAF is new software written by one author: treat "yes" as
"implemented and tested here", not as "audited".

| Feature | A Shield WAF | SafeLine Community | BunkerWeb free |
|---|---|---|---|
| License / cost | free, open source | free community edition; the console showed "Upgrade License" and a 7-day trial, so some features need a licence | free; 19 of 62 plugins are Pro (paid) |
| Web GUI | yes (sites, TLS, pages, logs, bans, settings, 2FA, audit) | yes (polished console) | yes (full UI) |
| Detection engine | ModSecurity + OWASP CRS (regex rules + anomaly scoring) | **semantic analysis engine** (understands the attack, not only patterns) | ModSecurity + OWASP CRS |
| Blocks OWASP-Top-10 style attacks | yes, tested (13 attack types) | yes (?) not tested here | yes, tested |
| False-positive tuning | paranoia level, threshold, **rule exclusions per path in the GUI**, detect-only mode | less tuning needed because of the semantic engine (?) | settings per site; exclusions via custom config |
| Rate limiting / HTTP flood | yes, tested (429) | yes ("HTTP Flood" menu) | yes (limit plugin) |
| IP allow / deny lists | yes, per site, tested | yes ("Allow & Deny" menu) | yes (blacklist/whitelist) |
| Auto-ban after repeated attacks | yes (GUI settings), tested | (?) | yes (bad behavior) |
| Bot protection | **proof-of-work challenge** (signed pass bound to IP + browser) and scanner blocking | yes ("Anti-Bot" menu); likely more mature | yes (antibot challenges) |
| Login / authentication gate | **yes** (user + password in front of a site) | yes ("Auth" menu) (?) | basic auth (free); OIDC/SAML/LDAP are Pro |
| TLS / certificates | **yes**: upload, self-signed, cert-manager mount, TLS 1.2/1.3, HSTS, redirect (no built-in ACME renewal) | yes (certificate management) | yes (Let's Encrypt, custom certs) |
| **Maintenance mode switch** | **yes: one click per site or all, free** | none seen in the console menu | **Pro only** (plugin exists, locked) |
| **Automatic "service is down" page** | **yes, colourful, auto-reloads, editable in GUI** | generic error page (?) | generic page; custom page needs Pro or a custom config |
| Edit visitor pages in the GUI | **yes, with live preview** | (?) | Pro only |
| Admin two-factor login (TOTP) | **yes**, with recovery codes | (?) | yes (UI) (?) |
| Admin hardening (lockout, revocable sessions, CSP, IP allow-list) | **yes** (see SECURITY.md) | (?) | partly (?) |
| Upstream SSRF protection (metadata / loopback) | **yes** | (?) | no |
| Country blocking, threat-intel feeds | not yet | (?) | country, DNSBL, CrowdSec, BunkerNet |
| Metrics / dashboards | built-in dashboard + Prometheus `/metrics` (token) | built-in statistics | built-in; Prometheus exporter is Pro |
| Attack log with rule ids | yes, searchable | yes ("Attacks" menu) | yes (Reports) |
| Audit trail of admin actions (with IPs) | yes | (?) | Pro (reporting/user manager) |
| Backup / restore of config | export/import JSON in GUI (validated, no secrets) | (?) | backup plugin (S3 is Pro) |
| Safe apply (test, confirm live, rollback) | **yes** | (?) | reload errors possible |
| Runs on Kubernetes | **yes, native, hardened (restricted PSS, read-only FS, NetworkPolicy)** | **no official support: Docker Compose only, failed here** | yes (Helm chart, 6 pods) |
| Memory used here | **about 230 MB** (4 sites) | about 1 GB (7 containers) | about 1 GB (6 pods) |
| Image scan | Trivy: 0 high/critical (unfixed ignored) | (?) | (?) |
| Maturity / support / audits | new, one author, **not independently audited, you own it** | mature product, vendor and community | mature product, vendor and community |

## Summary
- **Where SafeLine is better:** the detection engine (semantic analysis is harder to evade and gives fewer false positives than regex rules), a more mature anti-bot system, and a more polished console. Use it where you can run Docker Compose.
- **Where BunkerWeb is better:** the largest free plugin list (automatic certificates, CrowdSec, country blocking) and years of production use.
- **Where A Shield WAF is better for you:** it runs natively and hardened on your Kubernetes cluster with very little memory, and it gives you for free the things the other two lock or lack: **GUI maintenance switch, editable visitor pages, automatic service-down page, safe apply with rollback, rule exclusions in the GUI, two-factor admin login, audit trail, SSRF protection**.
- **Honest gaps in A Shield WAF today:** no automatic certificate renewal (use cert-manager), no country blocking or CrowdSec feeds, single admin, single replica, no independent audit, pattern-based detection only.

## Feature score (the author's own 20-item checklist of practical WAF features)
Verified here: **A Shield WAF about 18 / 20 (90%)**, BunkerWeb free about 15 / 20, SafeLine not measurable on this cluster.
Missing for the last two points: country blocking / threat-intel feeds, and Grafana-style dashboards. This is a self-assessment, not a benchmark.
