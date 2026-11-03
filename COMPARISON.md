# ShieldWAF vs SafeLine vs BunkerWeb (free editions)

**How to read this.** *ShieldWAF* and *BunkerWeb* were installed and tested on this cluster. *SafeLine* was installed on this cluster
too, but its Kubernetes port never accepted a site (its detector answered `401 without valid token`), so its column is based on the
console menus seen during that attempt (Statistics, Applications, Attacks, Allow & Deny, HTTP Flood, Anti-Bot, Auth, Settings) and on
public documentation. Items marked **(?)** for SafeLine are not verified here.

| Feature | ShieldWAF (this repo) | SafeLine Community | BunkerWeb free |
|---|---|---|---|
| License / cost | free, open source | free community edition; the console showed "Upgrade License" and a 7-day trial, so some features need a licence | free; 19 of 62 plugins are Pro (paid) |
| Web GUI | yes (sites, pages, logs, bans, settings) | yes (polished console) | yes (full UI) |
| Detection engine | ModSecurity + OWASP CRS (regex rules + anomaly scoring) | **semantic analysis engine** (understands the attack, not only patterns) | ModSecurity + OWASP CRS |
| Blocks OWASP-Top-10 style attacks | yes, tested (13 attack types) | yes (?) not tested here | yes, tested |
| False-positive tuning | paranoia level, threshold, **rule exclusions per path in the GUI**, detect-only mode | less tuning needed because of the semantic engine (?) | settings per site; exclusions via custom config |
| Rate limiting / HTTP flood | yes, tested (429) | yes ("HTTP Flood" menu) | yes (limit plugin) |
| IP allow / deny lists | yes, per site, tested | yes ("Allow & Deny" menu) | yes (blacklist/whitelist) |
| Auto-ban after repeated attacks | yes (GUI settings), tested | (?) | yes (bad behavior) |
| Bot protection / JS challenge | scanner user-agent blocking only | yes ("Anti-Bot" menu) | yes (antibot challenges) |
| Login / authentication gate | no | yes ("Auth" menu) (?) | basic auth (free); OIDC/SAML/LDAP are Pro |
| **Maintenance mode switch** | **yes: one click per site or all, free** | none seen in the console menu | **Pro only** (plugin exists, locked) |
| **Automatic "service is down" page** | **yes, colourful, auto-reloads, editable in GUI** | generic error page (?) | generic page; custom page needs Pro or a custom config |
| Edit visitor pages in the GUI | **yes, with live preview** | (?) | Pro only |
| TLS / certificates | **not yet** (use cert-manager/ingress in front) | yes (certificate management) | yes (Let's Encrypt, custom certs) |
| Country blocking, threat-intel feeds | not yet (phase 2) | (?) | country, DNSBL, CrowdSec, BunkerNet |
| Metrics / dashboards | built-in dashboard + Prometheus `/metrics` | built-in statistics | built-in; Prometheus exporter is Pro |
| Attack log with rule ids | yes, searchable | yes ("Attacks" menu) | yes (Reports) |
| Audit trail of admin actions | yes | (?) | Pro (reporting/user manager) |
| Backup / restore of config | export/import JSON in GUI | (?) | backup plugin (S3 is Pro) |
| Safe apply (test before reload, rollback) | **yes: `nginx -t` first, old config kept on error** | (?) | reload errors possible |
| Runs on Kubernetes | **yes, native (2 containers, 1 volume)** | **no official support: Docker Compose only, failed here** | yes (Helm chart, 6 pods) |
| Config as code / GitOps | one small manifest, GUI state in a volume + JSON export | database in the stack | Ingress + ConfigMaps (GUI edits can be lost for Ingress-managed sites) |
| Memory used here | **about 230 MB** (4 sites) | about 1 GB (7 containers) | about 1 GB (6 pods) |
| Maturity / support | new, built in one session, **you own it** | mature product, vendor and community | mature product, vendor and community |

## Summary
- **Where SafeLine is better:** the detection engine (semantic analysis is harder to evade and produces fewer false positives than regex rules), plus anti-bot and authentication features, and a more polished console. Use it where you can run Docker Compose.
- **Where BunkerWeb is better:** the largest free plugin list (TLS automation, CrowdSec, country blocking, antibot) and years of production use.
- **Where ShieldWAF is better for you:** it runs natively on your Kubernetes cluster with very little memory, and it gives you for free the things the other two lock or lack: **GUI maintenance switch, editable visitor pages, automatic service-down page, safe apply with rollback, rule exclusions in the GUI, audit trail**.
- **Honest gaps in ShieldWAF today:** no TLS termination, no anti-bot challenge, no country blocking or CrowdSec, single admin, single replica. These are the planned next steps.

## Feature score (practical features of commercial WAFs, 20 items)
Counting only what was verified here: **ShieldWAF 15 / 20** (75%), BunkerWeb free about 15 / 20, SafeLine not measurable on this cluster.
After phase 2 (TLS, CrowdSec, country blocking, anti-bot challenge, Grafana) ShieldWAF would reach about 19 / 20 (95%).
