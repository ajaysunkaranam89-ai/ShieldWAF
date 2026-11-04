# A Shield WAF 2.4 — Architecture

## Components

```
 clients ──► engine (nginx + ModSecurity v3 + OWASP CRS + njs)  ──► your applications
                │  reads rendered config, certificates, rules, feeds (read-only)
                │  asks 127.0.0.1:9101 for cluster-wide rate limits (optional)
 panel (Flask + gunicorn, HTTPS) ── renders configuration, runs background jobs, serves the GUI
                │  one PostgreSQL database (TLS) · optional Redis · optional CrowdSec LAPI
 PostgreSQL 16 ── configuration, users, logs, audit chain, encrypted shared files, schema migrations
```

* **Engine container** — nginx with ModSecurity and the OWASP Core Rule Set, plus njs scripts (`panel/njs/`): the anti-bot proof-of-work challenge (2.3) and the bot score (2.4). It parses untrusted traffic, so it gets the least: its `/data` is read-only except `rendered/` (status files) and `logs/`; it cannot see `/private`.
* **Panel container** — the GUI and every background job. It renders `nginx.conf` into `/data/rendered/gen-*` (tested with `nginx -t`), switches the `current` link, and the engine reloads. Panel-only secrets (session key, setup code, alert / ACME / OIDC / CrowdSec secrets) are in `/private`, a memory volume only the panel mounts (`SHIELD_PRIVATE`).
* **Database** — PostgreSQL with TLS, SCRAM and `pg_hba` rules that reject plain connections. Optional WAL archiving and replication connections (`db/tls-entrypoint.sh`).
* **Replicas** — any number of identical panel+engine pairs share one database. A cluster-wide advisory lock and a leader election decide who runs the jobs that must run once (feed refresh, health checks, ACME, audit verification). Configuration and the few shared files (certificates, keys, alert secrets, feeds, rules) are mirrored through the database, encrypted with `SHIELD_DATA_KEY` (`sharedfs.py`).

## Request path (what happens to one request)

1. nginx accepts the connection; `bans.conf` and the threat-intelligence list (`$shield_feed`) refuse listed addresses before anything else.
2. Server block of the site (found by `Host`): country rules, bot score (`bots.js`, optional block / challenge), scanner user agents, ModSecurity (OWASP CRS, custom rules, OpenAPI rules), login gate, rate limit (per replica `limit_req`, optionally also the cluster-wide check through `auth_request` to the local limiter and Redis).
3. Upstream choice: weighted / ip-hash balancing over the upstreams that passed the SSRF guard (optionally pinned to the checked address), retry of reads on the next upstream.
4. Access log (JSON) is read by the panel and stored in the database.

## 2.4 additions and where they live

| Area | Code | Data |
|---|---|---|
| SSRF guard | `panel/netguard.py` (used by upstream checks, alerts, feeds, ACME, OIDC, CrowdSec) | `ssrf_blocked` per site, allowlist in settings |
| OpenAPI validation | `panel/openapi.py` → ModSecurity rules | spec per site |
| Audit chain | `panel/store.py` (HMAC chain), `/audit` | `audit` table + anchor in `meta` |
| Backups | `panel/backupcrypt.py`, `k8s/backup.yaml` | `.swbk` files (AES-256-GCM), key ring secret |
| Database security | `panel/store.py` (connections, grants), `panel/dbadmin.py`, `db/` | roles, TLS |
| Rate limit | `panel/ratelimit.py`, `engine.rl_cluster_locations` | Redis token buckets |
| Bot protection | `panel/njs/bots.js` | per-site `bots` settings |
| Threat intel | `panel/feeds.py`, `panel/crowdsec.py` | `feeds/` files, decisions state |
| PITR | `db/archive-wal.sh`, `backupcrypt.py basebackup / pitr-prepare` | WAL archive, base backups |
| Posture | `panel/posture.py` | reads everything above |

## Trust boundaries

* Internet → engine: untrusted. Engine → applications: your network. Engine ↔ panel: same pod / network namespace, a shared folder with strict directions (panel writes, engine reads).
* Panel ↔ database: TLS, runtime role (data changes only; audit trail append-only) in the intended setup; migrations and audit retention on the owner connection.
* Operators → panel: HTTPS, 2FA / SSO, roles (admin / viewer), everything audited in the tamper-evident chain.
* Secrets: database secret, backup key ring and Redis secret are separate Kubernetes secrets; the backup key ring is never on the backup volume.

## Failure behaviour (designed, and where tested)

| Failure | Behaviour | Tested |
|---|---|---|
| Panel down | engines keep serving with the last configuration | HA suite |
| Database down | every replica still serves and blocks (data path does not need it) | HA suite |
| Database primary lost | panel reconnects to the new primary (multi-host URL) | `dbfailover.sh` |
| Redis down | rate limit falls back to per replica (fail-open; `SHIELD_RL_FAIL=closed` refuses) | `redis_ratelimit.sh` |
| CrowdSec unreachable | old decisions stay until they expire | `crowdsec.sh` |
| A threat feed down | its last good copy (≤ 7 days) stays in use | unit tests |
| A replica lost | others continue; leader re-elected | HA suite |
