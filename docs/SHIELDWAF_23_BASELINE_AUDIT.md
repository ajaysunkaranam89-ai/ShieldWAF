# ShieldWAF 2.3 baseline audit

Read-only review of the repository at tag `v2.3.0` (commit `73ef497`, 2026-11-04), made before the 2.4 work. Method: reading every source, manifest and script, running the existing
test suites, and **reproducing** the findings marked *(reproduced)* with a short experiment against the 2.3 code. Findings marked *(review)* come from reading the code only and were not exploited.
This is the author's own review, not an independent audit.

## 1. Architecture (as built)
| Layer | What |
|---|---|
| Data path | nginx + ModSecurity v3 + OWASP CRS 4.30 in the `engine` container; one shared CRS parse at http level, per-site settings chosen by Host header (`panel/engine.py`) |
| Control plane | Flask panel (`panel/app.py`, gunicorn, HTTPS) in the `panel` container of the same pod; renders configuration into `/data/rendered/gen-N`, the engine reloads it |
| State | PostgreSQL (`panel/store.py`): config JSON, events, access rows, sessions, audit, nodes, encrypted shared files (`sfiles`); SQLite fallback for tests |
| HA | N replicas, cluster-wide advisory lock, leader election, change propagation by version counters (`panel/cluster.py`, `panel/sharedfs.py`) |
| Identity | local users (PBKDF2 hash, TOTP + recovery codes, lockouts), OpenID Connect SSO (`panel/oidc.py`), roles admin/viewer |
| Delivery | `k8s/shieldwaf.yaml`, `k8s/backup.yaml`, Helm chart `charts/shieldwaf`, release workflow |

## 2. Modules and implemented features
`app.py` (routes, auth, sessions, sites, settings), `engine.py` (nginx/ModSecurity rendering), `store.py` (database layer, cluster lock), `security.py` (TOTP, upstream check, certificates),
`openapi.py` (OpenAPI to ModSecurity rules), `feeds.py` (Spamhaus DROP, FireHOL, RIR country data), `crsupdate.py` (OWASP rule updates with canary), `alerts.py` (webhook, email, syslog JSON/CEF, HTTP collector),
`background.py` (log ingestion, auto-ban, flood escalation, health checks, feeds), `acme.py`, `oidc.py`, `cluster.py`, `sharedfs.py`, `charts.py` (dashboards), `pages.py`, `tools.py`.
Implemented and tested (200 functional + 91 HA + 15 backup + 6 DB failover + 44 SSO + 18 ACME checks at 2.3): attack blocking, per-site modes, TLS incl. ACME, anti-bot proof-of-work, login gate, positive security model,
reputation feeds, country rules, under-attack mode, several upstreams with health checks, alerts/SIEM export, OWASP rule update cycle, OpenAPI validation, users/roles, SSO, HA, backups, dashboards.

## 3. Missing features (compared with the 2.4 request)
No Redis or any shared store for request rate limits (nginx `limit_req` is per replica); no per-user / per-API-key / per-endpoint limits; bot detection is user-agent list + proof-of-work only (no behaviour analysis, no
credential-stuffing detection); no CrowdSec; no Wazuh-specific decoders/rules (generic JSON/CEF export only); no p95/p99 latency, CPU, memory, certificate-expiry or CRS-rule metrics on `/metrics`; no multi-tenancy
(single organisation, two roles); no policy versioning, approval or rollback; no tamper-evident audit export; no database TLS or least-privilege database accounts; no load-test or performance report; no unit tests that run
without a cluster; CI does not run any functional test.

## 4. Findings
Severity scale: **P0** = fix before a 2.4 release; **P1** = should fix in 2.4; **P2** = improvement.

### F-01 SSRF validation of upstreams is name- and literal-only (P0, *reproduced*)
- **File:** `panel/security.py` `check_upstream()`, `panel/app.py` `UP_RE`.
- **Explanation:** only literal IPv4 addresses are tested against a short block list, plus a name list. A host name is never resolved, so `127.0.0.1.nip.io`, `169.254.169.254.nip.io` or `localtest.me` (public DNS names that
  resolve to loopback / the cloud metadata address) are accepted; also accepted: `0177.0.0.1` and `2130706433` (octal / decimal forms), `100.64.0.1`, and (if the pattern allowed brackets) `[::ffff:127.0.0.1]`, `[::]`.
  nginx resolves the name again for **every request** (variable `proxy_pass`), so a DNS answer can also change after validation (DNS rebinding).
- **Exploitability:** needs panel administrator rights (or a stolen admin session/SSO account) to add or edit a site; no other precondition. The cluster's own DNS and a public rebinding service are enough.
- **Impact:** the WAF becomes a proxy into the cluster network and the node's metadata service: theft of cloud credentials, access to unauthenticated internal services (the WAF's own panel on 9000, databases, Kubernetes API).
- **Fix (2.4 Module A):** resolve and validate every address, classify with `ipaddress` (including mapped / NAT64 / 6to4 forms), explicit private allowlists, periodic revalidation by the leader, event log, tests.

### F-02 Sensitive request data in the ModSecurity audit log (P1, *review*)
- **File:** `panel/engine.py` (`SecAuditLogParts ABIJDEFHZ`).
- **Explanation:** part B (request headers) and I/J (request body) are written to `/data/logs/audit.json` for every blocked or 4xx/5xx request. That includes `Authorization`, `Cookie`, and bodies containing passwords.
  The file lives on the volume shared by both containers and is ingested by the panel; query strings are also forwarded to SIEM channels (`alerts.forward_events`).
- **Exploitability:** anyone who can read the pod volume or the SIEM index (log readers, a compromised engine container).
- **Impact:** credential and token disclosure through logs.
- **Fix:** sanitise sensitive headers and arguments before they reach the log (2.4 Module F/L), redact in forwarded events.

### F-03 Audit trail is mutable and unbounded (P1, *review*)
- **File:** `panel/store.py` `audit()`, table `audit`; `panel/background.py` `prune()`.
- **Explanation:** the application database role can UPDATE and DELETE audit rows; rows carry no integrity data; retention is not configurable (audit is never pruned); the panel's role is the database owner. Detail is truncated to 500 characters.
- **Exploitability:** an attacker with code execution in the panel (or the database credentials) can edit history undetected.
- **Impact:** loss of forensic value.
- **Fix:** hash-chained records (tamper evident), append-only database privileges, signed exports, configurable retention (Module F).

### F-04 Backups use unauthenticated encryption with the same secret as everything else (P1, *review*)
- **File:** `k8s/backup.yaml`, `charts/shieldwaf/templates/backup.yaml`, `scripts/restore-db.*`.
- **Explanation:** AES-256-CBC (no authentication tag, a modified file may decrypt to garbage without detection); the key is `SHIELD_DATA_KEY`, which also protects the shared files and sits in the same Kubernetes secret as the database password;
  the backup volume is in the same cluster (no independent destination); no key rotation; no scheduled restore test.
- **Impact:** whoever reads the secret reads every backup; tampering is not reliably detected; one cluster loss destroys both data and backups.
- **Fix:** AES-256-GCM with a per-file nonce and header, an independent backup key with rotation, integrity verification, off-cluster destination support (Module E).

### F-05 Database connection is unencrypted and over-privileged (P1, *review*)
- **File:** `k8s/shieldwaf.yaml`, `scripts/create-db-secret.*`, `panel/store.py`.
- **Explanation:** the connection string has no `sslmode`; the bundled PostgreSQL has no TLS; the application connects as the database owner / superuser created by `POSTGRES_USER`; schema changes are `CREATE TABLE IF NOT EXISTS` at start (no versioned migrations);
  no connection timeout beyond `connect_timeout=10`, no statement timeout, no pool (one connection per thread, about 20 per replica).
- **Impact:** traffic readable inside the cluster network; a SQL injection or code flaw in the panel owns the whole database server.
- **Fix:** TLS with verification, separate migration and runtime roles, versioned migrations, timeouts (Module D).

### F-06 Sensitive panel files are readable by the engine container (P1, *review*)
- **File:** `k8s/shieldwaf.yaml` (volume `data` mounted in both containers), `panel/*.py` (paths under `/data`).
- **Explanation:** `secret.key` (Flask signing key), `bootstrap.code`, alert/SSO secrets (`/data/secrets`), the ACME account key and the panel's own TLS key live on the volume the internet-facing nginx process also mounts.
- **Exploitability:** a memory-safety bug or module vulnerability in nginx/ModSecurity yields read access to those files.
- **Impact:** forging panel sessions, reading SSO/alert secrets.
- **Fix:** a panel-private volume that the engine does not mount (Module C).

### F-07 No dedicated service accounts or per-component pod hardening differences (P2, *review*)
- **File:** `k8s/*.yaml`, chart. Pods use the namespace `default` service account (token not mounted). A dedicated account per component is the usual policy baseline. The database pod and the backup job share nothing but the secret.

### F-08 OpenAPI validation gaps (P1, *review*, partly *reproduced* in `tests/unit`)
- **File:** `panel/openapi.py`.
- **Explanation:** `required` is enforced for object properties but **not inside array items** (arrays are flattened with `required=False`); an optional parent object's required children are never enforced; object nesting deeper than 4 levels is treated as a scalar
  (valid deep payloads are then refused by the "unknown field" rule, or not checked); `pattern`, `format`, `oneOf/anyOf/allOf`, `minItems/maxItems`, `uniqueItems`, `exclusiveMinimum` are reported as not enforced; there is no per-operation body size or JSON depth limit (the global
  limits are 10 MB and depth 512); no schema size/recursion budget besides the `$ref` chain length.
- **Impact:** API schema bypass (missing required fields in list items, oversized or deeply nested bodies) and compile-time resource use on hostile specs.
- **Fix:** Module B.

### F-09 Rate limiting is per replica and per address only (P1, *review*)
- **File:** `panel/engine.py` (`limit_req_zone $binary_remote_addr`). With N replicas an address can use N times the configured rate; no per-user, per-API-key or per-endpoint limits; login brute force is limited by the database-backed lockout (good, cluster-wide).
- **Impact:** reduced protection against credential stuffing and API abuse behind a load balancer. **Fix:** Module G (needs Redis; not part of the P0 work).

### F-10 Dependencies are not pinned (P1, *review*)
- **File:** `Dockerfile`, `db/Dockerfile`. The base images are pinned by digest, but Python packages (flask, gunicorn, psycopg2, cryptography) and openssl come from Alpine's repository at build time (`apk add` without versions, `hadolint DL3018` is ignored on purpose because Alpine removes old versions). There is no lock file and no dependency inventory in the repository. Trivy (image scan) is clean at release time.
- **Impact:** non-reproducible builds, silent version drift. **Fix:** record the resolved versions (SBOM per release, already in the release workflow) and document supported versions; consider a pinned Python layer.

### F-11 CI runs no functional or unit tests (P1, *review*)
- **File:** `.github/workflows/security.yml`. Bandit, Trivy (config/image), hadolint only. The 350+ checks run on a developer's cluster by `tests/run.sh`. Gitleaks is not in CI. **Fix:** unit tests that run in CI (added in 2.4), keep the cluster suites as a documented pre-release step.

### F-12 Metrics are minimal (P2, *review*)
- **File:** `panel/app.py` `/metrics`: request counters by status, event counters, sites, bans, engine up. No latency histograms, CPU/memory, DB state, certificate expiry, rule-match counters. **Fix:** Module M (not in the P0 scope).

### F-13 Performance and scalability notes (P2, *review* and measured at 2.3)
80 sites apply in about 6 s thanks to the shared rule set; the access log is ingested into PostgreSQL by every replica (one row per request): at high request rates this becomes the bottleneck (insert volume, 7-day retention) long before nginx does. Dashboards aggregate `access` with sequential scans over the retention window.
The leader runs all once-only jobs; failover takes about 10 s. No load tests exist for 2.3 yet (this audit does not claim throughput numbers).

### F-14 Deployment limitations (P2, *review*)
One bundled PostgreSQL instance (HA option documented, not part of the tested default); no Docker Compose file; the release pipeline has never run; autoscaling is optional and untested under load.

### F-15 Positive observations (not findings)
Non-root containers with read-only root filesystems, all capabilities dropped, RuntimeDefault seccomp, default-deny network policies, TLS 1.2+ only, TOTP with replay protection, server-side revocable sessions, strict CSP, CSRF tokens, encrypted shared files (Fernet), signed releases, SBOM, SSO with PKCE and strict ID-token checks.

## 5. Recommended upgrades (order used for 2.4)
P0: A SSRF, B OpenAPI, C container separation, D PostgreSQL security, E backup security, F audit logging. P1: G distributed rate limiting (Redis), H bot protection, I threat intelligence, L Wazuh, M Prometheus/Grafana.
P2: J database HA test, K Kubernetes extras, N multi-tenancy, O policy management, P analytics.
