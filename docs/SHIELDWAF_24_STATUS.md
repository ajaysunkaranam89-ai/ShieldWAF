# A Shield WAF 2.4 — status, assessment and what remains

Date: 2026-11-04. Branch `release/2.4`. Version 2.4 in the panel, image label and chart. Tests were run on this machine (Docker Desktop + a kind cluster); counts are from the runs.

## Test results

| Suite | Result |
|---|---|
| Unit tests (`tests/unit/run.sh`) | 126 tests OK (SSRF 28, OpenAPI 32 on the real engine, bots 11 on the real engine, audit 19, backup format 24, feeds 6, posture 4, paths 2, others) |
| `tests/backup_crypto.sh` (real PostgreSQL + S3 server) | 25/25 |
| `tests/db_security.sh` (real PostgreSQL with TLS) | 33/33 |
| `tests/db_pitr.sh` (real PostgreSQL, point-in-time recovery) | 13/13 |
| `tests/dbfailover.sh` (primary stopped, standby promoted) | 6/6 |
| `tests/redis_ratelimit.sh` (real Redis + real nginx) | 14/14 + 6/6 (re-run after the keep-alive change to the limiter) |
| `tests/crowdsec.sh` (real CrowdSec Local API) | 15/15 |
| Cluster, `SUITES=hardening` | 24/24 |
| Cluster, `SUITES=functional` (2 replicas) | **202/202** (final run) |
| Cluster, `SUITES=ha` (3 replicas) | **91/91** (the layout check reads live replicas only; the shared-session-key check was fixed after this run and not re-run) |
| Cluster, `SUITES=backup` | 18/18 |
| Docker Compose deployment | started: database healthy, panel health check answers, engine serves its health URL. Not run through a protection test |

The cluster suites ran on the images built before the last small engine change (keep-alive upstream for the rate-limit limiter, used only by sites with a cluster-wide limit). That change is covered by the Docker test above, not by a cluster run.

## Performance (tests/perf, k6 against the real engine in Docker)

One run, on a shared Docker VM with the load generator on the same machine, no OWASP rules loaded: **treat as indicative only.** The throughput of the plain path differed by 50 % between the 2.3 and 2.4 images in the same run (the 2.3 case ran first), which shows the noise.

| Case | req/s | p50 ms | p95 ms |
|---|---|---|---|
| 2.3 plain | 9,769 | 4.8 | 16.0 |
| 2.4 plain | 15,111 | 3.6 | 7.8 |
| 2.4 per-replica rate limit | 14,966 | 3.7 | 7.8 |
| 2.4 bot protection | 7,662 | 7.5 | 13.1 |
| 2.4 cluster-wide limit (Redis), **before the keep-alive fix** | 1,082 | 8.6 | 201 |
| 2.4 bots + cluster-wide limit, before the fix | 1,149 | 8.6 | 201 |

What this says: (1) the new per-request features are visible on a trivial backend; bot scoring costs about 0.07 ms of CPU per request, small next to the OWASP rule set (not measured here); (2) **the cluster-wide limit was the expensive one** (a new connection and thread per request); kept-alive connections were added afterwards and are **not re-measured**: do not rely on any number for that case. Re-run `bash tests/perf/perf.sh` on an idle machine before quoting figures. There is no ModSecurity-with-CRS measurement and no 2.3 vs 2.4 comparison of the full path.

## Security assessment (self-review, not an independent audit)

Closed from the baseline audit: SSRF bypasses, mutable audit log, same-key CBC backups, unencrypted database traffic in code and image, OpenAPI gaps, no unit tests in CI, panel secrets visible to the engine container, no cluster-wide rate limit, no point-in-time recovery. Evidence and details: `SECURITY_HARDENING.md`.

Residual risks that matter most:
1. The stock manifests still give the panel container the database **owner** credential (the restricted runtime role exists and is tested but is not wired in): a compromise of the panel can still rewrite the audit trail.
2. No failover manager for the database; the WAL archive for point-in-time recovery is not encrypted.
3. The bot score is a hint; a real browser under automation passes it.
4. Database TLS is encryption without server authentication unless you mount your own certificate and use `verify-full`.
5. Redis (optional) is a single pod without persistence; the cluster-wide limit depends on it (fails open by default).

## Production readiness

**Better than 2.3 on every item above, but not recommended for production yet.** Before production: (a) wire the runtime database role (or accept risk 1 knowingly); (b) test the 2.3 → 2.4 upgrade and the rollback on a copy: neither was tested; (c) re-run the cluster suites on the final images and measure performance on an idle machine; (d) have the penetration-test plan (`PENETRATION_TESTING.md`) carried out; (e) decide on the optional features (Redis, CrowdSec, WAL archive). It is suitable for a test cluster.

## Not done

* Skipped on request: L Wazuh, M Prometheus/Grafana dashboards, N multi-tenancy, O policy workflow, P analytics.
* Not built: signed images / admission policy; the 18-section dashboard rework (replaced by the Security posture page); a database failover manager.
* Not tested: upgrade and rollback paths; Helm install of 2.4 in a cluster; Kubernetes manifests for Redis and point-in-time recovery (dry-run only); `rotate-backup-key.sh`; PowerShell scripts; solved-challenge hand-off of the bot protection.
* Full list: `KNOWN_LIMITATIONS.md`.

## Your production cluster

Unchanged and still on 2.3. The only action on it was scaling the `shieldwaf` deployment back to 2 replicas after it was found at 0 (cause not established). Pushing this code to GitHub deploys nothing.

## Branches

`audit/2.3-baseline`, `feature/ssrf-hardening`, `feature/api-validation`, `feature/audit-logging`, `feature/backup-security`, `feature/database-security`, `feature/container-security`, `feature/redis-ratelimit`, `feature/bot-protection`, `feature/threat-intel`, `feature/db-ha-pitr`, all merged into `release/2.4`; tag `v2.3.0` marks the previous release.
