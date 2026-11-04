# A Shield WAF 2.4 — status, assessment and what remains

Date: 2026-11-04. Branch `release/2.4`. Version 2.4 in the panel, image label and chart. Tests were run on this machine (Docker Desktop + a kind cluster); counts are from the runs.

## Test results

| Suite | Result |
|---|---|
| Unit tests (`tests/unit/run.sh`) | 126 tests OK (SSRF 28, OpenAPI 32 on the real engine, bots 11 on the real engine, audit 19, backup format 24, feeds 6, posture 4, paths 2, others) |
| `tests/backup_crypto.sh` (real PostgreSQL + S3 server) | 25/25 |
| `tests/db_security.sh` (real PostgreSQL with TLS, restricted role, wait-only startup) | 35/35 |
| `tests/db_pitr.sh` (real PostgreSQL, point-in-time recovery) | 13/13 |
| `tests/dbfailover.sh` (primary stopped, standby promoted) | 6/6 |
| `tests/redis_ratelimit.sh` (real Redis + real nginx) | 14/14 + 6/6 (re-run after the keep-alive change to the limiter) |
| `tests/crowdsec.sh` (real CrowdSec Local API) | 15/15 |
| Cluster, `SUITES=hardening` | 24/24 (also on the restricted-role layout) |
| Cluster, `SUITES=functional` (2 replicas) | **202/202**, also on the restricted-role layout (final) |
| Cluster, `SUITES=ha` (3 replicas) | **91/91** on the restricted-role layout (final) |
| Cluster, `SUITES=backup` | 18/18 (restricted-role layout, after fixing a Windows-only secret-script flake) |
| Docker Compose deployment | started: database healthy, panel health check answers, engine serves its health URL. Not run through a protection test |

The cluster suites ran on the images built before the last small engine change (keep-alive upstream for the rate-limit limiter, used only by sites with a cluster-wide limit). That change is covered by the Docker test above, not by a cluster run.

## Performance (tests/perf, k6 against the real engine in Docker)

Second run (idle machine, final code including kept-alive connections to the limiter), 64 virtual users, 15 s per case, one engine container with 2 workers, a trivial backend, no OWASP rules loaded. The load generator shares the Docker VM, so absolute numbers mean little; the relative ones are what to read. (A first run the same day, before the keep-alive change, showed the same picture for the cluster-wide limit: about 1,100 req/s.)

| Case | req/s | p50 ms | p95 ms | p99 ms | vs 2.4 plain |
|---|---|---|---|---|---|
| 2.3 plain | 11,224 | 4.8 | 11.1 | 15.7 | 97 % |
| 2.4 plain | 11,575 | 4.8 | 9.9 | 13.7 | 100 % |
| 2.4 per-replica rate limit | 11,201 | 5.0 | 10.1 | 13.8 | 97 % |
| 2.4 bot protection (block) | 6,253 | 9.6 | 15.7 | 21.2 | 54 % |
| 2.4 cluster-wide limit (Redis) | 1,092 | 54.7 | 78.4 | 200.7 | **9.4 %** |
| 2.4 bots + cluster-wide limit | 1,091 | 57.3 | 72.2 | 81.7 | 9.4 % |

What this says:
1. The plain request path is unchanged from 2.3 (within noise), and a per-replica rate limit costs about 3 %.
2. Bot scoring costs about 0.07 ms of CPU per request (54 % of the throughput of a request that does nothing else). Next to the OWASP rule set, which costs milliseconds per request (not measured here), this is small, but it is not free.
3. **The cluster-wide rate limit is the expensive feature: one engine replica tops out at about 1,100 requests per second on a site that uses it** (the limiter is a single Python process; keep-alive connections did not change this, so the bottleneck is the limiter itself, not connection setup). Sites with more traffic per replica than that must use the per-replica limit, or this component must be replaced by something faster (for example njs talking to Redis, or a native module). This is the main performance finding of the release.
4. Not measured: the OWASP rule set, TLS, real backends, several replicas, Redis on another host, the 2.3 vs 2.4 comparison of the full path.

## Security assessment (self-review, not an independent audit)

Closed from the baseline audit: SSRF bypasses, mutable audit log, same-key CBC backups, unencrypted database traffic in code and image, OpenAPI gaps, no unit tests in CI, panel secrets visible to the engine container, no cluster-wide rate limit, no point-in-time recovery. Evidence and details: `SECURITY_HARDENING.md`.

Residual risks that matter most:
1. New installations run the panel as the restricted database role (tested in the cluster); **existing 2.3 installations keep the owner credential in the panel until their secret is switched** (steps documented, not tested on an existing installation). In restricted mode the audit retention job cannot run.
2. No failover manager for the database; the WAL archive for point-in-time recovery is not encrypted.
3. The bot score is a hint; a real browser under automation passes it.
4. Database TLS is encryption without server authentication unless you mount your own certificate and use `verify-full`.
5. Redis (optional) is a single pod without persistence; the cluster-wide limit depends on it (fails open by default).

## Production readiness

**Better than 2.3 on every item above, but not recommended for production yet.** Before production: (a) switch an existing installation's secret to the restricted role (or accept risk 1 knowingly); (b) test the 2.3 → 2.4 upgrade and the rollback on a copy: neither was tested; (c) re-run the cluster suites on the final images and measure performance on an idle machine; (d) have the penetration-test plan (`PENETRATION_TESTING.md`) carried out; (e) decide on the optional features (Redis, CrowdSec, WAL archive). It is suitable for a test cluster.

## Not done

* Skipped on request: L Wazuh, M Prometheus/Grafana dashboards, N multi-tenancy, O policy workflow, P analytics.
* Not built: signed images / admission policy; the 18-section dashboard rework (replaced by the Security posture page); a database failover manager.
* Not tested: upgrade and rollback paths; Helm install of 2.4 in a cluster; Kubernetes manifests for Redis and point-in-time recovery (dry-run only); `rotate-backup-key.sh`; PowerShell scripts; solved-challenge hand-off of the bot protection.
* Full list: `KNOWN_LIMITATIONS.md`.

## Your production cluster

Unchanged and still on 2.3. The only action on it was scaling the `shieldwaf` deployment back to 2 replicas after it was found at 0 (cause not established). Pushing this code to GitHub deploys nothing.

## Branches

`audit/2.3-baseline`, `feature/ssrf-hardening`, `feature/api-validation`, `feature/audit-logging`, `feature/backup-security`, `feature/database-security`, `feature/container-security`, `feature/redis-ratelimit`, `feature/bot-protection`, `feature/threat-intel`, `feature/db-ha-pitr`, all merged into `release/2.4`; tag `v2.3.0` marks the previous release.
