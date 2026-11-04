# A Shield WAF 2.4 — status, assessment and what remains

Date of this report: 2026-11-04. Branch `release/2.4` (local; **nothing pushed, nothing deployed**; your cluster namespace `shieldwaf` still runs 2.3).

## Test results (all run on this machine; counts are from the runs)

| Suite | Result |
|---|---|
| Unit tests (`tests/unit/run.sh`) | 103 tests, OK (netguard 28, OpenAPI 32 against the real engine, audit 19, backup format 24) |
| `tests/backup_crypto.sh` (real PostgreSQL 16 + S3 server) | 25/25 |
| `tests/db_security.sh` (real PostgreSQL 16 with TLS) | 33/33 |
| Cluster backup suite (`SUITES=backup`, kind test namespace) | 18/18 |
| Cluster functional suite (`SUITES=functional`, 2 replicas, 2.4-dev images) | 199/200 on the first run; the one failure was a test that read page 1 of the now-paginated audit page. The test was changed to filter by action; the database showed the expected records exist (10 `login-failed` with 127.0.0.1, 1 `2fa enabled`, 77 newer records). **That test was not re-run after the change.** The earlier "country data" failure did not occur in this run; its cause is still unknown |
| High-availability suite (`SUITES=ha`, 3 replicas, 2.4-dev images) | 90/91. The one failure read the stats of a stale row of an already replaced replica (the nodes table keeps old rows for a while); the live replicas show 85 sites and 1 dedicated site. The test now only reads live replicas; **not re-run** |

Not run: ACME (Pebble), SSO (Dex) and DB-failover Docker tests against 2.4; Helm install in a cluster; any performance or penetration test.

## Security assessment (self-review, not an independent audit)

Closed from the baseline audit (`SHIELDWAF_23_BASELINE_AUDIT.md`): SSRF bypasses (F-01..), mutable audit log, same-key CBC backups, unencrypted/over-privileged database access in code and image, OpenAPI gaps, CI without unit tests. Details and test evidence: `SECURITY_HARDENING.md`.

Residual risks that matter most:
1. The panel container still holds the database owner credential in the stock manifests (runtime role is built and tested but not wired in), so a compromise of the panel can still rewrite the audit trail.
2. Panel and engine share a volume that includes panel-private secrets (module C not done).
3. Rate limiting is per replica; there is no bot protection or threat-intelligence feed beyond 2.3.
4. No PITR or database HA; recovery point is the last nightly backup.
5. Database TLS is encryption without server authentication unless you mount a certificate and use `verify-full`.

## Production readiness

**Not recommended for production yet.** Reasons: the functional fix is unverified, the HA/ACME/SSO/upgrade-path tests were not re-run on 2.4, the rollback path is untested, and modules C, G–P are not built. Suitable for a test cluster. Before production: re-run all cluster suites on the final image, test 2.3 → 2.4 → 2.3 on a copy, wire the runtime role, and decide on module C.

## What is not done

See `KNOWN_LIMITATIONS.md` (modules C, G, H, I, J, K, L, M, N, O, P, dashboard rework, performance comparison, penetration test, remaining documents).

## Branches and commits (local)

`audit/2.3-baseline`, `feature/ssrf-hardening`, `feature/api-validation`, `feature/audit-logging`, `feature/backup-security`, `feature/database-security`, all merged into `release/2.4`; tag `v2.3.0` marks the previous release. No `v2.4.0` tag has been created: create it after the suites are green.
