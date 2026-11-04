# A Shield WAF 2.4 — Known limitations and what is not done

Status of the 2.4 plan, stated plainly. "Done" means implemented **and** covered by a test that was run (counts in `SECURITY_HARDENING.md`).

## Delivered

| Module | State | Verified by |
|---|---|---|
| A SSRF protection | done | 28 unit tests, functional suite |
| B OpenAPI validation | done, with gaps below | 32 tests against the real engine |
| C Container security | done (panel-only secrets volume, read-only engine data, service accounts) | cluster hardening suite 24/24 |
| D Database security | done; the restricted runtime role is wired into the manifests and chart for new installations (init container does the migrations) | `tests/db_security.sh` 35/35, cluster suites on that layout |
| E Backup security | done | 24 unit tests, `tests/backup_crypto.sh` 25/25, cluster backup suite 18/18 |
| F Audit logging | done, with the limits below | 19 unit tests, real PostgreSQL with concurrent writers |
| G Cluster-wide rate limiting (Redis) | done in Docker; not run in a cluster | `tests/redis_ratelimit.sh` 20 checks |
| H Bot protection | done | 11 tests in the real engine |
| I Threat intelligence, CrowdSec | done | `tests/crowdsec.sh` 15 checks (real CrowdSec), 6 feed unit tests |
| J Point-in-time recovery, database failover | done in Docker; manifests not run in a cluster; no failover manager | `tests/db_pitr.sh` 13, `tests/dbfailover.sh` 6 |
| K Kubernetes hardening | partly (see below) | hardening suite |
| Posture page, new metrics, CI, Docker Compose, performance harness | done / written | unit tests; compose stack started and checked |

## Not implemented (by decision or time)

* **L Wazuh decoders and rules, M Prometheus/Grafana dashboards (beyond a few new metrics), N multi-tenancy, O policy approval workflow, P analytics:** skipped on request. The existing 2.3 Prometheus endpoint, built-in dashboards and SIEM forwarding are unchanged; new metrics: rate-limit checks, CrowdSec decisions, audit chain state, backup / verify timestamps.
* **K, remaining:** signed images and admission policy, user namespaces, an init container for migrations, HPA tuning, topology-aware routing.
* **The dashboard "18 sections" rework:** replaced by the Security posture page (11 sections); the dashboards of 2.3 are unchanged.
* **Penetration test:** not performed (`PENETRATION_TESTING.md` is a plan). **Performance comparison:** the k6 harness exists (`tests/perf`); see the status report for whether it was run and its numbers.
* **Documents:** the 2.3 guides (`INSTALL.md`, `USER-GUIDE.md`, `CLOUD.md`, `DDOS.md`, `TROUBLESHOOTING.md`, `README.md`) are not all updated for 2.4.

## Limits of what is delivered

* **Database roles in Kubernetes:** new installations run the panel as the restricted role. **Existing 2.3 installations keep the owner credential in the panel** until their secret is changed (steps in `SECURITY_HARDENING.md`; not tested on an existing installation). In restricted mode the audit retention job cannot run (no DELETE right by design).
* **TLS to the database is encryption only by default** (self-signed certificate, `sslmode=require`: protects against eavesdropping, not a man-in-the-middle). Mount your own certificate and use `verify-full` for that.
* **Audit trail:** someone who can run code inside the panel holds the audit key and can write a valid chain; deleting the end of the chain is only detected against an earlier signed export. There is no write-once storage for exports.
* **OpenAPI:** an empty array cannot be told from a missing one (`minItems` is enforced for required arrays only); `oneOf` / `anyOf` / `not` are not enforced.
* **Backups:** the key ring has no automatic offline copy (you must make one); the independent S3 copy is not re-encrypted by `reencrypt`; 2.3 backups cannot be read by the 2.4 tool. **The WAL archive for point-in-time recovery is not encrypted** (protect the volume).
* **Database HA:** a standby and promotion were tested by hand in Docker; there is no failover manager, no fencing, no automatic re-attachment of the old primary (use CloudNativePG, Patroni or a cloud database).
* **Rate limiting across replicas** adds one local HTTP call and one Redis call per request of a site that uses it. Measured (`tests/perf`, idle machine): **about 1,100 requests per second per replica is the ceiling** for such a site (single Python process); use the per-replica limit for busier sites. Redis is a single pod without persistence.
* **Bot protection** is a header-behaviour score: it cannot catch a real browser under automation. A valid-solved-challenge hand-off is implemented but has no test.
* **SSRF:** checked at configuration time and every 15 s by the leader; DNS pinning is optional and off by default, so without it there is a short window in which a name can change between check and use.
* **CrowdSec:** pull only (bouncer); existing installations do not get the extra optional feed sources automatically (only new settings do).
* **Docker Compose** deployment: one replica of each component, started and health-checked, not run through a complete protection test.
* **Not tested:** the rollback path 2.4 → 2.3; the Helm chart installed in a cluster with the 2.4 options (rendered and linted only); the Kubernetes parts of Redis and point-in-time recovery (manifests dry-run only); `rotate-backup-key.sh` (written, not run); the PowerShell scripts; SSO and ACME integration tests against 2.4 beyond what the HA suite covers.
