# A Shield WAF 2.4 — Known limitations and what is not done

Status of the 2.4 plan, stated plainly. "Done" means implemented **and** covered by a test that was run (counts in `SECURITY_HARDENING.md`).

## Delivered (modules and how they were verified)

| Module | State | Verified by |
|---|---|---|
| A SSRF protection | done | 28 unit tests, plus the functional suite |
| B OpenAPI validation | done, with gaps below | 32 tests against the real engine |
| D Database security | done in code, image and tests; manifest wiring of the separate runtime role not automated (below) | `tests/db_security.sh`, 33 checks on real PostgreSQL |
| E Backup security | done | 24 unit tests, `tests/backup_crypto.sh` 25 checks (PostgreSQL + S3 server), `tests/backup_test.py` 18 checks on a kind test namespace |
| F Audit logging | done, with the limits below | 19 unit tests, real PostgreSQL with concurrent writers |

## Not implemented in this release

* **C — container security:** the engine and the panel still share the `/data` volume, and the panel container still holds the files that should be panel-only (`secret.key`, bootstrap code, ACME account key, OIDC secret); separate service accounts per component are not created. The existing hardening of 2.3 (non-root, read-only root file system, dropped capabilities, seccomp, network policies) is unchanged.
* **G Redis distributed rate limiting, H bot protection, I threat-intelligence/CrowdSec:** not started. Rate limiting stays per replica (finding F-07 of the baseline audit).
* **J PostgreSQL HA with tested failover and point-in-time recovery:** not implemented. The 2.3 test `tests/dbfailover.sh` (client reconnect after a database restart/failover) still exists; there is no WAL archiving, so recovery is to the last backup (RPO up to 24 h by default).
* **K additional Kubernetes hardening** (pod anti-affinity beyond 2.3, topology spread, PSA labels, signed images): not done.
* **L Wazuh decoders and rules, M Prometheus/Grafana dashboards:** not started (the 2.3 built-in dashboards and Prometheus metrics endpoint are unchanged).
* **N multi-tenancy, O policy approval/versioning workflow, P analytics, the 18-section dashboard rework:** not started.
* **Performance comparison 2.3 vs 2.4 (k6/Locust) and a penetration-test report:** not run. No performance number is claimed for 2.4.
* **Remaining documents:** architecture, Docker/Kubernetes deployment guides, Wazuh, Prometheus/Grafana, penetration testing and administrator guide were not written. The existing `INSTALL.md`, `USER-GUIDE.md`, `CLOUD.md`, `DDOS.md` and `TROUBLESHOOTING.md` are from 2.3 and are not all updated for 2.4.

## Limits of what is delivered

* **Database roles in Kubernetes:** `dbadmin.py roles` creates and tests the runtime role, but the manifests/chart still hand the panel the owner connection string. Until the runtime and owner strings are split in the secret (see `SECURITY_HARDENING.md`) the panel can still change the audit trail through its own credential. An init container for migrations is the clean fix and is not built.
* **TLS to the database is encryption only by default** (self-signed certificate, `sslmode=require`: protects against eavesdropping, not against a man-in-the-middle). Mount your own certificate and use `verify-full` for that.
* **Audit trail:** someone who can run code inside the panel holds the audit key and can write a valid chain; deleting the end of the chain is only detected against an earlier signed export. There is no write-once storage for exports.
* **OpenAPI:** an empty array cannot be told from a missing one (`minItems` is enforced for required arrays only); `oneOf`/`anyOf`/`not` are not enforced; regex patterns that ModSecurity cannot express are reported and skipped, not silently dropped.
* **Backups:** no point-in-time recovery; the key ring has no automatic offline copy (you must make one); the independent S3 copy is not re-encrypted by `reencrypt`; 2.3 backups cannot be read by the 2.4 tool.
* **SSRF:** the check is at configuration time and every 15 s by the leader. DNS pinning is optional and off by default (it changes how the engine connects); without it there is a short window in which a name can change between check and use.
* **Not tested:** the rollback path 2.4 → 2.3, the Helm chart installed with the new backup options in a cluster (rendered and linted only), the `kubectl`-based key-rotation script `rotate-backup-key.sh` (written, not run), the PowerShell scripts (not run).
* **Open test failure from earlier work:** in the functional suite, the check "country data downloads from the five registries" failed once on the Module A build; its cause is unknown (see the status of the last full run in the 2.4 report).
