# Administrator guide (2.4 additions)

The 2.3 guide (`USER-GUIDE.md`) still describes sites, rules, bans, alerts, users and certificates. This page covers what is new in 2.4 and the routine jobs. Everything here is in the panel unless stated.

## Daily / weekly routine

| When | What | Where |
|---|---|---|
| Daily, 1 minute | Open **Security posture**: any "attention" or "problem" tells you what to do | Security posture |
| Daily | Look at the attack log and the dashboards for spikes | Dashboard, Attack log |
| Weekly | Check that the **weekly restore test** job passed: `kubectl -n shieldwaf get jobs` | cluster |
| Weekly | Review Audit → filter category "admin" and "policy" for changes you did not make | Audit |
| Monthly | Export the audit trail (Audit → Export) and keep the file outside the cluster | Audit |
| Monthly | Update OWASP rules (Rule updates), apply the canary channel first on one site | Rule updates |
| Yearly / on staff change | Rotate the backup key (`scripts/rotate-backup-key.sh`), the database password (`dbadmin.py rotate`) | cluster |

## Protections you can switch on per site

* **Rate limit** — "Counted: per replica" (fast, each replica counts alone) or "across all replicas (Redis)" (one counter for the whole cluster; needs `k8s/redis.yaml`). If Redis is unavailable the limit falls back to per replica; the site page and Security posture say so. **Capacity:** a site with a cluster-wide limit handles about 1,100 requests per second per replica (measured); busier sites should keep "per replica".
* **Bot protection** — mode `detect` first (the score appears in the access log and in the header `X-Shield-Bot-Score` to your application), look at what would be caught, then `block` or `challenge` (proof-of-work page; needs the anti-bot challenge on). Put machine clients' paths (`/api/`) in "never judged". Default threshold 6: an automation library alone (4 points) is not enough.
* **OpenAPI validation**, **country rules**, **login gate**, **maintenance page**, **custom rules**: as in 2.3; the OpenAPI settings now include body size and depth limits.

## Threat intelligence

Threat intel page: reputation feeds (a feed that is down keeps its last good copy for 7 days) and **CrowdSec**: enter the Local API address (for example `http://crowdsec:8080`) and the bouncer key from `cscli bouncers add shieldwaf`. The panel pulls bans every 30 seconds; the key is stored encrypted and never shown again. Private ranges, very wide ranges and your protected networks are never listed.

## When something goes wrong

| Symptom | First look | Fix |
|---|---|---|
| Site answers 502 and the site page says "refused (SSRF)" | upstream resolves to a forbidden address | fix DNS / add the private network in Settings → upstream private networks (loopback, link-local, metadata are never allowed) |
| Audit shows "chain BROKEN" | Audit → Verify names the first broken record | stop, preserve the database, compare with the last signed export; treat as an incident |
| Backup job fails | `kubectl logs job/<name>`; Security posture → Backups | wrong key ring, database unreachable, S3 credentials |
| "Redis NOT reachable" | Security posture → Rate limiting | Redis pod / secret; meanwhile limits are per replica |
| Panel will not start after an upgrade | panel container log (migrations print their version) | `docs/ROLLBACK_GUIDE.md` |
| Locked out of the panel | recovery codes; `docs/TROUBLESHOOTING.md` | |

## Restoring

`docs/DISASTER_RECOVERY.md` (dump restore, point-in-time recovery, total loss, key rotation). **Test a restore before you need one**: the weekly job does it automatically into a temporary database.

## Security basics for operators

Administrators with 2FA or SSO only; the panel never on the internet; the database secret, the backup key ring and the Redis secret kept as separate secrets with an offline copy of the key ring; read `docs/SECURITY_HARDENING.md` for the controls and `docs/KNOWN_LIMITATIONS.md` for what they do not cover.
