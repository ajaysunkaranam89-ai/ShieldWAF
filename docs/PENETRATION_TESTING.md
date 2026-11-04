# Penetration testing guide for A Shield WAF 2.4

**No penetration test was performed for this release.** This document is a plan you (or a tester you hire) can follow, and a list of what the project's own automated tests already cover, so a tester does not repeat it and knows where to look. Test only systems you own or have written permission to test.

## Scope and setup

Use a copy of the system: `deploy/docker-compose.yml` or a `shieldwaf-test` namespace (`SUITES=functional bash tests/run.sh` creates one). Targets: the engine (ports 8080 / 8443), the admin panel (9000), the database and backup tooling, the Kubernetes layout.

## What the project's tests already prove (do not take it on trust, re-run them)

| Area | Test | What it shows |
|---|---|---|
| SSRF | `tests/unit/test_netguard.py` | `127.0.0.1.nip.io`, `169.254.169.254.nip.io`, `localtest.me`, `0177.0.0.1`, `2130706433`, `100.64.0.1`, IPv6-mapped forms, redirects, DNS names with mixed answers are refused |
| OpenAPI rules | `tests/unit/test_openapi.py` | unknown fields, wrong types, bounds, enum, body size, depth, array limits at the real engine |
| Bot rules | `tests/unit/test_bots.py` | scanners, empty / automation agents, header anomalies, modes, exclusions, header spoofing |
| Audit chain | `tests/unit/test_audit.py`, `tests/db_security.sh` | any edit, deletion, reordering or truncation is detected; the runtime role cannot UPDATE / DELETE |
| Backups | `tests/unit/test_backupcrypt.py`, `tests/backup_crypto.sh` | bit flips, truncation, reordering, splicing, wrong key, S3 credentials |
| Database | `tests/db_security.sh` | no plain connection, TLS 1.3, no DDL / pg_authid for the runtime role, timeouts, rotation, failed migration rollback |
| Rate limit | `tests/redis_ratelimit.sh` | one bucket across replicas, IPv6 /64, Redis down (open / closed) |
| Containers | `tests/hardening_test.py` | engine cannot read panel secrets or write outside its folders; no service-account token; RBAC |

## Plan for a tester (what is NOT covered)

1. **WAF bypass** — the OWASP CRS is the detection engine: test with a recent bypass corpus at paranoia levels 1–3 (encoding tricks, HTTP request smuggling against nginx, HTTP/2 specifics, multipart and JSON edge cases). Record what passes at each level; raise the paranoia level or add rules.
2. **Admin panel** — authentication (lockout, 2FA, SSO), CSRF, session handling (`__Host-` cookie), authorization between `admin` and `viewer`, file upload (config import, OpenAPI spec, rule files), template injection, header injection through site settings, stored XSS in log views (user agent, URI).
3. **Configuration-to-nginx injection** — every site setting ends up in nginx or ModSecurity configuration: try newlines, quotes, `}` and `;` in host, upstream, paths, custom rules, bot exclude paths, allow-UA words, OpenAPI patterns.
4. **SSRF beyond the guard** — DNS rebinding with a very short TTL while DNS pinning is **off** (the window is ≤ 15 s by design), redirects to internal addresses through an upstream you control, the ACME and OIDC endpoints, alert webhooks.
5. **Rate limiting and bots** — distributed clients (many IPv4 /24s), IPv6 /64 rotation, forged `X-Forwarded-For` (only trusted proxies are honoured: check the setting), headless browsers with a full header set (the score cannot catch those; the challenge can slow them).
6. **Kubernetes** — from a compromised engine container: reach the panel secrets (should fail), the database (NetworkPolicy), the API server (no token), the node. From a compromised panel container: it holds the database credential (see `KNOWN_LIMITATIONS.md`).
7. **Backups** — restore with a stolen backup file but not the key ring (must fail), tamper with a stored backup, try to restore an old backup over a newer database (the tool replaces everything by design; check your own process around it).
8. **Denial of service** — slow requests, large headers (limits exist), many connections (`limit_conn`), expensive regexes in custom rules, a huge OpenAPI spec.

## Reporting

For every finding record: request or steps, affected component and version, impact, and the setting or fix. Send security reports as described in `SECURITY.md`.
