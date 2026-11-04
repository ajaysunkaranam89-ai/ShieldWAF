# A Shield WAF 2.4 — Security hardening

What 2.4 adds on top of 2.3, how to switch it on, and how each control was tested. Controls that are **not** in this release are listed in `KNOWN_LIMITATIONS.md`.

## 1. SSRF protection for everything the panel connects to (module A)

Every URL that an operator can enter (upstream servers, alert webhooks, threat-feed URLs, ACME directory, OIDC issuer) goes through one guard, `panel/netguard.py`:

* every address a name resolves to is classified; **one bad address blocks the name** (a name that returns a public and a private address is refused);
* never allowed, whatever the allowlist: loopback, link-local (including the cloud metadata address 169.254.169.254), unspecified, multicast, reserved, carrier-grade NAT;
* IPv6 forms that wrap an IPv4 address (mapped, NAT64, 6to4, Teredo) are unwrapped and judged as the IPv4 address; numeric forms (`2130706433`, `0177.0.0.1`) are normalized;
* private addresses are allowed only inside the allowlist (Settings → "Private networks that upstreams may use"; default RFC 1918 + `fc00::/7`, so 2.3 installations keep working);
* redirects are followed one hop at a time and each hop is checked again;
* the leader re-resolves upstream names every 15 s; a name that starts to point somewhere forbidden is taken out of rotation (`ssrf_blocked`, alert event, audit record);
* optional **DNS pinning** (Settings): the engine connects to the checked IP address and sends the original name for TLS (SNI), so the name cannot change between check and use.

Tested: `tests/unit/test_netguard.py` (28 tests, includes the bypasses reproduced against 2.3 such as `127.0.0.1.nip.io`, `169.254.169.254.nip.io`, `0177.0.0.1`, `100.64.0.1`, mapped IPv6).

## 2. OpenAPI request validation (module B)

Sites can upload an OpenAPI 3 document; `panel/openapi.py` compiles it into ModSecurity rules: allowed methods and paths, required and typed parameters, enums, formats, lengths, numeric ranges,
JSON body fields (including nested objects and arrays, `allOf` merging, unknown fields reported or blocked in strict mode), body size and nesting limits (`max_body_kb`, `max_depth`).
Tested against the real engine in `tests/unit/test_openapi.py` (32 tests). Known gaps (an empty array cannot be told from a missing one; `oneOf/anyOf` are not enforced) are listed in `KNOWN_LIMITATIONS.md`.

## 3. Database (module D)

| Control | Setting |
|---|---|
| TLS 1.2+ on the database, plain network connections rejected | built into `shieldwaf-db:2.4` (own certificate: mount a secret with `tls.crt`/`tls.key` at `/tls`; `SHIELD_DB_TLS=off` disables it, not recommended) |
| Panel connects with TLS | `SHIELD_DB_SSLMODE=require` (set in the manifest and chart); `verify-full` plus `SHIELD_DB_SSLROOTCERT` when you use your own CA |
| Least-privilege runtime role | `SHIELD_DB_URL` = role `shieldwaf_app` (data changes only; **audit trail: SELECT and INSERT only**; no DDL, no superuser); `SHIELD_DB_MIGRATE_URL` = the schema owner, used for migrations, grants and audit retention |
| Timeouts | statement 30 s, lock 10 s, idle-in-transaction 60 s, TCP keepalives (`SHIELD_DB_STATEMENT_TIMEOUT_MS`, `SHIELD_DB_LOCK_TIMEOUT_MS`, `SHIELD_DB_IDLE_TX_TIMEOUT_MS`); also set on the role itself |
| Credential rotation | `dbadmin.py rotate` sets a new random password and ends the open sessions of the role |
| Safe migrations | versioned, transactional (a failed migration leaves nothing behind), serialized across replicas by an advisory lock |

Set-up of the runtime role (run once, with the owner's connection string; the new password is printed once). The commands of `dbadmin.py` are tested against a real PostgreSQL (`tests/db_security.sh`); this `kubectl exec` wrapper around them was **not** run in a cluster:

```sh
kubectl -n shieldwaf exec deploy/shieldwaf -c panel -- env SHIELD_DB_SSLMODE=require \
  SHIELD_DB_MIGRATE_URL="$(kubectl -n shieldwaf get secret shieldwaf-db -o jsonpath='{.data.SHIELD_DB_URL}' | base64 -d)" \
  python3 /panel/dbadmin.py roles --print-password
```

Then put `postgresql://shieldwaf_app:<password>@shieldwaf-db:5432/shieldwaf` into the secret key `SHIELD_DB_URL`, the owner string into a new key `SHIELD_DB_MIGRATE_URL`, and set `SHIELD_DB_APP_ROLE=shieldwaf_app` on the panel container.
**This wiring is not automated in the manifests in 2.4** (see `KNOWN_LIMITATIONS.md`): the panel container still holds the owner credential as long as it runs the migrations itself.
`python3 /panel/dbadmin.py check` (with the runtime URL) prints what that connection can and cannot do and exits with 1 if something is unsafe.
Tested: `tests/db_security.sh` (33 checks on a real PostgreSQL: plain connection refused, TLS 1.3, UPDATE/DELETE/TRUNCATE/DROP on the audit trail refused, no CREATE, no pg_authid, rotation, failed-migration rollback).

## 4. Backups (module E)

AES-256-GCM, authenticated chunks, separate key ring, rotation, weekly restore test, independent S3 destination: see `DISASTER_RECOVERY.md`.

## 5. Audit trail (module F)

* every record carries a sequence number and `hash = HMAC-SHA256(key, record + previous hash)`; the key is **not** in the database (`SHIELD_AUDIT_KEY`, or derived from `SHIELD_DATA_KEY`);
* Audit → "Verify" names the first broken record; "Export" gives a JSON or CSV file with a signed checkpoint, so deleting the **end** of the trail is detected against an earlier export;
* retention (`audit_retention_days`) removes old records from the start only, and keeps an anchor so the rest still verifies;
* records are forwarded to your SIEM as JSON (alert channel event `audit_tamper` raises an alert when verification fails);
* every request gets a request id that is stored in the record and returned in the `X-Request-ID` header.

What this does not do: somebody who can run code **inside the panel** holds the audit key and can write a valid chain. Keep signed exports somewhere the panel cannot write (see `KNOWN_LIMITATIONS.md`).

## 5b. Containers and Kubernetes (modules C and K)

* The engine container reads `/data` **read-only** (rules, certificates, feeds); it writes only `rendered/` (its status files) and `logs/`. The panel-only secrets (session key, setup code, alert / ACME / OIDC / CrowdSec secrets) are in `/private`, a memory volume that only the panel container mounts (`SHIELD_PRIVATE=/private`; unset = the same folder as `/data`, as in 2.3).
* One service account per component (`shieldwaf-app`, `shieldwaf-db`, `shieldwaf-backup`, `shieldwaf-redis`), none with permissions or a token.
* Pods spread over nodes **and zones**; optional `k8s/namespace-guardrails.yaml` (LimitRange + ResourceQuota); the existing "restricted" Pod Security level, read-only root file systems, dropped capabilities, seccomp, default-deny NetworkPolicy.
* Tested in a cluster: `SUITES=hardening bash tests/run.sh` (24 checks: what the engine can and cannot read or write, tokens, RBAC, security contexts, spread, PDB, policies).
* Not done: signed images / admission policy, user namespaces, a separate init container for migrations (see 3 above).

## 5c. Rate limiting across replicas (module G)

A site can count its rate limit **across all replicas**: nginx asks a small server on `127.0.0.1:9101` (inside the pod) before passing a request on, and the answer comes from one token bucket per (site, client) in Redis (one Lua script, Redis's clock, IPv6 counted per /64). The per-replica `limit_req` stays as a safety net. Redis down → the request is allowed and counted as an error (a short circuit breaker avoids waiting on it); `SHIELD_RL_FAIL=closed` refuses instead. Redis needs a password and is reachable only from the WAF pods (`k8s/redis.yaml`); it holds only counters. Tested with real Redis and real nginx (`tests/redis_ratelimit.sh`, 20 checks). Not tested in a cluster.

## 5d. Bot protection (module H)

`panel/njs/bots.js` scores each request from header behaviour (no user agent, scanner and automation agents, a "browser" without Accept-Language / Accept-Encoding, headless browsers, modern Chrome without Sec-Fetch headers over HTTPS, malformed forwarding headers). Per site: off / detect / block / challenge, a threshold (default 6), paths and user agents that are never judged. Challenge mode sends suspects to the existing proof-of-work page and lets clients with a valid solved-challenge cookie through. **The score is a hint, not proof**: a real browser driven by automation passes it; combine with the rate limit and the challenge. The client-sent `X-Shield-Bot-Score` header is always replaced. Tested in the real engine (`tests/unit/test_bots.py`, 11 tests); the hand-off with a *solved* challenge cookie is not covered by a test.

## 5e. Threat intelligence and CrowdSec (module I)

Feeds: each source keeps a last-good copy (up to 7 days) so one feed being down does not remove its entries; the list is merged and filtered (private ranges, very wide prefixes, your protected networks). CrowdSec: the panel is a standard bouncer (`/v1/decisions/stream`, key in the panel-only secrets), only bans of addresses and ranges, applied by the leader every 30 s, decisions expire locally. Tested against a real CrowdSec Local API (`tests/crowdsec.sh`, 15 checks). Not done: sending the WAF's own blocks back to CrowdSec; mapping CrowdSec "captcha" decisions to the challenge.

## 5f. Recovery objectives (module J)

Nightly dump (RPO ≤ 24 h) or, with the optional WAL archive and weekly encrypted base backup, point-in-time recovery (RPO minutes). Details, the tested procedure and its limits: `DISASTER_RECOVERY.md`. The archived WAL is not encrypted by the tool.

## 6. Verify it yourself

```sh
bash tests/unit/run.sh          # unit tests (SSRF, OpenAPI, bots, audit, backup format, feeds, posture)  126 tests
bash tests/backup_crypto.sh     # real PostgreSQL + S3 server                              25 checks
bash tests/db_security.sh       # real PostgreSQL with TLS and the runtime role           33 checks
bash tests/db_pitr.sh           # point-in-time recovery on real PostgreSQL               13 checks
bash tests/dbfailover.sh        # primary stopped, standby promoted, panel keeps writing   6 checks
bash tests/redis_ratelimit.sh   # real Redis + real nginx                                  20 checks
bash tests/crowdsec.sh          # real CrowdSec Local API                                  15 checks
IMG_TAG=2.4-dev bash tests/run.sh   # cluster suites on a throw-away namespace (kind)
```
