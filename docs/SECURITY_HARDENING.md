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

## 6. Verify it yourself

```sh
bash tests/unit/run.sh          # unit tests (SSRF, OpenAPI, audit, backup format)         103 tests
bash tests/backup_crypto.sh     # real PostgreSQL + S3 server                              25 checks
bash tests/db_security.sh       # real PostgreSQL with TLS and the runtime role           33 checks
IMG_TAG=2.4-dev bash tests/run.sh   # cluster suites on a throw-away namespace (kind)
```
