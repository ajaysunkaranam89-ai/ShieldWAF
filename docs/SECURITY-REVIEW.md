# Security self-review of A Shield WAF 2.3

**This is a self-review, not an independent audit.** It was performed by the author with open-source tools and automated tests, and it
documents what was checked, what was found and what was done about it. It lowers the chance of mistakes; it cannot replace an
independent penetration test and code review by people who did not write the code. Commission one before using the product for
regulated or high-value systems. Date of this review: 2026-11-03, version 2.3.

**What was re-run for 2.3 (high availability, shared rule set, Dashboards):** Bandit, Trivy (image and manifests) and gitleaks, plus the automated tests
(sections 1, 4 and 6 below are updated). The OWASP ZAP baseline (section 5) was run on 2.2 and was **not** repeated for 2.3; the panel gained two read-only pages (Cluster, Dashboards)
that follow the same rules as the others (login, escaped output, strict CSP), but they were not scanned separately.
New things to review in 2.3 (in addition to the Pebble-tested ACME client, `panel/acme.py`): the encrypted file sharing through the database (`panel/sharedfs.py`: authenticated encryption, fixed list of path shapes, checked archive extraction),
the cluster-wide lock and leader election (`panel/store.py`, `panel/cluster.py`), and the per-site settings dispatch inside the shared rule set (`panel/engine.py`: wildcard and exact host names,
fail-closed default for a request that matches no site, tested with upper-case and trailing-dot host names).

## 1. Static analysis (Bandit, Python code, about 3,500 lines)
Result on 2.3: **0 high, 0 medium, 20 low** findings (2.2: 0 high, 1 medium, 14 low); the low ones are empty-string defaults flagged as passwords, subprocess calls with fixed arguments, and deliberate `except: pass` around clean-up. Every finding was reviewed (the 2.1 round fixed 5 real low findings: asserts used for validation, bare binary paths).

| Finding | Count | Verdict and action |
|---|---|---|
| B310 `urllib.urlopen` scheme (feeds download, health check) | 2 | False positives. The feed URL must be `https://` (checked twice: `check_url`, and an explicit guard right before the request) and its host must resolve to public addresses only; the health check is a fixed loopback URL. Annotated with the reason. |
| B108 hard-coded `/tmp` path | 1 | False positive. `/tmp` is the pod's private emptyDir, not a shared host directory. Annotated. |
| B101 `assert` used for input validation | 5 | **Real (low): asserts are skipped when Python runs with `-O`.** Replaced with explicit checks that raise errors. |
| B603 / B607 / B404 subprocess calls | 7 | The calls use fixed argument lists, never a shell, and no unvalidated user text (host names and mounted-secret names are validated before use; passwords go through stdin). **Hardened:** `nginx` and `openssl` are now called by absolute path. |
| B105 "hard-coded password" | 6 | False positives: empty-string defaults such as `"totp_secret": ""`. No secret is in the code. |
| B608 SQL built from a string | 1 | False positive: the only interpolated value is a code constant (`HOUR`, the hour-bucket expression that differs between PostgreSQL and SQLite); every value from a request is a bound parameter. Annotated. |
| B110 `try/except/pass` | 3 | Deliberate: alert delivery must never break the application. |

## 2. Configuration scan (Trivy, Kubernetes manifest + Dockerfiles)
**0 misconfigurations** at medium, high and critical severity (restricted Pod Security level, non-root, read-only filesystem, all capabilities
dropped, seccomp, no service-account token, resource limits, network policies, hardened PostgreSQL pod).
At low severity the scan reported 9 items; fixed: **CPU limits** on all containers, and the engine and panel now run as **UID/GID 10101** (above 10000). Accepted: the PostgreSQL pod runs as UID 70, because the PostgreSQL image's `initdb` must find its user in `/etc/passwd`.

## 3. Dockerfile lint (hadolint)
Two notes, both accepted: `USER root` is needed only during the build to install packages (the image runs as UID 101);
packages installed with `apk add` are not version-pinned because Alpine removes old versions from its repositories, which would break rebuilds;
instead the **base image is pinned by digest** and the image is re-scanned.

## 4. Image vulnerability scan (Trivy, OS and language packages)
- Panel / engine image `shieldwaf:2.3`: **0 high or critical** vulnerabilities (with fixes available) at the time of the scan.
- PostgreSQL: the official image's operating-system packages were clean, but it bundles `gosu`, a helper built with an outdated Go runtime (26 high / critical findings). It is never executed here (the pod is non-root), so it was **removed** in `db/Dockerfile`, and the derived image `shieldwaf-db:16` scans **clean**.
Re-run before every release (the CI workflow does it weekly).

## 5. Web scanner baseline (OWASP ZAP 2.x, passive scan + spider)
| Target | Fail | Warn | Pass |
|---|---|---|---|
| Admin panel (https) | **0** | 6 | 62 |
| A protected application through the WAF | **0** | 5 | 63 |

Panel warnings and actions:
- *Re-examine cache-control directives* and *non-storable content*: **fixed.** Panel pages now send `no-store, no-cache, must-revalidate, max-age=0` and `Pragma: no-cache`; static assets (logo, CSS, JS) are cacheable for an hour.
- *Cross-origin-embedder-policy missing*: **fixed** (`require-corp`).
- *CSP `style-src 'unsafe-inline'`*: **accepted risk.** Scripts are strictly `'self'` (no inline script, no `eval`); only inline *styles* are allowed because the templates use style attributes. Inline styles cannot execute code.
- *Authentication request / session management identified*: informational (the login form and session cookie were found, as expected).

Warnings on the protected application are about the application's own responses (for example no Content-Security-Policy header from the sample app).
A WAF should not invent application-specific policies; the WAF adds the generic ones (X-Frame-Options, nosniff, Referrer-Policy, Permissions-Policy, HSTS).

## 6. Automated attack and abuse tests (192 checks + HA checks, run on a live cluster with PostgreSQL)
All pass. The functional suite runs on **two replicas**; a second suite adds the high-availability checks on three replicas (shared sessions, keys and certificates, concurrent administrators, 80 sites, leader failure, database outage, rolling restart under load). They include attacks against the product itself, not only against the applications behind it:
weak and wrong passwords, setup-code abuse, login lockout, two-factor replay and recovery-code reuse, session revocation after logout and after
password change, stolen-cookie reuse, missing CSRF token, CSP / HSTS / cookie flags, metrics without token, panel allow-list self-lockout,
SSRF to loopback / cloud-metadata addresses and names, feed URLs that resolve to private addresses, malicious configuration import,
viewer role trying to change settings or read admin pages, deleting or demoting the last administrator, spoofed `X-Forwarded-For`,
oversized headers, forbidden methods, TLS 1.1 downgrade, handshake for unknown host names, mismatched certificate and key, private key
disclosure in the GUI, login-gate brute credentials, forged and replayed anti-bot proofs and cookies, positive-model bypass attempts,
reputation-listed and country-blocked addresses, request floods and automatic escalation, alert channels pointed at loopback and cloud-metadata addresses, secrets leaking into the GUI or its pages, secret files with loose permissions, a malformed or non-OpenAPI document, mass-assignment and over-long fields against an OpenAPI-protected API, a rule set promoted without confirmation, and state surviving a restart in PostgreSQL.

## 7. Design review notes (threat model summary)
| Threat | Mitigation | Residual risk |
|---|---|---|
| Admin account takeover | strong password policy, TOTP 2FA, lockout, revocable sessions, IP allow-list, audit | phishing of password + live TOTP code; a stolen session within its idle window |
| Panel used to attack the cluster (SSRF) | upstream and feed-URL validation, network policy without metadata egress | an admin can still point a site at any other internal service unless "allowed upstream suffixes" is set (set it) |
| Malicious configuration reaching nginx | form and import validation, `nginx -t`, no shell, custom rules limited and tested | an administrator can write custom ModSecurity rules (by design) |
| Container escape / pod compromise | non-root, read-only filesystem, no capabilities, seccomp, no service-account token, separate containers | shared data volume between the two containers (needed for hand-over) |
| Supply chain | base images pinned by digest, scanned, small package lists; OWASP rule updates are staged, canary-tested and approved by a person, downloaded from github.com over HTTPS only with size limits and safe unpacking | the download is not signature-verified (the SHA-256 is shown for you to compare); Alpine updates need a rebuild |
| Alert channels abused to reach internal services | targets validated (no loopback / link-local / metadata), admin-only, secrets stored 0600 and never displayed | an administrator can point an alert at any private address by design (an internal SIEM) |
| Database compromise | only the panel can reach PostgreSQL (network policy), random password in a cluster secret, non-root read-only pod | no TLS inside the cluster by default; use a managed database with `sslmode=require` in production |
| Rule bypass | positive model, reputation, country, challenge, flood defence on top of the OWASP rules | a determined attacker with an application-specific bypass |
| Volumetric DDoS | none in the product (impossible there) | must be handled upstream, see `DDOS.md` |

## 8. Known limitations that remain
No independent audit; the database is the single point of failure; pattern-based core rule set; no automatic certificate renewal (cert-manager recommended);
`style-src 'unsafe-inline'` on the admin panel; rate limits are counted per replica.
