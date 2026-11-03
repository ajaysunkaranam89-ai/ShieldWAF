# Security self-review of A Shield WAF 2.1

**This is a self-review, not an independent audit.** It was performed by the author with open-source tools and automated tests, and it
documents what was checked, what was found and what was done about it. It lowers the chance of mistakes; it cannot replace an
independent penetration test and code review by people who did not write the code. Commission one before using the product for
regulated or high-value systems. Date of this review: 2026-11-03, version 2.1.

## 1. Static analysis (Bandit, Python code, 2,000 lines)
Result: **0 high, 3 medium, 18 low** findings. Every finding was reviewed.

| Finding | Count | Verdict and action |
|---|---|---|
| B310 `urllib.urlopen` scheme (feeds download, health check) | 2 | False positives. The feed URL must be `https://` (checked twice: `check_url`, and an explicit guard right before the request) and its host must resolve to public addresses only; the health check is a fixed loopback URL. Annotated with the reason. |
| B108 hard-coded `/tmp` path | 1 | False positive. `/tmp` is the pod's private emptyDir, not a shared host directory. Annotated. |
| B101 `assert` used for input validation | 5 | **Real (low): asserts are skipped when Python runs with `-O`.** Replaced with explicit checks that raise errors. |
| B603 / B607 / B404 subprocess calls | 7 | The calls use fixed argument lists, never a shell, and no unvalidated user text (host names and mounted-secret names are validated before use; passwords go through stdin). **Hardened:** `nginx` and `openssl` are now called by absolute path. |
| B105 "hard-coded password" | 6 | False positives: empty-string defaults such as `"totp_secret": ""`. No secret is in the code. |

## 2. Configuration scan (Trivy, Kubernetes manifest + Dockerfile)
**0 misconfigurations** at medium, high and critical severity (restricted Pod Security level, non-root, read-only filesystem, all capabilities
dropped, seccomp, no service-account token, resource limits, network policies).

## 3. Dockerfile lint (hadolint)
Two notes, both accepted: `USER root` is needed only during the build to install packages (the image runs as UID 101);
packages installed with `apk add` are not version-pinned because Alpine removes old versions from its repositories, which would break rebuilds;
instead the **base image is pinned by digest** and the image is re-scanned.

## 4. Image vulnerability scan (Trivy, OS and language packages)
See the result recorded in `SECURITY.md` / release notes: **0 high or critical vulnerabilities** with fixes available at the time of the scan.
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

## 6. Automated attack and abuse tests (130 checks, run on a live cluster)
All pass. They include attacks against the product itself, not only against the applications behind it:
weak and wrong passwords, setup-code abuse, login lockout, two-factor replay and recovery-code reuse, session revocation after logout and after
password change, stolen-cookie reuse, missing CSRF token, CSP / HSTS / cookie flags, metrics without token, panel allow-list self-lockout,
SSRF to loopback / cloud-metadata addresses and names, feed URLs that resolve to private addresses, malicious configuration import,
viewer role trying to change settings or read admin pages, deleting or demoting the last administrator, spoofed `X-Forwarded-For`,
oversized headers, forbidden methods, TLS 1.1 downgrade, handshake for unknown host names, mismatched certificate and key, private key
disclosure in the GUI, login-gate brute credentials, forged and replayed anti-bot proofs and cookies, positive-model bypass attempts,
reputation-listed and country-blocked addresses, request floods and automatic escalation.

## 7. Design review notes (threat model summary)
| Threat | Mitigation | Residual risk |
|---|---|---|
| Admin account takeover | strong password policy, TOTP 2FA, lockout, revocable sessions, IP allow-list, audit | phishing of password + live TOTP code; a stolen session within its idle window |
| Panel used to attack the cluster (SSRF) | upstream and feed-URL validation, network policy without metadata egress | an admin can still point a site at any other internal service unless "allowed upstream suffixes" is set (set it) |
| Malicious configuration reaching nginx | form and import validation, `nginx -t`, no shell, custom rules limited and tested | an administrator can write custom ModSecurity rules (by design) |
| Container escape / pod compromise | non-root, read-only filesystem, no capabilities, seccomp, no service-account token, separate containers | shared data volume between the two containers (needed for hand-over) |
| Supply chain | base image pinned by digest, scanned, small package list | upstream OWASP / Alpine updates must be pulled by rebuilding |
| Rule bypass | positive model, reputation, country, challenge, flood defence on top of the OWASP rules | a determined attacker with an application-specific bypass |
| Volumetric DDoS | none in the product (impossible there) | must be handled upstream, see `DDOS.md` |

## 8. Known limitations that remain
Single replica; no independent audit; pattern-based core rule set; no automatic certificate renewal (cert-manager recommended);
`style-src 'unsafe-inline'` on the admin panel; reload time grows with the number of sites.
