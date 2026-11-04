# Security design of A Shield WAF

This document lists what the product does to protect itself and your applications, what it deliberately does **not** do, and what
you must do on your side. Read the sections "What it does NOT do" and "What you must do" before using it in production or in the cloud.

## How secure is it? (the honest summary)
A Shield WAF is **free, open-source software provided as is, with no warranty** (Apache-2.0). It was written by one author and has **not**
been independently audited or certified. It is built on proven components (nginx, ModSecurity, the OWASP Core Rule Set, PostgreSQL) and
was designed and tested with security first. Treat the table as the author's own assessment, not a guarantee.

| Area | Assessment | Evidence |
|---|---|---|
| Blocking common web attacks (SQL injection, XSS, file inclusion, command injection, Log4Shell, scanners) | **Good** (same rule set most commercial WAFs use) | 13 attack types blocked in the automated tests on every release |
| Resistance to determined bypass attempts | **Moderate**: the rule set is pattern-based; positive model, OpenAPI validation, reputation, country rules and the challenge add non-pattern layers | not tested by an outside attacker |
| Security of the admin panel | **Strong for its size**: HTTPS only, two-factor login, lockout, revocable sessions, strict CSP, IP allow-list, roles | 200 automated checks incl. abuse cases; OWASP ZAP baseline 0 failures |
| Container / cluster hardening | **Strong**: non-root, read-only filesystem, no capabilities, restricted Pod Security, network policies | Trivy configuration scan: 0 medium+ findings |
| Supply chain | **Good**: base images pinned by digest, image scans clean (0 high/critical), rule updates need human approval | Trivy image scans; see `docs/SECURITY-REVIEW.md` |
| Independent assurance (audit, pentest, certification) | **None yet** | you should commission one for high-value use |
| Availability | **2+ replicas** behind one Service, rolling updates, automatic leader failover; the database is the single point of failure unless you use a replicated one | high-availability suite: kill a replica, stop the database, rolling restart under load |
| Network (volumetric) DDoS | **not provided**: needs your cloud provider or a CDN | `docs/DDOS.md` |

**Suitable for:** labs, internal applications, small and medium sites, defence in depth next to other controls, learning, and as a base to
build on. **Not suitable on its own for:** regulated environments requiring certified products, or as the only protection of a high-value
target, until it has had an independent review.

## What is protected, and how

### The firewall (data plane)
| Control | How |
|---|---|
| Attack detection | ModSecurity v3 + OWASP Core Rule Set 4 (SQLi, XSS, RCE, LFI, scanners, protocol attacks), paranoia level 1-4 per site |
| Safe by default | unknown host names get **no reply** (HTTP 444), no version in the `Server` header, strict header sizes and timeouts (slow-loris protection), per-IP connection limit |
| Method allow-list | per site; anything else gets 405 |
| Real client IP | `X-Forwarded-For` is trusted **only** from proxies you list; the upstream receives the real client IP, never a client-supplied chain |
| TLS | TLS 1.2 / 1.3 only, AEAD ciphers only, no session tickets, HTTP/2, HSTS, HTTP to HTTPS redirect, handshake refused for unknown host names (no default certificate leak) |
| Anti-bot | proof-of-work challenge; the pass is an HMAC bound to client IP + browser + host + expiry; forged, replayed or foreign cookies are refused |
| Login gate | HTTP basic auth with SHA-512 crypt hashes; passwords never leave the GUI form |
| Rate limiting, IP lists, auto-ban | per site / global |
| **Positive security model** | per site: only listed paths, content types and URL lengths are accepted, everything else is refused (403 / 415 / 414). This is not pattern matching: unknown attacks against paths the application does not use never reach it |
| **IP reputation feeds** | Spamhaus DROP and FireHOL level 1 (or your own https lists) refreshed every few hours; listed addresses are refused before any rule runs; private/reserved/very broad ranges and your own admin/proxy addresses are never loaded |
| **Country rules** | per site allow or deny by registered country (data from the five regional internet registries, no licence key) |
| **OpenAPI validation** | per site, compiled into ModSecurity rules from your OpenAPI 3 document: unknown paths / methods / query parameters / JSON fields (mass assignment), missing required fields, wrong types, enums, ranges, lengths, content types |
| **Application-layer flood defence** | one-click **under-attack mode** (challenge for everyone + rate limit) and **automatic escalation** when a site exceeds a request-rate threshold; see `docs/DDOS.md` |
| Upstream (SSRF) protection | loopback, link-local and cloud-metadata addresses are refused; optional allowed-suffix list (for example `svc.cluster.local`) |

### The control panel (admin GUI)
| Control | How |
|---|---|
| Transport | **HTTPS only** (self-signed by default, bring your own certificate), HSTS |
| First-run | one-time setup code printed only in the pod log; no default password |
| Passwords | 12+ characters, 3 of 4 character types, not containing the user name; stored as salted hashes |
| Two-factor | TOTP (RFC 6238) with one-time recovery codes; a code cannot be replayed |
| Brute force | lockout after 5 wrong attempts per user or 15 per IP (15 minutes), timing-equalised unknown-user path |
| Sessions | server-side and revocable, idle timeout (default 30 min), absolute 8 h, cookie `__Host-`, Secure, HttpOnly, SameSite=Strict; password change signs out all other sessions |
| Browser protections | CSRF token on every POST, CSP without inline scripts, X-Frame-Options DENY, COOP/CORP, no caching |
| Network | optional IP allow-list for the panel (the panel refuses a rule that would lock you out) |
| Alerting | alerts for engine down, attack spikes, auto-bans, under-attack, lockouts, admin changes, certificate expiry, failed rule updates; delivery by webhook / email / syslog / HTTP collector with retries and a delivery log. Targets may be private (internal SIEM) but never loopback, link-local or cloud-metadata. Channel secrets live only in `/data/secrets/*.json` (mode 0600) and are never displayed or exported |
| Rule updates | releases are fetched from github.com over HTTPS only (redirects restricted to GitHub hosts), size-limited, unpacked without trusting archive paths, version-checked and fingerprinted; they run in **detect-only canary** first and are **promoted only by an administrator**, with one-click rollback; the engine tests the whole new rule set before accepting it |
| Roles | **administrator** and read-only **viewer**; viewers cannot change anything or see users, audit trail or backups; new users must choose their own password at first login; the last administrator cannot be deleted or demoted; admins can reset 2FA and revoke sessions |
| Metrics | `/metrics` needs a bearer token |
| Audit | every admin action and every login failure with the source IP |
| Config import | every imported site is re-validated like a form submission (an import cannot smuggle in a metadata-address upstream or an nginx directive) |
| Backups | export never contains password hashes, private keys, gate users or the metrics token |
| Config safety | every change is tested with `nginx -t` first; the engine confirms the reload and the panel rolls back if it refuses |

### The runtime (Kubernetes)
PostgreSQL runs as its own hardened pod (non-root, read-only filesystem, no capabilities, restricted Pod Security) reachable **only** from the panel (network policy); its password is generated by `scripts/create-db-secret.*` and exists only as a cluster secret. Traffic to the database is not TLS-encrypted inside the cluster by default: use encrypted storage, and for a managed PostgreSQL set `sslmode=require` in the connection string. Namespace enforces the **restricted** Pod Security level; non-root user 10101; read-only root filesystem; all Linux capabilities dropped;
no privilege escalation; seccomp RuntimeDefault; no service-account token; separate containers for engine and panel that share only
the data volume (no shared process namespace, no signals); resource limits; NetworkPolicy default-deny with explicit allows and no
egress to cloud-metadata addresses; base image pinned by digest; image scanned with Trivy.

### Replicas and shared secrets (high availability)
Replicas share certificates, private keys, alert secrets and the panel's session key through the PostgreSQL database. Everything stored there is **encrypted and authenticated** (Fernet:
AES-128-CBC with HMAC-SHA-256) with a key (`SHIELD_DATA_KEY`) that exists only in the cluster secret `shieldwaf-db`, so a database dump alone does not reveal a private key, and someone who can only write to the
database cannot plant files on a replica (forged rows fail authentication; only a fixed list of file names is ever written; archives are unpacked with path checks). Whoever can read **both** the database and the
secret can read the shared files, so protect them separately (RBAC on the secret, encrypted database volume). The key cannot be rotated from the GUI yet: to rotate it, create a new key, restart all replicas, and re-upload the certificates.
Administrator actions are serialised across replicas with a database lock (no lost updates, a 2FA or recovery code can never be used twice), and the replicas only ever talk to the database, never to each other.

### Several upstreams
Every extra backend goes through the same checks as the main one (address syntax, no loopback / link-local / cloud-metadata addresses, the allowed-suffix list), at most ten per site. The health probe is a plain GET without cookies or credentials to the address you configured, made by the leader replica, with a 3-second limit, without following redirects. Writes are never retried on another backend.

### Supply chain and releases
Release images are built by one workflow from a tag, scanned (the release stops on a fixable HIGH/CRITICAL vulnerability), pushed by digest, **signed keylessly** (cosign, with the workflow's identity, so there is no signing key to steal) and shipped with an **SBOM** and build provenance; the Helm chart is signed too. `docs/RELEASE.md` shows how to verify all of it and how to make the cluster refuse unsigned images. What it does not do: a signature proves where an image came from, not that it is bug-free; the workflow itself runs in GitHub, so GitHub and the repository's maintainers are part of the trust base. Base images are pinned by digest and rebuilt on release.

### Single sign-on
The OpenID Connect login (`panel/oidc.py`) uses the authorization code flow with PKCE. The identity provider's address must be https and, outside tests, public (no request into the cluster); the discovery document must name the same issuer; the ID token is verified (signature against the provider's published keys with RS256 or ES256 only, so unsigned and HMAC tokens are refused; issuer; audience and authorized party; expiry; the nonce of this very login; a verified e-mail address unless you turn that off). `state`, `nonce` and the PKCE verifier are random, kept on the server, used once, and tied to the browser that started the login by a Secure, HttpOnly, SameSite=Lax cookie (Lax because the provider's redirect back is a cross-site navigation), valid for 10 minutes. Who may sign in, and the role, are decided by the panel's own settings (allowed domains / addresses, administrator list or groups, read-only by default), never by the provider alone; SSO accounts have no password and cannot use the password form. The client secret is kept in the encrypted shared store, never shown again and never exported. The password login remains as the emergency access, so a provider outage or misconfiguration cannot lock you out. Limits: OpenID Connect only (no SAML), no hardware-key login, no "log out at the provider" (signing out ends only the panel session), and the sign-in was tested against Dex, not against each commercial provider.

### Backups
The nightly backup job (`k8s/backup.yaml`) runs as a non-root pod with a read-only filesystem, no capabilities and a network policy that allows only the database and DNS. The dump is encrypted with AES-256-CBC (PBKDF2, 200,000 iterations, random salt) using the key `SHIELD_DATA_KEY`, and read back before it counts as a backup. A backup contains everything in the database (configuration, password hashes, two-factor secrets, logs) and the encrypted shared files: **whoever holds a backup file AND the secret `shieldwaf-db` can read all of it**, so store the two in different places and protect both. Restoring needs rights on the namespace (it scales the deployment and runs a pod that mounts the secret). Backups are not tamper-proof: encryption protects secrecy, not authenticity; keep them on storage that others cannot write to.

### Automatic certificates (ACME)
The ACME client (`panel/acme.py`, RFC 8555) only talks to the authority address you chose in Settings: it must be https and, outside tests, must resolve to public addresses only (no request into the cluster);
every address the authority returns must be on the same host; the issued certificate is checked (right name, valid now, matches the freshly generated key) before it is used; the account key is created once, kept
encrypted in the shared store and never shown; the challenge answers are public by design and are served from a read-only folder. Failed orders are retried at most every 6 hours. Anyone who can change the sites in
the panel can order certificates for host names they enter, so keep the admin roles tight (viewers cannot).

## What it does NOT do (be honest with your auditors)
- It is **not a certified or independently audited product.** An independent audit can only be done by someone other than the author. What exists is a documented **self-review** (`docs/SECURITY-REVIEW.md`: static analysis, manifest and image scans, a web-scanner baseline, 200 automated attack and abuse tests, all fixed or explained) and a CI workflow that repeats the scans. Commission a third-party penetration test and code review before relying on it for regulated or high-value systems.
- The OWASP rule set is pattern-based, so a determined attacker may find bypasses that a commercial semantic engine catches. This is reduced, not removed: the positive security model, reputation feeds, country rules, the anti-bot challenge and flood defence do not depend on attack patterns. Run new sites in detect mode first, tune, then block, and keep your applications patched: a WAF reduces risk, it does not fix vulnerable code.
- **No volumetric DDoS protection.** That is physically impossible inside a cluster: the link is full before traffic reaches any pod. Only application-layer floods are handled here; put your cloud provider's DDoS protection or a CDN in front (`docs/DDOS.md`).
- **The database is the single point of failure.** The firewall replicas keep working without it, but configuration changes and the start of new replicas need it; use a managed replicated PostgreSQL for real redundancy. Rate limits are counted per replica. Several administrators and viewers are supported.
- No FIPS-validated cryptography and no hardware key (WebAuthn) support; two-factor is TOTP.
- The anti-bot challenge stops simple bots and scripts that cannot run JavaScript; it is not a defence against attackers driving real browsers.
- Login-gate passwords use SHA-512 crypt (strong, slow) but the gate is basic authentication; use it over HTTPS only.
- Automatic certificates (ACME, HTTP-01) need a public host name and port 80 and do not support wildcards; use cert-manager for those (`docs/CLOUD.md`). The ACME client was tested against Pebble, the official test server, not against the real Let's Encrypt.

## What you must do
1. Create the admin account yourself, choose a strong password and **enable two-factor login immediately**.
2. Never expose the panel service (port 9000) to the internet. Reach it with `kubectl port-forward`, a VPN or a private ingress, and set the panel allow-list.
3. Terminate TLS for every public site with a real certificate; keep HSTS on.
4. Put a cloud load balancer / DDoS protection in front of ports 80/443 and list its address range under "Real client IP" so real client addresses are logged.
5. Keep the image up to date: rebuild regularly (OS and rule-set fixes), re-run the Trivy scan, redeploy.
6. Back up the data volume and the exported configuration; protect the backup like a secret.
7. Watch the audit trail and the attack log, and alert on `shieldwaf_engine_up == 0`.
8. Have an independent security review done before production use.

## Break-glass
```
kubectl exec -n shieldwaf deploy/shieldwaf -c panel -- python3 /panel/tools.py reset-panel-allow
kubectl exec -n shieldwaf deploy/shieldwaf -c panel -- python3 /panel/tools.py reset-2fa <user>
```
These need `kubectl exec` rights, which already imply control of the pod.

## Reporting a vulnerability
Please report security problems **privately**, not as a public issue.

1. On the repository page open the **Security** tab, then **Report a vulnerability** (GitHub private vulnerability reporting).
2. Describe what you found, the version (shown in the panel menu), the steps to reproduce, and the impact. Please do not include real credentials or other people's data.
3. You will get a reply on a best-effort basis (this is a volunteer project with no service-level agreement; the aim is a first answer within about 7 days and a fix or mitigation for confirmed issues as soon as practical).
4. Please keep the details private until a fix is available; you will be credited in the release notes if you wish.

**Scope:** the code and configuration in this repository (panel, engine configuration generation, manifests, scripts). Vulnerabilities in the
upstream components (nginx, ModSecurity, OWASP CRS, PostgreSQL, Alpine) should be reported to those projects.
**Good-faith testing** against your own installation is welcome. Do not test against installations you do not own.

## Supported versions
Only the latest release receives security fixes. Upgrade by pulling the repository and rebuilding the images (see `docs/INSTALL.md`).
