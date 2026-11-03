# Security design of A Shield WAF

This document lists what the product does to protect itself and your applications, what it deliberately does **not** do, and what
you must do on your side. Read the last two sections before using it in production or in the cloud.

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
| Metrics | `/metrics` needs a bearer token |
| Audit | every admin action and every login failure with the source IP |
| Config import | every imported site is re-validated like a form submission (an import cannot smuggle in a metadata-address upstream or an nginx directive) |
| Backups | export never contains password hashes, private keys, gate users or the metrics token |
| Config safety | every change is tested with `nginx -t` first; the engine confirms the reload and the panel rolls back if it refuses |

### The runtime (Kubernetes)
Namespace enforces the **restricted** Pod Security level; non-root user 101; read-only root filesystem; all Linux capabilities dropped;
no privilege escalation; seccomp RuntimeDefault; no service-account token; separate containers for engine and panel that share only
the data volume (no shared process namespace, no signals); resource limits; NetworkPolicy default-deny with explicit allows and no
egress to cloud-metadata addresses; base image pinned by digest; image scanned with Trivy.

## What it does NOT do (be honest with your auditors)
- It is **not a certified or independently audited product.** It was built and tested by its author; it has not had a third-party penetration test or code review. Do that before relying on it for regulated or high-value systems.
- Detection uses the OWASP rule set (patterns and scoring). A determined attacker may find bypasses that commercial semantic engines or machine-learning WAFs catch. Run it in detect mode first, tune, then block, and keep your applications patched: a WAF reduces risk, it does not fix vulnerable code.
- **No volumetric DDoS protection.** Use your cloud provider's network protection or a CDN in front.
- Single admin account and a single replica (no high availability); the data volume is a single point of failure, so back it up.
- No FIPS-validated cryptography and no hardware key (WebAuthn) support; two-factor is TOTP.
- The anti-bot challenge stops simple bots and scripts that cannot run JavaScript; it is not a defence against attackers driving real browsers.
- Login-gate passwords use SHA-512 crypt (strong, slow) but the gate is basic authentication; use it over HTTPS only.
- Certificates are not auto-renewed by the product. Use cert-manager and mount the secret (see `docs/CLOUD.md`).

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
Open a private security advisory on the GitHub repository. Please do not publish details before a fix exists.
