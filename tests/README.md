# Regression and security test suite

`functional_test.py` drives a **real, throw-away copy** of A Shield WAF on a Kubernetes cluster through its GUI and through the firewall,
and checks **185** behaviours: setup and login security, two-factor login, lockouts, sessions, SSRF protection, attack blocking (13 types),
TLS, the anti-bot challenge, login gate, maintenance and service-down pages, rate limiting, auto-ban, threat feeds, country rules,
under-attack mode, roles, alert delivery (webhook, syslog, CEF, HTTP collector, email), the OpenAPI validator, the OWASP rule-update cycle
(a real download from GitHub) and persistence in PostgreSQL across a restart.

It uses randomly generated, throw-away passwords (never printed) and does not touch your real installation (`shieldwaf` namespace).

## Run it
Prerequisites: a **test** cluster (kind is fine), `kubectl`, `python3`, `curl`, `openssl`, and the two images already loaded
(`shieldwaf:2.2`, `shieldwaf-db:16`, see `docs/INSTALL.md`). The pods need outbound internet access.
```bash
bash tests/run.sh
```
The script recreates only the namespaces `shieldwaf-test`, `sink-test` and `shieldwaf-demo` (a copy of the firewall, a receiver for alerts, and two tiny demo
applications with unique names, so your own applications are never touched), opens local tunnels, runs the suite and prints `N/N checks passed`. Expect 15-25 minutes. Clean up afterwards:
```bash
kubectl delete namespace shieldwaf-test sink-test shieldwaf-demo
```

## Notes
- A few checks depend on the internet (GitHub, threat-feed and registry downloads). If your network blocks them those checks fail; that is a network result, not necessarily a bug.
- The tests are timing-sensitive (a configuration reload takes a couple of seconds). On a very slow cluster raise the `time.sleep` values or the memory limits.
- Windows: run `run.sh` from Git Bash.
