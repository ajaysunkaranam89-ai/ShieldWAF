# Regression and security test suite

Two suites run against **real, throw-away copies** of A Shield WAF on a Kubernetes cluster: `functional_test.py` (**192** checks, on **two replicas**) and
`ha_test.py` (**60** high-availability checks on **three replicas**: shared sessions and certificates, a change served by every replica, concurrent administrators,
80 sites reloaded in seconds with correct per-site behaviour, killing the leader, a database outage, a rolling restart under load with zero failed requests).
`functional_test.py` drives the firewall through its GUI and through the firewall,
and checks **192** behaviours: setup and login security, two-factor login, lockouts, sessions, SSRF protection, attack blocking (13 types),
TLS, the anti-bot challenge, login gate, maintenance and service-down pages, rate limiting, auto-ban, threat feeds, country rules,
under-attack mode, roles, alert delivery (webhook, syslog, CEF, HTTP collector, email), the OpenAPI validator, the OWASP rule-update cycle
(a real download from GitHub) and persistence in PostgreSQL across a restart.

It uses randomly generated, throw-away passwords (never printed) and does not touch your real installation (`shieldwaf` namespace).

## Run it
Prerequisites: a **test** cluster (kind is fine), `kubectl`, `python3`, `curl`, `openssl`, and the two images already loaded
(`shieldwaf:2.3`, `shieldwaf-db:16`, see `docs/INSTALL.md`). The pods need outbound internet access.
```bash
bash tests/run.sh
```
The script recreates only the namespaces `shieldwaf-test`, `sink-test` and `shieldwaf-demo` (a copy of the firewall, a receiver for alerts, and two tiny demo
applications with unique names, so your own applications are never touched), opens local tunnels, runs the suite and prints `N/N checks passed`. Expect about 35 minutes for both suites. Clean up afterwards:
```bash
kubectl delete namespace shieldwaf-test sink-test shieldwaf-demo
```

## Notes
- The high-availability suite deletes pods, stops the test database for about a minute and restarts the test deployment: it only touches the namespace `shieldwaf-test`, and needs a cluster with enough memory for three replicas (about 1.2 GB).
- A few checks depend on the internet (GitHub, threat-feed and registry downloads). If your network blocks them those checks fail; that is a network result, not necessarily a bug.
- The tests are timing-sensitive (a configuration reload takes a couple of seconds). On a very slow cluster raise the `time.sleep` values or the memory limits.
- Windows: run `run.sh` from Git Bash.
