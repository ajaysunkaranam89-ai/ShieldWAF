# Regression and security test suite

Two suites run against **real, throw-away copies** of A Shield WAF on a Kubernetes cluster: `functional_test.py` (**200** checks, on **two replicas**) and
`ha_test.py` (**91** high-availability checks on **three replicas**: shared sessions and certificates, a change served by every replica, concurrent administrators,
80 sites reloaded in seconds with correct per-site behaviour, an automatic certificate obtained from a Pebble test authority and served by every replica, several upstreams per site (spreading, weights, keep-a-visitor, failover with a dead backend, health checks out and back in), killing the leader, a database outage, a rolling restart under load with zero failed requests).
`functional_test.py` drives the firewall through its GUI and through the firewall,
and checks **200** behaviours: setup and login security, two-factor login, lockouts, sessions, SSRF protection, attack blocking (13 types),
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

`backup_test.py` takes an encrypted backup, damages the database, restores it and checks that the firewall is running again (`SUITES=backup bash tests/run.sh`). `dbfailover.sh` runs the panel's database layer against a real PostgreSQL primary and standby in Docker and fails the primary over (no cluster needed).
`sso.sh` runs the single sign-on flow against Dex, a real OpenID Connect provider, in Docker: a normal sign-in, roles, refusals, replay and stolen-callback attacks, and forged ID tokens (no cluster needed; 44 checks).
`DEPLOY_WITH=helm bash tests/run.sh` installs the test copy from `charts/shieldwaf` instead of the plain manifest and runs the same suites against it.
`acme.sh` runs the certificate client against Pebble in throw-away Docker containers (needs Docker and internet access to pull the images); it does not need a cluster.

## Notes
- The high-availability suite deletes pods, stops the test database for about a minute and restarts the test deployment: it only touches the namespace `shieldwaf-test`, and needs a cluster with enough memory for three replicas (about 1.2 GB).
- A few checks depend on the internet (GitHub, threat-feed and registry downloads). If your network blocks them those checks fail; that is a network result, not necessarily a bug.
- The tests are timing-sensitive (a configuration reload takes a couple of seconds). On a very slow cluster raise the `time.sleep` values or the memory limits.
- Windows: run `run.sh` from Git Bash.
