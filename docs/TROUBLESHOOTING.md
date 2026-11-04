# Troubleshooting

| Problem | Cause and fix |
|---|---|
| `https://localhost:9000` does not open | The tunnel is not running: `kubectl port-forward -n shieldwaf svc/shieldwaf-panel 9000:9000`. Use `https://`, not `http://`. If the port is "already in use" a tunnel is already running: just open the page. |
| Browser warns about the certificate | Expected: the panel creates its own certificate. Click Advanced, Proceed. In production mount your own (see `CLOUD.md`). |
| Setup page says "Wrong setup code" | Get the code again: `kubectl logs -n shieldwaf deploy/shieldwaf -c panel` (line "Setup code"). No spaces; `0` is zero. It works only until the first account exists. |
| Pods stay `0/2` or `CreateContainerConfigError` | The database secret is missing. Run `scripts/create-db-secret.*` (it does nothing if the secret already exists). |
| `ImagePullBackOff` / `ErrImageNeverPull` | The images are not on the cluster nodes. Load them (`kind load docker-image ...`) or push them to a registry and change the `image:` lines. |
| Panel pod restarts a few times at start | It waits for PostgreSQL to come up; this is normal during the first minute. |
| `curl` to the firewall returns an empty reply | The host name is not a configured site (unknown hosts are dropped on purpose). Add the site, and send the right `Host:` header. |
| A legitimate request is blocked (403) | Open **Attack log**, find the rule id, and add a **rule exclusion** for it (optionally for one path), or lower the paranoia level. Test new sites in *detect only* first. |
| HTTP 429 "Too many requests" | A rate limit or the auto-ban/bad-behaviour logic triggered. Check **IP bans**, the site's rate limit, and **Settings, Flood defence**. Add your own address under *Never ban*. |
| Visitors see the "getting back up" page | The application behind the site is unreachable or its pods are not ready. Check `kubectl get pods` for the application and that the upstream address is right. |
| "NOT applied (old config kept)" | The engine tested your change and rejected it; the message shows why (for example a bad custom rule or a missing certificate). Nothing was changed. |
| Cannot add a site: "Upstream host is not allowed" | Loopback and cloud-metadata addresses are always refused; or **Settings, Upstream restrictions** limits the allowed suffixes. |
| Alert test fails | Read the error in **Alerts, Recent deliveries**. Targets must resolve and must not be loopback or link-local. For SMTP check port and encryption. |
| Country rules say "country data has not been downloaded yet" | **Threat intel, Update country data** (takes about a minute; needs internet access). |
| Rule updates cannot reach GitHub | The pod needs outbound HTTPS to github.com. Check network policies and proxies. |
| Automatic certificate: "could not verify the host name over HTTP" | The authority must reach `http://<host>/.well-known/acme-challenge/...` on port 80: check that DNS points to your load balancer, that it forwards port 80 to the proxy (8080), and that no country rule, IP allow-list or login gate on the site blocks it. Retry with **Get / renew the certificate now** (failures are otherwise retried every 6 hours). Use *Let's Encrypt staging* while testing. |
| Automatic certificate: "needs a public host name" | Wildcard names and IP addresses cannot use the automatic HTTP check. Use a normal name like `app.example.com`, or cert-manager / an upload. |
| Automatic certificate keeps the self-signed one | Look at the site page: *waiting* means the first request is still running (about 30 s); *failed* shows the reason. Also check Settings: e-mail and the agreement box. |
| A backend is marked "out of rotation" but is fine | The health check asks for the health path with a plain GET and an answer of 500 or higher counts as failed. Check the path in the site form (the default `/` may need a login or return an error), and that the leader replica can reach the backend (it probes from its own pod). Switch the checks off to put everything back. |
| Some POST requests fail with 502 while one backend is down | Expected: writes are never replayed on another backend (it could execute twice). Turn on health checks so the dead backend leaves the rotation quickly. |
| The backup job fails | `kubectl logs -n shieldwaf job/<job name>`. Usual causes: the secret has no `SHIELD_DATA_KEY` (run `scripts/create-db-secret.*`), the volume `shieldwaf-backups` is full, or the database is down. |
| Restore says "no such backup" | List them with `sh scripts/restore-db.sh list`; names look like `shieldwaf-20261104-023000.dump.enc`. The firewall replicas are started again automatically after a failed restore. |
| Restore fails with "bad decrypt" | The backup was made with a different `SHIELD_DATA_KEY` than the one in the secret now. Use the secret that was current when it was made. |
| SSO: "the identity provider could not be reached or is not valid" when saving | The panel must reach `<issuer>/.well-known/openid-configuration` over https from inside the cluster: check the address (no trailing path mistakes), DNS and the network policy (egress to the internet is allowed by default). The address must resolve to a public address. |
| SSO: "is not allowed to sign in to this panel" | The e-mail address is not in the allowed domains or addresses of Settings, Single sign-on (nobody is allowed by default). |
| SSO: "the identity provider has not verified your e-mail address" | The provider says the address is unverified (common with some Microsoft/Google accounts). Fix it at the provider, or untick *Only accept addresses the provider has verified* (less safe). |
| SSO: "redirect_uri mismatch" at the provider | The redirect address registered at the provider must be exactly `<panel public address>/sso/callback`, with the same scheme and host as in Settings. |
| SSO: "started in another browser" / "unknown or too old" | A sign-in must finish within 10 minutes in the same browser (it needs the short-lived `__Host-sso` cookie). Start again with the button. |
| Locked out of the panel | See "If you are locked out" in `USER-GUIDE.md`. |
| Reload is slow with many sites | Normally the OWASP rules are loaded once and reloads take well under a second even with hundreds of sites (see **Cluster**, "Rule layout"). If it says *one rule set per site*, a canary rule set is being tested (Rule updates page): finish or roll back the canary. Also check that `SHIELD_SHARED_RULES` is not set to `0` on the engine. |
| **Cluster** shows a replica as "cannot apply" | Read the note in the table: usually a shared file has not arrived yet (it retries every 5 seconds) or the configuration refers to something that only exists on another replica. If it persists, `kubectl logs <pod> -c panel`. |
| Warning "shared files are off" on the Cluster page | The secret has no `SHIELD_DATA_KEY` (installation older than 2.3). Run `sh scripts/create-db-secret.sh` (the database password is not changed) and restart the replicas: `kubectl rollout restart deploy/shieldwaf -n shieldwaf`. Until then use one replica. |
| A change seems to apply on one replica only | The confirmation message says how many replicas applied it. A replica that is still applying keeps retrying; the Cluster page shows its status. |
| The panel returns errors but the sites still work | The database is probably down: `kubectl get pods -n shieldwaf`, `kubectl logs shieldwaf-db-0 -n shieldwaf`. Traffic is unaffected; the panel returns when the database does. |
| Pod stays `1/2` after an upgrade from 2.2 | Missing `SHIELD_DATA_KEY` in the secret: run `sh scripts/create-db-secret.sh` once, then `kubectl rollout restart deploy/shieldwaf -n shieldwaf`. |

## Useful commands
```bash
kubectl get pods -n shieldwaf
kubectl logs -n shieldwaf deploy/shieldwaf -c engine      # the firewall (blocked requests appear here too)
kubectl logs -n shieldwaf deploy/shieldwaf -c panel       # the admin panel
kubectl logs -n shieldwaf shieldwaf-db-0                  # PostgreSQL
kubectl describe pod -n shieldwaf -l app=shieldwaf        # events, probe failures
```
If you report a problem, include the output of these (remove anything private) and the A Shield WAF version shown in the panel's menu.
