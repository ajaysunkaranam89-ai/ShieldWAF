# A Shield WAF Helm chart

Installs A Shield WAF (firewall engine + admin panel, highly available) and, by default, its PostgreSQL database.
Documentation for the product: <https://github.com/ajaysunkaranam89-ai/ShieldWAF>. How releases are built, signed and verified: `docs/RELEASE.md`.

```bash
helm install shieldwaf ./charts/shieldwaf -n shieldwaf --create-namespace          # or oci://ghcr.io/<owner>/charts/shieldwaf --version 2.3.0
```
Then follow the notes Helm prints (setup code, tunnel to the admin panel). Every option is in `values.yaml` with a comment; the common ones:

| Value | Default | What |
|---|---|---|
| `image.repository` / `image.tag` / `image.digest` | ghcr.io/.../shieldwaf, chart appVersion, empty | the image (a digest wins over the tag) |
| `replicaCount` | 2 | replicas (ignored with autoscaling) |
| `autoscaling.enabled` | false | HorizontalPodAutoscaler (needs the metrics-server) |
| `service.proxy.type` | ClusterIP | `LoadBalancer` to expose the protected ports |
| `backup.enabled` | false | encrypted nightly backups (CronJob + volume) |
| `database.bundled` | true | false = your own PostgreSQL (`secret.create=false`, or `secret.externalDbUrl`) |
| `secret.create` | true | generate the database password and the key for shared files (kept on upgrade and after uninstall) |
| `certs.secrets` | [] | cert-manager secrets to mount for the "mounted secret" certificate source |
| `networkPolicy.*` | enabled | default deny + the needed allows; `proxyFrom` restricts who reaches the protected ports |

The chart creates the same objects as `k8s/shieldwaf.yaml` (and `k8s/backup.yaml`), and the project's test suites also run against a chart-installed copy (`DEPLOY_WITH=helm bash tests/run.sh`).
Limits: one release per namespace (object names are fixed on purpose, the docs and scripts use them); the chart does not create the namespace (use `--create-namespace`) or label it for Pod Security.
