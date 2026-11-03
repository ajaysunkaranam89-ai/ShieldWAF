# Installation guide

This guide gets **A Shield WAF** running on a Kubernetes cluster and protecting your first application. It takes about 15 minutes.
For production in the cloud, read [`CLOUD.md`](CLOUD.md) and [`../SECURITY.md`](../SECURITY.md) as well.

## What you need
| Tool | Why | Check |
|---|---|---|
| A Kubernetes cluster (1.27 or newer) | where it runs. For a local test use [kind](https://kind.sigs.k8s.io) or Docker Desktop's Kubernetes | `kubectl get nodes` |
| `kubectl` | talks to the cluster | `kubectl version --client` |
| Docker | builds the two images | `docker version` |
| About **1.5 GB** of free memory in the cluster | the WAF itself needs about 250 MB; PostgreSQL about 130 MB | |
| An application inside the cluster to protect (any HTTP service) | to try it on | |

Your cluster's network plugin should **enforce NetworkPolicy** (Calico, Cilium, cloud CNIs). kind's default plugin may not; everything still works, the network isolation just is not enforced.

## 1. Get the code
```bash
git clone https://github.com/ajaysunkaranam89-ai/ShieldWAF.git
cd ShieldWAF
```

## 2. Build the two images
```bash
docker build -t shieldwaf:2.2 .          # the firewall engine and the admin panel
docker build -t shieldwaf-db:16 db       # PostgreSQL (official image, pinned, unused helper removed)
```

## 3. Make the images available to the cluster
- **kind:** `kind load docker-image shieldwaf:2.2 shieldwaf-db:16 --name <your-cluster-name>`
- **Docker Desktop Kubernetes:** nothing to do (it shares your local images).
- **A real or cloud cluster:** tag the images with your registry name, `docker push` them, and change the `image:` lines in `k8s/shieldwaf.yaml` (see `CLOUD.md`).

## 4. Create the database secret
A random password is generated and stored **only in the cluster** (never in git or on disk):
```bash
sh scripts/create-db-secret.sh            # Linux / macOS / Git Bash
```
```powershell
.\scripts\create-db-secret.ps1            # Windows PowerShell
```

## 5. Deploy
```bash
kubectl apply -f k8s/shieldwaf.yaml
kubectl get pods -n shieldwaf             # wait until shieldwaf-... shows 2/2 and shieldwaf-db-0 shows 1/1 (about one minute)
```

## 6. Open the admin panel and create your account
The admin panel is deliberately **not exposed**. Reach it through a local tunnel (leave this running):
```bash
kubectl port-forward -n shieldwaf svc/shieldwaf-panel 9000:9000
```
Find the one-time **setup code**:
```bash
kubectl logs -n shieldwaf deploy/shieldwaf -c panel         # look for the line "Setup code: ........"
```
Open **https://localhost:9000** (use `https`). Your browser warns about the certificate because the panel makes its own: click
**Advanced**, then **Proceed**. Enter the setup code, choose your own admin name and a strong password (12+ characters, three of lower case,
upper case, digits, symbols). Then open **Security (2FA)** and turn on two-factor login.

## 7. Protect your first application
1. In the panel open **Sites**, then **+ Add site**.
2. **Host name:** the name your users will type, for example `app.example.com` (for a local test use `app.waf.local`).
3. **Upstream:** the in-cluster address of the application, for example `http://my-app.my-namespace.svc.cluster.local:80`.
4. Leave the defaults (WAF mode *block*, paranoia level 1) and press **Save and apply**.

Tip: start with WAF mode **detect only**, watch the **Attack log** for a few days, tune false positives, then switch to **block**.

## 8. Send traffic through the firewall and check it works
Open a second tunnel to the firewall itself:
```bash
kubectl port-forward -n shieldwaf svc/shieldwaf-proxy 8088:8080
```
Then, from another terminal (replace the host name with yours):
```bash
curl -H "Host: app.waf.local" http://127.0.0.1:8088/                                  # your application answers (HTTP 200)
curl -G -H "Host: app.waf.local" http://127.0.0.1:8088/ --data-urlencode "id=1' OR '1'='1"      # SQL injection: blocked, HTTP 403
curl -G -H "Host: app.waf.local" http://127.0.0.1:8088/ --data-urlencode "q=<script>alert(1)</script>"   # XSS: blocked, HTTP 403
```
The blocked requests appear in the panel under **Attack log** with the OWASP rule that caught them.

For a browser test add `127.0.0.1  app.waf.local` to your hosts file and open `http://app.waf.local:8088`.
(Windows: edit `C:\Windows\System32\drivers\etc\hosts` as Administrator; Linux/macOS: `/etc/hosts`.)

## 9. Going further
| I want to... | See |
|---|---|
| use HTTPS, maintenance mode, alerts, rule updates, OpenAPI validation, roles | [`USER-GUIDE.md`](USER-GUIDE.md) |
| run it in AWS / Azure / Google Cloud | [`CLOUD.md`](CLOUD.md) |
| understand the security design and limits | [`../SECURITY.md`](../SECURITY.md) |
| defend against floods / DDoS | [`DDOS.md`](DDOS.md) |
| fix a problem | [`TROUBLESHOOTING.md`](TROUBLESHOOTING.md) |

## Upgrading
```bash
git pull
docker build -t shieldwaf:<new-version> . && docker build -t shieldwaf-db:16 db
# load / push the images as in step 3, update the image tag in k8s/shieldwaf.yaml, then:
kubectl apply -f k8s/shieldwaf.yaml
```
Your sites, users and logs are in PostgreSQL and on the data volume, so they are kept. Back up first (see below).

## Backup and restore
- **Configuration:** in the panel, **Backup, Download config** (sites, settings, pages; never passwords, keys or secrets). **Import** restores it.
- **Everything:** snapshot the two volumes (`shieldwaf-data`, `pgdata-shieldwaf-db-0`) with your storage provider, or run `kubectl exec -n shieldwaf shieldwaf-db-0 -- pg_dump -U shieldwaf shieldwaf > backup.sql`. Protect backups like secrets.

## Uninstall
```bash
kubectl delete namespace shieldwaf       # removes the firewall, the database and all volumes (your data is lost)
```
Your applications are untouched. Remove the hosts-file lines and DNS records you added.
