# Installation guide

This guide gets **A Shield WAF** running on a Kubernetes cluster and protecting your first application. It takes about 15 minutes.
For production in the cloud, read [`CLOUD.md`](CLOUD.md) and [`../SECURITY.md`](../SECURITY.md) as well.

## What you need
| Tool | Why | Check |
|---|---|---|
| A Kubernetes cluster (1.27 or newer) | where it runs. For a local test use [kind](https://kind.sigs.k8s.io) or Docker Desktop's Kubernetes | `kubectl get nodes` |
| `kubectl` | talks to the cluster | `kubectl version --client` |
| Docker | builds the two images | `docker version` |
| About **1.5 GB** of free memory in the cluster | each of the 2 replicas needs about 250 MB; PostgreSQL about 130 MB. For one replica set `replicas: 1` | |
| An application inside the cluster to protect (any HTTP service) | to try it on | |

Your cluster's network plugin should **enforce NetworkPolicy** (Calico, Cilium, cloud CNIs). kind's default plugin may not; everything still works, the network isolation just is not enforced.

## 1. Get the code
```bash
git clone https://github.com/ajaysunkaranam89-ai/ShieldWAF.git
cd ShieldWAF
```

## 2. Build the two images
```bash
docker build -t shieldwaf:2.3 .          # the firewall engine and the admin panel
docker build -t shieldwaf-db:16 db       # PostgreSQL (official image, pinned, unused helper removed)
```

## 3. Make the images available to the cluster
- **kind:** `kind load docker-image shieldwaf:2.3 shieldwaf-db:16 --name <your-cluster-name>`
- **Docker Desktop Kubernetes:** nothing to do (it shares your local images).
- **A real or cloud cluster:** tag the images with your registry name, `docker push` them, and change the `image:` lines in `k8s/shieldwaf.yaml` (see `CLOUD.md`).

## 4. Create the secret
A random database password **and** a random key that encrypts the files the replicas share (certificates, private keys, alert secrets) are
generated and stored **only in the cluster** (never in git or on disk). Do not lose this secret: without the key the shared files cannot be read:
```bash
sh scripts/create-db-secret.sh            # Linux / macOS / Git Bash
```
```powershell
.\scripts\create-db-secret.ps1            # Windows PowerShell
```

## 5. Deploy
```bash
kubectl apply -f k8s/shieldwaf.yaml
kubectl get pods -n shieldwaf             # wait until both shieldwaf-... pods show 2/2 and shieldwaf-db-0 shows 1/1 (about one minute)
```
By default **two replicas** start (see [High availability](#high-availability)). Everything below works the same with any number.

## 6. Open the admin panel and create your account
The admin panel is deliberately **not exposed**. Reach it through a local tunnel (leave this running):
```bash
kubectl port-forward -n shieldwaf svc/shieldwaf-panel 9000:9000
```
Find the one-time **setup code**:
```bash
kubectl logs -n shieldwaf deploy/shieldwaf -c panel         # look for the line "Setup code: ........" (all replicas show the same code)
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

## High availability
The manifest runs **two replicas**. Each replica is a complete firewall (nginx + ModSecurity + the OWASP rules) with its own admin panel; all of
them use the same PostgreSQL database, so a configuration change made on any of them reaches all of them within about a second. What you get:

| Situation | What happens |
|---|---|
| A replica crashes or its node is lost | the Service stops sending traffic to it; the other replicas keep serving; a new replica starts and catches up by itself |
| You upgrade or restart (`kubectl rollout restart deploy/shieldwaf`) | replicas are replaced one at a time, a new one is ready before an old one stops; tested with zero failed requests |
| The leader replica dies | another replica becomes leader within about 10 seconds and takes over the once-only jobs (threat-feed and country downloads, rule-set checks, auto-ban, flood escalation) |
| The database stops | the firewall keeps serving and blocking with the configuration it has; the panel and configuration changes wait until the database is back |

**Change the number of replicas:** `kubectl scale deploy/shieldwaf -n shieldwaf --replicas=3` (also edit `replicas:` in the manifest so it stays that way). Use 2 or 3; every replica needs about 250 MB and keeps about 20 database connections (the bundled PostgreSQL allows 200).
**Spread them over nodes:** the manifest asks Kubernetes to put replicas on different nodes when it can, and a PodDisruptionBudget keeps at least one replica up during node maintenance.
**Check them:** open **Cluster** in the panel: it lists every replica, which one is the leader, whether each one has applied the newest configuration and how long the last reload took.
**Good to know:** rate limits and the per-address connection cap are counted per replica (an address can use up to N times the limit with N replicas). The database is the single point of failure: for real redundancy use a managed, replicated PostgreSQL ([`CLOUD.md`](CLOUD.md)).
**One replica only?** Set `replicas: 1`. The product works exactly the same.

## Upgrading
```bash
git pull
docker build -t shieldwaf:<new-version> . && docker build -t shieldwaf-db:16 db
# load / push the images as in step 3, update the image tag in k8s/shieldwaf.yaml, then:
sh scripts/create-db-secret.sh            # only needed once when coming from 2.2: adds the key for shared files (the database password is NOT changed)
kubectl apply -f k8s/shieldwaf.yaml
```
Your sites, users and logs are in PostgreSQL, so they are kept. Back up first (see below). Replicas are replaced one at a time without downtime.

**Coming from 2.2 or older:** version 2.3 no longer uses the `shieldwaf-data` volume (each replica rebuilds its local files from the database). After the upgrade
worked you may delete the old volume: `kubectl delete pvc shieldwaf-data -n shieldwaf`. Certificates you uploaded or generated, and alert secrets, lived on that volume:
if the Sites page reports a missing certificate after the upgrade, paste it again (or generate a new self-signed one) once; they are then shared automatically.
Settings, sites, users, the attack log and the audit trail are kept.

## Backup and restore
**Automatic encrypted backups (recommended, 2 minutes):**
```bash
kubectl apply -f k8s/backup.yaml
```
Every night at 02:30 UTC a job dumps the database, encrypts it (AES-256, the key is `SHIELD_DATA_KEY` from the secret `shieldwaf-db`), proves the file can be read back, and removes backups older than 14 days. They are kept on the volume `shieldwaf-backups` (5 Gi).
```bash
kubectl create job --from=cronjob/shieldwaf-db-backup backup-now -n shieldwaf      # a backup right now
sh scripts/restore-db.sh list                                                      # which backups exist (Windows: .\scripts\restore-db.ps1 list)
sh scripts/restore-db.sh latest                                                    # restore the newest (asks first; Windows: .\scripts\restore-db.ps1 latest)
```
**Restore** stops the firewall replicas, REPLACES the database with the backup (everything saved after it is lost), and starts the replicas again with the same count. It is meant to work onto a new, empty installation too (not tested here: create the secret with the same `SHIELD_DATA_KEY`, apply the manifests, apply `k8s/backup.yaml`, copy the backup file onto the volume, restore).
**Important:** a backup on the same cluster does not survive losing the cluster. Copy the files off it regularly (for example `kubectl cp` from a pod that mounts the volume, or your storage provider's snapshots of `shieldwaf-backups`), and keep a copy of the secret `shieldwaf-db`: **without its key a backup cannot be decrypted**.

- **Configuration:** in the panel, **Backup, Download config** (sites, settings, pages; never passwords, keys or secrets). **Import** restores it.
- **By hand:** snapshot the database volume (`pgdata-shieldwaf-db-0`, it also holds the encrypted shared files) with your storage provider, and keep a copy of the secret `shieldwaf-db` (it holds the key for those files), or run `kubectl exec -n shieldwaf shieldwaf-db-0 -- pg_dump -U shieldwaf shieldwaf > backup.sql`. Protect backups like secrets.

## Uninstall
```bash
kubectl delete namespace shieldwaf       # removes the firewall, the database and all volumes (your data is lost)
```
Your applications are untouched. Remove the hosts-file lines and DNS records you added.
