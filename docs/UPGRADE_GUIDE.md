# Upgrading A Shield WAF 2.3 → 2.4

Do this on a test copy first (`IMG_TAG=2.4 bash tests/run.sh` creates and removes one), then on the real installation. Nothing here is done for you automatically.

## Before you start

1. Take a backup with the 2.3 job and **keep the file** (`kubectl create job --from=cronjob/shieldwaf-db-backup backup-pre24 -n shieldwaf`). 2.4 cannot read 2.3 backups with its own tool (new format), so this file is your way back, see `ROLLBACK_GUIDE.md`.
2. Export the audit trail (Audit → Export) and keep the file outside the cluster.
3. Note the current image tags: `kubectl -n shieldwaf get deploy,sts -o wide`.

## What changes

| Area | Change | Action |
|---|---|---|
| Database schema | versioned migrations run automatically at start (leader and replicas are serialized by a lock). Existing audit rows are added to the new tamper-evident chain once | none; the first start after the upgrade takes a few seconds longer |
| Database image | `shieldwaf-db:2.4`: TLS on, plain network connections rejected | build and load it (`docker build -t shieldwaf-db:2.4 db`); the panel is configured with `SHIELD_DB_SSLMODE=require` by the manifest/chart. **Any other client of the database (your own tools, an external backup) must use TLS now** |
| Backups | new format and a separate key ring | `sh scripts/create-backup-key.sh`, `kubectl apply -f k8s/backup.yaml`, then take a first 2.4 backup. Keep an offline copy of the key ring |
| SSRF guard | stricter: upstreams that resolve to loopback, link-local, metadata or carrier-grade-NAT addresses are refused; private addresses stay allowed (RFC 1918 allowlist) | check Settings → upstream private networks if your upstreams are in other private ranges. A site that is now refused is shown as `ssrf_blocked` |
| Audit trail | verification, export, retention, SIEM forwarding | optional: set the retention in Settings |
| Panel-only secrets | the session key, setup code and alert / ACME / OIDC secrets move to `/private` (memory volume, panel container only); the engine's `/data` is read-only | the manifest and chart do this; the new volume starts empty and the panel restores the secrets from their encrypted copies in the database (the same mechanism that gives every replica the same files). This upgrade path was **not tested** (the 2.4 test deployments start fresh): after the upgrade check that alert channels still send and that you can sign in; if the session key were not restored everybody would just have to sign in again |
| Service accounts | `shieldwaf-app`, `shieldwaf-db`, `shieldwaf-backup` (no permissions, no token) | created by the manifest / chart |
| Optional features | Redis rate limits, bot protection, CrowdSec, point-in-time recovery, guard rails | all off until you switch them on; see `ADMINISTRATOR_GUIDE.md` and `KUBERNETES_DEPLOYMENT.md` |
| Existing sites | new per-site settings (`bots`, `rate_limit.scope`) | they appear with safe defaults (off / per replica); nothing changes until you edit them |

## Steps (manifest installation)

```sh
docker build -t shieldwaf:2.4 . && docker build -t shieldwaf-db:2.4 db
kind load docker-image shieldwaf:2.4 shieldwaf-db:2.4 --name <cluster>        # or push to your registry
sh scripts/create-backup-key.sh
kubectl apply -f k8s/shieldwaf.yaml                                           # rolls the database pod (a short outage of the panel's writes) and the panel replicas one by one
kubectl apply -f k8s/backup.yaml
kubectl -n shieldwaf rollout status deploy/shieldwaf
kubectl create job --from=cronjob/shieldwaf-db-backup backup-first24 -n shieldwaf
```

Helm: `helm upgrade shieldwaf charts/shieldwaf --set backup.enabled=true ...` (the chart creates the key ring once and keeps it).

## After the upgrade — check

* Cluster page: all replicas on version 2.4 and "in sync".
* Audit → Verify: "chain valid".
* `kubectl -n shieldwaf logs job/<first 2.4 backup job>` shows "backup written and verified" and `kubectl create job --from=cronjob/shieldwaf-db-backup-verify verify-now -n shieldwaf` passes.
* Traffic to every site works (a site refused by the SSRF guard shows in the panel).
