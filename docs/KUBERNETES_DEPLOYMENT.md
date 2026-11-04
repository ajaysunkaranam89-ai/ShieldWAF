# Kubernetes deployment

Two ways: plain manifests (`k8s/`) or the Helm chart (`charts/shieldwaf`). Both create the same things: Namespace (Pod Security "restricted"), service accounts without permissions or tokens, the WAF Deployment (2 replicas, engine + panel containers), PostgreSQL StatefulSet, services, NetworkPolicies (default deny + explicit allows), PodDisruptionBudget, optional HPA (chart).

## Manifests

```sh
docker build -t shieldwaf:2.4 . && docker build -t shieldwaf-db:2.4 db
kind load docker-image shieldwaf:2.4 shieldwaf-db:2.4 --name <cluster>       # or push to your registry and change the image names
sh scripts/create-db-secret.sh                    # database password + key for the shared files (cluster only)
kubectl apply -f k8s/shieldwaf.yaml
sh scripts/create-backup-key.sh && kubectl apply -f k8s/backup.yaml          # authenticated backups + weekly restore test
# optional:
sh scripts/create-redis-secret.sh && kubectl apply -f k8s/redis.yaml          # cluster-wide rate limits (then: kubectl -n shieldwaf rollout restart deploy/shieldwaf)
kubectl apply -f k8s/namespace-guardrails.yaml                                # LimitRange + ResourceQuota
kubectl apply -f k8s/db-pitr.yaml && kubectl -n shieldwaf patch statefulset shieldwaf-db --patch-file k8s/db-pitr.patch.yaml     # point-in-time recovery
```

Admin panel: label the namespace that may reach it (`kubectl label ns <ns> shieldwaf-admin=true`) and use a port-forward or an internal ingress; the protected traffic is the Service `shieldwaf-proxy` (put your load balancer in front of 80/443 only).

## Helm

```sh
helm install shieldwaf charts/shieldwaf -n shieldwaf --create-namespace \
  --set image.repository=<registry>/shieldwaf --set image.tag=2.4 --set database.image.repository=<registry>/shieldwaf-db --set database.image.tag=2.4 \
  --set backup.enabled=true --set redis.enabled=true --set networkPolicy.enabled=true
```

The chart creates the database secret, the backup key ring and the Redis secret once and keeps them on upgrade and uninstall (`helm.sh/resource-policy: keep`). `helm lint` and `helm template` pass in CI; the chart installs in a kind cluster through `DEPLOY_WITH=helm bash tests/run.sh` (that suite was last run for 2.3, not for 2.4).

## What the layout enforces (tested by `SUITES=hardening bash tests/run.sh`, 24 checks)

* Engine: `/data` read-only except `rendered/` and `logs/`, no `/private`, non-root, read-only root file system, all capabilities dropped, seccomp RuntimeDefault, no service-account token.
* Pods spread over nodes and zones, PodDisruptionBudget, requests and limits on every container, default-deny NetworkPolicy.

## Tests

```sh
IMG_TAG=2.4-dev SUITES=functional bash tests/run.sh     # 200 checks on 2 replicas
IMG_TAG=2.4-dev SUITES=ha bash tests/run.sh             # 91 checks on 3 replicas (rolling restart, database outage, leader, ACME, ...)
IMG_TAG=2.4-dev SUITES=backup bash tests/run.sh         # 18 checks: backup, weekly restore test, disaster, restore
IMG_TAG=2.4-dev SUITES=hardening bash tests/run.sh      # 24 checks
```

They create and delete the namespaces `shieldwaf-test`, `sink-test` and `shieldwaf-demo` only. They need about 1.5 GB of free memory on the cluster: **on a small shared cluster run them one at a time and watch the other workloads.**
