# Running A Shield WAF in the cloud (EKS, AKS, GKE or any Kubernetes)

Read [`../SECURITY.md`](../SECURITY.md) first. This page only covers the cloud-specific steps.

## 1. Image
**Easiest:** use the published, signed images and the Helm chart (`docs/RELEASE.md`), pin them by digest, and install with `helm install shieldwaf oci://ghcr.io/<owner>/charts/shieldwaf -n shieldwaf --create-namespace --set service.proxy.type=LoadBalancer --set autoscaling.enabled=true --set backup.enabled=true`. Or build your own as follows.
Build once, push to **your private registry**, and reference it by digest.
```bash
docker build -t <registry>/a-shield-waf:2.3 .
docker push <registry>/a-shield-waf:2.3
docker build -t <registry>/a-shield-waf-db:16 db && docker push <registry>/a-shield-waf-db:16     # only if you use the bundled PostgreSQL
# then set image: <registry>/a-shield-waf@sha256:<digest> in k8s/shieldwaf.yaml (both containers) and imagePullSecrets if needed
```
Scan it before every release: `trivy image --severity HIGH,CRITICAL --ignore-unfixed <registry>/a-shield-waf:2.3`.

## 2. Storage and database
The configuration, attack log, sessions and audit trail are in **PostgreSQL**. Either keep the bundled hardened StatefulSet (create its secret with `scripts/create-db-secret.sh`) or use a **managed PostgreSQL** (Amazon RDS, Azure Database for PostgreSQL, Cloud SQL): delete the `shieldwaf-db` StatefulSet / Service / policy from the manifest and create the secret yourself with `SHIELD_DB_URL=postgresql://user:password@host:5432/dbname?sslmode=require` (key `SHIELD_DB_URL`). Enable the provider's backups and encryption.
The replicas themselves are stateless: each one has a private scratch volume (`emptyDir`) for its rendered configuration and logs and rebuilds everything else from the
database. Certificates, private keys, alert secrets, threat-feed data and downloaded rule sets are shared between replicas **through the database, encrypted** with the key in the secret
key `SHIELD_DATA_KEY` (create it with `scripts/create-db-secret.*`, or put a random 32-byte url-safe base64 value there yourself). Use an encrypted storage class for the database volume
(EBS gp3 with KMS, Azure Disk with CMK, GCE PD with CMEK), snapshot it on a schedule, and back up the secret separately. A managed PostgreSQL must allow about 20 connections per replica.

### Replicated database (no single point of failure)
The firewall replicas keep working while the database is down, but changes and new replicas need it. To remove that single point of failure use a **replicated PostgreSQL**:
- **Managed:** Multi-AZ Amazon RDS, Azure Database for PostgreSQL (zone redundant), Cloud SQL (high availability). Use their failover endpoint in `SHIELD_DB_URL`.
- **In the cluster:** `k8s/ha-database/cloudnative-pg.yaml` (CloudNativePG operator: a primary and two standbys with automatic failover). Steps are in the file. This manifest was **not** run in this project's tests.
- **Any primary/standby setup:** list every database host in the connection string and the panel finds the writable one by itself:
  `postgresql://shieldwaf:<password>@db1:5432,db2:5432/shieldwaf?target_session_attrs=read-write`.
**What the panel does when the primary fails** (tested against a real PostgreSQL primary and streaming standby, `tests/dbfailover.sh`): the first database calls after the failure are retried on a new connection, the panel finds the promoted standby on its own, and writes continue; the test saw about 7 seconds of interruption (including the seconds the test waited before promoting) and no lost acknowledged write.
**Backups still matter** with a replicated database (a replica copies mistakes too): use `k8s/backup.yaml` and set its `PGHOST` to your database service.

## 3. Exposing the protected traffic (only 80/443)
Create a **separate** Service of type LoadBalancer that exposes the proxy ports only, never the panel:
```yaml
apiVersion: v1
kind: Service
metadata:
  name: shieldwaf-public
  namespace: shieldwaf
  annotations:
    # AWS example (NLB, keep the client address):  service.beta.kubernetes.io/aws-load-balancer-type: "nlb"
spec:
  type: LoadBalancer
  externalTrafficPolicy: Local          # keeps the real client IP
  selector: { app: shieldwaf }
  ports:
    - { name: http,  port: 80,  targetPort: 8080 }
    - { name: https, port: 443, targetPort: 8443 }
```
In the panel: Sites, TLS on, redirect port empty (443). If a cloud load balancer or CDN sits in front and does **not** preserve the
client address, add its CIDR under Settings, "Real client IP", so `X-Forwarded-For` is trusted from it and only from it.
Restrict the NetworkPolicy `ingress` rule for 8080/8443 to the load balancer's address range.

## 4. The admin panel stays private
Keep `shieldwaf-panel` as ClusterIP. Reach it with `kubectl port-forward`, a VPN, a bastion, or a **private** ingress. Then set
Settings, "Admin panel access" to your admin network, and enable two-factor login. To allow a namespace to reach port 9000, label it:
`kubectl label namespace <ns> shieldwaf-admin=true`.

## 5. Certificates: automatic (built in) or cert-manager
**Simplest:** in the panel choose certificate source *Let's Encrypt (automatic, free)* for a site (see `USER-GUIDE.md`, "Automatic certificates"). Needs port 80 of your load balancer to reach the proxy (`80 -> 8080`, see section 3) and a public DNS name for the site. No wildcards.
**Wildcards, or you already run cert-manager:** use cert-manager as follows.
Ask cert-manager for a certificate per site, then mount the secrets so the WAF serves them (no keys are ever pasted into the GUI):
```yaml
# 1) a Certificate in the shieldwaf namespace
apiVersion: cert-manager.io/v1
kind: Certificate
metadata: { name: notes-tls, namespace: shieldwaf }
spec:
  secretName: notes-tls
  dnsNames: [notes.example.com]
  issuerRef: { name: letsencrypt-prod, kind: ClusterIssuer }
```
Uncomment the `certs` volume and mounts in `k8s/shieldwaf.yaml` (both containers) so that the files appear as `/certs/notes-tls/tls.crt` and
`/certs/notes-tls/tls.key`, then in the GUI choose TLS source **mounted secret** with the name `notes-tls`. cert-manager renews the
secret; run "Re-apply config" (or restart the pod) after a renewal so nginx reloads it.
The admin panel can use its own certificate the same way (`/panel-tls/tls.crt` + `tls.key`).

## 6. Upstream restrictions
Set Settings, "Upstream restrictions" to the suffixes of your internal services (for example `svc.cluster.local`). Loopback, link-local
and cloud-metadata addresses are always refused, which also blocks the classic `169.254.169.254` credential theft path.

## 7. Network policy
`k8s/shieldwaf.yaml` ships a default-deny policy with explicit allows. Your cluster's CNI must **enforce** NetworkPolicy (Calico, Cilium,
AWS VPC CNI with network policy enabled, Azure NPM, GKE Dataplane V2). Check with a test pod before relying on it.

## 8. Alerts and log export
Add your channels on the **Alerts** page: a Slack/Teams webhook for the on-call team, an email channel, and a syslog or HTTP collector channel with *SIEM export* ticked so every blocked request reaches your SIEM (Splunk, Elastic, Sentinel, ...). Use **Test** to verify each channel. NetworkPolicy already allows egress to private and public addresses except link-local.

## 9. Monitoring
Scrape `https://shieldwaf-panel.shieldwaf.svc:9000/metrics` with the bearer token from the panel (Settings). Alert on:
`shieldwaf_engine_up == 0`, a sudden rise of `shieldwaf_requests_total{status="403"}`, and certificate expiry warnings on the dashboard.

## 10. Availability and limits
**Replicas:** the manifest runs two (set `replicas:` to 3 for the most common production layout: one replica per availability zone). The Deployment spreads them over nodes
(`topologySpreadConstraints`; with a zone label use `topology.kubernetes.io/zone` instead of the hostname key for zone spreading), a PodDisruptionBudget keeps one up during node
drains, and rolling updates never remove a replica before its replacement is ready. Point your load balancer's health check at the proxy Service; a replica that is not ready is taken out of rotation.
**Database:** the replicas keep serving when it is down, but it is the single point of failure for changes and for starting new replicas. Use a managed, replicated PostgreSQL
(Multi-AZ RDS, Azure zone-redundant, Cloud SQL HA) rather than the bundled single StatefulSet.
**Per-replica counters:** rate limits and the connection cap are applied by each replica to its own share of the traffic; with N replicas an address can use up to N times the configured rate.
**Memory:** the OWASP rules are loaded once and shared by all sites, so memory barely grows with the number of sites (about 250 MB per replica for 80 sites).
Only while a canary rule set is tested does each site load its own copy again.
