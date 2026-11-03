# Running A Shield WAF in the cloud (EKS, AKS, GKE or any Kubernetes)

Read [`../SECURITY.md`](../SECURITY.md) first. This page only covers the cloud-specific steps.

## 1. Image
Build once, push to **your private registry**, and reference it by digest.
```bash
docker build -t <registry>/a-shield-waf:2.1 .
docker push <registry>/a-shield-waf:2.1
# then set image: <registry>/a-shield-waf@sha256:<digest> in k8s/shieldwaf.yaml (both containers) and imagePullSecrets if needed
```
Scan it before every release: `trivy image --severity HIGH,CRITICAL --ignore-unfixed <registry>/a-shield-waf:2.1`.

## 2. Storage
The PVC (`shieldwaf-data`) holds the configuration, logs, certificates and the audit trail. Use an encrypted storage class
(EBS gp3 with KMS, Azure Disk with CMK, GCE PD with CMEK) and snapshot it on a schedule.

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

## 5. Certificates with cert-manager
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

## 8. Monitoring
Scrape `https://shieldwaf-panel.shieldwaf.svc:9000/metrics` with the bearer token from the panel (Settings). Alert on:
`shieldwaf_engine_up == 0`, a sudden rise of `shieldwaf_requests_total{status="403"}`, and certificate expiry warnings on the dashboard.

## 9. Availability and limits
One replica, one volume: plan maintenance windows or run a second, independent instance behind DNS failover. Memory grows with the
number of sites because the rule set is loaded per site; raise the panel limit (768 Mi) and the engine limit (1 Gi) accordingly.
