# Releases, signatures and the Helm chart

## What a release contains
Pushing a tag such as `v2.3.0` runs `.github/workflows/release.yml`, which:
1. builds the two images, **scans them with Trivy** and stops if there is a fixable HIGH or CRITICAL vulnerability;
2. pushes them to GitHub Container Registry as `ghcr.io/<owner>/shieldwaf:<version>` (engine and admin panel) and `ghcr.io/<owner>/shieldwaf-db:<version>` (PostgreSQL), with BuildKit provenance and an SBOM;
3. **signs** each image by digest, without a key to keep (keyless signing with this workflow's identity), and attaches an **SPDX SBOM** (list of every package inside) as a signed attestation;
4. packages the **Helm chart** and publishes it as `oci://ghcr.io/<owner>/charts/shieldwaf`, also signed;
5. creates the GitHub release with the chart, both SBOM files and a `SHA256SUMS` file.

> The workflow is written for GitHub Actions and was **not run** in this project's own tests (it needs GitHub). Expect to fix small things on the first tag. New packages on ghcr.io start **private**: after the first release open the package settings on GitHub and make them public if you want others to pull them.

## Install from the Helm chart
```bash
helm install shieldwaf oci://ghcr.io/<owner>/charts/shieldwaf --version 2.3.0 -n shieldwaf --create-namespace
kubectl get pods -n shieldwaf          # then follow the notes Helm printed (setup code, tunnel)
```
From a checkout instead: `helm install shieldwaf ./charts/shieldwaf -n shieldwaf --create-namespace` (build and load the images first, or point `image.repository` at your own registry).
Useful options (all in `charts/shieldwaf/values.yaml`): `replicaCount`, `autoscaling.enabled`, `backup.enabled`, `service.proxy.type=LoadBalancer`, `image.digest`, `database.bundled=false`, `certs.secrets`, `networkPolicy.proxyFrom`.
**Upgrade:** `helm upgrade shieldwaf <chart> -n shieldwaf` (replicas are replaced one at a time, no downtime). **Uninstall:** `helm uninstall shieldwaf -n shieldwaf` keeps the secret `shieldwaf-db` (database password and the key for shared files and backups) and the database volume on purpose; delete them yourself when you really want everything gone. To install again in the same namespace add `--set secret.create=false`.
**Installing over an existing manual installation** (made with `k8s/shieldwaf.yaml`): Helm refuses to take over resources it did not create. Either install the chart into a new namespace and restore a backup into it (`docs/INSTALL.md`), or remove the old objects first.

## Autoscaling
`--set autoscaling.enabled=true` adds a HorizontalPodAutoscaler (2 to 6 replicas at 70% CPU by default, slow to scale down). It needs the **metrics-server** in the cluster. Remember that rate limits are counted per replica, so more replicas means a higher effective limit, and that every replica keeps about 20 database connections (the bundled PostgreSQL allows 200).

## Verify what you download
Install [cosign](https://docs.sigstore.dev/cosign/installation/). Replace `<owner>` and the version.
```bash
# the image was built and signed by this repository's release workflow (and nobody else)
cosign verify ghcr.io/<owner>/shieldwaf:2.3.0 \
  --certificate-identity-regexp '^https://github.com/<owner>/ShieldWAF/\.github/workflows/release\.yml@refs/tags/v.*$' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com

# the SBOM that was signed together with the image
cosign verify-attestation ghcr.io/<owner>/shieldwaf:2.3.0 --type spdxjson \
  --certificate-identity-regexp '^https://github.com/<owner>/ShieldWAF/\.github/workflows/release\.yml@refs/tags/v.*$' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com | head -c 600

# the chart
cosign verify ghcr.io/<owner>/charts/shieldwaf:2.3.0 --certificate-identity-regexp '...same...' --certificate-oidc-issuer https://token.actions.githubusercontent.com
```
**Pin by digest in production.** The tag `2.3.0` could in principle be re-pushed; a digest cannot. Take the digest the verification prints (or the release notes) and install with `--set image.digest=sha256:...` and `--set database.image.digest=sha256:...`.
Make the cluster itself enforce signatures with a policy controller (Sigstore policy-controller, Kyverno `verifyImages`, or your cloud's admission service) using the same identity and issuer as above.

## What this does and does not prove
A valid signature proves the image was produced by this repository's workflow from a tag, not that the code is free of bugs: that is what the tests, the scans and an independent review are for (`SECURITY.md`). The SBOM lets you check the packages inside against new vulnerability reports at any time (for example `trivy sbom shieldwaf-2.3.0.spdx.json`).
