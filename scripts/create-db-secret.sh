#!/bin/sh
# Creates the secret for A Shield WAF: a random database password and a random key that encrypts the files shared between replicas
# (private keys, certificates, alert secrets). Both are stored ONLY in the cluster, never in git.
# Usage: sh scripts/create-db-secret.sh [namespace]      (default namespace: shieldwaf)
# Safe to run again: an existing password is never changed; a missing encryption key (older installation) is added.
set -e
export MSYS_NO_PATHCONV=1     # Git Bash on Windows would turn a value that starts with "/" into a Windows path
NS="${1:-shieldwaf}"
kubectl create namespace "$NS" --dry-run=client -o yaml | kubectl apply -f - >/dev/null
newkey() { head -c 32 /dev/urandom | base64 | tr '+/' '-_' | tr -d '\n'; }
if kubectl -n "$NS" get secret shieldwaf-db >/dev/null 2>&1; then
  if kubectl -n "$NS" get secret shieldwaf-db -o jsonpath='{.data.SHIELD_DATA_KEY}' | grep -q .; then
    echo "secret shieldwaf-db already exists in $NS (left unchanged)"; exit 0
  fi
  B64=$(newkey | base64 | tr -d '\n')
  kubectl -n "$NS" patch secret shieldwaf-db -p "{\"data\":{\"SHIELD_DATA_KEY\":\"$B64\"}}" >/dev/null
  echo "secret shieldwaf-db in $NS: encryption key for shared files added (database password unchanged)"; exit 0
fi
PW=$(head -c 24 /dev/urandom | od -An -tx1 | tr -d ' \n')
APW=$(head -c 24 /dev/urandom | od -An -tx1 | tr -d ' \n')
# New installations run least-privilege: the panel connects as the role shieldwaf_app (data changes only; the audit trail is append-only; no DDL) and the schema
# is migrated by an init container with the owner credential (SHIELD_DB_OWNER_URL, used only there). SHIELD_DB_MIGRATE=off tells the panel not to touch the schema.
kubectl -n "$NS" create secret generic shieldwaf-db \
  --from-literal=POSTGRES_PASSWORD="$PW" \
  --from-literal=SHIELD_DB_OWNER_URL="postgresql://shieldwaf:$PW@shieldwaf-db:5432/shieldwaf" \
  --from-literal=SHIELD_DB_APP_PASSWORD="$APW" \
  --from-literal=SHIELD_DB_URL="postgresql://shieldwaf_app:$APW@shieldwaf-db:5432/shieldwaf" \
  --from-literal=SHIELD_DB_MIGRATE="off" \
  --from-literal=SHIELD_DATA_KEY="$(newkey)"
echo "secret shieldwaf-db created in $NS (least-privilege database role)"
