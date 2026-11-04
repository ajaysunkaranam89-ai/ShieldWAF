#!/bin/sh
# Creates the encryption key ring for the database backups: a Kubernetes secret that is separate from the database secret
# (shieldwaf-backup-keys: `current` = id of the key used for new backups, key-<id> = 32 random bytes, base64). Safe to run again: an existing ring is never changed.
# Usage: sh scripts/create-backup-key.sh [namespace]      (default namespace: shieldwaf)
# IMPORTANT: store an offline copy of the key ring (for example: kubectl -n shieldwaf get secret shieldwaf-backup-keys -o yaml > keys.yaml, kept in a safe place that is not the
# cluster and not the backup destination). Without the key a backup cannot be read, by anybody.
set -e
NS="${1:-shieldwaf}"
kubectl create namespace "$NS" --dry-run=client -o yaml | kubectl apply -f - >/dev/null
if kubectl -n "$NS" get secret shieldwaf-backup-keys >/dev/null 2>&1; then
  echo "secret shieldwaf-backup-keys already exists in $NS (left unchanged; rotate with scripts/rotate-backup-key.sh)"; exit 0
fi
KID=$(head -c 4 /dev/urandom | od -An -tx1 | tr -d ' \n')
KEY=$(head -c 32 /dev/urandom | base64 | tr -d '\n')
kubectl -n "$NS" create secret generic shieldwaf-backup-keys --from-literal=current="$KID" --from-literal="key-$KID=$KEY"
echo "secret shieldwaf-backup-keys created in $NS (current key id $KID). Make an offline copy of it now (see the comment at the top of this script)."
