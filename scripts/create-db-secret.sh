#!/bin/sh
# Creates the database secret for A Shield WAF: a random password, stored ONLY in the cluster (never in git).
# Usage: sh scripts/create-db-secret.sh [namespace]      (default namespace: shieldwaf)
set -e
NS="${1:-shieldwaf}"
kubectl create namespace "$NS" --dry-run=client -o yaml | kubectl apply -f - >/dev/null
if kubectl -n "$NS" get secret shieldwaf-db >/dev/null 2>&1; then echo "secret shieldwaf-db already exists in $NS (left unchanged)"; exit 0; fi
PW=$(head -c 24 /dev/urandom | od -An -tx1 | tr -d ' \n')
kubectl -n "$NS" create secret generic shieldwaf-db \
  --from-literal=POSTGRES_PASSWORD="$PW" \
  --from-literal=SHIELD_DB_URL="postgresql://shieldwaf:$PW@shieldwaf-db:5432/shieldwaf"
echo "secret shieldwaf-db created in $NS"
