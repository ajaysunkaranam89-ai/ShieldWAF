#!/bin/sh
# Creates the secret for the optional Redis (cluster-wide rate limiting): a random password and the connection URL the panel reads (SHIELD_REDIS_URL).
# Usage: sh scripts/create-redis-secret.sh [namespace]      (default namespace: shieldwaf). Safe to run again: an existing secret is never changed.
set -e
export MSYS_NO_PATHCONV=1     # Git Bash on Windows would turn a value that starts with "/" into a Windows path
NS="${1:-shieldwaf}"
kubectl create namespace "$NS" --dry-run=client -o yaml | kubectl apply -f - >/dev/null
if kubectl -n "$NS" get secret shieldwaf-redis >/dev/null 2>&1; then echo "secret shieldwaf-redis already exists in $NS (left unchanged)"; exit 0; fi
PW=$(head -c 24 /dev/urandom | od -An -tx1 | tr -d ' \n')
kubectl -n "$NS" create secret generic shieldwaf-redis --from-literal=REDIS_PASSWORD="$PW" --from-literal=SHIELD_REDIS_URL="redis://:$PW@shieldwaf-redis:6379/0"
echo "secret shieldwaf-redis created in $NS"
