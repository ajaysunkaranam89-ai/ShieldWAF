#!/usr/bin/env bash
# Upgrade and rollback test on a THROW-AWAY copy (namespace shieldwaf-test; your real namespace is never touched):
#   1. install 2.3 exactly as released (git tag v2.3.0: its manifest, its images, a 2.3-style secret), create an admin, two sites, audit entries
#   2. upgrade to 2.4 (the 2.4 manifest applied over it; the secret stays in the 2.3 format)            -> everything must still be there
#   3. roll back to 2.3 (images of the WAF deployment set back; the database keeps the 2.4 image)        -> everything must still be there
#   4. upgrade to 2.4 again (what 2.3 wrote while rolled back must be chained)                           -> everything must still be there
#   5. switch the secret to the restricted database role as described in docs/SECURITY_HARDENING.md     -> everything must still be there
# Needs: kubectl on a test cluster, the images shieldwaf:2.3, shieldwaf-db:16 and shieldwaf:${IMG_TAG:-2.4-dev}, shieldwaf-db:${IMG_TAG:-2.4-dev} loaded, git with the tag v2.3.0.
set -u
HERE="$(cd "$(dirname "$0")" && (pwd -W 2>/dev/null || pwd))"; ROOT="$(dirname "$HERE")"
TAG="${IMG_TAG:-2.4-dev}"; NS=shieldwaf-test
export MSYS_NO_PATHCONV=1
PY="$(command -v python3 || command -v python)"
PIDS=(); cleanup() { for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null; done; }; trap cleanup EXIT
RC=0
run() { "$PY" -u "$HERE/upgrade_test.py" "$@" || RC=1; }
rollout() { kubectl -n $NS rollout status sts/shieldwaf-db --timeout=300s >/dev/null 2>&1; kubectl -n $NS rollout status deploy/shieldwaf-test --timeout=400s >/dev/null 2>&1 || echo "(rollout did not finish in time)"; }
# the port-forwards bind to one pod: restart them after every step
fwd_start() { fwd_stop; for spec in "shieldwaf-panel 19000:9000" "shieldwaf-proxy 18088:8080"; do set -- $spec; ( while true; do kubectl -n $NS port-forward "svc/$1" "$2" >/dev/null 2>&1; sleep 1; done ) & PIDS+=($!); done
  for i in $(seq 1 40); do curl -sk -m 5 -o /dev/null https://127.0.0.1:19000/healthz && curl -s -m 5 -o /dev/null -H "Host: x" http://127.0.0.1:18088/__shieldwaf_health && break; sleep 2; done; }
fwd_stop() { for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null; done; PIDS=(); sleep 1; }
m24() { sed -e 's#namespace: shieldwaf$#namespace: '$NS'#; s#^  name: shieldwaf$#  name: shieldwaf-test#; s#image: shieldwaf:[0-9.a-z-]*#image: shieldwaf:'"$TAG"'#; s#image: shieldwaf-db:[0-9.a-z-]*#image: shieldwaf-db:'"$TAG"'#' "$ROOT/k8s/shieldwaf.yaml"; }

echo "== reset"
kubectl delete namespace $NS sink-test shieldwaf-demo --wait=false >/dev/null 2>&1
for ns in sink-test shieldwaf-demo; do kubectl -n "$ns" delete pod --all --force --grace-period=0 >/dev/null 2>&1; done
kubectl wait --for=delete namespace/$NS namespace/sink-test namespace/shieldwaf-demo --timeout=180s >/dev/null 2>&1
kubectl apply -f "$HERE/demo-apps.yaml" >/dev/null
rm -f "$HERE/.upg-state.json"

echo "== 1. 2.3 as released"
git -C "$ROOT" show v2.3.0:k8s/shieldwaf.yaml | sed -e 's#namespace: shieldwaf$#namespace: '$NS'#; s#^  name: shieldwaf$#  name: shieldwaf-test#' > "$HERE/.upg-v23.yaml"
kubectl apply -f "$HERE/.upg-v23.yaml" >/dev/null
PW=$(head -c 24 /dev/urandom | od -An -tx1 | tr -d ' \n'); KEY=$(head -c 32 /dev/urandom | base64 | tr '+/' '-_' | tr -d '\n')
kubectl -n $NS create secret generic shieldwaf-db --from-literal=POSTGRES_PASSWORD="$PW" --from-literal=SHIELD_DB_URL="postgresql://shieldwaf:$PW@shieldwaf-db:5432/shieldwaf" --from-literal=SHIELD_DATA_KEY="$KEY" >/dev/null
rollout; fwd_start
run seed

echo "== 2. upgrade to 2.4 (2.3-style secret, the panel migrates itself)"
m24 | kubectl apply -f - >/dev/null
sleep 5; rollout; fwd_start
run check upgraded

echo "== 3. roll back to 2.3 (WAF images only; the database keeps the 2.4 image)"
kubectl -n $NS set image deploy/shieldwaf-test engine=shieldwaf:2.3 panel=shieldwaf:2.3 >/dev/null
sleep 5; rollout; fwd_start
run check rolled-back --version 2.3

echo "== 4. upgrade to 2.4 again"
m24 | kubectl apply -f - >/dev/null
sleep 5; rollout; fwd_start
run check upgraded-again

echo "== 5. switch to the restricted database role (steps of docs/SECURITY_HARDENING.md)"
OWNER=$(kubectl -n $NS get secret shieldwaf-db -o jsonpath='{.data.SHIELD_DB_URL}' | base64 -d)
APW=$(head -c 24 /dev/urandom | od -An -tx1 | tr -d ' \n')
B64() { printf '%s' "$1" | base64 | tr -d '\n'; }
kubectl -n $NS patch secret shieldwaf-db -p "{\"data\":{\"SHIELD_DB_OWNER_URL\":\"$(B64 "$OWNER")\",\"SHIELD_DB_APP_PASSWORD\":\"$(B64 "$APW")\",\"SHIELD_DB_MIGRATE\":\"$(B64 off)\",\"SHIELD_DB_URL\":\"$(B64 "postgresql://shieldwaf_app:$APW@shieldwaf-db:5432/shieldwaf")\"}}" >/dev/null
kubectl -n $NS rollout restart deploy/shieldwaf-test >/dev/null
sleep 5; rollout; fwd_start
run check restricted --restricted

echo; [ $RC = 0 ] && echo "upgrade and rollback test: ALL STEPS PASSED" || echo "upgrade and rollback test: FAILURES (see above)"
exit $RC
