#!/usr/bin/env bash
# Runs the full regression suite (185 checks, on 2 replicas) and then the high-availability suite (3 replicas) against THROW-AWAY copies of
# A Shield WAF in the namespace "shieldwaf-test".
# It does not touch your real installation in the namespace "shieldwaf".
#
# Needs: kubectl (pointing at a test cluster), python 3.9+, curl, openssl, sed. The images shieldwaf:2.3 and shieldwaf-db:16 must already
# be on the cluster (see docs/INSTALL.md). The pods need outbound internet (GitHub, threat feeds, the registries' country files).
# SUITES=functional runs only the 192-check suite (default: both suites).
# Careful: the namespaces "shieldwaf-test", "sink-test" and "shieldwaf-demo" are deleted and recreated. Nothing else is touched.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"; ROOT="$(dirname "$HERE")"
PY="$(command -v python3 || command -v python)"
PIDS=()
cleanup() { for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null; done; }
trap cleanup EXIT

deploy_waf() {
  kubectl delete namespace shieldwaf-test --wait=true >/dev/null 2>&1
  sed -e 's#namespace: shieldwaf$#namespace: shieldwaf-test#; s#^  name: shieldwaf$#  name: shieldwaf-test#' "$ROOT/k8s/shieldwaf.yaml" > "$HERE/.shieldwaf-test.yaml"
  sh "$ROOT/scripts/create-db-secret.sh" shieldwaf-test >/dev/null
  kubectl apply -f "$HERE/.shieldwaf-test.yaml" >/dev/null
  for i in $(seq 1 90); do
    P=$(kubectl -n shieldwaf-test get pods --no-headers 2>/dev/null)
    [ "$(echo "$P" | grep -c '^shieldwaf-test.* 2/2')" -ge 2 ] && echo "$P" | grep -q "shieldwaf-db-0 .*1/1"       && kubectl -n sink-test get pods --no-headers 2>/dev/null | grep -q " 1/1"       && [ "$(kubectl -n shieldwaf-demo get pods --no-headers 2>/dev/null | grep -c ' 1/1')" = "2" ] && break
    sleep 4
  done
}

echo "== resetting test namespaces"
kubectl delete namespace sink-test shieldwaf-demo --wait=false >/dev/null 2>&1
# the tiny demo servers ignore SIGTERM, which can leave their pods "Terminating" for a long time: remove them at once (they are throw-away test pods)
for ns in sink-test shieldwaf-demo; do kubectl -n "$ns" delete pod --all --force --grace-period=0 >/dev/null 2>&1; done
kubectl wait --for=delete namespace/sink-test namespace/shieldwaf-demo --timeout=120s >/dev/null 2>&1
kubectl apply -f "$HERE/demo-apps.yaml" -f "$HERE/sink.yaml" >/dev/null

echo "== deploying a test copy of A Shield WAF (2 replicas)"
deploy_waf

echo "== opening the three local tunnels (panel 19000, proxy 18088, tls 18443)"
fwd() { ( while true; do kubectl -n shieldwaf-test port-forward "svc/$1" "$2" >/dev/null 2>&1; sleep 1; done ) & PIDS+=($!); }
fwd shieldwaf-panel 19000:9000; fwd shieldwaf-proxy 18088:8080; fwd shieldwaf-proxy 18443:8443
for i in $(seq 1 30); do curl -sk -m 5 -o /dev/null https://127.0.0.1:19000/healthz && curl -s -m 5 -o /dev/null -H "Host: x" http://127.0.0.1:18088/__shieldwaf_health && break; sleep 3; done

echo "== running the functional tests (about 15-25 minutes)"
cd "$HERE" && "$PY" -u functional_test.py
RC=$?
cleanup; PIDS=()
if [ "${SUITES:-all}" = "functional" ]; then
  echo "== finished (functional suite only): exit code $RC (0 = all checks passed). Run without SUITES=functional to include the high-availability suite."
  exit $RC
fi
echo "== functional suite finished with exit code $RC; now the high-availability suite on a fresh copy (about 10 minutes)"
deploy_waf
"$PY" -u ha_test.py
RC2=$?
echo "== finished: functional exit code $RC, high-availability exit code $RC2 (0 = all checks passed). Remove the test namespaces with:"
echo "   kubectl delete namespace shieldwaf-test sink-test shieldwaf-demo"
[ "$RC" = 0 ] && [ "$RC2" = 0 ]
exit $?
