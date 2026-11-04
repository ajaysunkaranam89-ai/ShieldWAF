#!/usr/bin/env bash
# Overhead of the 2.4 request-path features, measured with k6 against the real engine in Docker (see harness.py for what is and is not included).
#   bash tests/perf/perf.sh     runs: 2.3 plain, 2.4 plain, 2.4 per-replica limit, 2.4 bot protection, 2.4 cluster-wide limit (Redis), 2.4 bots + cluster-wide limit
# Needs Docker, the images ${OLD_IMAGE:-shieldwaf:2.3} (optional) and ${IMAGE:-shieldwaf:2.4-dev}, internet access for redis:7-alpine and grafana/k6.
# Run it on an otherwise idle machine: the numbers depend on the machine (here: everything shares one Docker VM, including the load generator) and are only meaningful
# relative to each other. Results: tests/perf/.out/*.json and the table printed at the end.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"; ROOT="$(dirname "$(dirname "$HERE")")"
NET=shieldwaf-perf; IMG="${IMAGE:-shieldwaf:2.4-dev}"; OLD="${OLD_IMAGE:-shieldwaf:2.3}"; OUT="$HERE/.out"
export MSYS_NO_PATHCONV=1
WIN() { cygpath -m "$1" 2>/dev/null || echo "$1"; }
cleanup() { docker rm -f sw-perf-engine sw-perf-redis >/dev/null 2>&1; docker network rm $NET >/dev/null 2>&1; }
trap cleanup EXIT
cleanup; rm -rf "$OUT"; mkdir -p "$OUT"; chmod 777 "$OUT"
docker network create $NET >/dev/null
docker run -d --name sw-perf-redis --network $NET --network-alias redis redis:7-alpine redis-server --requirepass pw --save "" --appendonly no >/dev/null
start_engine() {   # $1 = image, $2 = "mount" to use the working tree's panel code instead of the one in the image
  docker rm -f sw-perf-engine >/dev/null 2>&1
  local mount=""; [ "${2:-}" = mount ] && mount="-v $(WIN "$ROOT")/panel:/panel:ro"
  docker run -d --name sw-perf-engine --network $NET --network-alias engine -e SHIELD_DATA=/tmp/d -e SHIELD_REDIS_URL="redis://:pw@redis:6379/0" --user 10101:10101 \
    $mount -v "$(WIN "$HERE")/harness.py:/t/harness.py:ro" --entrypoint python3 "$1" -u /t/harness.py >/dev/null
  for i in $(seq 1 30); do docker logs sw-perf-engine 2>&1 | grep -q READY && return 0; sleep 1; done
  docker logs sw-perf-engine 2>&1 | tail -5; return 1
}
run_k6() {   # $1 = host, $2 = label
  docker run --rm --network $NET -e TARGET_HOST="$1" -e VUS="${VUS:-64}" -e DURATION="${DURATION:-20}" -v "$(WIN "$HERE")/k6.js:/k6.js:ro" -v "$(WIN "$OUT"):/out" grafana/k6:latest run -q /k6.js >/dev/null 2>&1
  mv "$OUT/$1.json" "$OUT/$2.json" 2>/dev/null
}
if docker image inspect "$OLD" >/dev/null 2>&1; then
  start_engine "$OLD" && run_k6 plain.test v23_plain
fi
start_engine "$IMG" mount || exit 1
run_k6 plain.test v24_plain
run_k6 local.test v24_replica_limit
run_k6 bots.test v24_bots
run_k6 rl.test v24_cluster_limit
run_k6 all.test v24_bots_and_cluster_limit
python3 "$HERE/report.py" "$OUT" 2>/dev/null || python "$HERE/report.py" "$OUT"
