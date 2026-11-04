#!/usr/bin/env bash
# Cluster-wide rate limiting test with a REAL Redis and the real engine in Docker (no cluster needed). Needs Docker, the image ${IMAGE:-shieldwaf:2.4-dev} and
# internet access to pull redis:7-alpine. Phase 1 runs with Redis up, then Redis is stopped and phase 2 checks the fail-open / fail-closed behaviour.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"; ROOT="$(dirname "$HERE")"
NET=shieldwaf-rl-test; IMG="${IMAGE:-shieldwaf:2.4-dev}"
export MSYS_NO_PATHCONV=1
WIN() { cygpath -m "$1" 2>/dev/null || echo "$1"; }
cleanup() { docker rm -f sw-rl-redis >/dev/null 2>&1; docker network rm $NET >/dev/null 2>&1; }
[ "${KEEP:-}" = 1 ] || trap cleanup EXIT
cleanup
docker network create $NET >/dev/null || exit 1
docker run -d --name sw-rl-redis --network $NET --network-alias redis redis:7-alpine redis-server --requirepass rlpw --save "" --appendonly no >/dev/null || exit 1
sleep 3
run() { docker run --rm --network $NET -e SHIELD_DATA=/tmp/d -e SHIELD_REDIS_URL="redis://:rlpw@redis:6379/0" ${2:-} -v "$(WIN "$ROOT")/panel:/panel:ro" -v "$(WIN "$HERE")/redis_ratelimit_test.py:/t/t.py:ro" --entrypoint python3 "$IMG" -u /t/t.py $1; }
run up; RC1=$?
docker stop sw-rl-redis >/dev/null
run down; RC2=$?
echo "phase up exit $RC1, phase down exit $RC2"
[ "$RC1" = 0 ] && [ "$RC2" = 0 ]
