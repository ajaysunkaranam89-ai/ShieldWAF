#!/usr/bin/env bash
# CrowdSec bouncer test against a REAL CrowdSec Local API in Docker. Needs Docker, the image ${IMAGE:-shieldwaf:2.4-dev} and internet access to pull crowdsecurity/crowdsec.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"; ROOT="$(dirname "$HERE")"
NET=shieldwaf-cs-test; IMG="${IMAGE:-shieldwaf:2.4-dev}"
export MSYS_NO_PATHCONV=1
WIN() { cygpath -m "$1" 2>/dev/null || echo "$1"; }
cleanup() { docker rm -f sw-cs-lapi >/dev/null 2>&1; docker network rm $NET >/dev/null 2>&1; }
[ "${KEEP:-}" = 1 ] || trap cleanup EXIT
cleanup
docker network create $NET >/dev/null || exit 1
docker run -d --name sw-cs-lapi --network $NET --network-alias crowdsec -e DISABLE_ONLINE_API=true -e DISABLE_AGENT=true -e CROWDSEC_BYPASS_DB_VOLUME_CHECK=true crowdsecurity/crowdsec:latest >/dev/null || exit 1
for i in $(seq 1 60); do docker exec sw-cs-lapi cscli lapi status >/dev/null 2>&1 && break; sleep 3; done
docker exec sw-cs-lapi cscli lapi status >/dev/null 2>&1 || { echo "CrowdSec did not become ready"; docker logs sw-cs-lapi 2>&1 | tail -5; exit 1; }
KEY=$(docker exec sw-cs-lapi cscli bouncers add shieldwaf -o raw | tr -d '\r\n')
[ -n "$KEY" ] || { echo "no bouncer key"; exit 1; }
docker exec sw-cs-lapi cscli decisions add --ip 45.9.148.10 --duration 2h --type ban --reason test >/dev/null
docker exec sw-cs-lapi cscli decisions add --range 91.92.240.0/24 --duration 2h --type ban --reason test >/dev/null
docker exec sw-cs-lapi cscli decisions add --ip 10.1.2.3 --duration 2h --type ban --reason private >/dev/null
docker exec sw-cs-lapi cscli decisions add --range 80.0.0.0/4 --duration 2h --type ban --reason wide >/dev/null
docker exec sw-cs-lapi cscli decisions add --ip 45.9.148.11 --duration 2h --type captcha --reason captcha >/dev/null
docker volume create sw-cs-state >/dev/null
run() { docker run --rm --network $NET -e CS_KEY="$KEY" -v sw-cs-state:/state --user 0 -v "$(WIN "$ROOT")/panel:/panel:ro" -v "$(WIN "$HERE")/crowdsec_test.py:/t/t.py:ro" --entrypoint python3 "$IMG" -u /t/t.py "$1"; }
trap 'cleanup; docker volume rm sw-cs-state >/dev/null 2>&1' EXIT
run 1; RC1=$?
docker exec sw-cs-lapi cscli decisions delete --ip 45.9.148.10 >/dev/null
docker exec sw-cs-lapi cscli decisions add --ip 185.220.101.5 --duration 30m --type ban --reason test2 >/dev/null
sleep 2
run 2; RC2=$?
echo "phase 1 exit $RC1, phase 2 exit $RC2"
[ "$RC1" = 0 ] && [ "$RC2" = 0 ]
