#!/usr/bin/env bash
# Tests the automatic-certificate (ACME) client against Pebble, the official Let's Encrypt test server, with throw-away Docker containers.
# Needs Docker and internet access for the three images. Nothing outside the containers and the private network "shieldwaf-acme-test" is touched.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"; ROOT="$(dirname "$HERE")"
NET=shieldwaf-acme-test
cleanup() { docker rm -f sw-pebble sw-challtest sw-acme-client >/dev/null 2>&1; docker network rm $NET >/dev/null 2>&1; rm -f "$HERE/.pebble-ca.pem"; }
trap cleanup EXIT
cleanup
docker network create --subnet 10.77.0.0/24 $NET >/dev/null || exit 1
docker run -d --name sw-challtest --network $NET --ip 10.77.0.3 ghcr.io/letsencrypt/pebble-challtestsrv:latest -defaultIPv4 10.77.0.4 -defaultIPv6 "" >/dev/null || exit 1
MSYS_NO_PATHCONV=1 docker run -d --name sw-pebble --network $NET --ip 10.77.0.2 --network-alias pebble -e PEBBLE_VA_NOSLEEP=1 -e PEBBLE_WFE_NONCEREJECT=20 \
  ghcr.io/letsencrypt/pebble:latest -config /test/config/pebble-config.json -dnsserver 10.77.0.3:8053 >/dev/null || exit 1
sleep 5
MSYS_NO_PATHCONV=1 docker cp sw-pebble:/test/certs/pebble.minica.pem "$(cygpath -m "$HERE" 2>/dev/null || echo "$HERE")/.pebble-ca.pem" || exit 1
MSYS_NO_PATHCONV=1 docker run --rm --name sw-acme-client --network $NET --ip 10.77.0.4 --add-host pebble:10.77.0.2 \
  -e SHIELD_ACME_TEST_CA=/ca.pem -e SHIELD_ACME_ALLOW_PRIVATE=1 --entrypoint python3 \
  -v "$HERE/.pebble-ca.pem:/ca.pem:ro" -v "$ROOT/panel:/panel:ro" -v "$HERE/acme_pebble_test.py:/t/acme_pebble_test.py:ro" shieldwaf:2.3 -u /t/acme_pebble_test.py
