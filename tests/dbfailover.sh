#!/usr/bin/env bash
# Database failover test: a real PostgreSQL primary with a streaming standby (throw-away Docker containers), the panel's database layer writing
# once a second through a two-host connection string; the primary is stopped and the standby promoted. Shows what the panel does during a
# primary failure with ANY primary/standby setup (CloudNativePG, Patroni, a cloud service, plain streaming replication).
# Needs Docker and the images ${IMAGE:-shieldwaf:2.4-dev} and ${DBIMAGE:-shieldwaf-db:2.4-dev} (TLS only, replication over TLS with a SCRAM password). Uses only containers and the network "shieldwaf-dbfail-test".
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"; ROOT="$(dirname "$HERE")"
NET=shieldwaf-dbfail-test; IMG="${IMAGE:-shieldwaf:2.4-dev}"; DBIMG="${DBIMAGE:-shieldwaf-db:2.4-dev}"
export MSYS_NO_PATHCONV=1
D="docker"; PYH="$(command -v python3 || command -v python)"
cleanup() { $D rm -f sw-pg1 sw-pg2 sw-loop >/dev/null 2>&1; $D network rm $NET >/dev/null 2>&1; }
trap cleanup EXIT
cleanup
PASS=0; FAIL=0
check() { if [ "$2" = "1" ]; then echo "PASS  $1"; PASS=$((PASS+1)); else echo "FAIL  $1   [$3]"; FAIL=$((FAIL+1)); fi; }

$D network create --subnet 10.78.0.0/24 $NET >/dev/null || exit 1
$D run -d --name sw-pg1 --network $NET --ip 10.78.0.2 --network-alias pg1 -e POSTGRES_USER=shieldwaf -e POSTGRES_PASSWORD=pw -e POSTGRES_DB=shieldwaf \
  -e PGDATA=/var/lib/postgresql/data/pgdata -e SHIELD_DB_REPLICATION=on --tmpfs /tmp:exec,mode=1777 "$DBIMG" >/dev/null || exit 1
for i in $(seq 1 40); do $D exec sw-pg1 pg_isready -U shieldwaf -d shieldwaf >/dev/null 2>&1 && break; sleep 2; done
$D exec sw-pg1 psql -U shieldwaf -d shieldwaf -c "create role repl with replication login password 'rp'" >/dev/null
$D run -d --name sw-pg2 --network $NET --ip 10.78.0.3 --network-alias pg2 -e PGPASSWORD=rp -e PGSSLMODE=require -e PGDATA=/var/lib/postgresql/data/pgdata --tmpfs /tmp:exec,mode=1777 --entrypoint sh "$DBIMG" -c \
  'D=/var/lib/postgresql/data/pgdata; mkdir -p $D && chmod 700 $D && pg_basebackup -h pg1 -U repl -D $D -R -X stream && exec tls-entrypoint.sh postgres -D $D' >/dev/null || exit 1
for i in $(seq 1 40); do $D exec sw-pg2 pg_isready -U shieldwaf -d shieldwaf >/dev/null 2>&1 && break; sleep 2; done
REC=$($D exec sw-pg2 psql -U shieldwaf -d shieldwaf -tA -c "select pg_is_in_recovery()" 2>/dev/null)
check "the standby is running and replicating (in recovery)" "$([ "$REC" = "t" ] && echo 1 || echo 0)" "$REC"

URL="postgresql://shieldwaf:pw@pg1:5432,pg2:5432/shieldwaf?target_session_attrs=read-write&connect_timeout=5&sslmode=require"
$D run -d --name sw-loop --network $NET --ip 10.78.0.4 -e SHIELD_DB_URL="$URL" -e SHIELD_DB_SSLMODE=require -e SHIELD_DATA=/tmp/data --entrypoint python3 \
  -v "$ROOT/panel:/panel:ro" -v "$HERE/dbfailover_loop.py:/t/loop.py:ro" "$IMG" -u /t/loop.py 75 >/dev/null || exit 1
sleep 12
OK_BEFORE=$($D logs sw-loop 2>&1 | grep -c "^ok .* standby=False")
check "before the failure the panel writes to the primary (pg1)" "$([ "$OK_BEFORE" -ge 5 ] && echo 1 || echo 0)" "ok lines: $OK_BEFORE"
sleep 4
echo "== stopping the primary and promoting the standby"
T_STOP=$(date +%s)
$D stop -t 5 sw-pg1 >/dev/null
sleep 3
$D exec sw-pg2 sh -c 'pg_ctl promote -D /var/lib/postgresql/data/pgdata' >/dev/null 2>&1
T_PROMOTED=$(date +%s)
for i in $(seq 1 50); do
  [ "$($D logs sw-loop 2>&1 | tail -n 3 | grep -c 'standby=False.*')" -ge 1 ] && $D logs sw-loop 2>&1 | tail -n 3 | grep -q "10.78.0.3" && break
  sleep 2
done
sleep 10
LOG=$($D logs sw-loop 2>&1)
AFTER=$(echo "$LOG" | grep -c "^ok .* 10.78.0.3.* standby=False")
check "after the failover the panel writes to the new primary (pg2) again" "$([ "$AFTER" -ge 5 ] && echo 1 || echo 0)" "ok lines on pg2: $AFTER"
ERRS=$(echo "$LOG" | grep -c "^err ")
echo "   (errors during the switch: $ERRS, time from stop to the first write on pg2 shown below)"
FIRST_PG2=$(echo "$LOG" | grep "10.78.0.3" | head -1 | awk '{print $3}')
STOP_TS=$(echo "$LOG" | grep "10.78.0.2" | tail -1 | awk '{print $3}')
GAP=$($PYH -c "print(round(float('${FIRST_PG2:-0}') - float('${STOP_TS:-0}'), 1))" 2>/dev/null || echo "?")
echo "   write gap: ${GAP} s"
check "the interruption was short (under 40 seconds including the 3 s I waited before promoting)" "$($PYH -c "print(1 if 0 < float('${GAP:-999}') < 40 else 0)" 2>/dev/null || echo 0)" "gap $GAP"
# every acknowledged write must be on the new primary
ACKED=$(echo "$LOG" | grep "^ok " | awk '{print $2}' | sort -u | wc -l | tr -d ' ')
ON_PG2=$($D exec sw-pg2 psql -U shieldwaf -d shieldwaf -tA -c "select count(*) from meta where k like 'fo_%'" 2>/dev/null)
check "no acknowledged write was lost ($ACKED acknowledged, $ON_PG2 rows on the new primary)" "$([ -n "$ON_PG2" ] && [ "$ON_PG2" -ge "$ACKED" ] && echo 1 || echo 0)" "$ACKED vs $ON_PG2"
IN_REC=$($D exec sw-pg2 psql -U shieldwaf -d shieldwaf -tA -c "select pg_is_in_recovery()" 2>/dev/null)
check "pg2 is now a normal read-write primary" "$([ "$IN_REC" = "f" ] && echo 1 || echo 0)" "$IN_REC"
echo
echo "$PASS/$((PASS+FAIL)) database failover checks passed"
[ "$FAIL" = 0 ]
