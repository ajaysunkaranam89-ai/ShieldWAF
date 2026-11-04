#!/usr/bin/env bash
# Point-in-time recovery test with a REAL PostgreSQL in Docker: WAL archiving, an encrypted base backup, an "accident", and a recovery to the moment before it.
# Needs Docker and the images ${IMAGE:-shieldwaf:2.4-dev} and ${DBIMAGE:-shieldwaf-db:2.4-dev}.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"; ROOT="$(dirname "$HERE")"
NET=shieldwaf-pitr-test; IMG="${IMAGE:-shieldwaf:2.4-dev}"; DBIMG="${DBIMAGE:-shieldwaf-db:2.4-dev}"
export MSYS_NO_PATHCONV=1
WIN() { cygpath -m "$1" 2>/dev/null || echo "$1"; }
WORK="$HERE/.pitr-work"
VOLS="sw-pitr-data1 sw-pitr-data2 sw-pitr-archive sw-pitr-backups"
cleanup() { docker rm -f sw-pitr-pg1 sw-pitr-pg2 >/dev/null 2>&1; docker network rm $NET >/dev/null 2>&1; for v in $VOLS; do docker volume rm "$v" >/dev/null 2>&1; done; rm -rf "$WORK"; }
[ "${KEEP:-}" = 1 ] || trap cleanup EXIT
cleanup; mkdir -p "$WORK/keys" "$WORK/keys2"
PASS=0; FAIL=0
check() { if [ "$2" = "1" ]; then echo "PASS  $1"; PASS=$((PASS+1)); else echo "FAIL  $1   [${3:-}]"; FAIL=$((FAIL+1)); fi; }
q() { docker exec "$1" psql -U shieldwaf -d shieldwaf -tAc "$2"; }

docker network create $NET >/dev/null || exit 1
for v in $VOLS; do docker volume create "$v" >/dev/null; done
# the folders must belong to the database user (uid 70) / the backup user
docker run --rm -v sw-pitr-archive:/archive -v sw-pitr-data2:/data2 -v sw-pitr-backups:/backups --entrypoint sh alpine -c 'chown 70:70 /archive /data2 && chown 10101:10101 /backups' >/dev/null

PGENV="-e POSTGRES_USER=shieldwaf -e POSTGRES_PASSWORD=pw -e POSTGRES_DB=shieldwaf -e PGDATA=/var/lib/postgresql/data/pgdata --tmpfs /tmp:exec,mode=1777"
docker run -d --name sw-pitr-pg1 --network $NET --network-alias pg $PGENV -e SHIELD_DB_ARCHIVE_DIR=/archive -e SHIELD_DB_ARCHIVE_TIMEOUT=3 -e SHIELD_DB_REPLICATION=on \
  -v sw-pitr-data1:/var/lib/postgresql/data -v sw-pitr-archive:/archive "$DBIMG" >/dev/null || exit 1
for i in $(seq 1 40); do docker exec sw-pitr-pg1 pg_isready -U shieldwaf -d shieldwaf >/dev/null 2>&1 && break; sleep 2; done
check "archive_mode is on and the archive command is the safe copy script" "$([ "$(q sw-pitr-pg1 'show archive_mode')" = on ] && q sw-pitr-pg1 'show archive_command' | grep -q archive-wal.sh && echo 1 || echo 0)"

# an independent key ring
docker run --rm -v "$(WIN "$ROOT")/panel:/panel:ro" -v "$(WIN "$WORK")/keys:/keys" --user 0 --entrypoint python3 "$IMG" -c "
import sys; sys.path.insert(0,'/panel'); import backupcrypt as b
kid, mat = b.new_key(); open('/keys/key-' + kid, 'w').write(mat); open('/keys/current', 'w').write(kid)
kid, mat = b.new_key(); open('/keys2/key-' + kid, 'w').write(mat) if False else None"
chmod -R a+rX "$WORK/keys"
BK() { docker run --rm --network $NET -e PGHOST=pg -e PGUSER=shieldwaf -e PGPASSWORD=pw -e PGSSLMODE=require -e SHIELD_DATA=/tmp/d -v "$(WIN "$ROOT")/panel:/panel:ro" \
  -v "$(WIN "$WORK")/${KEYS:-keys}:/keys:ro" -v sw-pitr-backups:/backups -v sw-pitr-archive:/archive:ro -v "$1:/pgdata2" ${USERARG:---user 10101:10101} --entrypoint python3 "$IMG" /panel/backupcrypt.py "${@:2}"; }

q sw-pitr-pg1 "create table orders(id int primary key, note text)" >/dev/null
q sw-pitr-pg1 "insert into orders select g, 'before-backup' from generate_series(1,100) g" >/dev/null
OUT=$(BK sw-pitr-data2 basebackup --out /backups/base 2>&1)
echo "$OUT" | grep -q "base backup written and verified"; check "an encrypted base backup is written (pg_basebackup -> AES-256-GCM) and read back" "$([ $? = 0 ] && echo 1 || echo 0)" "$OUT"
q sw-pitr-pg1 "insert into orders select g, 'after-backup' from generate_series(101,150) g" >/dev/null
sleep 2
T=$(q sw-pitr-pg1 "select to_char(now(), 'YYYY-MM-DD HH24:MI:SS.US TZH')")
sleep 2
echo "== the accident at a time after $T"
q sw-pitr-pg1 "delete from orders where id <= 100" >/dev/null
q sw-pitr-pg1 "insert into orders select g, 'garbage' from generate_series(1000,1049) g" >/dev/null
q sw-pitr-pg1 "select pg_switch_wal()" >/dev/null
for i in $(seq 1 30); do N=$(docker run --rm -v sw-pitr-archive:/archive:ro --entrypoint sh alpine -c 'ls /archive | grep -vc "\.part$"'); [ "${N:-0}" -ge 3 ] && break; sleep 1; done
check "WAL segments reach the archive (without half-written files)" "$([ "${N:-0}" -ge 3 ] && docker run --rm -v sw-pitr-archive:/archive:ro --entrypoint sh alpine -c 'ls /archive | grep -c "\.part$"' | grep -q '^0$' && echo 1 || echo 0)" "files: $N"
check "the accident is real on the running database (100 rows deleted, 50 garbage rows)" "$([ "$(q sw-pitr-pg1 'select count(*) from orders')" = "100" ] && echo 1 || echo 0)"

echo "== archive script safety"
OUT=$(docker run --rm --user 70 -e SHIELD_DB_ARCHIVE_DIR=/archive -v sw-pitr-archive:/archive --entrypoint sh "$DBIMG" -c 'F=$(ls /archive | grep -v "\.part$" | head -1); cp /archive/$F /tmp/same; sh /usr/local/bin/archive-wal.sh /tmp/same $F; echo "same=$?"; echo different > /tmp/diff; sh /usr/local/bin/archive-wal.sh /tmp/diff $F; echo "diff=$?"' 2>&1)
check "archiving the same segment again is a no-op; a different file with the same name is refused (history is never overwritten)" "$(echo "$OUT" | grep -q 'same=0' && echo "$OUT" | grep -q 'diff=1' && echo 1 || echo 0)" "$OUT"

docker rm -f sw-pitr-pg1 >/dev/null
echo "== recovery"
OUT=$(KEYS=keys USERARG="--user 70:70 --group-add 10101" BK sw-pitr-data2 pitr-prepare latest --dir /backups/base --pgdata /pgdata2/pgdata --archive /archive --time "$T" 2>&1)
check "pitr-prepare verifies the backup, unpacks it and sets the recovery target" "$(echo "$OUT" | grep -q 'prepared from' && echo 1 || echo 0)" "$OUT"
OUT=$(KEYS=keys USERARG="--user 70:70 --group-add 10101" BK sw-pitr-data2 pitr-prepare latest --dir /backups/base --pgdata /pgdata2/pgdata --archive /archive 2>&1); RC=$?
check "it refuses to overwrite a data directory that is not empty" "$([ $RC = 2 ] && echo "$OUT" | grep -q 'not empty' && echo 1 || echo 0)" "rc=$RC $OUT"
docker run -d --name sw-pitr-pg2 --network $NET --network-alias pg $PGENV -v sw-pitr-data2:/var/lib/postgresql/data -v sw-pitr-archive:/archive:ro "$DBIMG" >/dev/null
for i in $(seq 1 60); do [ "$(q sw-pitr-pg2 'select pg_is_in_recovery()' 2>/dev/null)" = "f" ] && break; sleep 2; done
check "PostgreSQL replays the archive up to the target and becomes a normal database" "$([ "$(q sw-pitr-pg2 'select pg_is_in_recovery()' 2>/dev/null)" = "f" ] && echo 1 || echo 0)" "$(docker logs sw-pitr-pg2 2>&1 | tail -3)"
check "the state is the one just BEFORE the accident: all 150 rows are back, with their original text" "$([ "$(q sw-pitr-pg2 'select count(*) from orders' 2>/dev/null)" = "150" ] && [ "$(q sw-pitr-pg2 "select count(*) from orders where note='before-backup'" 2>/dev/null)" = "100" ] && [ "$(q sw-pitr-pg2 "select count(*) from orders where note='after-backup'" 2>/dev/null)" = "50" ] && echo 1 || echo 0)" "$(q sw-pitr-pg2 'select note, count(*) from orders group by 1' 2>&1)"
check "...and none of the garbage rows of the accident is there" "$([ "$(q sw-pitr-pg2 "select count(*) from orders where note='garbage'" 2>/dev/null)" = "0" ] && echo 1 || echo 0)"
docker rm -f sw-pitr-pg2 >/dev/null

echo "== refusals"
docker run --rm -v sw-pitr-data2:/d --entrypoint sh alpine -c 'rm -rf /d/pgdata /d/*.tmp' >/dev/null
OUT=$(KEYS=keys2 USERARG="--user 70:70 --group-add 10101" BK sw-pitr-data2 pitr-prepare latest --dir /backups/base --pgdata /pgdata2/pgdata --archive /archive 2>&1); RC=$?
check "without the key ring nothing is unpacked" "$([ $RC = 2 ] && [ -z "$(docker run --rm -v sw-pitr-data2:/d --entrypoint sh alpine -c 'ls /d/pgdata 2>/dev/null')" ] && echo 1 || echo 0)" "rc=$RC $OUT"
F=$(docker run --rm -v sw-pitr-backups:/b --entrypoint sh alpine -c 'ls /b/base | grep "\.swbk$" | head -1')
docker run --rm -v sw-pitr-backups:/b --entrypoint sh alpine -c "printf 'X' | dd of=/b/base/$F bs=1 seek=5000 conv=notrunc 2>/dev/null"
OUT=$(KEYS=keys USERARG="--user 70:70 --group-add 10101" BK sw-pitr-data2 pitr-prepare latest --dir /backups/base --pgdata /pgdata2/pgdata --archive /archive 2>&1); RC=$?
check "a damaged base backup is refused before anything is unpacked" "$([ $RC = 2 ] && echo "$OUT" | grep -q 'authentication failed' && [ -z "$(docker run --rm -v sw-pitr-data2:/d --entrypoint sh alpine -c 'ls /d/pgdata 2>/dev/null')" ] && echo 1 || echo 0)" "rc=$RC $OUT"
OUT=$(KEYS=keys USERARG="--user 70:70 --group-add 10101" BK sw-pitr-data2 pitr-prepare latest --dir /backups/base --pgdata /pgdata2/pgdata --archive /archive --time "yesterday; drop table orders" 2>&1); RC=$?
check "a malformed recovery time is refused (it ends up in a configuration file)" "$([ $RC = 2 ] && echo 1 || echo 0)" "rc=$RC $OUT"

echo
echo "$PASS/$((PASS+FAIL)) point-in-time recovery checks passed"
[ "$FAIL" = 0 ]
