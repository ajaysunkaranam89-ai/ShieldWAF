#!/usr/bin/env bash
# Backup crypto integration test with REAL services in throw-away Docker containers: PostgreSQL (the project's database image), Zenko CloudServer (an S3
# implementation that verifies AWS Signature V4, as the independent destination) and the shieldwaf image running panel/backupcrypt.py. No cluster needed.
# Needs Docker, the images shieldwaf-db:16 and ${IMAGE:-shieldwaf:2.4-dev}, and internet access to pull zenko/cloudserver.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"; ROOT="$(dirname "$HERE")"
NET=shieldwaf-bk-test; IMG="${IMAGE:-shieldwaf:2.4-dev}"
export MSYS_NO_PATHCONV=1
WIN() { cygpath -m "$1" 2>/dev/null || echo "$1"; }
WORK="$HERE/.bk-work"
cleanup() { docker rm -f sw-bk-pg sw-bk-s3 >/dev/null 2>&1; docker network rm $NET >/dev/null 2>&1; rm -rf "$WORK"; }
[ "${KEEP:-}" = 1 ] || trap cleanup EXIT
cleanup; mkdir -p "$WORK/keys" "$WORK/keys2" "$WORK/backups"
PASS=0; FAIL=0
check() { if [ "$2" = "1" ]; then echo "PASS  $1"; PASS=$((PASS+1)); else echo "FAIL  $1   [${3:-}]"; FAIL=$((FAIL+1)); fi; }
ok() { [ "$1" = "0" ] && echo 1 || echo 0; }
PYM="-v $(WIN "$ROOT")/panel:/panel:ro -e SHIELD_DATA=/tmp/d -e SHIELD_BACKUP_ALLOW_HTTP=1"
PY="docker run --rm --network $NET $PYM -v $(WIN "$WORK")/keys:/keys -v $(WIN "$WORK")/backups:/backups --entrypoint python3 $IMG"
bk() {   # the backup tool with database and destination settings
  docker run --rm --network $NET -e PGHOST=pg -e PGUSER=shieldwaf -e PGPASSWORD=pw -e PGDATABASE=shieldwaf -e PGSSLMODE=prefer \
    -e BACKUP_S3_ENDPOINT=http://s3:8000 -e AWS_ACCESS_KEY_ID="${S3KEY:-minioadmin}" -e AWS_SECRET_ACCESS_KEY=minioadmin123 $PYM \
    -v "$(WIN "$WORK")/${KEYDIR:-keys}:/keys:ro" -v "$(WIN "$WORK")/backups:/backups" --entrypoint python3 "$IMG" /panel/backupcrypt.py "$@"
}
psqlx() { docker exec sw-bk-pg psql -U shieldwaf -d shieldwaf -tAc "$1"; }

docker network create $NET >/dev/null || exit 1
docker run -d --name sw-bk-pg --network $NET --network-alias pg -e POSTGRES_USER=shieldwaf -e POSTGRES_PASSWORD=pw -e POSTGRES_DB=shieldwaf shieldwaf-db:16 >/dev/null || exit 1
docker run -d --name sw-bk-s3 --network $NET --network-alias s3 -e S3BACKEND=mem -e SCALITY_ACCESS_KEY_ID=minioadmin -e SCALITY_SECRET_ACCESS_KEY=minioadmin123 \
  -e REMOTE_MANAGEMENT_DISABLE=1 -e ENDPOINT=s3 zenko/cloudserver:latest >/dev/null || exit 1
for i in $(seq 1 40); do docker exec sw-bk-pg pg_isready -U shieldwaf -d shieldwaf >/dev/null 2>&1 && break; sleep 2; done
sleep 8
$PY -c "
import sys; sys.path.insert(0,'/panel'); import backupcrypt as b
print('bucket', b.s3_make_bucket('http://s3:8000', 'bkt', 'minioadmin', 'minioadmin123'))" 2>&1 | tail -1 | grep -q "bucket True" || echo "(could not create the test bucket)"

# the schema is created by the panel's migrations on a real PostgreSQL, and the audit chain works there
OUT=$(docker run --rm --network $NET -e SHIELD_DB_URL=postgresql://shieldwaf:pw@pg:5432/shieldwaf -e SHIELD_AUDIT_KEY=k -e SHIELD_DATA=/tmp/d -v "$(WIN "$ROOT")/panel:/panel:ro" --entrypoint python3 "$IMG" -c "
import sys; sys.path.insert(0,'/panel')
import store, threading
store.init_db(); store.init_db()
def w(n):
    for i in range(10): store.audit('t%d' % n, 'login', str(i))
ts=[threading.Thread(target=w,args=(n,)) for n in range(4)]; [t.start() for t in ts]; [t.join() for t in ts]
r = store.verify_audit(); print('CHAIN', r['ok'], r['records'], store.current_schema_version())
" 2>&1 | tail -3)
echo "$OUT" | grep -q "CHAIN True 40 2"; check "PostgreSQL: migrations applied (twice, idempotent) and 4 concurrent writers keep one valid audit chain" "$(ok $?)" "$OUT"

# an independent key ring (a directory that would be a Kubernetes secret of its own)
$PY -c "
import sys; sys.path.insert(0,'/panel'); import backupcrypt as b
kid, mat = b.new_key(); open('/keys/key-' + kid, 'w').write(mat); open('/keys/current', 'w').write(kid); print(kid)
" > "$WORK/kid1.txt"; KID1=$(tr -d '\r\n' < "$WORK/kid1.txt")
check "a backup key was generated (8-hex id, 32 random bytes)" "$([ ${#KID1} = 8 ] && echo 1 || echo 0)" "$KID1"

OUT=$(bk backup --out /backups --keep-days 14 --s3-bucket bkt --s3-prefix nightly 2>&1)
echo "$OUT" | grep -q "backup written and verified"; check "a backup is written, authenticated and read back by the job" "$(ok $?)" "$OUT"
echo "$OUT" | grep -q "copied to the independent destination"; check "...and copied to the independent S3 destination" "$(ok $?)" "$OUT"
F=$(ls "$WORK/backups" | grep '\.swbk$' | head -1)
check "the file starts with the SWBK header, not with a PostgreSQL dump header" "$([ "$(head -c 4 "$WORK/backups/$F")" = "SWBK" ] && ! grep -aq PGDMP "$WORK/backups/$F" && echo 1 || echo 0)"
check "no table or user name appears in the file (it is encrypted)" "$(! grep -aq "schema_migrations\|shieldwaf" "$WORK/backups/$F" && echo 1 || echo 0)"
LOCAL=$(wc -c < "$WORK/backups/$F" | tr -d ' ')
HEAD=$($PY -c "
import sys; sys.path.insert(0,'/panel'); import backupcrypt as b
print(*b.s3_head('http://s3:8000', 'bkt', 'nightly/$F', 'minioadmin', 'minioadmin123'))" 2>&1 | tail -1)
check "the object in the independent store exists and has exactly the size of the local file" "$([ "$HEAD" = "200 $LOCAL" ] && echo 1 || echo 0)" "$HEAD vs 200 $LOCAL"

OUT=$(bk verify latest 2>&1); echo "$OUT" | grep -q "every authentication tag is valid"; check "verify: every authentication tag of the backup is valid" "$(ok $?)" "$OUT"
OUT=$(bk verify latest --restore-test 2>&1); echo "$OUT" | grep -q "restore test passed"; check "scheduled validation: the backup is restored into a temporary database, which is removed again" "$(ok $?)" "$OUT"
check "no temporary verification database is left behind" "$([ "$(psqlx "select count(*) from pg_database where datname like 'swverify_%'")" = "0" ] && echo 1 || echo 0)"

# tampering, truncation, wrong key
cp "$WORK/backups/$F" "$WORK/backups/shieldwaf-99990101-000000.swbk"
$PY -c "
p='/backups/shieldwaf-99990101-000000.swbk'; b=bytearray(open(p,'rb').read()); b[len(b)//2]^=1; open(p,'wb').write(bytes(b))"
OUT=$(bk verify shieldwaf-99990101-000000.swbk 2>&1); RC=$?
check "a single flipped bit makes verification fail (exit 2, 'authentication failed')" "$([ $RC = 2 ] && echo "$OUT" | grep -q 'authentication failed' && echo 1 || echo 0)" "rc=$RC $OUT"
$PY -c "
p='/backups/shieldwaf-99990101-000000.swbk'; b=open(p,'rb').read(); open(p,'wb').write(b[:-20])"
OUT=$(bk verify shieldwaf-99990101-000000.swbk 2>&1); RC=$?
check "a truncated copy is refused" "$([ $RC = 2 ] && echo 1 || echo 0)" "rc=$RC $OUT"
OUT=$(bk restore shieldwaf-99990101-000000.swbk 2>&1); RC=$?
check "restore refuses a damaged file BEFORE touching the database" "$([ $RC = 2 ] && [ "$(psqlx 'select count(*) from audit')" = "40" ] && echo 1 || echo 0)" "rc=$RC $OUT"
rm -f "$WORK/backups/shieldwaf-99990101-000000.swbk"
$PY -c "
import sys; sys.path.insert(0,'/panel'); import backupcrypt as b
kid, mat = b.new_key(); open('/backups/.otherkey', 'w').write(kid + ' ' + mat)"
read -r OKID OMAT < "$WORK/backups/.otherkey"; rm -f "$WORK/backups/.otherkey"
echo -n "$OMAT" > "$WORK/keys2/key-$OKID"; echo -n "$OKID" > "$WORK/keys2/current"
OUT=$(KEYDIR=keys2 bk verify latest 2>&1); RC=$?
check "with a different key ring the backup cannot be opened" "$([ $RC = 2 ] && echo "$OUT" | grep -q 'key ring' && echo 1 || echo 0)" "rc=$RC $OUT"

# rotation
sleep 1
$PY -c "
import sys; sys.path.insert(0,'/panel'); import backupcrypt as b
kid, mat = b.new_key(); open('/keys/key-' + kid, 'w').write(mat); open('/keys/current', 'w').write(kid); print(kid)" > "$WORK/kid2.txt"; KID2=$(tr -d '\r\n' < "$WORK/kid2.txt")
bk backup --out /backups --keep-days 14 >/dev/null 2>&1
OUT2=$(bk list 2>&1)
echo "$OUT2" | grep -q "key $KID1" && echo "$OUT2" | grep -q "key $KID2"; check "after a rotation the new backup uses the new key and old backups stay readable (list shows both key ids)" "$(ok $?)" "$OUT2"
OUT=$(bk verify latest 2>&1); echo "$OUT" | grep -q "tag is valid"; check "the newest backup verifies with the new key" "$(ok $?)"
OLD=$(ls "$WORK/backups" | grep '\.swbk$' | head -1)
OUT=$(bk verify "$OLD" 2>&1); echo "$OUT" | grep -q "tag is valid"; check "the old backup still verifies (old key stays in the ring)" "$(ok $?)" "$OUT"
OUT=$(bk reencrypt 2>&1); echo "$OUT" | grep -q "1 backup(s) re-encrypted"; check "re-encryption moves the old backup to the current key" "$(ok $?)" "$OUT"
rm -f "$WORK/keys/key-$KID1"
OUT=$(bk verify "$OLD" 2>&1); echo "$OUT" | grep -q "tag is valid"; check "after re-encryption the old key can be retired" "$(ok $?)" "$OUT"

# the job events are in the audit trail table (checked before the restore, which brings back the older database state)
check "backup and verify events were recorded for the audit trail (backup_log)" "$([ "$(psqlx "select count(distinct kind) from backup_log where kind in ('backup','verify')")" = "2" ] && echo 1 || echo 0)" "$(psqlx 'select kind from backup_log')"

# real restore
B0=$(psqlx "select count(*) from audit"); psqlx "delete from audit" >/dev/null; psqlx "insert into meta(k,v) values('after_backup','1') on conflict do nothing" >/dev/null
OUT=$(bk restore latest 2>&1); RC=$?
check "restore from the encrypted backup succeeds" "$([ $RC = 0 ] && echo "$OUT" | grep -q 'database restored' && echo 1 || echo 0)" "rc=$RC $OUT"
check "the data of the backup is back and later changes are gone" "$([ "$(psqlx 'select count(*) from audit')" = "$B0" ] && [ "$(psqlx "select count(*) from meta where k='after_backup'")" = "0" ] && echo 1 || echo 0)" "audit $(psqlx 'select count(*) from audit')"
OUT=$(docker run --rm --network $NET -e SHIELD_DB_URL=postgresql://shieldwaf:pw@pg:5432/shieldwaf -e SHIELD_AUDIT_KEY=k -e SHIELD_DATA=/tmp/d -v "$(WIN "$ROOT")/panel:/panel:ro" --entrypoint python3 "$IMG" -c "
import sys; sys.path.insert(0,'/panel'); import store; print('CHAIN', store.verify_audit()['ok'])" 2>&1 | tail -1)
check "the restored audit chain still verifies" "$([ "$OUT" = "CHAIN True" ] && echo 1 || echo 0)" "$OUT"
OUT=$(bk restore nothing.swbk 2>&1); RC=$?
check "restoring a file that does not exist fails cleanly (exit 2)" "$([ $RC = 2 ] && echo 1 || echo 0)" "rc=$RC"
OUT=$(S3KEY=wrong bk backup --out /backups --keep-days 14 --s3-bucket bkt --s3-prefix nightly 2>&1); RC=$?
check "wrong credentials for the independent destination make the job FAIL (not silently succeed)" "$([ $RC != 0 ] && echo 1 || echo 0)" "rc=$RC"

echo
echo "$PASS/$((PASS+FAIL)) backup crypto checks passed"
[ "$FAIL" = 0 ]
