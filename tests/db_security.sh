#!/usr/bin/env bash
# Database security test with REAL PostgreSQL in Docker (the project's database image with TLS): plain connections rejected, TLS on, least-privilege runtime role
# (audit trail append-only), timeouts, password rotation, safe migrations. Needs Docker and the images ${DBIMAGE:-shieldwaf-db:2.4-dev} and ${IMAGE:-shieldwaf:2.4-dev}.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"; ROOT="$(dirname "$HERE")"
NET=shieldwaf-dbsec-test; IMG="${IMAGE:-shieldwaf:2.4-dev}"; DBIMG="${DBIMAGE:-shieldwaf-db:2.4-dev}"
export MSYS_NO_PATHCONV=1
WIN() { cygpath -m "$1" 2>/dev/null || echo "$1"; }
cleanup() { docker rm -f sw-dbsec-pg >/dev/null 2>&1; docker network rm $NET >/dev/null 2>&1; }
[ "${KEEP:-}" = 1 ] || trap cleanup EXIT
cleanup
PASS=0; FAIL=0
check() { if [ "$2" = "1" ]; then echo "PASS  $1"; PASS=$((PASS+1)); else echo "FAIL  $1   [${3:-}]"; FAIL=$((FAIL+1)); fi; }
PYM="-v $(WIN "$ROOT")/panel:/panel:ro -v $(WIN "$ROOT")/tests:/t:ro -e SHIELD_DATA=/tmp/d -e SHIELD_AUDIT_KEY=k"
OWNER="postgresql://shieldwaf:pw@pg:5432/shieldwaf"
cl() { docker run --rm --network $NET $PYM "$@"; }                        # a client container; the first argument after the options is the command
psqlc() { docker run --rm --network $NET -e PGPASSWORD="${PW:-pw}" --entrypoint psql "$IMG" "$@"; }

docker network create $NET >/dev/null || exit 1
docker run -d --name sw-dbsec-pg --network $NET --network-alias pg -e POSTGRES_USER=shieldwaf -e POSTGRES_PASSWORD=pw -e POSTGRES_DB=shieldwaf --tmpfs /tmp:exec,mode=1777 "$DBIMG" >/dev/null || exit 1
for i in $(seq 1 40); do docker exec sw-dbsec-pg pg_isready -U shieldwaf -d shieldwaf >/dev/null 2>&1 && break; sleep 2; done
sleep 3

OUT=$(psqlc "host=pg user=shieldwaf dbname=shieldwaf sslmode=disable" -tAc "select 1" 2>&1); RC=$?
check "a connection WITHOUT TLS is rejected by the database" "$([ $RC != 0 ] && echo "$OUT" | grep -qi "pg_hba\|SSL\|encryption" && echo 1 || echo 0)" "rc=$RC $OUT"
OUT=$(psqlc "host=pg user=shieldwaf dbname=shieldwaf sslmode=require" -tAc "select ssl||' '||version from pg_stat_ssl where pid=pg_backend_pid()" 2>&1)
check "a TLS connection works and is TLS 1.2 or newer" "$(echo "$OUT" | grep -Eq '^true TLSv1\.[23]' && echo 1 || echo 0)" "$OUT"
OUT=$(PW=wrong psqlc "host=pg user=shieldwaf dbname=shieldwaf sslmode=require" -tAc "select 1" 2>&1); RC=$?
check "a wrong password is rejected" "$([ $RC != 0 ] && echo 1 || echo 0)" "$OUT"

# the panel in least-privilege mode must not change the schema: on a database nobody has migrated yet it waits and then refuses
OUT=$(cl -e SHIELD_DB_SSLMODE=require -e SHIELD_DB_URL="$OWNER" -e SHIELD_DB_MIGRATE=off -e SHIELD_DB_MIGRATE_WAIT_S=6 --entrypoint python3 "$IMG" -c "
import sys; sys.path.insert(0,'/panel'); import store; store.init_db()" 2>&1); RC=$?
check "SHIELD_DB_MIGRATE=off: on an unmigrated database the panel waits and then refuses (it never creates tables itself)" "$([ $RC != 0 ] && echo "$OUT" | grep -q 'not up to date' && [ "$(psqlx 'select count(*) from information_schema.tables where table_schema=$$public$$ and table_name=$$audit$$' 2>/dev/null || echo 0)" = 0 ] && echo 1 || echo 0)" "rc=$RC $OUT"

# the runtime role
OUT=$(cl -e SHIELD_DB_SSLMODE=require -e SHIELD_DB_MIGRATE_URL="$OWNER" --entrypoint python3 "$IMG" /panel/dbadmin.py roles --print-password 2>&1)
APPPW=$(echo "$OUT" | tail -1)
check "dbadmin roles creates the runtime role and applies migrations and grants" "$(echo "$OUT" | grep -q "created; grants applied" && [ ${#APPPW} -ge 24 ] && echo 1 || echo 0)" "$OUT"
OUT=$(cl -e SHIELD_DB_SSLMODE=require -e SHIELD_DB_MIGRATE_URL="$OWNER" --entrypoint python3 "$IMG" /panel/dbadmin.py roles 2>&1)
check "running it again is safe (the role is hardened, not duplicated)" "$(echo "$OUT" | grep -q "hardened" && echo 1 || echo 0)" "$OUT"
APP="postgresql://shieldwaf_app:$APPPW@pg:5432/shieldwaf"
OUT=$(cl -e SHIELD_DB_SSLMODE=require -e SHIELD_DB_URL="$APP" --entrypoint python3 "$IMG" /panel/dbadmin.py check 2>&1); RC=$?
check "dbadmin check: runtime role has TLS, no superuser rights, audit trail SELECT+INSERT only, no CREATE, timeouts set" "$([ $RC = 0 ] && echo "$OUT" | grep -q '"update": false' && echo 1 || echo 0)" "rc=$RC $OUT"
OUT=$(cl -e SHIELD_DB_SSLMODE=require -e SHIELD_DB_URL="$OWNER" --entrypoint python3 "$IMG" /panel/dbadmin.py check 2>&1); RC=$?
check "dbadmin check flags the OWNER connection as not least-privilege (exit 1)" "$([ $RC = 1 ] && echo 1 || echo 0)" "rc=$RC"

OUT=$(cl -e SHIELD_DB_SSLMODE=require -e SHIELD_DB_URL="$APP" -e SHIELD_DB_MIGRATE=off -e SHIELD_AUDIT_KEY=k --entrypoint python3 "$IMG" -c "
import sys; sys.path.insert(0,'/panel'); import store; store.init_db(); store.audit('t','startup','ok'); print('STARTED', store.current_schema_version())" 2>&1 | tail -2)
check "after the init step the panel starts as the runtime role with SHIELD_DB_MIGRATE=off and can write the audit trail" "$(echo "$OUT" | grep -q STARTED && echo 1 || echo 0)" "$OUT"
echo "--- the panel code on the runtime role"
OUT=$(cl -e SHIELD_DB_SSLMODE=require -e SHIELD_DB_URL="$APP" -e SHIELD_DB_MIGRATE_URL="$OWNER" -e SHIELD_DB_APP_ROLE=shieldwaf_app --entrypoint python3 "$IMG" /t/db_security_app.py 2>&1)
echo "$OUT" | grep -E "^(PASS|FAIL)"
P=$(echo "$OUT" | grep -c "^PASS"); F=$(echo "$OUT" | grep -c "^FAIL")
PASS=$((PASS+P)); FAIL=$((FAIL+F))
[ "$F" = 0 ] && [ "$P" -gt 10 ] || { echo "$OUT" | tail -15; FAIL=$((FAIL+1)); }

echo "--- credential rotation"
OUT=$(cl -e SHIELD_DB_SSLMODE=require -e SHIELD_DB_MIGRATE_URL="$OWNER" --entrypoint python3 "$IMG" /panel/dbadmin.py rotate 2>/dev/null)
NEWPW=$(echo "$OUT" | tail -1)
check "rotation prints a new random password" "$([ ${#NEWPW} -ge 24 ] && [ "$NEWPW" != "$APPPW" ] && echo 1 || echo 0)" "${#NEWPW}"
OUT=$(PW=$APPPW psqlc "host=pg user=shieldwaf_app dbname=shieldwaf sslmode=require" -tAc "select 1" 2>&1); RC=$?
check "the OLD password no longer works" "$([ $RC != 0 ] && echo 1 || echo 0)" "$OUT"
OUT=$(PW=$NEWPW psqlc "host=pg user=shieldwaf_app dbname=shieldwaf sslmode=require" -tAc "select count(*) from audit" 2>&1); RC=$?
check "the NEW password works and still has the same limited rights" "$([ $RC = 0 ] && echo 1 || echo 0)" "$OUT"

echo
echo "$PASS/$((PASS+FAIL)) database security checks passed"
[ "$FAIL" = 0 ]
