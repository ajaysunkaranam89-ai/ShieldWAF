"""Runs inside the shieldwaf image against a real PostgreSQL (tests/db_security.sh): what the RUNTIME role can and cannot do, timeouts, safe migrations.
Environment: SHIELD_DB_URL (runtime role), SHIELD_DB_MIGRATE_URL (owner), SHIELD_DB_APP_ROLE. Prints one line per check: 'PASS name' or 'FAIL name [why]'."""
import os
import sys
import time

sys.path.insert(0, "/panel")
import psycopg2  # noqa: E402

import store  # noqa: E402

OK = True


def check(name, cond, why=""):
    global OK
    OK = OK and bool(cond)
    print(("PASS  " if cond else "FAIL  ") + name + ("" if cond else f"   [{why}]"), flush=True)


def denied(sql_text, params=()):
    """True if the RUNTIME role is refused (permission denied) for this statement."""
    con = psycopg2.connect(os.environ["SHIELD_DB_URL"], sslmode="require")
    try:
        cur = con.cursor()
        cur.execute(sql_text, params)
        con.commit()
        return False, "was allowed"
    except psycopg2.errors.InsufficientPrivilege as e:
        return True, str(e).strip().splitlines()[0]
    except Exception as e:  # noqa: BLE001
        return False, type(e).__name__ + ": " + str(e)[:100]
    finally:
        con.close()


store.init_db()
check("migrations ran on the owner connection and the runtime role works after them", store.current_schema_version() >= 1)
for i in range(5):
    store.audit("tester", "login", f"n{i}")
r = store.verify_audit()
check("the runtime role appends to the audit chain and the chain verifies", r["ok"] and r["records"] >= 5, r)

for name, stmt in (("UPDATE on the audit trail", "UPDATE audit SET detail='x'"), ("DELETE on the audit trail", "DELETE FROM audit"),
                   ("TRUNCATE of the audit trail", "TRUNCATE audit"), ("DROP of the audit trail", "DROP TABLE audit"),
                   ("creating a table", "CREATE TABLE evil(a int)"), ("changing the schema_migrations table", "DELETE FROM schema_migrations"),
                   ("reading the password hashes (pg_authid)", "SELECT * FROM pg_authid"), ("creating a role", "CREATE ROLE evil LOGIN"),
                   ("creating a function in the public schema", "CREATE FUNCTION evil() RETURNS int AS 'select 1' LANGUAGE sql")):
    ok, why = denied(stmt)
    check(f"the runtime role is refused: {name}", ok, why)
ok, why = denied("INSERT INTO audit(seq,ts,username,action,detail,ip,category,request_id,prev_hash,hash) VALUES(999999,1,'a','b','c','d','e','f','g','h')")
check("the runtime role MAY insert into the audit trail (and a forged record is then caught by the chain check)", not ok and "allowed" in why, why)
r = store.verify_audit()
check("...the forged record is detected by verification", not r["ok"], r)
owner = psycopg2.connect(os.environ["SHIELD_DB_MIGRATE_URL"], sslmode="require")
owner.autocommit = True
owner.cursor().execute("DELETE FROM audit WHERE seq=999999")
owner.close()
r = store.verify_audit()
check("...and after the owner removes it the chain is valid again", r["ok"], r)

# retention needs DELETE on the audit trail: it runs on the owner connection (the runtime role cannot)
n = store.audit_purge(time.time() + 10)
r = store.verify_audit()
check("audit retention works through the maintenance connection and leaves a verifiable chain (anchor)", n >= 5 and r["ok"], (n, r))
store.audit("tester", "after purge", "x")
check("appending after a purge continues the chain", store.verify_audit()["ok"])

# timeouts
os.environ["SHIELD_DB_STATEMENT_TIMEOUT_MS"] = "500"
c = psycopg2.connect(os.environ["SHIELD_DB_URL"], **store.connect_args())
try:
    t0 = time.time()
    c.cursor().execute("SELECT pg_sleep(5)")
    check("a runaway statement is cancelled by statement_timeout", False, "ran to completion")
except psycopg2.errors.QueryCanceled:
    check("a runaway statement is cancelled by statement_timeout (0.5 s)", time.time() - t0 < 3)
finally:
    c.close()
os.environ["SHIELD_DB_IDLE_TX_TIMEOUT_MS"] = "800"
c = psycopg2.connect(os.environ["SHIELD_DB_URL"], **store.connect_args())
c.cursor().execute("SELECT 1")
time.sleep(2.5)
try:
    c.cursor().execute("SELECT 1")
    check("an idle transaction is ended by idle_in_transaction_session_timeout", False, "still open")
except (psycopg2.OperationalError, psycopg2.InterfaceError):
    check("an idle transaction is ended by idle_in_transaction_session_timeout", True)
os.environ.pop("SHIELD_DB_STATEMENT_TIMEOUT_MS"), os.environ.pop("SHIELD_DB_IDLE_TX_TIMEOUT_MS")
c = psycopg2.connect(os.environ["SHIELD_DB_URL"], **store.connect_args())
cur = c.cursor()
cur.execute("SHOW statement_timeout")
check("by default every runtime connection has a 30 s statement timeout", cur.fetchone()[0] == "30s")
cur.execute("SELECT ssl FROM pg_stat_ssl WHERE pid=pg_backend_pid()")
check("by default connections are made with SHIELD_DB_SSLMODE (TLS)", cur.fetchone()[0] is True)
c.close()

# safe migrations: a failing migration leaves nothing behind (DDL is transactional) and the next start retries it
orig = store._migrations
store._migrations = lambda: list(orig()) + [(9999, "probe-bad", ["CREATE TABLE probe_half_done(a int)", "SELECT * FROM table_that_does_not_exist"])]
try:
    store.migrate()
    check("a failing migration raises", False, "no error")
except Exception:  # noqa: BLE001
    check("a failing migration raises", True)
store._local.con = None
con = store.db()
left = con.execute("SELECT to_regclass('probe_half_done') t").fetchone()["t"]
con.commit()
rec = con.execute("SELECT COUNT(*) c FROM schema_migrations WHERE version=9999").fetchone()["c"]
con.commit()
check("...the half-done table was rolled back and the migration is not recorded", left is None and rec == 0, (left, rec))
store._migrations = orig
store.migrate()
check("the application still works after the failed migration attempt", store.verify_audit()["ok"])
sys.exit(0 if OK else 1)
