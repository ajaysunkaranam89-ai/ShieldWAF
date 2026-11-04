"""Writes one row per second through the panel's own database layer (store.py) and logs what happened: used by tests/dbfailover.sh,
which kills the primary database and promotes the standby while this runs. Connection string: SHIELD_DB_URL with two hosts."""
import os
import sys
import time

os.environ.setdefault("SHIELD_DATA", "/tmp/data")
sys.path.insert(0, "/panel")
import store  # noqa: E402

store.init_db()
n = 0
t_end = time.time() + float(sys.argv[1] if len(sys.argv) > 1 else 90)
while time.time() < t_end:
    n += 1
    try:
        store.meta_set(f"fo_{n:05d}", "x")
        host = store.db().execute("SELECT inet_server_addr()::text AS h, pg_is_in_recovery() AS r").fetchone()
        store.db().commit()
        print(f"ok {n} {time.time():.1f} {host['h']} standby={host['r']}", flush=True)
    except Exception as e:  # noqa: BLE001
        print(f"err {n} {time.time():.1f} {type(e).__name__}", flush=True)
    time.sleep(1)
print("done", flush=True)
