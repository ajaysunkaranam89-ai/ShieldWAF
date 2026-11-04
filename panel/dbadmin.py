"""Database administration for the least-privilege setup (docs/SECURITY_HARDENING.md). Run it with the SCHEMA OWNER's connection string:

  SHIELD_DB_MIGRATE_URL=postgresql://owner:pw@host:5432/db  python3 dbadmin.py roles   [--app-role shieldwaf_app] [--print-password]
      creates (or hardens) the runtime role: LOGIN only, no superuser / createdb / createrole / replication / bypassrls, a connection limit, then applies the migrations
      and the grants: DML on the tables, and on the audit trail SELECT and INSERT only.
  SHIELD_DB_MIGRATE_URL=...  python3 dbadmin.py rotate [--app-role shieldwaf_app]
      sets a NEW random password for the runtime role and prints it (and only it) on standard output. Existing connections of that role are ended so that the old
      password stops working at once. Put the new password in the secret and restart the panel.
  SHIELD_DB_URL=... python3 dbadmin.py check
      a JSON report on what this connection can and cannot do: TLS, role attributes, privileges on the audit trail, timeouts. Exit code 1 if something is unsafe.
"""
import argparse
import json
import os
import re
import secrets
import sys

import psycopg2
from psycopg2 import sql

ROLE_RE = re.compile(r"[a-z_][a-z0-9_]{0,62}")


def _connect(env_names):
    url = next((os.environ[n] for n in env_names if os.environ.get(n)), "")
    if not url:
        sys.exit("ERROR: set " + " or ".join(env_names))
    args = {"connect_timeout": 10}
    if os.environ.get("SHIELD_DB_SSLMODE"):
        args["sslmode"] = os.environ["SHIELD_DB_SSLMODE"]
    if os.environ.get("SHIELD_DB_SSLROOTCERT"):
        args["sslrootcert"] = os.environ["SHIELD_DB_SSLROOTCERT"]
    return psycopg2.connect(url, **args)


def _role(name):
    if not ROLE_RE.fullmatch(name or ""):
        sys.exit("ERROR: the role name must be lower-case letters, digits and underscores")
    return name


def new_password():
    return secrets.token_urlsafe(24)


def cmd_roles(a):
    role = _role(a.app_role)
    pw = os.environ.get("SHIELD_DB_APP_PASSWORD") or new_password()
    con = _connect(("SHIELD_DB_MIGRATE_URL", "SHIELD_DB_URL"))
    con.autocommit = True
    cur = con.cursor()
    cur.execute("SELECT 1 FROM pg_roles WHERE rolname=%s", (role,))
    verb = "ALTER" if cur.fetchone() else "CREATE"
    set_pw = verb == "CREATE" or a.reset_password or bool(os.environ.get("SHIELD_DB_APP_PASSWORD"))     # running it again never changes a working password by accident
    cur.execute(sql.SQL(verb + " ROLE {} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS INHERIT CONNECTION LIMIT {}" + (" PASSWORD {}" if set_pw else "")).format(
        *([sql.Identifier(role), sql.Literal(a.connection_limit)] + ([sql.Literal(pw)] if set_pw else []))))
    for setting, value in (("statement_timeout", "30s"), ("lock_timeout", "10s"), ("idle_in_transaction_session_timeout", "60s")):    # enforced by the server for this role, whatever the client sets up
        cur.execute(sql.SQL("ALTER ROLE {} SET {} = {}").format(sql.Identifier(role), sql.Identifier(setting), sql.Literal(value)))
    cur.execute(sql.SQL("REVOKE ALL ON DATABASE {} FROM PUBLIC").format(sql.Identifier(con.get_dsn_parameters()["dbname"])))
    con.close()
    # migrations and grants run on the owner's connection (store.as_owner); store reads its settings at import time
    os.environ["SHIELD_DB_URL"] = os.environ.get("SHIELD_DB_MIGRATE_URL") or os.environ["SHIELD_DB_URL"]
    os.environ["SHIELD_DB_APP_ROLE"] = role
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import store
    store.init_db()
    print(f"role {role} {'hardened' if verb == 'ALTER' else 'created'}; grants applied (audit trail: SELECT and INSERT only)")
    if a.print_password and set_pw and not os.environ.get("SHIELD_DB_APP_PASSWORD"):
        print(pw)


def cmd_rotate(a):
    role = _role(a.app_role)
    pw = new_password()
    con = _connect(("SHIELD_DB_MIGRATE_URL", "SHIELD_DB_URL"))
    con.autocommit = True
    cur = con.cursor()
    cur.execute("SELECT 1 FROM pg_roles WHERE rolname=%s", (role,))
    if not cur.fetchone():
        sys.exit(f"ERROR: role {role} does not exist (run: dbadmin.py roles)")
    cur.execute(sql.SQL("ALTER ROLE {} PASSWORD {}").format(sql.Identifier(role), sql.Literal(pw)))
    cur.execute("SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE usename=%s AND pid<>pg_backend_pid()", (role,))
    ended = sum(1 for r in cur.fetchall() if r[0])
    con.close()
    print(f"password of {role} changed, {ended} open connection(s) ended; the new password follows", file=sys.stderr)
    print(pw)


def report():
    """What the connection in SHIELD_DB_URL can do. Every `ok` False is a finding."""
    con = _connect(("SHIELD_DB_URL",))
    con.autocommit = True
    cur = con.cursor()
    out = {}
    cur.execute("SELECT ssl, version, cipher FROM pg_stat_ssl WHERE pid=pg_backend_pid()")
    r = cur.fetchone()
    out["tls"] = {"ok": bool(r and r[0]), "version": r[1] if r else None, "cipher": r[2] if r else None}
    cur.execute("SELECT rolname, rolsuper, rolcreatedb, rolcreaterole, rolreplication, rolbypassrls FROM pg_roles WHERE rolname=current_user")
    n = cur.fetchone()
    out["role"] = {"name": n[0], "superuser": n[1], "createdb": n[2], "createrole": n[3], "replication": n[4], "bypassrls": n[5], "ok": not any(n[1:])}
    cur.execute("SELECT has_table_privilege(current_user,'audit',p) FROM unnest(ARRAY['SELECT','INSERT','UPDATE','DELETE','TRUNCATE']) p")
    s, i, u, d, t = [x[0] for x in cur.fetchall()]
    out["audit_privileges"] = {"select": s, "insert": i, "update": u, "delete": d, "truncate": t, "ok": s and i and not (u or d or t)}
    cur.execute("SELECT has_schema_privilege(current_user,'public','CREATE')")
    out["can_create_objects"] = {"value": cur.fetchone()[0]}
    out["can_create_objects"]["ok"] = not out["can_create_objects"]["value"]
    cur.execute("SHOW statement_timeout")
    st = cur.fetchone()[0]
    cur.execute("SHOW idle_in_transaction_session_timeout")
    out["timeouts"] = {"statement": st, "idle_in_transaction": cur.fetchone()[0], "ok": st != "0"}
    cur.execute("SHOW server_version")
    out["server_version"] = cur.fetchone()[0]
    con.close()
    out["ok"] = all(v.get("ok", True) for v in out.values() if isinstance(v, dict))
    return out


def cmd_check(_a):
    out = report()
    print(json.dumps(out, indent=2))
    return 0 if out["ok"] else 1


def main(argv=None):
    ap = argparse.ArgumentParser(prog="dbadmin")
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name in ("roles", "rotate"):
        s = sub.add_parser(name)
        s.add_argument("--app-role", default=os.environ.get("SHIELD_DB_APP_ROLE", "shieldwaf_app"))
        if name == "roles":
            s.add_argument("--connection-limit", type=int, default=60)
            s.add_argument("--print-password", action="store_true")
            s.add_argument("--reset-password", action="store_true", help="also set a new password on an existing role (see also: rotate)")
    sub.add_parser("check")
    a = ap.parse_args(argv)
    return {"roles": cmd_roles, "rotate": cmd_rotate, "check": cmd_check}[a.cmd](a) or 0


if __name__ == "__main__":
    sys.exit(main())
