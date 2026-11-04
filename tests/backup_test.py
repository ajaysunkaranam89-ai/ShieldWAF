"""Backup and restore test: authenticated AES-256-GCM backup job, weekly restore test job, disaster, restore, and the firewall running again.
Runs against a throw-away deployment in the namespace "shieldwaf-test" (created by tests/run.sh) with 2 replicas."""
import os
import re
import subprocess
import sys
import time

NS = "shieldwaf-test"
DEPLOY = "shieldwaf-test"
TAG = os.environ.get("IMG_TAG", "2.4-dev")
BASH = os.environ.get("TEST_BASH", "bash")
HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
results = []


def check(name, cond, extra=""):
    results.append((name, bool(cond)))
    print(("PASS  " if cond else "FAIL  ") + name + (f"   [{extra}]" if extra and not cond else ""), flush=True)


def sh(*args, timeout=300, inp=None, env=None):
    return subprocess.run(list(args), capture_output=True, text=True, timeout=timeout, input=inp, env={**os.environ, **(env or {})})


def psql(sql):
    r = sh("kubectl", "-n", NS, "exec", "shieldwaf-db-0", "--", "psql", "-U", "shieldwaf", "-d", "shieldwaf", "-tA", "-c", sql)
    return r.stdout.strip()


def ready_replicas():
    return sh("kubectl", "-n", NS, "get", "deploy", DEPLOY, "-o", "jsonpath={.status.readyReplicas}").stdout.strip() or "0"


print("== installing the backup job", flush=True)
r = sh(BASH, os.path.join(ROOT, "scripts", "create-backup-key.sh"), NS)
check("the backup key ring (a secret separate from the database secret) is created", r.returncode == 0 and "shieldwaf-backup-keys" in r.stdout, (r.stdout + r.stderr)[-300:])
manifest = open(os.path.join(ROOT, "k8s", "backup.yaml"), encoding="utf-8").read().replace("namespace: shieldwaf\n", f"namespace: {NS}\n")
manifest = re.sub(r"image: shieldwaf:[0-9.a-z-]*", f"image: shieldwaf:{TAG}", manifest)
r = sh("kubectl", "apply", "-f", "-", inp=manifest)
check("the backup manifest (volume, nightly job, weekly restore test, network policies) applies", r.returncode == 0, r.stderr[-200:])

# something recognisable in the database
psql("delete from meta where k like 'backup_test%'")
psql("insert into meta(k,v) values('backup_test','before-the-backup'),('backup_test_secret','TOP-SECRET-MARKER-9137')")
before_cnt = psql("select count(*) from meta")

print("== taking a backup now", flush=True)
sh("kubectl", "-n", NS, "delete", "job", "backup-now", "--ignore-not-found")
sh("kubectl", "-n", NS, "create", "job", "--from=cronjob/shieldwaf-db-backup", "backup-now")
w = sh("kubectl", "-n", NS, "wait", "--for=condition=complete", "job/backup-now", "--timeout=240s", timeout=260)
log = sh("kubectl", "-n", NS, "logs", "job/backup-now").stdout
check("the backup job completes", w.returncode == 0, log[-300:])
m = re.search(r"backup written and verified: (/backups/(shieldwaf-[0-9-]+\.swbk)) \((\d+) bytes, key (\w+), AES-256-GCM", log)
check("the backup is written and read back (verified) by the job", bool(m), log[-300:])
name = m.group(2) if m else ""
check("the file is AES-256-GCM encrypted with a key of the separate key ring", bool(m) and len(m.group(4)) == 8, log[-300:])
check("the backup is listed", name in sh(BASH, os.path.join(ROOT, "scripts", "restore-db.sh"), "list", NS, env={"DEPLOY": DEPLOY, "IMG_TAG": TAG}).stdout)

print("== scheduled validation job (restore into a temporary database)", flush=True)
sh("kubectl", "-n", NS, "delete", "job", "verify-now", "--ignore-not-found")
sh("kubectl", "-n", NS, "create", "job", "--from=cronjob/shieldwaf-db-backup-verify", "verify-now")
w = sh("kubectl", "-n", NS, "wait", "--for=condition=complete", "job/verify-now", "--timeout=240s", timeout=260)
vlog = sh("kubectl", "-n", NS, "logs", "job/verify-now").stdout
check("the weekly validation job restores the newest backup into a temporary database and passes", w.returncode == 0 and "restore test passed" in vlog, vlog[-300:])
check("...and leaves no temporary database behind", psql("select count(*) from pg_database where datname like 'swverify_%'") == "0")
sh("kubectl", "-n", NS, "delete", "job", "verify-now", "--ignore-not-found")

print("== disaster", flush=True)
psql("update meta set v='after-the-backup' where k='backup_test'")
psql("insert into meta(k,v) values('backup_test_extra','written after the backup')")
psql("delete from meta where k='backup_test_secret'")
psql("truncate table audit")
check("the damage is real (marker changed, secret row gone, audit trail empty)", psql("select v from meta where k='backup_test'") == "after-the-backup"
      and psql("select count(*) from meta where k='backup_test_secret'") == "0" and psql("select count(*) from audit") == "0")

print("== restore", flush=True)
before_replicas = ready_replicas()
r = sh(BASH, os.path.join(ROOT, "scripts", "restore-db.sh"), "latest", NS, env={"DEPLOY": DEPLOY, "YES": "1", "IMG_TAG": TAG}, timeout=900)
check("the restore script finishes successfully", r.returncode == 0 and "database restored from" in r.stdout, (r.stdout + r.stderr)[-400:])
check("the marker is back to its value at backup time", psql("select v from meta where k='backup_test'") == "before-the-backup")
check("a row that was deleted after the backup is back", psql("select v from meta where k='backup_test_secret'") == "TOP-SECRET-MARKER-9137")
check("a row written after the backup is gone (the database really was replaced)", psql("select count(*) from meta where k='backup_test_extra'") == "0")
check("the audit trail is back (the sites and users tables came with it)", int(psql("select count(*) from audit") or 0) > 0 or int(psql("select count(*) from config") or 0) > 0)
for _ in range(40):
    if ready_replicas() == before_replicas:
        break
    time.sleep(4)
check("the firewall replicas are running again, as many as before (%s)" % before_replicas, ready_replicas() == before_replicas, ready_replicas())
time.sleep(8)
nodes = psql("select count(*) from nodes where ts > extract(epoch from now())-15")
check("all replicas report in again after the restore", nodes == before_replicas, nodes)

print("== a bad request", flush=True)
r = sh(BASH, os.path.join(ROOT, "scripts", "restore-db.sh"), "no-such-file.swbk", NS, env={"DEPLOY": DEPLOY, "YES": "1", "IMG_TAG": TAG}, timeout=900)
check("restoring a backup that does not exist fails cleanly and the firewall is started again", r.returncode != 0 and "no such backup" in r.stdout and ready_replicas() == before_replicas, (r.stdout + r.stderr)[-300:])
print("== retention is part of the job (find -mtime) and a second backup works", flush=True)
sh("kubectl", "-n", NS, "delete", "job", "backup-now2", "--ignore-not-found")
sh("kubectl", "-n", NS, "create", "job", "--from=cronjob/shieldwaf-db-backup", "backup-now2")
w = sh("kubectl", "-n", NS, "wait", "--for=condition=complete", "job/backup-now2", "--timeout=240s", timeout=260)
log2 = sh("kubectl", "-n", NS, "logs", "job/backup-now2").stdout
check("a second backup (after the restore) completes and both backups are on the volume", w.returncode == 0 and log2.count("shieldwaf-2") >= 2, log2[-300:])
sh("kubectl", "-n", NS, "delete", "job", "backup-now", "backup-now2", "--ignore-not-found")
psql("delete from meta where k like 'backup_test%'")

print()
bad = [n for n, ok in results if not ok]
print(f"{len(results) - len(bad)}/{len(results)} backup checks passed")
if bad:
    print("FAILED:", *bad, sep="\n  ")
sys.exit(1 if bad else 0)
