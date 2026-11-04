# Rolling back from 2.4 to 2.3

## Facts you need to decide

* **Database migrations are one-way.** 2.4 adds columns (audit chain: `seq`, `prev_hash`, `hash`, `category`, `request_id`), tables (`schema_migrations`, `backup_log`) and a meta anchor. The 2.3 code does not select the extra columns and tables, so the 2.3 image is **expected** to run on the 2.4 database (reasoned from the code, **not tested**). The audit rows keep their 2.4 fields.
* **The database image is different** (TLS only). The 2.3 panel does not set an `sslmode`; with `shieldwaf-db:2.4` it needs `SHIELD_DB_SSLMODE=require`, which 2.3 does not read (libpq default `prefer` does use TLS when the server offers it, and the 2.4 server rejects non-TLS, so the default works). If a 2.3 client fails to connect, run the 2.3 database image (`shieldwaf-db:16`, plain) instead; the data directory is compatible (both are PostgreSQL 16).
* **Backups:** 2.4 backups (`.swbk`) cannot be read by 2.3 tools. Use the 2.4 image's `backupcrypt.py` (it runs from any container with the image) to restore to the database, or keep a 2.3 backup from before the upgrade.

## Option 1 (simple, keeps the data): switch the images back

```sh
kubectl -n shieldwaf set image deploy/shieldwaf engine=shieldwaf:2.3 panel=shieldwaf:2.3
kubectl -n shieldwaf rollout status deploy/shieldwaf
```

Leave the 2.4 database image (it works with the 2.3 panel as explained above). Backups: the 2.3 backup job is not part of 2.4 manifests; re-apply the 2.3 `k8s/backup.yaml` from the `v2.3.0` tag if you want the old job (`git show v2.3.0:k8s/backup.yaml | kubectl apply -f -`) and delete the 2.4 jobs (`kubectl -n shieldwaf delete cronjob shieldwaf-db-backup shieldwaf-db-backup-verify` first, as both use the same volume name).

## Option 2 (full return to the state before the upgrade)

1. Stop the panel: `kubectl -n shieldwaf scale deploy/shieldwaf --replicas=0`.
2. Restore the 2.3 backup you took before the upgrade with the 2.3 restore procedure (`git show v2.3.0:scripts/restore-db.sh`), **using 2.3 images**. Everything saved after that backup is lost.
3. `git checkout v2.3.0 -- k8s/shieldwaf.yaml && kubectl apply -f k8s/shieldwaf.yaml`.

## What is lost on a rollback

* The 2.4 audit-trail **protection** (the 2.3 panel writes plain rows into the table; they are not chained, so verification of the trail will report them as unchained after you upgrade again; the migration chains such rows once).
* The SSRF guard's stricter rules, OpenAPI validation limits, backup verification and key ring (the key ring secret stays in the cluster; keep it: it is the only way to read 2.4 backups).

## Test it

The 2.3 → 2.4 → 2.3 path on a test copy: install 2.3 in a test namespace, upgrade to 2.4, add data, switch back with Option 1, and run `IMG_TAG=2.3 bash tests/run.sh`. This was **not** run for this release (see `KNOWN_LIMITATIONS.md`).
