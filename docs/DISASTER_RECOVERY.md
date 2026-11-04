# A Shield WAF 2.4 — Backup and disaster recovery

This document describes what is backed up, how backups are protected, how to prove they work and how to restore. Everything here is tested by
`tests/backup_crypto.sh` (real PostgreSQL + a real S3 server in Docker, 25 checks) and `tests/backup_test.py` (cluster: backup job, validation job, disaster, restore).

## What is protected

The PostgreSQL database holds the configuration of every site, users, rules, alert settings, logs, the tamper-evident audit trail and the encrypted shared files
(certificates, private keys). Losing it means losing the firewall configuration. The backup is a full `pg_dump` of it.

## How a backup is protected (format SWBK v1)

| Property | How |
|---|---|
| Confidentiality | AES-256-GCM, 1 MiB chunks. The file contains no table name, user name or plaintext. |
| Integrity and authenticity | Every chunk has its own 16-byte authentication tag. The header, the chunk index and a "this is the last chunk" flag are authenticated too, so a flipped bit, a truncated file, dropped, duplicated or reordered chunks and chunks spliced in from another backup are all detected. |
| Unique nonces | A random 8-byte prefix per file plus a 4-byte chunk counter. The same key is never used with the same nonce twice. |
| Keys are independent | The key ring is the Kubernetes secret `shieldwaf-backup-keys` (`current` + `key-<id>`). It is **not** the database secret and **not** on the backup volume. Someone who has the database secret or the backup volume cannot read a backup. |
| No plaintext before verification | Restore authenticates the whole file first and only then touches the database. A damaged file never reaches `pg_restore`. |
| Independent destination | Optional upload to an S3-compatible store (AWS Signature V4, https only). The upload size is checked. A failing upload makes the job fail. |
| Events | Backup, verify and restore events are written to the `backup_log` table and into the audit chain. |

## Setup

```sh
sh scripts/create-backup-key.sh            # once; Windows: .\scripts\create-backup-key.ps1
kubectl apply -f k8s/backup.yaml           # volume, nightly job 02:30 UTC, weekly restore test Sunday 04:00 UTC, network policies
```

Helm: `--set backup.enabled=true` (the chart creates the key ring once and keeps it on upgrade and uninstall).

**Make an offline copy of the key ring now** and keep it where neither the cluster nor the backup destination can reach it:

```sh
kubectl -n shieldwaf get secret shieldwaf-backup-keys -o yaml > shieldwaf-backup-keys.yaml
```

Without the key ring a backup cannot be read by anybody. Nobody, including the project, can recover it.

### Independent destination

Create the secret `shieldwaf-backup-s3` (keys `endpoint` = `https://...`, `bucket`, `prefix`, `access-key`, `secret-key`). Use a bucket in another account or
another provider, with a key that may only write new objects (no delete). Narrow the policy `shieldwaf-backup-s3` in `k8s/backup.yaml` to the destination's addresses.
A backup that sits in the same cluster as the database does not protect against losing the cluster.

## Proving that backups work

* The backup job reads the file back and authenticates every tag before it reports success.
* The weekly job `shieldwaf-db-backup-verify` restores the newest backup into a temporary database (`swverify_*`), checks that it loads, and drops it. A failed job
  means: take a new backup now and look at the log. Check with `kubectl get jobs -n shieldwaf`.
* On demand: `kubectl create job --from=cronjob/shieldwaf-db-backup-verify verify-now -n shieldwaf`.

## Restore

```sh
sh scripts/restore-db.sh list              # backups on the volume, with the key id of each
sh scripts/restore-db.sh latest            # the newest backup   (Windows: .\scripts\restore-db.ps1 latest)
sh scripts/restore-db.sh shieldwaf-20261104-023000.swbk
```

The firewall replicas are stopped, the file is authenticated, the database is replaced by the backup (everything written after the backup is lost), and the replicas
start again. `YES=1` skips the question. A backup that does not exist or is damaged fails cleanly and the replicas are started again.

### Total loss of the cluster

1. Create a new cluster, install A Shield WAF as usual (an empty database is created).
2. Restore the **key ring** from your offline copy: `kubectl apply -f shieldwaf-backup-keys.yaml` (remove `resourceVersion`/`uid` lines if the cluster refuses them).
3. Copy a backup from the independent destination onto the backup volume (any S3 client; the file name must end in `.swbk`).
4. `sh scripts/restore-db.sh <file>`.
5. Secrets that are not in the database must be recreated from your records: the database secret (`scripts/create-db-secret.sh` creates a new one; the shared-file
   encryption key `SHIELD_DATA_KEY` must be the **old** one, otherwise certificates and keys inside the backup cannot be decrypted. Keep an offline copy of `shieldwaf-db` too).

Recovery objectives with the defaults: RPO up to 24 hours (nightly), RTO about 10–20 minutes for a small database. Point-in-time recovery needs WAL archiving, which this
release does not provide (see `docs/KNOWN_LIMITATIONS.md` / the 2.4 report).

## Key rotation

```sh
sh scripts/rotate-backup-key.sh shieldwaf                 # new key becomes current; old backups stay readable
sh scripts/rotate-backup-key.sh shieldwaf reencrypt       # move the backups on the volume to the new key
sh scripts/rotate-backup-key.sh shieldwaf retire <old id> # remove the old key (only when no backup needs it, including the independent copies)
```

Rotate at least yearly and whenever someone with access to the key ring leaves. Update the offline copy after every rotation. Copies in the independent destination
are not changed by `reencrypt`; upload the re-encrypted files again before retiring a key.

## Tamper and corruption cases (all tested)

| Event | Result |
|---|---|
| One flipped bit anywhere in the file | verify and restore fail with "authentication failed", exit code 2 |
| Truncated or extended file | refused |
| Chunks reordered, duplicated, or taken from another backup | refused |
| Wrong key ring or unknown key id | refused, clear message |
| Missing file | clean error, database untouched |
| Wrong credentials for the S3 destination | the backup job fails (it does not report success) |

## Not covered

* Backups made by 2.3 (`.dump.enc`, AES-CBC with the database encryption key) are not read by the 2.4 tool. Take a fresh 2.4 backup right after the upgrade and keep the old files
  until then; they can still be decrypted with `openssl` as described in the 2.3 install guide.
* Point-in-time recovery and streaming replication (Phase 4 of the 2.4 plan) are not implemented in this release.
