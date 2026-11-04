# Docker deployment (one host)

`deploy/docker-compose.yml` runs the database, the panel and the engine on one host. It mirrors the two containers of a Kubernetes pod: the engine runs in the network namespace of the panel, sees `/data` read-only (plus its own `rendered/` and `logs/` volumes) and cannot see the panel-only secrets (`/private` is a memory volume in the panel container only). All containers have a read-only root file system, no capabilities and `no-new-privileges`. This was started and checked on Docker Desktop: database healthy, panel health check answers, engine serves its health URL; it was **not** run through a full site-protection test, and it has one replica of each (no high availability).

## Steps

```sh
docker build -t shieldwaf:2.4 . && docker build -t shieldwaf-db:2.4 db
sh deploy/docker-init.sh                                   # creates deploy/.env with random secrets (once; back it up)
docker compose -f deploy/docker-compose.yml --env-file deploy/.env up -d
docker compose -f deploy/docker-compose.yml logs panel | grep "Setup code"
```

Open `https://127.0.0.1:9000` (self-signed certificate), create the admin account with the setup code, add a site. Protected traffic: ports 8080 / 8443 (change with `HTTP_PORT`, `HTTPS_PORT`, `PANEL_PORT` in `deploy/.env`). The panel port is bound to 127.0.0.1 only: reach it through a VPN or an SSH tunnel, never publish it.

## Operating it

* **Update:** build the new images, `docker compose ... up -d` (the panel runs the database migrations at start).
* **Backups:** the Kubernetes jobs are not part of the Compose file. Run the tool by hand or from the host's scheduler:
  `docker run --rm --network shieldwaf_internal -e PGHOST=db -e PGUSER=shieldwaf -e PGPASSWORD=... -e PGSSLMODE=require -e SHIELD_DATA=/tmp/d -v <key ring dir>:/keys:ro -v <backup dir>:/backups --user 10101:10101 --entrypoint python3 shieldwaf:2.4 /panel/backupcrypt.py backup --out /backups`
  (the key ring: `backupcrypt.py` functions `new_key`; see `docs/DISASTER_RECOVERY.md` and `scripts/create-backup-key.sh` for the layout). Keep the key ring off the backup volume.
* **Optional services** (Redis for cluster-wide rate limits, CrowdSec, WAL archiving): set `SHIELD_REDIS_URL` on the panel service, give the database `SHIELD_DB_ARCHIVE_DIR` and a volume; these are tested in Docker by `tests/redis_ratelimit.sh`, `tests/crowdsec.sh`, `tests/db_pitr.sh`, but not wired into the Compose file.
* **Stop and remove data:** `docker compose ... down` keeps the volumes; `down -v` deletes the database and everything else.

## Limits

One host is one failure domain. For rolling updates, several replicas and node failures use Kubernetes (`docs/KUBERNETES_DEPLOYMENT.md`).
