#!/bin/sh
# TLS for the database. A certificate from the secret mounted at /tls (tls.crt, tls.key) is used when present, otherwise a self-signed one is generated at start
# (encrypts the traffic; clients can only VERIFY it with sslmode=verify-full and the CA that you mount). SHIELD_DB_TLS=off turns this off (not recommended).
# Optional features (environment):
#   SHIELD_DB_ARCHIVE_DIR=/archive   ship every finished WAL segment to that folder (point-in-time recovery, db/archive-wal.sh); SHIELD_DB_ARCHIVE_TIMEOUT seconds (300)
#   SHIELD_DB_REPLICATION=on         allow replication connections (a streaming standby, pg_basebackup) over TLS with a SCRAM password; SHIELD_DB_WAL_KEEP (256MB)
set -eu
if [ "${SHIELD_DB_TLS:-on}" = "off" ]; then exec docker-entrypoint.sh "$@"; fi
D=/tmp/pgtls
mkdir -p "$D"; chmod 700 "$D"
if [ -r /tls/tls.crt ] && [ -r /tls/tls.key ]; then
  cp /tls/tls.crt "$D/server.crt"; cp /tls/tls.key "$D/server.key"
else
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 825 -subj "/CN=shieldwaf-db" \
    -addext "subjectAltName=DNS:shieldwaf-db,DNS:localhost" -keyout "$D/server.key" -out "$D/server.crt" 2>/dev/null
fi
chmod 600 "$D/server.key"
HBA=/etc/shieldwaf/pg_hba.conf
ARGS=""
if [ -n "${SHIELD_DB_ARCHIVE_DIR:-}" ]; then
  ARGS="$ARGS -c wal_level=replica -c archive_mode=on -c archive_command=/usr/local/bin/archive-wal.sh%20%p%20%f -c archive_timeout=${SHIELD_DB_ARCHIVE_TIMEOUT:-300}"
fi
if [ "${SHIELD_DB_REPLICATION:-off}" = "on" ]; then
  HBA=/etc/shieldwaf/pg_hba_repl.conf
  ARGS="$ARGS -c wal_level=replica -c max_wal_senders=5 -c wal_keep_size=${SHIELD_DB_WAL_KEEP:-256MB}"
fi
# the archive command contains spaces: it is passed with %20 for the space and turned back here (a word-split argument list cannot carry a quoted space)
# shellcheck disable=SC2086
set -- "$@" -c ssl=on -c "ssl_cert_file=$D/server.crt" -c "ssl_key_file=$D/server.key" -c ssl_min_protocol_version=TLSv1.2 -c "hba_file=$HBA" -c password_encryption=scram-sha-256
for w in $ARGS; do
  case "$w" in archive_command=*) set -- "$@" "archive_command=/usr/local/bin/archive-wal.sh %p %f" ;; *) set -- "$@" "$w" ;; esac
done
exec docker-entrypoint.sh "$@"
