#!/bin/sh
# TLS for the database. A certificate from the secret mounted at /tls (tls.crt, tls.key) is used when present, otherwise a self-signed one is generated at start
# (encrypts the traffic; clients can only VERIFY it with sslmode=verify-full and the CA that you mount). SHIELD_DB_TLS=off turns this off (not recommended).
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
exec docker-entrypoint.sh "$@" -c ssl=on -c "ssl_cert_file=$D/server.crt" -c "ssl_key_file=$D/server.key" -c ssl_min_protocol_version=TLSv1.2 \
  -c hba_file=/etc/shieldwaf/pg_hba.conf -c password_encryption=scram-sha-256
