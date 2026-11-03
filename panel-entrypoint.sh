#!/bin/sh
# Panel container: make sure the TLS certificate for the admin panel and the challenge key exist, then serve the panel over HTTPS only.
set -e
umask 077
mkdir -p /data/certs/panel /data/logs /tmp
if [ ! -f /data/challenge.key ]; then
  head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n' > /data/challenge.key
  chmod 600 /data/challenge.key
fi
CERT=/data/certs/panel/fullchain.pem
KEY=/data/certs/panel/privkey.pem
# Optional: mount your own certificate at /panel-tls/tls.crt + tls.key (for example from cert-manager) to replace the self-signed one.
if [ -f /panel-tls/tls.crt ] && [ -f /panel-tls/tls.key ]; then CERT=/panel-tls/tls.crt; KEY=/panel-tls/tls.key; fi
if [ ! -f "$CERT" ]; then
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 825 -subj "/CN=shieldwaf-panel" \
    -addext "subjectAltName=DNS:shieldwaf-panel,DNS:localhost,IP:127.0.0.1" -keyout "$KEY" -out "$CERT" 2>/dev/null
fi
exec gunicorn -w 1 --threads 6 -b 0.0.0.0:9000 --certfile "$CERT" --keyfile "$KEY" \
  --no-control-socket --access-logfile - --limit-request-line 4094 --limit-request-fields 50 --timeout 60 app:app
