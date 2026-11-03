#!/bin/sh
# Panel container: make sure the challenge key and the TLS certificate for the admin panel exist (shared by all replicas, see
# panel/prepare.py), then serve the panel over HTTPS only.
set -e
umask 077
mkdir -p /data/logs /tmp
python3 /panel/prepare.py
CERT=/data/certs/panel/fullchain.pem
KEY=/data/certs/panel/privkey.pem
# Optional: mount your own certificate at /panel-tls/tls.crt + tls.key (for example from cert-manager) to replace the self-signed one.
if [ -f /panel-tls/tls.crt ] && [ -f /panel-tls/tls.key ]; then CERT=/panel-tls/tls.crt; KEY=/panel-tls/tls.key; fi
exec gunicorn -w 1 --threads 6 -b 0.0.0.0:9000 --certfile "$CERT" --keyfile "$KEY" \
  --no-control-socket --access-logfile - --limit-request-line 4094 --limit-request-fields 50 --timeout 60 app:app
