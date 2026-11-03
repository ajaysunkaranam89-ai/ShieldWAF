#!/bin/sh
# Engine container: wait until the panel has rendered a config, then run nginx in the foreground.
# The panel hot-reloads it (SIGHUP) whenever the configuration changes.
mkdir -p /tmp/nx /data/logs
echo "[engine] waiting for the panel to render /data/rendered/current/nginx.conf ..."
while [ ! -f /data/rendered/current/nginx.conf ]; do sleep 1; done
echo "[engine] starting nginx"
exec nginx -g 'daemon off;' -c /data/rendered/current/nginx.conf
