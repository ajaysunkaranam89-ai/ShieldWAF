#!/bin/sh
# Engine container: run nginx in the foreground and apply new configurations safely.
# The panel (a separate container, no shared process namespace) renders generations under /data/rendered and switches the
# `current` link. This loop notices the change (or a reload.request), tests the config, reloads nginx and reports the result
# in reload.status ("<generation>|ok|<time>" or "<generation>|failed|<time>"). If a reload fails nginx keeps the old workers.
D=/data/rendered
mkdir -p /tmp/nx /data/logs "$D"
echo "[engine] waiting for the panel to render $D/current/nginx.conf ..."
while [ ! -f "$D/current/nginx.conf" ]; do sleep 1; done
echo "[engine] starting nginx"
nginx -g 'daemon off;' -c "$D/current/nginx.conf" &
NPID=$!
trap 'kill -QUIT $NPID 2>/dev/null; wait $NPID; exit 0' TERM INT
last=$(readlink "$D/current")
while kill -0 $NPID 2>/dev/null; do
  touch "$D/engine.alive"
  cur=$(readlink "$D/current")
  if [ "$cur" != "$last" ] || [ -f "$D/reload.request" ]; then
    rm -f "$D/reload.request"
    res=failed
    # the panel already ran `nginx -t` on exactly this generation (marker .tested): do not parse the whole configuration a second time
    if { [ -f "$cur/.tested" ] || nginx -t -c "$D/current/nginx.conf" >/dev/null 2>&1; } && nginx -s reload -c "$D/current/nginx.conf" 2>/dev/null; then
      # "ok" only when the NEW generation answers
      gen=$(basename "$cur")
      w=$(cat "$cur/.wait" 2>/dev/null || echo 60)
      max=$((w * 2 + 20))
      i=0
      while [ $i -lt $max ]; do
        if wget -qO- -T 2 http://127.0.0.1:8080/__shieldwaf_health 2>/dev/null | grep -q "$gen"; then res=ok; break; fi
        touch "$D/engine.alive"; i=$((i+1)); sleep 0.5
      done
    fi
    echo "[engine] reload $cur: $res"
    echo "$cur|$res|$(date +%s)" > "$D/reload.status.tmp" && mv "$D/reload.status.tmp" "$D/reload.status"
    last=$cur
  fi
  sleep 0.3
done
wait $NPID
