# ShieldWAF: nginx + ModSecurity v3 + OWASP Core Rule Set (engine) and a Python control panel (GUI) in ONE image.
# Kubernetes runs it as two containers (engine, panel) that share the /data volume and the process namespace.
FROM owasp/modsecurity-crs:nginx-alpine

USER root
RUN apk add --no-cache python3 py3-flask py3-gunicorn \
 && mkdir -p /data /panel \
 && chown -R 101:101 /data /panel

COPY --chown=101:101 panel /panel
COPY --chown=101:101 engine-entrypoint.sh /usr/local/bin/engine-entrypoint.sh
RUN chmod +x /usr/local/bin/engine-entrypoint.sh

USER 101
WORKDIR /panel
ENTRYPOINT []
# default = the panel; the engine container overrides the command
CMD ["gunicorn", "-w", "1", "--threads", "6", "-b", "0.0.0.0:9000", "--access-logfile", "-", "app:app"]
