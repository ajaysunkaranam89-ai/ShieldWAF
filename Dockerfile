# A Shield WAF 2.0: nginx + ModSecurity v3 + OWASP Core Rule Set (engine) and a Python control panel (GUI) in ONE image.
# Kubernetes runs it as two containers (engine, panel) that share only the /data volume.
# Base image pinned by digest (reproducible, no surprise updates). Rebuild regularly to pick up OS security fixes.
FROM owasp/modsecurity-crs@sha256:873ce68a658d2e3b61484a8a24d215f7d15456e7ce5aec5e7114bf000d743365

LABEL org.opencontainers.image.title="A Shield WAF" org.opencontainers.image.version="2.0" \
      org.opencontainers.image.description="Open-source WAF: nginx + ModSecurity + OWASP CRS with a web GUI"

USER root
RUN apk upgrade --no-cache \
 && apk add --no-cache python3 py3-flask py3-gunicorn \
 && rm -rf /var/cache/apk/* \
 && mkdir -p /data /panel \
 && chown -R 101:101 /data /panel

COPY --chown=101:101 panel /panel
COPY --chown=101:101 engine-entrypoint.sh panel-entrypoint.sh /usr/local/bin/
RUN chmod 0555 /usr/local/bin/engine-entrypoint.sh /usr/local/bin/panel-entrypoint.sh \
 && chmod -R a-w /panel \
 && chmod 0555 /panel/njs

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
USER 101
WORKDIR /panel
ENTRYPOINT []
HEALTHCHECK NONE
# default command = the panel (HTTPS); the engine container overrides it with engine-entrypoint.sh
CMD ["/usr/local/bin/panel-entrypoint.sh"]
