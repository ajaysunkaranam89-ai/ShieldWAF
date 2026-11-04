# PostgreSQL for A Shield WAF: the official image (pinned by digest) with OS fixes applied and the unused `gosu` helper removed.
# TLS is on by default (tls-entrypoint.sh) and network connections without TLS are rejected (pg_hba.conf). Optional: WAL archiving for point-in-time recovery
# (SHIELD_DB_ARCHIVE_DIR, archive-wal.sh) and replication connections (SHIELD_DB_REPLICATION=on, pg_hba_repl.conf).
# gosu is only used by the entrypoint when the container starts as root; the pod runs as UID 70, so it is never executed, but its
# outdated Go runtime carried known vulnerabilities, so it is deleted instead of shipped. openssl is needed for the self-signed certificate.
FROM postgres:16-alpine@sha256:0cefaabd882e42bcb2a2f3dc56d3ce4770560ba62fd7f197f1a2e008fd5731ab
USER root
RUN apk upgrade --no-cache && apk add --no-cache openssl && rm -f /usr/local/bin/gosu
COPY tls-entrypoint.sh archive-wal.sh /usr/local/bin/
COPY pg_hba.conf pg_hba_repl.conf /etc/shieldwaf/
RUN chmod 0555 /usr/local/bin/tls-entrypoint.sh /usr/local/bin/archive-wal.sh && chmod 0444 /etc/shieldwaf/pg_hba.conf /etc/shieldwaf/pg_hba_repl.conf
USER 70
HEALTHCHECK NONE
ENTRYPOINT ["tls-entrypoint.sh"]
CMD ["postgres"]
