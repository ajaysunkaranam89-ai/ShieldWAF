# PostgreSQL for A Shield WAF: the official image (pinned by digest) with OS fixes applied and the unused `gosu` helper removed.
# gosu is only used by the entrypoint when the container starts as root; the pod runs as UID 70, so it is never executed, but its
# outdated Go runtime carried known vulnerabilities, so it is deleted instead of shipped.
FROM postgres:16-alpine@sha256:0cefaabd882e42bcb2a2f3dc56d3ce4770560ba62fd7f197f1a2e008fd5731ab
USER root
RUN apk upgrade --no-cache && rm -f /usr/local/bin/gosu
USER 70
HEALTHCHECK NONE
