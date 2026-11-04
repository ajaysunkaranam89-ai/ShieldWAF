#!/bin/sh
# Restore the A Shield WAF database from an encrypted backup (AES-256-GCM, authenticated) made by k8s/backup.yaml. The file is verified BEFORE the database is touched.
#   sh scripts/restore-db.sh list                          show the backups on the backup volume
#   sh scripts/restore-db.sh latest                        restore the newest backup
#   sh scripts/restore-db.sh shieldwaf-20261104-023000.swbk
# Optional second argument: namespace (default shieldwaf). Environment: DEPLOY (deployment name, default shieldwaf), DB_HOST (database service, default shieldwaf-db), YES=1 (no question).
# What happens: the firewall replicas are stopped (traffic through them stops for the duration; nothing else is touched), the database is
# REPLACED by the backup (everything saved after the backup is lost), the replicas are started again with the same count as before.
set -eu
WHICH="${1:-}"
NS="${2:-shieldwaf}"
DEPLOY="${DEPLOY:-shieldwaf}"
[ -n "$WHICH" ] || { sed -n '2,6p' "$0"; exit 1; }
JOB="shieldwaf-restore-$(date +%s)"

run_job() {   # $1 = shell script to run inside a pod that has the backup volume and the database client
  kubectl -n "$NS" delete job "$JOB" --ignore-not-found >/dev/null
  cat <<EOF | kubectl -n "$NS" apply -f - >/dev/null
apiVersion: batch/v1
kind: Job
metadata: {name: $JOB, namespace: $NS}
spec:
  backoffLimit: 0
  ttlSecondsAfterFinished: 600
  template:
    metadata: {labels: {app: shieldwaf-backup}}
    spec:
      restartPolicy: Never
      automountServiceAccountToken: false
      securityContext: {runAsNonRoot: true, runAsUser: 10101, runAsGroup: 10101, fsGroup: 10101, seccompProfile: {type: RuntimeDefault}}
      containers:
        - name: restore
          image: shieldwaf:${IMG_TAG:-2.4}
          imagePullPolicy: IfNotPresent
          securityContext: {allowPrivilegeEscalation: false, readOnlyRootFilesystem: true, capabilities: {drop: ["ALL"]}}
          env:
            - {name: PGPASSWORD, valueFrom: {secretKeyRef: {name: shieldwaf-db, key: POSTGRES_PASSWORD}}}
            - {name: SHIELD_DATA, value: /tmp}
            - {name: PGUSER, value: shieldwaf}
            - {name: PGDATABASE, value: shieldwaf}
            - {name: WHICH, value: "$WHICH"}
            - {name: PGHOST, value: "${DB_HOST:-shieldwaf-db}"}
          command: ["sh", "-c"]
          args:
            - |
$(printf '%s\n' "$1" | sed 's/^/              /')
          volumeMounts: [{name: backups, mountPath: /backups}, {name: keys, mountPath: /keys, readOnly: true}, {name: tmp, mountPath: /tmp}]
      volumes:
        - {name: backups, persistentVolumeClaim: {claimName: shieldwaf-backups}}
        - {name: keys, secret: {secretName: shieldwaf-backup-keys, defaultMode: 0440}}
        - {name: tmp, emptyDir: {sizeLimit: 256Mi}}
EOF
  rc=1
  for _ in $(seq 1 450); do           # up to 15 minutes; stop as soon as the job has succeeded OR failed
    st=$(kubectl -n "$NS" get "job/$JOB" -o jsonpath='{.status.succeeded}/{.status.failed}' 2>/dev/null || echo "/")
    case "$st" in 1/*) rc=0; break ;; */[1-9]*) rc=1; break ;; esac
    sleep 2
  done
  kubectl -n "$NS" logs "job/$JOB" 2>&1 || true
  kubectl -n "$NS" delete job "$JOB" --ignore-not-found >/dev/null
  return $rc
}

if [ "$WHICH" = "list" ]; then
  run_job "python3 /panel/backupcrypt.py list --dir /backups"
  exit $?
fi

if [ "${YES:-}" != "1" ]; then
  printf 'This REPLACES the database in namespace %s with backup "%s". Everything saved after that backup is lost.\nThe firewall replicas are stopped while it runs. Type yes to continue: ' "$NS" "$WHICH"
  read -r ans
  [ "$ans" = "yes" ] || { echo "cancelled"; exit 1; }
fi

REPLICAS=$(kubectl -n "$NS" get deploy "$DEPLOY" -o jsonpath='{.spec.replicas}')
echo "stopping $REPLICAS replica(s) of $DEPLOY ..."
kubectl -n "$NS" scale "deploy/$DEPLOY" --replicas=0 >/dev/null
for i in $(seq 1 60); do
  [ -z "$(kubectl -n "$NS" get pods -l app=shieldwaf --no-headers 2>/dev/null)" ] && break
  sleep 3
done

RESTORE='python3 /panel/backupcrypt.py restore "$WHICH" --dir /backups'
if run_job "$RESTORE"; then RESULT=ok; else RESULT=failed; fi

echo "starting $REPLICAS replica(s) again ..."
kubectl -n "$NS" scale "deploy/$DEPLOY" --replicas="$REPLICAS" >/dev/null
kubectl -n "$NS" rollout status "deploy/$DEPLOY" --timeout=300s >/dev/null 2>&1 || true
if [ "$RESULT" = ok ]; then echo "done: restore finished, the firewall is running again"; else echo "RESTORE FAILED (see the log above); the replicas were started again, check the panel and the database before relying on it"; exit 1; fi
