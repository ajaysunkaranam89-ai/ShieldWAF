#!/bin/sh
# Key rotation for the database backups: adds a NEW key to the ring and makes it the current one. New backups use it at once; old backups stay readable because
# the old keys stay in the ring until you retire them (after `reencrypt`, see below).
#   sh scripts/rotate-backup-key.sh [namespace]             add a new key, make it current
#   sh scripts/rotate-backup-key.sh [namespace] reencrypt   also re-encrypt all backups on the volume with the current key (a Job; needs the volume free)
#   sh scripts/rotate-backup-key.sh [namespace] retire ID   remove an old key (only after every backup was re-encrypted, including the copies in the independent destination)
set -e
NS="${1:-shieldwaf}"; ACTION="${2:-}"; OLD="${3:-}"
kubectl -n "$NS" get secret shieldwaf-backup-keys >/dev/null 2>&1 || { echo "no key ring yet: run scripts/create-backup-key.sh first"; exit 1; }
case "$ACTION" in
  "")
    KID=$(head -c 4 /dev/urandom | od -An -tx1 | tr -d ' \n')
    KEY=$(head -c 32 /dev/urandom | base64 | tr -d '\n' | base64 | tr -d '\n')
    CUR=$(printf '%s' "$KID" | base64 | tr -d '\n')
    kubectl -n "$NS" patch secret shieldwaf-backup-keys -p "{\"data\":{\"key-$KID\":\"$KEY\",\"current\":\"$CUR\"}}" >/dev/null
    echo "new key $KID is now the current key. Update your offline copy of the key ring. Old backups stay readable; run '$0 $NS reencrypt' to move them to the new key."
    ;;
  reencrypt)
    JOB="shieldwaf-reencrypt-$(date +%s)"
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
        - name: reencrypt
          image: shieldwaf:2.4
          imagePullPolicy: IfNotPresent
          securityContext: {allowPrivilegeEscalation: false, readOnlyRootFilesystem: true, capabilities: {drop: ["ALL"]}}
          env: [{name: SHIELD_DATA, value: /tmp}]
          command: ["python3", "/panel/backupcrypt.py", "reencrypt", "--dir", "/backups"]
          volumeMounts: [{name: backups, mountPath: /backups}, {name: keys, mountPath: /keys, readOnly: true}, {name: tmp, mountPath: /tmp}]
      volumes:
        - {name: backups, persistentVolumeClaim: {claimName: shieldwaf-backups}}
        - {name: keys, secret: {secretName: shieldwaf-backup-keys, defaultMode: 0440}}
        - {name: tmp, emptyDir: {sizeLimit: 256Mi}}
EOF
    kubectl -n "$NS" wait --for=condition=complete "job/$JOB" --timeout=900s >/dev/null || { kubectl -n "$NS" logs "job/$JOB" || true; echo "re-encryption FAILED"; exit 1; }
    kubectl -n "$NS" logs "job/$JOB"
    echo "Backups copied to an independent destination are NOT changed by this: upload the re-encrypted files again before you retire the old key."
    ;;
  retire)
    [ -n "$OLD" ] || { echo "usage: $0 $NS retire <key id>"; exit 1; }
    CUR=$(kubectl -n "$NS" get secret shieldwaf-backup-keys -o jsonpath='{.data.current}' | base64 -d)
    [ "$OLD" != "$CUR" ] || { echo "$OLD is the current key; rotate first"; exit 1; }
    kubectl -n "$NS" patch secret shieldwaf-backup-keys --type=json -p "[{\"op\":\"remove\",\"path\":\"/data/key-$OLD\"}]" >/dev/null
    echo "key $OLD removed from the ring. Backups still encrypted with it can no longer be read."
    ;;
  *) echo "unknown action $ACTION"; exit 1 ;;
esac
