# Restore the A Shield WAF database from an encrypted backup made by k8s/backup.yaml (Windows PowerShell version of restore-db.sh).
#   .\scripts\restore-db.ps1 list                          show the backups on the backup volume
#   .\scripts\restore-db.ps1 latest                        restore the newest backup
#   .\scripts\restore-db.ps1 shieldwaf-20261104-023000.swbk
# Optional: -Namespace shieldwaf  -Deploy shieldwaf  -DbHost shieldwaf-db (database service)  -Yes (no question)
# The firewall replicas are stopped, the database is REPLACED by the backup (everything saved after it is lost), the replicas are started again.
param([Parameter(Mandatory = $true)][string]$Which, [string]$Namespace = "shieldwaf", [string]$Deploy = "shieldwaf", [string]$DbHost = "shieldwaf-db", [string]$ImageTag = "2.4", [switch]$Yes)
$ErrorActionPreference = "Stop"
$job = "shieldwaf-restore-" + [int][double]::Parse((Get-Date -UFormat %s))

function Invoke-Job([string]$script) {
    kubectl -n $Namespace delete job $job --ignore-not-found | Out-Null
    $indented = ($script -split "`n" | ForEach-Object { "              " + $_ }) -join "`n"
    $yaml = @"
apiVersion: batch/v1
kind: Job
metadata: {name: $job, namespace: $Namespace}
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
          image: shieldwaf:$ImageTag
          imagePullPolicy: IfNotPresent
          securityContext: {allowPrivilegeEscalation: false, readOnlyRootFilesystem: true, capabilities: {drop: ["ALL"]}}
          env:
            - {name: PGPASSWORD, valueFrom: {secretKeyRef: {name: shieldwaf-db, key: POSTGRES_PASSWORD}}}
            - {name: SHIELD_DATA, value: /tmp}
            - {name: PGUSER, value: shieldwaf}
            - {name: PGDATABASE, value: shieldwaf}
            - {name: WHICH, value: "$Which"}
            - {name: PGHOST, value: "$DbHost"}
          command: ["sh", "-c"]
          args:
            - |
$indented
          volumeMounts: [{name: backups, mountPath: /backups}, {name: keys, mountPath: /keys, readOnly: true}, {name: tmp, mountPath: /tmp}]
      volumes:
        - {name: backups, persistentVolumeClaim: {claimName: shieldwaf-backups}}
        - {name: keys, secret: {secretName: shieldwaf-backup-keys, defaultMode: 0440}}
        - {name: tmp, emptyDir: {sizeLimit: 256Mi}}
"@
    $file = Join-Path ([IO.Path]::GetTempPath()) "$job.yaml"
    [IO.File]::WriteAllText($file, $yaml, (New-Object Text.UTF8Encoding($false)))
    try { kubectl -n $Namespace apply -f $file | Out-Null } finally { Remove-Item $file -ErrorAction SilentlyContinue }
    $ok = $false
    for ($i = 0; $i -lt 450; $i++) {       # up to 15 minutes; stop as soon as the job has succeeded OR failed
        $st = kubectl -n $Namespace get "job/$job" -o jsonpath='{.status.succeeded}/{.status.failed}' 2>$null
        if ($st -match '^1/') { $ok = $true; break }
        if ($st -match '/[1-9]') { break }
        Start-Sleep 2
    }
    kubectl -n $Namespace logs "job/$job"
    kubectl -n $Namespace delete job $job --ignore-not-found | Out-Null
    return $ok
}

if ($Which -eq "list") { Invoke-Job "python3 /panel/backupcrypt.py list --dir /backups" | Out-Null; exit 0 }

if (-not $Yes) {
    $ans = Read-Host "This REPLACES the database in namespace $Namespace with backup '$Which'. Everything saved after that backup is lost. The firewall replicas are stopped while it runs. Type yes to continue"
    if ($ans -ne "yes") { Write-Host "cancelled"; exit 1 }
}
$replicas = kubectl -n $Namespace get deploy $Deploy -o jsonpath='{.spec.replicas}'
Write-Host "stopping $replicas replica(s) of $Deploy ..."
kubectl -n $Namespace scale "deploy/$Deploy" --replicas=0 | Out-Null
for ($i = 0; $i -lt 60; $i++) { if (-not (kubectl -n $Namespace get pods -l app=shieldwaf --no-headers 2>$null)) { break }; Start-Sleep 3 }

$restore = 'python3 /panel/backupcrypt.py restore "$WHICH" --dir /backups'
$ok = Invoke-Job $restore
Write-Host "starting $replicas replica(s) again ..."
kubectl -n $Namespace scale "deploy/$Deploy" --replicas=$replicas | Out-Null
kubectl -n $Namespace rollout status "deploy/$Deploy" --timeout=300s 2>$null | Out-Null
if ($ok) { Write-Host "done: restore finished, the firewall is running again" } else { Write-Host "RESTORE FAILED (see the log above); the replicas were started again, check the panel and the database before relying on it"; exit 1 }
