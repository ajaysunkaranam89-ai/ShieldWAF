# Creates the encryption key ring for the database backups: a Kubernetes secret that is separate from the database secret
# (shieldwaf-backup-keys: `current` = id of the key used for new backups, key-<id> = 32 random bytes, base64). Safe to run again: an existing ring is never changed.
# Usage: .\scripts\create-backup-key.ps1 [-Namespace shieldwaf]
# IMPORTANT: store an offline copy of the key ring (kubectl -n shieldwaf get secret shieldwaf-backup-keys -o yaml, kept somewhere that is neither the cluster nor the
# backup destination). Without the key a backup cannot be read, by anybody. Rotation: use scripts/rotate-backup-key.sh (Git Bash / WSL).
param([string]$Namespace = "shieldwaf")
kubectl create namespace $Namespace --dry-run=client -o yaml | kubectl apply -f - | Out-Null
kubectl -n $Namespace get secret shieldwaf-backup-keys 2>$null | Out-Null
if ($LASTEXITCODE -eq 0) { Write-Host "secret shieldwaf-backup-keys already exists in $Namespace (left unchanged)"; exit 0 }
$rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
$id = New-Object byte[] 4; $rng.GetBytes($id); $kid = -join ($id | ForEach-Object { $_.ToString("x2") })
$k = New-Object byte[] 32; $rng.GetBytes($k)
kubectl -n $Namespace create secret generic shieldwaf-backup-keys --from-literal=current=$kid --from-literal="key-$kid=$([Convert]::ToBase64String($k))" | Out-Null
Write-Host "secret shieldwaf-backup-keys created in $Namespace (current key id $kid). Make an offline copy of it now."
