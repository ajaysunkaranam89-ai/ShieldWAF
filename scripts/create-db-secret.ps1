# Creates the database secret for A Shield WAF: a random password, stored ONLY in the cluster (never in git).
# Usage: .\scripts\create-db-secret.ps1 [-Namespace shieldwaf]
param([string]$Namespace = "shieldwaf")
kubectl create namespace $Namespace --dry-run=client -o yaml | kubectl apply -f - | Out-Null
kubectl -n $Namespace get secret shieldwaf-db 2>$null | Out-Null
if ($LASTEXITCODE -eq 0) { Write-Host "secret shieldwaf-db already exists in $Namespace (left unchanged)"; exit 0 }
$bytes = New-Object byte[] 24
[System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
$pw = ($bytes | ForEach-Object { $_.ToString("x2") }) -join ""
kubectl -n $Namespace create secret generic shieldwaf-db --from-literal=POSTGRES_PASSWORD=$pw --from-literal="SHIELD_DB_URL=postgresql://shieldwaf:$pw@shieldwaf-db:5432/shieldwaf"
