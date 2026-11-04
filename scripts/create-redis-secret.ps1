# Creates the secret for the optional Redis (cluster-wide rate limiting). Usage: .\scripts\create-redis-secret.ps1 [-Namespace shieldwaf]. Safe to run again.
param([string]$Namespace = "shieldwaf")
kubectl create namespace $Namespace --dry-run=client -o yaml | kubectl apply -f - | Out-Null
kubectl -n $Namespace get secret shieldwaf-redis 2>$null | Out-Null
if ($LASTEXITCODE -eq 0) { Write-Host "secret shieldwaf-redis already exists in $Namespace (left unchanged)"; exit 0 }
$b = New-Object byte[] 24; [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($b)
$pw = -join ($b | ForEach-Object { $_.ToString("x2") })
kubectl -n $Namespace create secret generic shieldwaf-redis --from-literal=REDIS_PASSWORD=$pw --from-literal="SHIELD_REDIS_URL=redis://:$pw@shieldwaf-redis:6379/0" | Out-Null
Write-Host "secret shieldwaf-redis created in $Namespace"
