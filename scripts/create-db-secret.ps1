# Creates the secret for A Shield WAF: a random database password and a random key that encrypts the files shared between replicas
# (private keys, certificates, alert secrets). Both are stored ONLY in the cluster, never in git.
# Usage: .\scripts\create-db-secret.ps1 [-Namespace shieldwaf]
# Safe to run again: an existing password is never changed; a missing encryption key (older installation) is added.
param([string]$Namespace = "shieldwaf")
function New-DataKey {
    $b = New-Object byte[] 32
    [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($b)
    return ([Convert]::ToBase64String($b)).Replace("+", "-").Replace("/", "_")
}
kubectl create namespace $Namespace --dry-run=client -o yaml | kubectl apply -f - | Out-Null
kubectl -n $Namespace get secret shieldwaf-db 2>$null | Out-Null
if ($LASTEXITCODE -eq 0) {
    $have = kubectl -n $Namespace get secret shieldwaf-db -o jsonpath='{.data.SHIELD_DATA_KEY}'
    if ($have) { Write-Host "secret shieldwaf-db already exists in $Namespace (left unchanged)"; exit 0 }
    $b64 = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes((New-DataKey)))
    kubectl -n $Namespace patch secret shieldwaf-db -p "{`"data`":{`"SHIELD_DATA_KEY`":`"$b64`"}}" | Out-Null
    Write-Host "secret shieldwaf-db in ${Namespace}: encryption key for shared files added (database password unchanged)"; exit 0
}
$bytes = New-Object byte[] 24
[System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
$pw = ($bytes | ForEach-Object { $_.ToString("x2") }) -join ""
$key = New-DataKey
kubectl -n $Namespace create secret generic shieldwaf-db --from-literal=POSTGRES_PASSWORD=$pw --from-literal="SHIELD_DB_URL=postgresql://shieldwaf:$pw@shieldwaf-db:5432/shieldwaf" --from-literal="SHIELD_DATA_KEY=$key"
