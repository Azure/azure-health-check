Write-Host "******** Azure Container Apps assessment" -ForegroundColor Cyan


$subscriptions = az account subscription list -o json --only-show-errors  | ConvertFrom-Json

foreach ($currentSubscription in $subscriptions) {
      
    Write-Host "***** Assessing the subscription $($currentSubscription.displayName) ($($currentSubscription.id)..." -ForegroundColor Cyan
    az account set -s $currentSubscription.SubscriptionId --only-show-errors 

    $jsonACAEnv = az containerapp env list -o json --only-show-errors 
    $jsonACAEnv | Out-File -FilePath "$OutPath\aca_env_raw_$today.json" -Append
    $acaEnvs = $jsonACAEnv | ConvertFrom-Json -AsHashTable
    
    foreach ($acaEnv in $acaEnvs) {
        Write-Host ""
        Write-Host "**** Assessing the Container App Environment $($acaEnv.name)..." -ForegroundColor Blue
        $acaEnvInstance = [ACAEnvCheck]::new($currentSubscription.id, $currentSubscription.displayName, $acaEnv)

        $acaEnvInstance.assess().GetAllResults() | Export-Csv -Path "$OutPath\aca_env_assess_$today.csv" -NoTypeInformation -Append -Delimiter $csvDelimiter
        Write-Host ""

        $jsonACA = az containerapp list --environment $acaEnv.name -o json --only-show-errors
        $jsonACA | Out-File -FilePath "$OutPath\aca_raw_$today.json" -Append
        $acaList = $jsonACA | ConvertFrom-Json -AsHashTable

        foreach ($aca in $acaList) {
            Write-Host "**** Assessing the Container App $($aca.name) from environment $($acaEnv.name)..." -ForegroundColor Blue
            $acaCheck = [ACACheck]::new($currentSubscription.id, $currentSubscription.displayName, $acaEnv.name, $aca)

            $acaCheck.assess().GetAllResults() | Export-Csv -Path "$OutPath\aca_assess_$today.csv" -NoTypeInformation -Append -Delimiter $csvDelimiter
            Write-Host ""
        }

    }
}