Write-Host "******** Azure API Management assessment ********" -ForegroundColor Cyan


$subscriptions = az account subscription list -o json --only-show-errors  | ConvertFrom-Json

foreach ($currentSubscription in $subscriptions) {
      
    Write-Host "***** Assessing the subscription $($currentSubscription.displayName) ($($currentSubscription.id)..." -ForegroundColor Cyan
    az account set -s $currentSubscription.SubscriptionId --only-show-errors 

    $jsonAPIM = az apim list -o json --only-show-errors 
    $jsonAPIM | Out-File -FilePath "$OutPath\apim_raw_$today.json" -Append
    $apims = $jsonAPIM | ConvertFrom-Json -AsHashTable
    
    foreach ($apim in $apims) {
        Write-Host ""
        Write-Host "**** Assessing the APIM $($apim.name)..." -ForegroundColor Blue
        $apimInstance = [APIMCheck]::new($currentSubscription.id, $currentSubscription.displayName, $apim)

        $apimInstance.assess().GetAllResults() | Export-Csv -Path "$OutPath\apim_assess_$today.csv" -NoTypeInformation -Append -Delimiter $csvDelimiter
        Write-Host ""
    }
}