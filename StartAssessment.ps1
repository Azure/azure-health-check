using module ./AKS/AKSClusterCheck.psm1
using module ./AKS/AKSNodePoolCheck.psm1
using module ./APIM/APIMCheck.psm1
using module ./SQL/SQLServerCheck.psm1
using module ./SQL/SQLDBCheck.psm1
using module ./ACA/ACAEnvCheck.psm1
using module ./ACA/ACACheck.psm1


param (
    [Parameter(Mandatory = $false)][string]$OutPath = "", # Output path for the assessment results
    [Parameter(Mandatory = $false)][string]$csvDelimiter = ",", # Delimiter for CSV files
    [Parameter(Mandatory = $false)][ValidateSet("user", "sp", "none")][string]$AuthType = "none", 
    [Parameter(Mandatory = $false)][string]$ClientId = "", # ClientId is required when using Service Principal authentication
    [Parameter(Mandatory = $false)][string]$ClientSecret = "", # ClientSecret is required when using Service Principal authentication
    [Parameter(Mandatory = $false)][string]$TenantId = "", # TenantId is required when using Service Principal authentication
    [Parameter(Mandatory = $false)][string]$Services = "all" # comma separated list of services to assess

)

$allSupportedServices = [string[]]@("aks", "apim", "sql", "aca") # Add more supported services here

# Check if the Azure CLI is installed
if (-not(Get-Command az)) {
    Write-Host "Azure CLI is not installed. Please install it from https://docs.microsoft.com/en-us/cli/azure/install-azure-cli" -ForegroundColor Red
    exit
}

# Check if parameters are provided
if ($AuthType -eq "sp" -and ($ClientId.Trim() -eq '' -or $ClientSecret.Trim() -eq '' -or $TenantId.Trim() -eq '')) {
    Write-Host "ClientId, ClientSecret and TenantId are required when using Service Principal authentication" -ForegroundColor Red
    exit
}

# Authenticate using Service Principal
if ($AuthType -eq "sp") {
    az login --service-principal -u $ClientId -p $ClientSecret --tenant $TenantId
}
elseif ($AuthType -eq "user") {
    if ($TenantId.Trim() -ne '') {
        az login --tenant $TenantId
    }
    else {
        az login
    }
}
elseif ($AuthType -eq "none") {
    Write-Host "Re-using existing Azure CLI session" 
}
else {
    Write-Host "Invalid authentication type. Please use 'user', 'sp' or 'none'" -ForegroundColor Red
    exit
}

$today = [DateTime]::Now.ToString("yyyy-MM-dd_HH-mm-ss")

if ($OutPath.Trim() -eq '' -or -not(Test-Path -Path $OutPath)) {
    $OutPath = "$PSScriptRoot\out\Assessment_$today\"
}


Write-Host "Output Path: $OutPath" -ForegroundColor Blue

Start-Transcript -Path "$OutPath\log_$today.txt"

$servicesList = $allSupportedServices
if ($Services.Trim() -eq '' -or $Services.Trim() -eq 'all') {
    Write-Host "No services provided. Defaulting to all supported services" -ForegroundColor Yellow
}
else {
    $servicesList = $Services.Split(',') | ForEach-Object { $_.Trim() }
}


foreach ($svc in $servicesList) {
    if ($allSupportedServices -contains $svc.ToLower()) {
        $svcUpper = $svc.ToUpper()
        . "./$svcUpper/Start${svcUpper}Assessment.ps1"
    }
    else {
        Write-Host "Unsupported service: $svc" -ForegroundColor Red
    }

}


Stop-Transcript