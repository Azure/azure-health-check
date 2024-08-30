using module ../ResourceCheck.psm1
using module ../CheckResults.psm1


class APIMCheck: ResourceCheck {
    
    [object]$apimObject


    APIMCheck([string] $subscriptionId, [string] $subscriptionName, [object] $apimObject): base($subscriptionId, $subscriptionName) {
        $this.apimObject = $apimObject
    }

    [string] getName() {
        return $this.apimObject.name
    }

    [string] getLocation() {
        return $this.apimObject.name
    }

    [string] getResourceGroup() {
        return $this.apimObject.resourceGroup
    }

    [string] getskuTier() {
        return $this.apimObject.sku.name 
    }

    [string] getAPIID() {
        $apiID = az apim api list --resource-group $this.getResourceGroup() --service-name $this.getName() --query "[].{API_id:id, API_name:displayName}"
        return $apiID.API_name 
    }

    [string] getAPIURI() {
        $apiID = az apim api list --resource-group $this.getResourceGroup() --service-name $this.getName() --query "[].{API_id:id, API_name:displayName}"
        return $apiID.API_id
    }

    [bool] isStv2() {
        return $this.apimObject.platformVersion -eq "stv2"
    }

    [bool] hasAvailabilityZones() {
        return $this.apimObject.sku.name -eq "Premium" -and $this.apimObject.sku.capacity -gt 1
    }

    [bool] hasPrivateEndpointConnections() {
        return $this.apimObject.privateEndpointConnections -ne $null -and $this.apimObject.privateEndpointConnections.Count -gt 0
    }

    [bool] hasPublicNetworkAccessDisabled() {
        return $this.apimObject.publicNetworkAccess -eq "Disabled"
    }

    [bool] hasCorrectBackendProtocols() {
        return $this.apimObject.customProperties.Microsoft.WindowsAzure.ApiManagement.Gateway.Security.Backend.Protocols.Ssl30 -eq "False" 
        and $this.apimObject.customProperties.Microsoft.WindowsAzure.ApiManagement.Gateway.Security.Backend.Protocols.Tls10 -eq "False" 
        and $this.apimObject.customProperties.Microsoft.WindowsAzure.ApiManagement.Gateway.Security.Backend.Protocols.Tls11 -eq "False" 
    }

    [bool] hasClientCertificateEnabled() {
        return $this.apimObject.enableClientCertificate -ne $null
    }

    [bool] hasMinimumApiVersion() {
        return $this.apimObject.apiVersionConstraint.minApiVersion -ne $null
    }

    [bool] hasEncryptedValues() {
        $APIMnv = az apim nv list -g $this.getResourceGroup() -n $this.getName() -o json | ConvertFrom-Json
        if ($APIMnv.keyvault -ne $null -and $APIMnv.secret -eq "true") {
            return $true
        }
        return $false
    }

    [bool] hasAdditionalLocations() {
        return $this.apimObject.additionalLocations -ne $null
    }

    [bool] hasMultiRegionGateway() {
        $Gatewaybools = az apim list --query "[].additionalLocations[].disableGateway" -o json | ConvertFrom-Json
        foreach ($gateway in $Gatewaybools) {
            if (-not $gateway) {
                return $true
            }
        }
        return $false
    }

    [bool] hasInsecureCiphers() {

        $weakCiphers = @(
            "TripleDes168",
            "TLS_RSA_WITH_AES_128_CBC_SHA",
            "TLS_RSA_WITH_AES_256_CBC_SHA",
            "TLS_RSA_WITH_AES_128_CBC_SHA256",
            "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
            "TLS_RSA_WITH_AES_256_CBC_SHA256",
            "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
            "TLS_RSA_WITH_AES_128_GCM_SHA256"
        )
        $propertyPrefix = "Microsoft.WindowsAzure.ApiManagement.Gateway.Security.Ciphers."
        $cipherProperties = $this.apimObject.customProperties
        foreach ($cipher in $weakCiphers) {
            
            if (-not ($cipherProperties.ContainsKey($propertyPrefix + $cipher)) -or $cipherProperties[$propertyPrefix + $cipher] -eq $true) {
                return $true
            }
        }
        return $false
    }

    [bool] hasBasedPolicies() {
        $suffix = "/policies?api-version=2023-09-01-preview"
        $apimAPIs = az apim api list --resource-group $this.getResourceGroup() --service-name $this.getName() --query "id" 
        foreach ($api in $apimAPIs) {
            $policyContent = az rest --method get --uri $api.id + $suffix
            $baseCount = [regex]::Matches($policyContent, "<base/>").Count
            if ($baseCount -lt 5) {
                Write-Host "$api fails"
                return $false
            }
        }
        return $true
    }

    [bool] hasAPIDescriptors() {
        $apimAPis = az apim api list --resource-group $this.getResourceGroup() --service-name $this.getName() -o json | ConvertFrom-Json
        foreach ($api in $apimAPIs) {
            if (-not $api.description -or $api.description -eq ""){
                return $false
            }
        }
        return $true
    }

    [bool] hasProductApprovalRequired() {
        $apimProducts = az apim product list -g $this.getResourceGroup() -n $this.getName() -o json | ConvertFrom-Json
        foreach ($product in $apimProducts) {
            if (-not $product.approvalRequired){
                return $false
            }
        }
        return $true
    }

    [bool] hasProductSubscriptionRequired() {
        $apimProducts = az apim product list -g $this.getResourceGroup() -n $this.getName() -o json | ConvertFrom-Json
        foreach ($product in $apimProducts) {
            if (-not $product.subscriptionRequired){
                return $false
            }
        }
        return $true
    }

    [bool] hasProductTermsRequired(){
        $apimProducts = az apim product list -g $this.getResourceGroup() -n $this.getName() -o json | ConvertFrom-Json
        foreach ( $product in $apimProducts){
            if (-not $product.terms -or $product.terms -eq ""){
                return $false
            }
        }
        return $true
    }

    [bool] hasProductDescriptors() {
        $apimProducts = az apim product list -g $this.getResourceGroup() -n $this.getName() -o json | ConvertFrom-Json
        foreach ($product in $apimProducts) {
            if (-not $product.description -or $product.description -eq ""){
                return $false
            }
        }
        return $true
    }

    [bool] hasSampleProducts() {
        $apimProducts = az apim product list -g $this.getResourceGroup() -n $this.getName() -o json | ConvertFrom-Json
        foreach ($product in $apimProducts) {
            if ($product.name -eq "starter" -or $product.name -eq "unlimited"){
                return $false
            }
        }
        return $true
    }

    [bool] hasIdentityEnabled() {
        if ($this.identity.type -eq "SystemAssigned" -or $this.identity.type -eq "UserAssigned" -or $this.identity.type -eq "SystemAssigned, UserAssigned"){
            return $true
        }
        return $false
    }


    [bool] isDefenderEnabled() {
        $apimDefender = az security api-collection apim list --resource-group $this.getResourceGroup() --service-name $this.getName() -o json | ConvertFrom-Json
        return $apimDefender.Length -gt 0
    }

    [CheckResults] assess() {
        $rules = Get-Content APIM/apimRules.json | ConvertFrom-Json

        $this.Results.Add("Name", $this.getName())
        $this.Results.Add("Location", $this.getLocation())
        $this.Results.Add("Resource_Group", $this.getResourceGroup())
        $this.Results.Add("SKU", $this.getskuTier())

        foreach ($ruleTuple in $rules.PSObject.Properties) {
            $this.Results.Add($ruleTuple.Name, $this.checkRule($ruleTuple.Name, $ruleTuple.Value))
        }

        return $this.Results
    }

}
