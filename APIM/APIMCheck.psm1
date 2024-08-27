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

    [bool] hasCorrectBackendProtocols(){
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

    [bool] hasAdditionalLocations(){
        return $this.apimObject.additionalLocations -ne $null
    }

    [bool] hasSecureCiphers([array]$expectedCiphers = @("TripleDes168","TLS_RSA_WITH_AES_128_CBC_SHA","TLS_RSA_WITH_AES_256_CBC_SHA","TLS_RSA_WITH_AES_128_CBC_SHA256","TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA","TLS_RSA_WITH_AES_256_CBC_SHA256","TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA","TLS_RSA_WITH_AES_128_GCM_SHA256")) {
        $collectedCiphers = @()
        $cipherProperties = $this.apimObject.customProperties["Microsoft.WindowsAzure.ApiManagement.Gateway.Security.Ciphers"]
        foreach ($cipherName in $cipherProperties.Keys) {
            if ($cipherProperties[$cipherName]) {
                $collectedCiphers += $cipherName
            }
        }
        # Check if all expected ciphers are present in the collected ciphers
        foreach ($expectedCipher in $expectedCiphers) {
            if ($collectedCiphers -notcontains $expectedCipher) {
                return $false
            }
        }
        return $true
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
