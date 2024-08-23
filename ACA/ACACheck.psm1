using module ../ResourceCheck.psm1
using module ../CheckResults.psm1


class ACACheck: ResourceCheck {
    
    [object]$acaObject
    [string]$acaEnvName


    ACACheck([string] $subscriptionId, [string] $subscriptionName, [string] $acaEnvName, [object] $acaObject): base($subscriptionId, $subscriptionName) {
        $this.acaObject = $acaObject
        $this.acaEnvName = $acaEnvName
    }

    [string] getName() {
        return $this.acaObject.name
    }

    [string] getEnvironmentName() {
        return $this.acaEnvName
    }

    [string] getLocation() {
        return $this.acaObject.location
    }

    [string] getResourceGroup() {
        return $this.acaObject.resourceGroup
    }

    [bool] isSessionAffinityEnabled() {
        return $this.acaObject.properties.configuration.ingress.stickySessions?.affinity -eq "sticky" 
    }

    [bool] isExternalIngressEnabled() {
        return $this.acaObject.properties.configuration.ingress.external
    }

    [bool] isInsecureIngressAllowed() {
        return $this.acaObject.properties.configuration.ingress.allowInsecure
    }

    [bool] isManagedIdentityEnabled() {
        return $this.acaObject.identity.type -ne "None"
    }

    [bool] hasIPSecurityRestrictions() {
        if (-not $this.isExternalIngressEnabled()) {
            return $true
        }
        return ($this.acaObject.properties.configuration.ingress.ipSecurityRestrictions -ne $null)
    }


    [CheckResults] assess() {
        $rules = Get-Content ACA/acaRules.json | ConvertFrom-Json

        $this.Results.Add("Name", $this.getName())
        $this.Results.Add("Location", $this.getLocation())
        $this.Results.Add("Resource_Group", $this.getResourceGroup())
        $this.Results.Add("Environment", $this.getEnvironmentName())

        foreach ($ruleTuple in $rules.PSObject.Properties) {
            $this.Results.Add($ruleTuple.Name, $this.checkRule($ruleTuple.Name, $ruleTuple.Value))
        }

        return $this.Results
    }

}
