using module ../ResourceCheck.psm1
using module ../CheckResults.psm1


class ACAEnvCheck: ResourceCheck {
    
    [object]$acaEnvObject


    ACAEnvCheck([string] $subscriptionId, [string] $subscriptionName, [object] $acaEnvObject): base($subscriptionId, $subscriptionName) {
        $this.acaEnvObject = $acaEnvObject
    }

    [string] getName() {
        return $this.acaEnvObject.name
    }

    [string] getLocation() {
        return $this.acaEnvObject.name
    }

    [string] getResourceGroup() {
        return $this.acaEnvObject.resourceGroup
    }

    [bool] hasAvailabilityZones() {
        return $this.acaEnvObject.properties.zoneRedundant
    }

    [bool] isPublicAccessEnabled() {
        return -not $this.acaEnvObject.properties.vnetConfiguration.internal 
    }


    [CheckResults] assess() {
        $rules = Get-Content ACA/acaEnvRules.json | ConvertFrom-Json

        $this.Results.Add("Name", $this.getName())
        $this.Results.Add("Location", $this.getLocation())
        $this.Results.Add("Resource_Group", $this.getResourceGroup())

        foreach ($ruleTuple in $rules.PSObject.Properties) {
            $this.Results.Add($ruleTuple.Name, $this.checkRule($ruleTuple.Name, $ruleTuple.Value))
        }

        return $this.Results
    }

}
