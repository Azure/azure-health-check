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

    [bool] isStv2() {
        return $this.apimObject.platformVersion -eq "stv2"
    }


    [CheckResults] assess() {
        $rules = Get-Content APIM/apimRules.json | ConvertFrom-Json

        $this.Results.Add("Name", $this.getName())
        $this.Results.Add("Location", $this.getLocation())
        $this.Results.Add("Resource_Group", $this.getResourceGroup())

        foreach ($ruleTuple in $rules.PSObject.Properties) {
            $this.Results.Add($ruleTuple.Name, $this.checkRule($ruleTuple.Name, $ruleTuple.Value))
        }

        return $this.Results
    }

}
