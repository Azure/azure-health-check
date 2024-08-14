using module ../ResourceCheck.psm1
using module ../CheckResults.psm1

class SQLDBCheck: ResourceCheck {
    
    [object]$DBObject
    [object]$ServerObject

    SQLDBCheck([string] $subscriptionId, [string] $subscriptionName, [object] $db, [object]$server): base($subscriptionId, $subscriptionName) {
        $this.DBObject = $db
        $this.ServerObject = $server
    }

    [string] getServerName() {
        return $this.ServerObject.name
    }

    [string] getDBName() {
        return $this.DBObject.name
    }

    [string] getDBResourceGroup() {
        return $this.DBObject.resourceGroup
    }

    [string] getDBLocation() {
        return $this.DBObject.location
    }

    # Checks if Auditing on server level is enabled
    [bool] hasAuditingDBEnabled() {
        $DBAuditing = az sql db audit-policy show --name $this.getDBName() --resource-group $this.getDBResourceGroup() --server $this.getServerName() --query 'state' -o json | ConvertFrom-Json 
        return $DBAuditing -eq "Enabled"
    }

    # Checks if autoPauseDelay is enabled
    [bool] hasAutopauseDelayEnabled() {
        if ($this.DBObject.sku.tier -eq 'GeneralPurpose' -and $this.DBObject.sku.family -eq 'Gen5') {
            return $this.DBObject.autoPauseDelay -ne $null
        }
        else {
            return $false
        }
    }

    # Checks if Back Ups are enabled
    [bool] hasBackUpsEnabled() {
        $DBbackupJson = az sql db ltr-backup list --location $this.getDBLocation() --resource-group $this.getDBResourceGroup() --server $this.getServerName() | ConvertFrom-Json
        return $DBbackupJson.count -gt 0
    }

    # Checks if SQL TDE is enabled
    [bool] hasTDEenabled() {
        $DBTDE = az sql db tde show --database $this.getDBName() --server $this.getServerName() --resource-group $this.getDBResourceGroup() --query 'state'  -o json | ConvertFrom-Json
        return $DBTDE -eq "Enabled"
    }

    #Checks if there are replica's configured
    [bool] hasReplicasConfigured() {
        $DBReplica = az sql db replica list-links --name $this.getDBName() --server $this.getServerName() --resource-group $this.getDBResourceGroup() -o json | ConvertFrom-Json
        return $DBReplica.count -gt 0
    }


    # Checks if the database size exceeds 90% of the limit
    [bool] isDatabaseSizeWithinLimit() {
        $databaseSizeInBytes = az sql db show --name $this.getDBName() --server $this.getServerName() --resource-group $this.getDBResourceGroup() --query 'properties.currentServiceObjectiveName' --output tsv
        $maxSizeInBytes = az sql db show --name $this.getDBName() --server $this.getServerName() --resource-group $this.getDBResourceGroup() --query 'properties.maxSizeBytes' --output tsv

        if ($databaseSizeInBytes -eq $null -or $maxSizeInBytes -eq $null) {
            return $false
        }

        $databaseSizeInMB = [math]::Round($databaseSizeInBytes / 1MB, 2)
        $maxSizeInMB = [math]::Round($maxSizeInBytes / 1MB, 2)
        $threshold = $maxSizeInMB * 0.9

        return $databaseSizeInMB -le $threshold
    }


    [string] toString() {
        return ""
    }

    [CheckResults] assess() {
        $rules = Get-Content SQL/sqlDBRules.json | ConvertFrom-Json

        $this.Results.Add("Name", $this.getDBName())
        $this.Results.Add("Server", $this.getServerName())
        $this.Results.Add("Resource_Group", $this.getDBResourceGroup())
        $this.Results.Add("Name", $this.getDBLocation())

        foreach ($ruleTuple in $rules.PSObject.Properties) {
            $this.Results.Add($ruleTuple.Name, $this.checkRule($ruleTuple.Name, $ruleTuple.Value))
        }

        return $this.Results
    }

}