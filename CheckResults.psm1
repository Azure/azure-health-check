class CheckResults {
    [hashtable] $Results

    static [string] $Pass = "PASS"
    static [string] $Fail = "FAIL"
    static [string] $Err = "ERROR"

    CheckResults([string]$subscriptionId, [string]$subscriptionName) {
        $this.Results = [Ordered]@{
            SubscriptionId   = $subscriptionId
            SubscriptionName = $subscriptionName
        }
    }

    [void] Add($ruleName, $result) {
        $this.Results[$ruleName] = $result
    }

    [string] Get($ruleName) {
        return $this.Results[$ruleName]
    }

    [hashtable] GetAllResults() {
        return $this.Results
    }

}