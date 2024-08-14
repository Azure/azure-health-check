using module ./CheckResults.psm1

[string] $global:Pass = "PASS"
[string] $global:Fail = "FAIL"
[string] $global:Err = "ERROR"



class ResourceCheck {
    [string]$SubscriptionId
    [string]$SubscriptionName
    [CheckResults]$Results

    ResourceCheck([string]$subscriptionId, [string]$subscriptionName) {
        $this.SubscriptionId = $subscriptionId
        $this.SubscriptionName = $subscriptionName
        $this.Results = [CheckResults]::new($subscriptionId, $subscriptionName)
    }


    <#
    .SYNOPSIS
    Checks a rule with a given name.

    .DESCRIPTION
    This function checks a rule by invoking a specified function and comparing the returned value with the expected value. 
    If the returned value matches the expected value, the function returns "Pass". 
    If the returned value does not match the expected value, the function returns "Fail" along with an explanation. 
    If an error occurs during the process, the function returns "Err" along with the error message.

    .PARAMETER name
    The name of the rule being checked.

    .PARAMETER rule
    The rule object containing the function to invoke and the expected value to compare against.

    .EXAMPLE
    checkRule -name "Rule 1" -rule @{
        function = "CheckFunction"
        expected = "ExpectedValue"
        explanation = "This is the explanation for Rule 1"
    }

    This example checks "Rule 1" by invoking the "CheckFunction" and comparing the returned value with "ExpectedValue". 
    If the returned value matches the expected value, it prints "✅ Rule 1: Pass" in green. 
    If the returned value does not match the expected value, it prints "⚠️ Rule 1: Fail. This is the explanation for Rule 1" in yellow. 
    If an error occurs during the process, it prints "⛔ Rule 1: Err. An error occurred: <error message>" in red.

    #>
    [string] checkRule ($name, $rule) {
        try {
            $functionName = $rule.function
            $returnedValue = $this.PSObject.Methods[$functionName].Invoke()
            $isExpected = $returnedValue -eq $rule.expected
            
            if ($isExpected) {
                Write-Host "✅ $($name): $global:Pass" -ForegroundColor Green
                return $global:Pass
            }
            else {
                Write-Host "⚠️  $($name): $global:Fail. $($rule.explanation)" -ForegroundColor Yellow
                return $global:Fail
            }
        }
        catch {
            Write-Host "⛔ $($name): $($global:Err). An error occurred: $($_)" -ForegroundColor Red
            return $global:Err
        }
    }
}