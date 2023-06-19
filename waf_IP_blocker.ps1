# Set the required parameters
$rg_name = "rg-waf-demo"
$policyName = "waf-demo-001"
$csvPath = "./IPAddresses.csv"
$ruleName = "newage"
$rulePriority = 51 # set the priority

# This block of code is created to inform the user about certain limitations.
Write-Host "╔════════════════════════════════════════════════════════════╗"
Write-Host "║                    Limitations Notice                      ║"
Write-Host "╟────────────────────────────────────────────────────────────╢"
Write-Host "║ The maximum number of WAF custom rules is 100.             ║"
Write-Host "║ The maximum IP addresses in a WAF custom rule is 600.      ║"
Write-Host "║ For more information about limitations, please visit:      ║"
Write-Host "║ https://learn.microsoft.com/.../custom-waf-rules-overview  ║"
Write-Host "╚════════════════════════════════════════════════════════════╝"

$confirmed = $false
while (-not $confirmed) {
    $confirm = Read-Host -Prompt "Please read the limitation above and acknoledge you are. (Y/N)"
    if ($confirm -eq "Y") {
        $confirmed = $true
    }
    elseif ($confirm -eq "N") {
        Write-Host "To proceed please read and acknowlege, Thank You!"
        Exit
    }
    else {
        Write-Host "Invalid input. Please enter 'Y' or 'N'."
    }
}

# Check if rule priority is already assigned
$existingRules = Get-AzApplicationGatewayFirewallPolicy -Name $policyName -ResourceGroupName $rg_name |
Select-Object -ExpandProperty CustomRules
if ($existingRules -ne $null) {
    $existingPriority = $existingRules | Where-Object { $_.Priority -eq $rulePriority }
    if ($existingPriority -ne $null) {
        Write-Host "Error: Rule priority $rulePriority is already assigned in the firewall policy." -ForegroundColor Red
        Exit
    }
}

# Read the list of IP addresses from the CSV file
$ipAddresses = Import-Csv -Path $csvPath | Select-Object -ExpandProperty IPAddress

# Check if the number of IP addresses exceeds the limit
if ($ipAddresses.Count -gt 600) {
    Write-Host "Warning: The number of IP addresses in the custom rule exceeds the limit of 600." -ForegroundColor Yellow
    $confirm = Read-Host -Prompt "Do you want to proceed? (Y/N)"
    if ($confirm -ne "Y") {
        Write-Host "Operation cancelled by user." -ForegroundColor Green
        Exit
    }
}

Write-Host "The following IP addresses will be blocked:`n$($ipAddresses -join ', ')" -ForegroundColor Yellow

# Warn the USER & Get user confirmation
$confirm = Read-Host -Prompt "Do you want to proceed? (Y/N)"

if ($confirm -ne "Y") {
    Write-Host "Operation cancelled by user." -ForegroundColor Green
    Exit
}

# Create the firewall rule
$variable = New-AzApplicationGatewayFirewallMatchVariable -VariableName RemoteAddr

$condition = New-AzApplicationGatewayFirewallCondition `
    -MatchVariable $variable `
    -Operator IPMatch `
    -MatchValue ($ipAddresses) `
    -NegationCondition $False

$rule = New-AzApplicationGatewayFirewallCustomRule `
    -Name $ruleName `
    -Priority $rulePriority `
    -RuleType MatchRule `
    -MatchCondition $condition `
    -Action Block `
    -State Enabled

# Add the rule to the firewall policy
$policy = Get-AzApplicationGatewayFirewallPolicy -Name $policyName -ResourceGroupName $rg_name
$policy.CustomRules.Add($rule)

Write-Host "Adding the following custom rule to the firewall policy:`n$($rule | Format-List | Out-String)" -ForegroundColor Yellow

Set-AzApplicationGatewayFirewallPolicy -InputObject $policy

Write-Host "Custom rule added successfully." -ForegroundColor Green
