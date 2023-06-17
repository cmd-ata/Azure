# Set the required parameters
$rg_name = "ENTER_RG_NAME"
$policyName = "ENTER_WAF_POLICY_NAME"
$csvPath = "./IPAddresses.csv"
$ruleName = "ENTER_RULE_NAME"
$rulePriority = 100 # set the priority


# Read the list of IP addresses from the CSV file
$ipAddresses = Import-Csv -Path $csvPath | Select-Object -ExpandProperty IPAddress
Write-Host "The following IP addresses will be blocked:`n$($ipAddresses -join ', ')" -ForegroundColor Yellow

# Warn the USER & Get user confirmation
$confirm = Read-Host -Prompt "Do you want to proceed? (Y/N)" #-ForegroundColor Red

if ($confirm -ne "Y") {
    Write-Host "Operation cancelled by user." -ForegroundColor Green
    Exit
}

# Create the firewall rule
$variable = New-AzApplicationGatewayFirewallMatchVariable `
    -VariableName RemoteAddr

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