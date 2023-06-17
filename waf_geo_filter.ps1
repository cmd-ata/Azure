# Define variables
$rg_name = "ENTER_RG_NAME"
$policyName = "ENTER_WAF_POLICY_NAME"
$ruleName = "ENTER_RULE_NAME"
$rulePriority = <rule-priority>

# Define list of allowed locations
$allowedLocations = @(
    "FI"
    "AX"
    "SE"
    "NO"
    "DK"
    "EE"
    "IE"
    "NL"
)

# Enable geo-filtering and allow specific locations
$geoMatchCondition = New-AzApplicationGatewayFirewallCustomRuleMatchVariable -VariableName "ClientGeoMatch"
$geoMatchValues = New-AzApplicationGatewayFirewallMatchVariable -VariableName "RequestHeaders[\"X-Azure-FDID\"]" -Operator "GeoMatch" -Values $allowedLocations
$geoMatchCondition.MatchVariables = $geoMatchValues

$geoFilterRule = New-AzApplicationGatewayFirewallCustomRule -Name $ruleName -Priority $rulePriority -MatchCondition $geoMatchCondition

$wafPolicy = Get-AzApplicationGatewayWebApplicationFirewallPolicy -ResourceGroupName $rg_name -Name $policyName
$wafPolicy.CustomRules.Rules.Add($geoFilterRule)

# Confirm and apply the changes
Write-Host "The following changes will be made:"
Write-Host "  - Add a custom rule for geo-filtering in the Azure WAF policy"
Write-Host "  - Allow traffic only from specific locations"
Write-Host ""
Write-Host "Resource Group: $rg_name"
Write-Host "WAF Policy Name: $policyName"
Write-Host "Rule Name: $ruleName"
Write-Host "Rule Priority: $rulePriority"
Write-Host "Allowed Locations: $($allowedLocations -join ', ')"
Write-Host ""

$confirm = Read-Host "Do you want to proceed with these changes? (Y/N)"

if ($confirm -eq "Y" -or $confirm -eq "y") {
    Set-AzApplicationGatewayWebApplicationFirewallPolicy -ResourceGroupName $rg_name -Name $policyName -Policy $wafPolicy
    Write-Host "Geo-filtering configuration applied successfully."
}
else {
    Write-Host "Operation cancelled."
}
