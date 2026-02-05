## Check for ESET Firewall
$esetProducts = Get-CimInstance -Namespace "root\SecurityCenter2" -ClassName "FirewallProduct" | Where-Object { $_.displayName -like "*ESET*" }
$esetEnabled = $false

if ($esetProducts) {
    # Check if any ESET entries are active
    foreach ($product in $esetProducts) {
        $stateHex = "0x{0:x}" -f $product.productState

        # In WMI SecurityCenter2, the 3rd byte '10' or '11' indicates 'Enabled'
        if ($stateHex -like "*10??" -or $stateHex -like "*11??") {
            $esetEnabled = $true
            break
        }
    }
}

if ($esetEnabled) {
    # Apply findings to Action1 UDF
    $overallCheckResult = "Pass"
    Action1-Set-CustomAttribute "Firewall" $overallCheckResult;

    return # If ESET Firewall is active skip Defender check
} else {
    # Get list of firewall profiles
    $firewallProfiles = Get-NetFirewallProfile

    # Overall check result
    $overallCheckResult = "Pass"

    # Loop through each profile and check if enabled
    for ($i = 0; $i -lt $firewallProfiles.Count; $i++) {
        $checkResult = if ($firewallProfiles[$i].Enabled) { "Pass" } else { "Fail" }

        if ($checkResult -eq "Fail") {
            $overallCheckResult = "Fail"
        }
    }

    # Apply findings to Action1 UDF
    Action1-Set-CustomAttribute "Firewall" $overallCheckResult;
}
