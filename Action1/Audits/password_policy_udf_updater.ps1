# Parse local password policy
$localPasswordPolicyRawOutput = net accounts | Where-Object { $_ -match ":" }

$localPasswordPolicy = @{}
foreach ($line in $localPasswordPolicyRawOutput) {
    # Split by the colon and trim whitespace
    $name, $value = $line -split ':', 2
    $localPasswordPolicy[$name.Trim()] = $value.Trim()
}

$localCheckResult = if ($localPasswordPolicy["Minimum password length"] -ge 8) { "Pass" } else { "Fail" }

# Check if Domain Joined before running Domain Audit
$sysInfo = Get-CimInstance Win32_ComputerSystem

if ($sysInfo.PartOfDomain) {
    # Parse domain password policy
    $domainPasswordPolicyRawOutput = net accounts /domain | Where-Object { $_ -match ":" }

    $domainPasswordPolicy = @{}
    foreach ($line in $domainPasswordPolicyRawOutput) {
        # Split by the colon and trim whitespace
        $name, $value = $line -split ':', 2
        $domainPasswordPolicy[$name.Trim()] = $value.Trim()
    }

    $domainCheckResult = if ($domainPasswordPolicy["Minimum password length"] -ge 8) { "Pass" } else { "Fail" }

    $overallCheckResult = if($localCheckResult -eq "Pass" -and $domainCheckResult -eq "Pass") { "Pass" } else { "Fail" }

    # Apply findings to Action1 UDF
    Action1-Set-CustomAttribute "Password Policy" "$overallCheckResult";
} else {
    $domainCheckResult = "Info"

    # Apply findings to Action1 UDF
    Action1-Set-CustomAttribute "Password Policy" "Info: Azure";
}
