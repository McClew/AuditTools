# Cyber Essentials Basic Audit Script

# Globals:
$result = "Pass"
$defaultOutputOption = "Default"
# Default output option only displays failed audits
# Case insensitive
# Options: "Default", "Silent", "Verbose"

# Output Header
function Write-Header {
    Write-Host "--- Cyber Essentials Audit Results ---" -ForegroundColor Blue
}

# Check Autoplay is Disabled
function Get-AutoplayStatus {
    param (
        [String]$output # Options: "DEFAULT", "SILENT", "VERBOSE"
    )

    $autoplayResults = @()

    # Check user configuration
    $userAutoplayStatus = Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers" -Name "DisableAutoplay" -ErrorAction SilentlyContinue
    # value of 1 means autoplay is disabled
    # value of 0 or missing means autoplay is enabled

    # Check machine configuration - overrides user settings
    $machineAutoplayStatus = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -ErrorAction SilentlyContinue
    # value of 255 or 0xFF means autoplay is disabled for all drives
    # other values (145 or 0x91) mean autoplay is enabled for some drive types

    if ($userAutoplayStatus.DisableAutoplay -eq 0) {
        $userAutoplayOutput = "Disabled"
    } else {
        $userAutoplayOutput = "Enabled"
        $result = "Fail"
    }

    if ($machineAutoplayStatus.NoDriveTypeAutoRun -eq 255) {
        $machineAutoplayOutput = "Disabled"
    } else {
        $machineAutoplayOutput = "Enabled (for some drive types)"
        $result = "Fail"
    }

    $autoplayResults += [PSCustomObject]@{ Audit = "User Configuration"; Status = $userAutoplayOutput }
    $autoplayResults += [PSCustomObject]@{ Audit = "Machine Configuration"; Status = $machineAutoplayOutput }

    Get-CheckResults -output $output -checkName "Autoplay Audit" -result $result -resultsTable $autoplayResults

    return $result
}


# Check Firewall is Enabled
function Get-FirewallStatus {
    param (
        [String]$output # Options: "DEFAULT", "SILENT", "VERBOSE"
    )

    $firewallResults = @()

    # Get list of firewall profiles
    $firewallProfiles = Get-NetFirewallProfile

    # Loop through each profile and check if enabled
    for ($i = 0; $i -lt $firewallProfiles.Count; $i++) {
        $firewallResults += [PSCustomObject]@{ Audit = "Firewall Profile: $($firewallProfiles[$i].Name)"; Status = $firewallProfiles[$i].Enabled }

        if ($firewallProfiles[$i].Enabled -eq $false) {
            $result = "Fail"
        }
    }

    Get-CheckResults -output $output -checkName "Firewall Status" -result $result -resultsTable $firewallResults

    return $result
}

 
# Check Password Policy (Min 8 characters required)
function Get-PasswordPolicy {
    param (
        [String]$output # Options: "DEFAULT", "SILENT", "VERBOSE"
    )
    
    $passwordResults = @()

    $localPasswordPolicyRawOutput = net accounts | Where-Object { $_ -match ":" }

    $localPasswordPolicy = @{}
    foreach ($line in $localPasswordPolicyRawOutput) {
        # Split by the colon and trim whitespace
        $name, $value = $line -split ':', 2
        $localPasswordPolicy[$name.Trim()] = $value.Trim()
    }

    $domainPasswordPolicyRawOutput = net accounts /domain | Where-Object { $_ -match ":" }

    $domainPasswordPolicy = @{}
    foreach ($line in $domainPasswordPolicyRawOutput) {
        # Split by the colon and trim whitespace
        $name, $value = $line -split ':', 2
        $domainPasswordPolicy[$name.Trim()] = $value.Trim()
    }

    $passwordResults += [PSCustomObject]@{ Audit = "Local Policy Minimum Password Length"; Status = $localPasswordPolicy["Minimum password length"] }
    $passwordResults += [PSCustomObject]@{ Audit = "Domain Policy Minimum Password Length"; Status = $domainPasswordPolicy["Minimum password length"] }

    # Failure check
    if ($localPasswordPolicy["Minimum password length"] -lt 8 -or $domainPasswordPolicy["Minimum password length"] -lt 8) {
        $result = "Fail"
    }

    Get-CheckResults -output $output -checkName "Password Policy Audit" -result $result -resultsTable $passwordResults

    return $result
}

 
# Check for Local Administrator Accounts
function Get-LocalAdminAccounts {
    param (
        [String]$output # Options: "DEFAULT", "SILENT", "VERBOSE"
    )

    $adminResults = @()

    $localAdmins = Get-LocalGroupMember -Group "Administrators" | Select-Object Name

    for ($i = 0; $i -lt $localAdmins.Count; $i++) {
        $adminResults += [PSCustomObject]@{ "Local Administrator Accounts" = $localAdmins[$i].Name }
    }

    # Check if pass failed
    if ($localAdmins.Count -gt 2) {
        $result = "Fail"
    }

    Get-CheckResults -output $output -checkName "Local Administrator Accounts Audit" -result $result -resultsTable $adminResults

    return $result
}
 
# Check for Antivirus
function Get-AntivirusStatus {
    param (
        [String]$output # Options: "DEFAULT", "SILENT", "VERBOSE"
    )
    
    $antivirusResults = @()

    $antivirusOutput = Get-MpComputerStatus
    $antivirusResults += [PSCustomObject]@{ "Windows Defender" = 'Enabled'; Status = $antivirusOutput.AMServiceEnabled }
    $antivirusResults += [PSCustomObject]@{ "Windows Defender" = 'Up to Date'; Status = ($antivirusOutput.AntispywareSignatureAge -lt 2) }

    if (-not $antivirusOutput.AMServiceEnabled -or $antivirusOutput.AntispywareSignatureAge -ge 2) {
        $result = "Fail"
    }

    Get-CheckResults -output $output -checkName "Antivirus Status Audit" -result $result -resultsTable $antivirusResults

    return $result
}

# Print Check Results
function Get-CheckResults {
    param (
        [String]$output, # Options: "DEFAULT", "SILENT", "VERBOSE"
        [string]$checkName,
        [String]$result,
        [PSCustomObject]$resultsTable
    )

    if ($output.ToUpper() -eq "DEFAULT" -and $result -eq "Fail") {
        Write-Host "`n$checkName : " -ForegroundColor Blue -NoNewline;
        Write-Host "$result" -ForegroundColor Red
        Write-Host ($resultsTable | Format-Table -AutoSize | Out-String)
    } elseif ($output.ToUpper() -eq "VERBOSE") {
        Write-Host "`n$checkName : " -ForegroundColor Blue -NoNewline;
        Write-Host "$result" -ForegroundColor (if ($result -eq "Pass") { "Green" } else { "Red" })
        Write-Host ($resultsTable | Format-Table -AutoSize | Out-String)
    }
}

# Print Results
function Get-AuditResult {
    param (
        [String]$result
    )

    Write-Host "`nAudit Result: " -ForegroundColor Blue -NoNewline;
    if ($result -eq "Pass") {
        Write-Host "PASS" -ForegroundColor Green
    } else {
        Write-Host "FAIL" -ForegroundColor Red
    }
}
 
# Execution
Write-Header
$result = Get-AutoplayStatus -output $defaultOutputOption
$result = Get-FirewallStatus -output $defaultOutputOption
$result = Get-PasswordPolicy -output $defaultOutputOption
$result = Get-LocalAdminAccounts -output $defaultOutputOption
$result = Get-AntivirusStatus -output $defaultOutputOption
Get-AuditResult -result $result
