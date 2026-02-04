# Cyber Essentials Basic Audit Script

# Globals:
$result = "Pass"
$currentUser = whoami
$defaultOutputOption = "Default" # Default output option only displays failed audits

# Check Autoplay is Disabled
#-----------------------------------------------------
function Get-AutoplayStatus {
    param (
        [String]$output # Options: "DEFAULT", "SILENT", "VERBOSE"
    )

    $autoplayResults = @()
    $result = "Pass"

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

    $autoplayResults += [PSCustomObject]@{ Audit = "Autoplay User Configuration"; Status = $userAutoplayOutput }
    $autoplayResults += [PSCustomObject]@{ Audit = "Autoplay Machine Configuration"; Status = $machineAutoplayOutput }

    if ($output.ToUpper() -eq "DEFAULT" -and $result -eq "Fail") {
        Write-Host "`nAutoplay Configuration:"
        $autoplayResults | Format-Table -AutoSize
    } elseif ($output.ToUpper() -eq "VERBOSE") {
        Write-Host "`nAutoplay Configuration:"
        $autoplayResults | Format-Table -AutoSize
    }

    return $result
}


# Check Firewall is Enabled
#-----------------------------------------------------
function Get-FirewallStatus {
    param (
        [String]$output # Options: "DEFAULT", "SILENT", "VERBOSE"
    )

    $firewallResults = @()
    $result = "Pass"

    # Get list of firewall profiles
    $firewallProfiles = Get-NetFirewallProfile

    # Loop through each profile and check if enabled
    for ($i = 0; $i -lt $firewallProfiles.Count; $i++) {
        $firewallResults += [PSCustomObject]@{ Audit = "Firewall Profile: $($firewallProfiles[$i].Name)"; Status = $firewallProfiles[$i].Enabled }

        if ($firewallProfiles[$i].Enabled -eq $false) {
            $result = "Fail"
        }
    }

    if ($output.ToUpper() -eq "DEFAULT" -and $result -eq "Fail") {
        Write-Host "`nFirewall Configuration:"
        $firewallResults | Format-Table -AutoSize
    } elseif ($output.ToUpper() -eq "VERBOSE") {
        Write-Host "`nFirewall Configuration:"
        $firewallResults | Format-Table -AutoSize
    }

    return $result
}

 
# Check Password Policy (Min 8 characters required)
#-----------------------------------------------------
function Get-PasswordPolicy {
    param (
        [String]$output # Options: "DEFAULT", "SILENT", "VERBOSE"
    )
    
    $passwordResults = @()
    $result = "Pass"

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

    $passwordResults += [PSCustomObject]@{ Audit = "Local Password Policy Minimum Password Length"; Status = $localPasswordPolicy["Minimum password length"] }
    $passwordResults += [PSCustomObject]@{ Audit = "Domain Password Policy Minimum Password Length"; Status = $domainPasswordPolicy["Minimum password length"] }

    # Failure check
    if ($localPasswordPolicy["Minimum password length"] -lt 8 -or $domainPasswordPolicy["Minimum password length"] -lt 8) {
        $result = "Fail"
    }

    if ($output.ToUpper() -eq "DEFAULT" -and $result -eq "Fail") {
        Write-Host "`nPassword Policy Configuration:"
        $passwordResults | Format-Table -AutoSize
    } elseif ($output.ToUpper() -eq "VERBOSE") {
        Write-Host "`nPassword Policy Configuration:"
        $passwordResults | Format-Table -AutoSize
    }

    return $result
}

 
# Check for Local Administrator Accounts
#-----------------------------------------------------
function Get-LocalAdminAccounts {
    param (
        [String]$output # Options: "DEFAULT", "SILENT", "VERBOSE"
    )

    $adminResults = @()
    $result = "Pass"

    $localAdmins = Get-LocalGroupMember -Group "Administrators" | Select-Object Name
    $localAdminsOutput = $localAdmins.Name -join ", "

    $adminResults += [PSCustomObject]@{ Audit = "Local Administrators"; Status = $localAdminsOutput }

    if ($localAdminsOutput.ToUpper() -Contains $currentUser.ToUpper()) {
        $result = "Fail"
    }

    if ($output.ToUpper() -eq "DEFAULT" -and $result -eq "Fail") {
        Write-Host "`nLocal Administrator Accounts:"
        $adminResults | Format-Table -AutoSize
    } elseif ($output.ToUpper() -eq "VERBOSE") {
        Write-Host "`nLocal Administrator Accounts:"
        $adminResults | Format-Table -AutoSize
    }

    return $result
}
 
# Check for Antivirus
#-----------------------------------------------------
function Get-AntivirusStatus {
    param (
        [String]$output # Options: "DEFAULT", "SILENT", "VERBOSE"
    )
    
    $antivirusResults = @()
    $result = "Pass"

    $antivirusOutput = Get-MpComputerStatus
    $antivirusResults += [PSCustomObject]@{ Audit = 'Windows Defender Enabled'; Status = $antivirusOutput.AMServiceEnabled }
    $antivirusResults += [PSCustomObject]@{ Audit = 'Windows Defender Up to Date'; Status = ($antivirusOutput.AntispywareSignatureAge -lt 2) }

    if (-not $antivirusOutput.AMServiceEnabled -or $antivirusOutput.AntispywareSignatureAge -ge 2) {
        $result = "Fail"
    }

    if ($output.ToUpper() -eq "DEFAULT" -and $result -eq "Fail") {
        Write-Host "`nAntivirus Status:"
        $antivirusResults | Format-Table -AutoSize
    } elseif ($output.ToUpper() -eq "VERBOSE") {
        Write-Host "`nAntivirus Status:"
        $antivirusResults | Format-Table -AutoSize
    }

    return $result
}

 
# Output Results
#-----------------------------------------------------
Write-Host "--- Cyber Essentials Audit Results ---"
$result = Get-AutoplayStatus -output $defaultOutputOption
$result = Get-FirewallStatus -output $defaultOutputOption
$result = Get-PasswordPolicy -output $defaultOutputOption
$result = Get-LocalAdminAccounts -output $defaultOutputOption
$result = Get-AntivirusStatus -output $defaultOutputOption
Write-Host "`nAudit Result: $result"