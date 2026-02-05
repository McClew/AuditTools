# Cyber Essentials Basic Audit Script
$lastUserCaption, $lastUserName, $lastUserDomain, $lastUserSID = Get-LastUserDetails

# Check Autoplay is Disabled
function Get-AutoplayStatus {
    # Check user configuration
    $userAutoplayStatus = Get-ItemProperty "Registry::HKEY_USERS\$lastUserSID\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers" -Name DisableAutoplay -ErrorAction SilentlyContinue
    # value of 1 means autoplay is disabled
    # value of 0 or missing means autoplay is enabled

    # Check machine configuration - overrides user settings
    $machineAutoplayStatus = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -ErrorAction SilentlyContinue
    # value of 255 or 0xFF means autoplay is disabled for all drives
    # other values (145 or 0x91) mean autoplay is enabled for some drive types

    # Determine outputs
    if ($userAutoplayStatus.DisableAutoplay -eq 0) {
        $userAutoplayOutput = "Disabled"
        $userAutoplayCheckResult = "Pass"
    } else {
        $userAutoplayOutput = "Enabled"
        $userAutoplayCheckResult = "Fail"
    }

    if ($machineAutoplayStatus.NoDriveTypeAutoRun -eq 255) {
        $machineAutoplayOutput = "Disabled"
        $machineAutoplayCheckResult = "Pass"
    } else {
        $machineAutoplayOutput = "Enabled (for some drive types)"
        $machineAutoplayCheckResult = "Fail"
    }

    # Send results
    Send-Action1Data -auditName "Autoplay Audit" -checkName "User Configuration" -checkResult $userAutoplayCheckResult -resultDetails $userAutoplayOutput -UID "AutoplayAudit-UserConfiguration" 
    Send-Action1Data -auditName "Autoplay Audit" -checkName "Machine Configuration" -checkResult $machineAutoplayCheckResult -resultDetails $machineAutoplayOutput -UID "AutoplayAudit-MachineConfiguration"
}

# Check Firewall is Enabled
# - ESET Firewall
# - Defender Firewall
function Get-FirewallStatus {
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
            } else {
                # If ESET Firewall is found but disabled - send result and continue to check Defender Firewall
                Send-Action1Data -auditName "Firewall Audit" -checkName "ESET Firewall" -checkResult "Fail" -resultDetails "ESET Firewall is installed but not active" -UID "FirewallAudit-ESET"
            }
        }
    }

    if ($esetEnabled) {
        # Send result
        Send-Action1Data -auditName "Firewall Audit" -checkName "ESET Firewall" -checkResult "Pass" -resultDetails "ESET Firewall is active" -UID "FirewallAudit-ESET"

        return # If ESET Firewall is active skip Defender check
    } else {
        # Get list of firewall profiles
        $firewallProfiles = Get-NetFirewallProfile

        # Loop through each profile and check if enabled
        for ($i = 0; $i -lt $firewallProfiles.Count; $i++) {
            # Prepare result
            $status = if ($firewallProfiles[$i].Enabled) { "Enabled" } else { "Disabled" }
            $checkResult = if ($firewallProfiles[$i].Enabled) { "Pass" } else { "Fail" }

            # Send result
            Send-Action1Data -auditName "Firewall Audit" -checkName "Firewall Profile: $($firewallProfiles[$i].Name)" -checkResult $checkResult -resultDetails $status -UID "FirewallAudit-$($firewallProfiles[$i].Name)"
        }
    }
}

# Check Password Policy (Min 8 characters required)
function Get-PasswordPolicy {
    # Parse local password policy
    $localPasswordPolicyRawOutput = net accounts | Where-Object { $_ -match ":" }

    $localPasswordPolicy = @{}
    foreach ($line in $localPasswordPolicyRawOutput) {
        # Split by the colon and trim whitespace
        $name, $value = $line -split ':', 2
        $localPasswordPolicy[$name.Trim()] = $value.Trim()
    }

    # Parse domain password policy
    $domainPasswordPolicyRawOutput = net accounts /domain | Where-Object { $_ -match ":" }

    $domainPasswordPolicy = @{}
    foreach ($line in $domainPasswordPolicyRawOutput) {
        # Split by the colon and trim whitespace
        $name, $value = $line -split ':', 2
        $domainPasswordPolicy[$name.Trim()] = $value.Trim()
    }

    $localCheckResult = if ($localPasswordPolicy["Minimum password length"] -ge 8) { "Pass" } else { "Fail" }
    $domainCheckResult = if ($domainPasswordPolicy["Minimum password length"] -ge 8) { "Pass" } else { "Fail" }

    # Send results
    Send-Action1Data -auditName "Local Password Policy Audit" -checkName "Minimum Password Length" -checkResult $localCheckResult -resultDetails $localPasswordPolicy["Minimum password length"] -UID "PasswordPolicyAudit-Local-MimimumLength"
    Send-Action1Data -auditName "Domain Password Policy Audit" -checkName "Minimum Password Length" -checkResult $domainCheckResult -resultDetails $domainPasswordPolicy["Minimum password length"] -UID "PasswordPolicyAudit-Domain-MimimumLength"
}

# Check for Local Administrator Accounts
function Get-LocalAdminAccounts {
    # Get local administrator accounts
    $localAdmins = Get-LocalGroupMember -Group "Administrators" | Select-Object Name

    [String]$adminAccouts = ""

    for ($i = 0; $i -lt $localAdmins.Count; $i++) {
        $adminAccouts += $localAdmins[$i].Name
        if ($i -lt $localAdmins.Count - 1) {
            $adminAccouts += ", "
        }
    }

    $checkResult = if($localAdmins.Count -gt 0) { "Info" } else { "Pass" }

    # Send results
    Send-Action1Data -auditName "Local Administrator Accounts Audit" -checkName "Local Administrators" -checkResult $checkResult -resultDetails $adminAccouts -UID "LocalAdminAccountsAudit-AdminsList"
}

# Check for Antivirus
function Get-AntivirusStatus {
    # Check Windows Defender status
    $antivirusOutput = Get-MpComputerStatus

    $updated = if ($antivirusOutput.AntispywareSignatureAge -lt 2) { "True" } else { "False" }

    $defenderEnabledCheckResult = if ($antivirusOutput.AMServiceEnabled) { "Pass" } else { "Fail" }
    $defenderUpdatedCheckResult = if ($updated -eq "True") { "Pass" } else { "Fail" }
    
    # Send results
    Send-Action1Data -auditName "Antivirus Status Audit" -checkName "Windows Defender Enabled" -checkResult $defenderEnabledCheckResult -resultDetails $antivirusOutput.AMServiceEnabled -UID "AntivirusAudit-WindowsDefenderEnabled"
    Send-Action1Data -auditName "Antivirus Status Audit" -checkName "Windows Defender Up to Date" -checkResult $defenderUpdatedCheckResult -resultDetails $updated -UID "AntivirusAudit-WindowsDefenderUpToDate"
}

# Action1 Data Source Integration
function Send-Action1Data {
    param (
        [string]$auditName,
        [string]$checkName,
        [string]$checkResult,
        [string]$resultDetails,
        [string]$UID
    )

    # Prepare output object
    $output = [PSCustomObject]@{
        "Audit Name" = $auditName
        "Check Name" = $checkName
        "Check Result" = $checkResult
        "Result Details" = $resultDetails
        "A1_Key" = $UID
            # A1_Key field must uniquely, but stably identify the object on one particular endpoint
            # The value of A1_Key for the same object must not change between script runs (it shall not be randomly generated)
            # Correct examples of A1_Key: disk drive letter, MAC address, user SID
            # Wrong examples of A1_Key: sequential number (1,2,3...), newly generated UUID
    }

    # Pipeline the output object for processing
    Write-Output $output
}

# Get details of the last logged in user
function Get-LastUserDetails {
    $lastUserSID = Get-CimInstance -Class Win32_UserProfile -Filter "Special = False" | Sort-Object LastUseTime -Descending | Select-Object -First 1 | Select-Object -ExpandProperty SID
    $lastUserDomain = Get-CimInstance -Class Win32_UserAccount | Where-Object SID -eq $lastUserSID | Select-Object -ExpandProperty Domain
    $lastUserName = Get-CimInstance -Class Win32_UserAccount | Where-Object SID -eq $lastUserSID | Select-Object -ExpandProperty Name
    $lastUserCaption = "$lastUserDomain\$lastUserName"

    return $lastUserCaption, $lastUserName, $lastUserDomain, $lastUserSID
}

# Execution
Get-AutoplayStatus
Get-FirewallStatus
Get-PasswordPolicy
Get-LocalAdminAccounts
Get-AntivirusStatus