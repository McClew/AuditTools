# Cyber Essentials Basic Audit Script

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
        $userAutoplayCheckResult = "Pass"
    } else {
        $userAutoplayCheckResult = "Fail"
    }

    if ($machineAutoplayStatus.NoDriveTypeAutoRun -eq 255) {
        $machineAutoplayCheckResult = "Pass"
    } else {
        $machineAutoplayCheckResult = "Fail"
    }

    # Apply findings to Action1 UDF
    $overallCheckResult = if ($userAutoplayCheckResult -eq "Pass" -and $machineAutoplayCheckResult -eq "Pass") { "Pass" } else { "Fail" }
    Action1-Set-CustomAttribute "Autoplay" $overallCheckResult;
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
        # Apply findings to Action1 UDF
        $overallCheckResult = "Pass"
        Action1-Set-CustomAttribute "Firewall" $overallCheckResult;

        # Send result
        Send-Action1Data -auditName "Firewall Audit" -checkName "ESET Firewall" -checkResult "Pass" -resultDetails "ESET Firewall is active" -UID "FirewallAudit-ESET"

        return # If ESET Firewall is active skip Defender check
    } else {
        # Get list of firewall profiles
        $firewallProfiles = Get-NetFirewallProfile

        # Overall check result
        $overallCheckResult = "Pass"

        # Loop through each profile and check if enabled
        for ($i = 0; $i -lt $firewallProfiles.Count; $i++) {
            # Prepare result
            $status = if ($firewallProfiles[$i].Enabled) { "Enabled" } else { "Disabled" }
            $checkResult = if ($firewallProfiles[$i].Enabled) { "Pass" } else { "Fail" }

            if ($checkResult -eq "Fail") {
                $overallCheckResult = "Fail"
            }

            # Send result
            Send-Action1Data -auditName "Firewall Audit" -checkName "Firewall Profile: $($firewallProfiles[$i].Name)" -checkResult $checkResult -resultDetails $status -UID "FirewallAudit-$($firewallProfiles[$i].Name)"
        }

        # Apply findings to Action1 UDF
        Action1-Set-CustomAttribute "Firewall" $overallCheckResult;
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

    $localCheckResult = if ($localPasswordPolicy["Minimum password length"] -ge 8) { "Pass" } else { "Fail" }

    # Send results
    Send-Action1Data -auditName "Local Password Policy Audit" -checkName "Minimum Password Length" -checkResult $localCheckResult -resultDetails $localPasswordPolicy["Minimum password length"] -UID "PasswordPolicyAudit-Local-MimimumLength"

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

        # Apply findings to Action1 UDF
        Action1-Set-CustomAttribute "Password Policy" (if($localCheckResult -eq "Pass" -and $domainCheckResult -eq "Pass") { "Pass" } else { "Fail" });

        # Send results
        Send-Action1Data -auditName "Domain Password Policy Audit" -checkName "Minimum Password Length" -checkResult $domainCheckResult -resultDetails $domainPasswordPolicy["Minimum password length"] -UID "PasswordPolicyAudit-Domain-MimimumLength"
    } else {
        $domainCheckResult = "Info"

        # Apply findings to Action1 UDF
        Action1-Set-CustomAttribute "Password Policy" $localCheckResult;

        # Send results
        Send-Action1Data -auditName "Domain Password Policy Audit" -checkName "Minimum Password Length" -checkResult $domainCheckResult -resultDetails "Not Domain Joined" -UID "PasswordPolicyAudit-Domain-MimimumLength"
    }
}

# Check for Local Administrator Accounts
function Get-LocalAdminAccounts {
    try {
        # Using WMI/CIM is more robust than Get-LocalGroupMember for unresolved SIDs
        $group = Get-CimInstance -ClassName Win32_Group -Filter "Name='Administrators' AND LocalAccount=True"
        $query = "Associators of {Win32_Group.Domain='$($group.Domain)',Name='$($group.Name)'} Where AssocClass=Win32_GroupUser Role=GroupComponent ResultClass=Win32_UserAccount"
        $localAdmins = Get-CimInstance -Query $query -ErrorAction SilentlyContinue

        if (-not $localAdmins) {
            # Fallback for systems where the query returns null but members exist
            $localAdmins = Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue
        }

        [String]$adminAccounts = ""
        $adminList = @()

        if ($localAdmins) {
            foreach ($admin in $localAdmins) {
                $adminList += $admin.Name
            }
            $adminAccounts = $adminList -join ", "
        }

        $checkResult = if($adminList.Count -gt 0) { "Info" } else { "Pass" }

    } catch {
        $checkResult = "Info"
        $adminAccounts = "Error retrieving admin list: $($_.Exception.Message)"
    }

    # Apply findings to Action1 UDF
    Action1-Set-CustomAttribute "Local Administrators" (if($checkResult -eq "Pass") { "Pass" } else { "Fail" });

    # Send results
    Send-Action1Data -auditName "Local Administrator Accounts Audit" -checkName "Local Administrators" -checkResult $checkResult -resultDetails $adminAccounts -UID "LocalAdminAccountsAudit-AdminsList"
}

# Check for Antivirus
function Get-AntivirusStatus {
    # Check Windows Defender status
    $antivirusOutput = Get-MpComputerStatus

    $updated = if ($antivirusOutput.AntispywareSignatureAge -lt 2) { "True" } else { "False" }

    $defenderEnabledCheckResult = if ($antivirusOutput.AMServiceEnabled) { "Pass" } else { "Fail" }
    $defenderUpdatedCheckResult = if ($updated -eq "True") { "Pass" } else { "Fail" }
    
    # Apply findings to Action1 UDF
    Action1-Set-CustomAttribute "Anti-Malware" (if($defenderEnabledCheckResult -eq "Pass" -and $defenderUpdatedCheckResult -eq "Pass") { "Pass" } else { "Fail" });

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
$lastUserCaption, $lastUserName, $lastUserDomain, $lastUserSID = Get-LastUserDetails

Get-AutoplayStatus
Get-FirewallStatus
Get-PasswordPolicy
Get-LocalAdminAccounts
Get-AntivirusStatus