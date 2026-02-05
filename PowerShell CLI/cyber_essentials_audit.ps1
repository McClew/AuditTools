# Cyber Essentials Basic Audit Script

# Globals:
$result = "Pass"
$checkCount = 0
$checkFails = 0
$defaultOutputOption = "Default"
# Default output option only displays failed audits
# Case insensitive
# Options: "Default", "Simple", "Verbose"
$lastUserCaption, $lastUserName, $lastUserDomain, $lastUserSID = Get-LastUserDetails

# Output Header
function Write-Header {
    Write-Host "--- Cyber Essentials Audit Results ---" -ForegroundColor Blue
}

# Check Autoplay is Disabled
function Get-AutoplayStatus {
    param (
        [String]$output # Options: "DEFAULT", "SIMPLE", "VERBOSE"
    )

    $autoplayResults = @()
    $faliureCheck = "Pass"

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
    } else {
        $userAutoplayOutput = "Enabled"
        $faliureCheck = "Fail"
    }

    if ($machineAutoplayStatus.NoDriveTypeAutoRun -eq 255) {
        $machineAutoplayOutput = "Disabled"
    } else {
        $machineAutoplayOutput = "Enabled (for some drive types)"
        $faliureCheck = "Fail"
    }

    # Failure check
    $checkCount++
    if ($faliureCheck -eq "Fail") {
        $result = "Fail"
        $checkFails++
    }

    # Prepare results
    $autoplayResults += [PSCustomObject]@{ Audit = "User Configuration"; Status = $userAutoplayOutput }
    $autoplayResults += [PSCustomObject]@{ Audit = "Machine Configuration"; Status = $machineAutoplayOutput }

    # Display results
    Get-CheckResults -output $output -checkName "Autoplay Audit" -result $faliureCheck -resultsTable $autoplayResults

    return $result, $checkCount, $checkFails
}

# Check Firewall is Enabled
function Get-FirewallStatus {
    param (
        [String]$output # Options: "DEFAULT", "SIMPLE", "VERBOSE"
    )

    $firewallResults = @()
    $faliureCheck = "Pass"

    # Get list of firewall profiles
    $firewallProfiles = Get-NetFirewallProfile

    # Loop through each profile and check if enabled
    for ($i = 0; $i -lt $firewallProfiles.Count; $i++) {
        $firewallResults += [PSCustomObject]@{ Audit = "Firewall Profile: $($firewallProfiles[$i].Name)"; Status = $firewallProfiles[$i].Enabled }

        if ($firewallProfiles[$i].Enabled -eq $false) {
            $faliureCheck = "Fail"
        }
    }

    # Failure check
    $checkCount++
    if ($faliureCheck -eq "Fail") {
        $result = "Fail"
        $checkFails++
    }

    # Display results
    Get-CheckResults -output $output -checkName "Firewall Status" -result $faliureCheck -resultsTable $firewallResults

    return $result, $checkCount, $checkFails
}

# Check Password Policy (Min 8 characters required)
function Get-PasswordPolicy {
    param (
        [String]$output # Options: "DEFAULT", "SIMPLE", "VERBOSE"
    )
    
    $passwordResults = @()
    $faliureCheck = "Pass"

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

    # Prepare results
    $passwordResults += [PSCustomObject]@{ Audit = "Local Policy Minimum Password Length"; Status = $localPasswordPolicy["Minimum password length"] }
    $passwordResults += [PSCustomObject]@{ Audit = "Domain Policy Minimum Password Length"; Status = $domainPasswordPolicy["Minimum password length"] }

    # Failure check
    $checkCount++
    if ($localPasswordPolicy["Minimum password length"] -lt 8 -or $domainPasswordPolicy["Minimum password length"] -lt 8) {
        $faliureCheck = "Fail"
        $result = "Fail"
        $checkFails++
    }

    # Display results
    Get-CheckResults -output $output -checkName "Password Policy Audit" -result $faliureCheck -resultsTable $passwordResults

    return $result, $checkCount, $checkFails
}

# Check for Local Administrator Accounts
function Get-LocalAdminAccounts {
    param (
        [String]$output # Options: "DEFAULT", "SIMPLE", "VERBOSE"
    )

    $adminResults = @()
    $failureCheck = "Pass"

    # Get local administrator accounts
    $localAdmins = Get-LocalGroupMember -Group "Administrators" | Select-Object Name

    for ($i = 0; $i -lt $localAdmins.Count; $i++) {
        $adminResults += [PSCustomObject]@{ "Local Administrator Accounts" = $localAdmins[$i].Name }

        if ($localAdmins[$i].Name -eq $lastUserCaption) {
            $failureCheck = "Fail"
        }
    }

    # Check if pass failed
    $checkCount++
    if ($failureCheck -eq "Fail") {
        $result = "Fail"
        $checkFails++
    }

    # Display results
    Get-CheckResults -output $output -checkName "Local Administrator Accounts Audit" -result $failureCheck -resultsTable $adminResults

    return $result, $checkCount, $checkFails
}
 
# Check for Antivirus
function Get-AntivirusStatus {
    param (
        [String]$output # Options: "DEFAULT", "SIMPLE", "VERBOSE"
    )
    
    $antivirusResults = @()
    $failureCheck = "Pass"

    # Check Windows Defender status
    $antivirusOutput = Get-MpComputerStatus
    $antivirusResults += [PSCustomObject]@{ "Windows Defender" = 'Enabled'; Status = $antivirusOutput.AMServiceEnabled }
    $antivirusResults += [PSCustomObject]@{ "Windows Defender" = 'Up to Date'; Status = ($antivirusOutput.AntispywareSignatureAge -lt 2) }

    # Failure check
    $checkCount++
    if (-not $antivirusOutput.AMServiceEnabled -or $antivirusOutput.AntispywareSignatureAge -ge 2) {
        $failureCheck = "Fail"
        $result = "Fail"
        $checkFails++
    }

    # Display results
    Get-CheckResults -output $output -checkName "Antivirus Status Audit" -result $failureCheck -resultsTable $antivirusResults

    return $result, $checkCount, $checkFails
}

# Print Check Results
function Get-CheckResults {
    param (
        [String]$output, # Options: "DEFAULT", "SIMPLE", "VERBOSE"
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
        [String]$result,
        [String]$output # Options: "DEFAULT", "SIMPLE", "VERBOSE"
    )

    Write-Host "`nAudit Result: " -ForegroundColor Blue -NoNewline;
    if ($result -eq "Pass") {
        Write-Host "PASS" -ForegroundColor Green
    } else {
        Write-Host "FAIL" -ForegroundColor Red
    }

    if ($result -eq "Fail") {
        Write-Host "$checkFails out of $checkCount checks failed." -ForegroundColor Red
    } else {
        Write-Host "All $checkCount checks passed." -ForegroundColor Green
    }
}

function Get-LastUserDetails {
    $lastUserCaption = Get-CimInstance -Class Win32_ComputerSystem | Select-Object -ExpandProperty UserName
    $lastUserName = $lastUserCaption.Split('\')[-1]
    $lastUserDomain = $lastUserCaption.Split('\')[0]
    $lastUserSID = Get-CimInstance -Class Win32_UserAccount | Where-Object Caption -like "*$lastuserName" | Select-Object -ExpandProperty SID

    return $lastUserCaption, $lastUserName, $lastUserDomain, $lastUserSID
}

# Execution
Write-Header
$result, $checkCount, $checkFails = Get-AutoplayStatus -output $defaultOutputOption
$result, $checkCount, $checkFails = Get-FirewallStatus -output $defaultOutputOption
$result, $checkCount, $checkFails = Get-PasswordPolicy -output $defaultOutputOption
$result, $checkCount, $checkFails = Get-LocalAdminAccounts -output $defaultOutputOption
$result, $checkCount, $checkFails = Get-AntivirusStatus -output $defaultOutputOption
Get-AuditResult -result $result -output $defaultOutputOption
