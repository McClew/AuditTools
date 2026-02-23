# Get the SID of the last user logged in
$lastUserSID = Get-CimInstance -Class Win32_UserProfile -Filter "Special = False" | Sort-Object LastUseTime -Descending | Select-Object -First 1 | Select-Object -ExpandProperty SID

# Check user configuration
# Registry paths for user and machine autoplay settings
$userRegBase = "Registry::HKEY_USERS\$lastUserSID"
$userAutoplayPath = "$userRegBase\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers"

# Ensure the key exists if not: create it, then check the current value
if (-not (Test-Path $userAutoplayPath)) {
    New-Item -Path $userAutoplayPath -Force | Out-Null
    Write-Host "Created registry key for user autoplay settings at $userAutoplayPath"
}

# Get current user autoplay status
$userAutoplayStatus = Get-ItemProperty -Path $userAutoplayPath -Name "DisableAutoplay" -ErrorAction SilentlyContinue
# value of 1 means autoplay is disabled
# value of 0 or missing means autoplay is enabled

# Registry path for machine autoplay settings
$machinePath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"

# Ensure the key exists if not: create it, then check the current value
if (-not (Test-Path $machinePath)) {
    New-Item -Path $machinePath -Force | Out-Null
    Write-Host "Created registry key for machine autoplay settings at $machinePath"
}

# Get current machine autoplay status
$machineAutoplayStatus = Get-ItemProperty -Path $machinePath -Name "NoDriveTypeAutoRun" -ErrorAction SilentlyContinue
# value of 255 or 0xFF means autoplay is disabled for all drives
# other values (145 or 0x91) mean autoplay is enabled for some drive types

# Determine outputs
if ($null -eq $userAutoplayStatus -or $userAutoplayStatus.DisableAutoplay -ne 1) {
    $userAutoplayCheckResult = "Fail"
} else {
    $userAutoplayCheckResult = "Pass"
}

if ($null -eq $machineAutoplayStatus -or $machineAutoplayStatus.NoDriveTypeAutoRun -ne 255) {
    $machineAutoplayCheckResult = "Fail"
} else {
    $machineAutoplayCheckResult = "Pass"
}

# Apply findings to Action1 UDF
$overallCheckResult = if ($userAutoplayCheckResult -eq "Pass" -and $machineAutoplayCheckResult -eq "Pass") { "Pass" } else { "Fail" }
Action1-Set-CustomAttribute "Autoplay" "$overallCheckResult"