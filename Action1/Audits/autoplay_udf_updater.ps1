# Get the SID of the last user logged in
$lastUserSID = Get-CimInstance -Class Win32_UserProfile -Filter "Special = False" | Sort-Object LastUseTime -Descending | Select-Object -First 1 | Select-Object -ExpandProperty SID

# Check user configuration
$userAutoplayStatus = Get-ItemProperty "Registry::HKEY_USERS\$lastUserSID\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers" -Name DisableAutoplay -ErrorAction SilentlyContinue
# value of 1 means autoplay is disabled
# value of 0 or missing means autoplay is enabled

# Check machine configuration - overrides user settings
$machineAutoplayStatus = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -ErrorAction SilentlyContinue
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