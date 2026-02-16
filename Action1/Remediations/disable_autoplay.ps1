# Get last user details
$lastUserSID = Get-CimInstance -Class Win32_UserProfile -Filter "Special = False" | Sort-Object LastUseTime -Descending | Select-Object -First 1 | Select-Object -ExpandProperty SID
$lastUserDomain = Get-CimInstance -Class Win32_UserAccount | Where-Object SID -eq $lastUserSID | Select-Object -ExpandProperty Domain
$lastUserName = Get-CimInstance -Class Win32_UserAccount | Where-Object SID -eq $lastUserSID | Select-Object -ExpandProperty Name
$lastUserCaption = "$lastUserDomain\$lastUserName"

# Output user
Write-Host "Last user found: $lastUserCaption"
Write-Host "SID found: $lastUserSID"

# Registry paths for user and machine autoplay settings
$userRegBase = "Registry::HKEY_USERS\$lastUserSID"
$userAutoplayPath = "$userRegBase\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers"

# Ensure the key exists if not: create it, then check the current value
if (-not (Test-Path $userAutoplayPath)) {
    New-Item -Path $userAutoplayPath -Force | Out-Null
    Write-Host "Created registry key for user autoplay settings at $userAutoplayPath"
}

# Get current user autoplay status
$userStatus = Get-ItemProperty -Path $userAutoplayPath -Name "DisableAutoplay" -ErrorAction SilentlyContinue

if ($null -eq $userStatus -or $userStatus.DisableAutoplay -ne 1) {
    # if the value is missing or not set to 1: set it to 1 to disable autoplay
    Set-ItemProperty -Path $userAutoplayPath -Name "DisableAutoplay" -Value 1 -Type DWord
    Write-Host "Autoplay has been " -NoNewline;
    Write-Host "Disabled" -ForegroundColor Green -NoNewline;
    Write-Host " for user $lastUserCaption"
} else {
    Write-Host "Autoplay is already " -NoNewline;
    Write-Host "Disabled" -ForegroundColor Green
    Write-Host " for user $lastUserCaption"
}

# Registry path for machine autoplay settings
$machinePath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"

# Ensure the key exists if not: create it, then check the current value
if (-not (Test-Path $machinePath)) {
    New-Item -Path $machinePath -Force | Out-Null
    Write-Host "Created registry key for machine autoplay settings at $machinePath"
}

# Get current machine autoplay status
$machineStatus = Get-ItemProperty -Path $machinePath -Name "NoDriveTypeAutoRun" -ErrorAction SilentlyContinue

# 255 (0xFF) disables AutoRun on all drive types
if ($null -eq $machineStatus -or $machineStatus.NoDriveTypeAutoRun -ne 255) {
    Set-ItemProperty -Path $machinePath -Name "NoDriveTypeAutoRun" -Value 255 -Type DWord
    Write-Host "Autoplay has been " -NoNewline;
    Write-Host "Disabled" -ForegroundColor Green -NoNewline;
    Write-Host " for all users (machine setting)"
} else {
    Write-Host "Autoplay is already " -NoNewline;
    Write-Host "Disabled" -ForegroundColor Green -NoNewline;
    Write-Host " for all users (machine setting)"
}

# Apply to Action1 UDF
Action1-Set-CustomAttribute "Autoplay" "Pass";