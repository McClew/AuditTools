# Get the last user SID via CimInstance
$lastUserProfile = Get-CimInstance -Class Win32_UserProfile -Filter "Special = False" | 
    Sort-Object LastUseTime -Descending | Select-Object -First 1

if ($null -eq $lastUserProfile) {
    Write-Error "No valid user profile found."
    exit
}

$lastUserSID = $lastUserProfile.SID

# Azure AD Compatible Name Resolution
try {
    $objSID = New-Object System.Security.Principal.SecurityIdentifier($lastUserSID)
    $lastUserCaption = $objSID.Translate([System.Security.Principal.NTAccount]).Value
} catch {
    $lastUserCaption = "Unknown/Cloud User"
}

Write-Host "Targeting User: $lastUserCaption ($lastUserSID)"

# Handle the User Registry Hive (Load if not logged in)
$hiveLoaded = $false
if (-not (Test-Path "Registry::HKEY_USERS\$lastUserSID")) {
    $ntuserDat = Join-Path $lastUserProfile.LocalPath "NTUSER.DAT"
    if (Test-Path $ntuserDat) {
        # Using 'reg load' to mount the offline registry file
        & reg load "HKEY_USERS\$lastUserSID" "$ntuserDat" | Out-Null
        $hiveLoaded = $true
    }
}

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

# Cleanup Hive if loaded
if ($hiveLoaded) {
    # Ensure all file locks are released before unloading
    [GC]::Collect()
    [GC]::WaitForPendingFinalizers()
    & reg unload "HKEY_USERS\$lastUserSID" | Out-Null
    Write-Host "Unloaded user registry hive."
}

# Apply to Action1 UDF
Action1-Set-CustomAttribute "Autoplay" "Pass"