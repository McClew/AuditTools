# Install and import Graph module
Set-ExecutionPolicy RemoteSigned -Scope CurrentUser

$RequiredModules = @("Microsoft.Graph.Authentication", "Microsoft.Graph.Users")

foreach ($ModuleName in $RequiredModules) {
    if (Get-Module -ListAvailable -Name $ModuleName) {
        Write-Host "$ModuleName is already installed." -ForegroundColor Green
    } else {
        Write-Host "$ModuleName missing. Installing now..." -ForegroundColor Yellow
        Install-Module -Name $ModuleName -Scope CurrentUser -Force -AllowClobber
    }
}

Write-Host "Importing modules..."
Import-Module Microsoft.Graph.Authentication
Import-Module Microsoft.Graph.Users

# Get user details
$lastUserSID = Get-CimInstance -Class Win32_UserProfile -Filter "Special = False" | Sort-Object LastUseTime -Descending | Select-Object -First 1 | Select-Object -ExpandProperty SID
$lastUserDomain = Get-CimInstance -Class Win32_UserAccount | Where-Object SID -eq $lastUserSID | Select-Object -ExpandProperty Domain
$lastUserName = Get-CimInstance -Class Win32_UserAccount | Where-Object SID -eq $lastUserSID | Select-Object -ExpandProperty Name

# Requires Policy.Read.All or Policy.ReadWrite.AuthenticationMethod
Connect-MgGraph -Scopes "Policy.Read.All", "User.Read.All" -NoWelcome

$UserUPN = "$lastUserName@lucidgrp.co.uk"
$Uri = "https://graph.microsoft.com/beta/users/$UserUPN/authentication/requirements"

try {
    $mfaStatus = Invoke-MgGraphRequest -Method GET -Uri $Uri
    Write-Host "Per-User MFA State for $UserUPN is: $($mfaStatus.perUserMfaState)" -ForegroundColor Cyan
} catch {
    Write-Host "Could not retrieve status. User likely has the default 'Disabled' state."
}

# Clean up
Disconnect-MgGraph

Write-Host "Cleaning up modules..."
Uninstall-Module Microsoft.Graph.Users -ErrorAction SilentlyContinue
Uninstall-Module Microsoft.Graph.Authentication -ErrorAction SilentlyContinue
Write-Host "Script execution completed"