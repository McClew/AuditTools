# Get list of firewall profiles
$firewallProfiles = Get-NetFirewallProfile

# Loop through each profile and check if enabled
for ($i = 0; $i -lt $firewallProfiles.Count; $i++) {    
    if ($firewallProfiles[$i].Name -ne "Domain" -and $firewallProfiles[$i].Name -ne "Public" -and $firewallProfiles[$i].Name -ne "Private" ) {
        # If the profile is not one of the standard profiles, notify the user
        Write-Host "Unexpected Firewall Profile found: $($firewallProfiles[$i].Name)" -ForegroundColor Yellow
        Write-Host "Manually enable this profile via PowerShell" -ForegroundColor Yellow
    } else {
        if ($firewallProfiles[$i].Enabled -eq $false) {
            # Alert the user about the current status of the profile
            Write-Host "Firewall Profile: $($firewallProfiles[$i].Name) is " -NoNewline;
            Write-Host "Disabled" -ForegroundColor Red
            Write-Host "Enabling Firewall Profile: $($firewallProfiles[$i].Name)" -ForegroundColor Yellow

            # Enable the firewall profile
            Set-NetFirewallProfile -Profile $firewallProfiles[$i].Name -Enabled True

            # Confirm the change
            $updatedProfile = Get-NetFirewallProfile -Name $firewallProfiles[$i].Name
            if ($updatedProfile.Enabled -eq $true) {
                Write-Host "Firewall Profile: $($firewallProfiles[$i].Name) has been " -NoNewline; 
                Write-Host "Enabled" -ForegroundColor Green
            } else {
                Write-Host "Failed to enable Firewall Profile: $($firewallProfiles[$i].Name)" -ForegroundColor Red
            }
        } else {
            Write-Host "Firewall Profile: $($firewallProfiles[$i].Name) is already " -NoNewline;
            Write-Host "Enabled" -ForegroundColor Green
        }
    }
}