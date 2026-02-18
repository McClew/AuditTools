$allowList = @("lucid")
$deleteList = @()

# Get current members
$members = Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue

foreach ($member in $members) {
    # Extract just the name (strips Domain\ if present)
    $memberName = $member.Name -split '\\' | Select-Object -Last 1
    $memberNameLower = $memberName.ToLower()

    if ($allowList -notcontains $memberNameLower) {
        if ($deleteList -contains $memberNameLower) {
            Write-Host "Deleting user: $memberName"
            Remove-LocalUser -Name $memberName -ErrorAction SilentlyContinue
        } else {
            Write-Host "Demoting user: $memberName"
            # FIX: Use the SID string value directly. 
            # This avoids the "LocalPrincipal" conversion error.
            Remove-LocalGroupMember -Group "Administrators" -Member $member.SID.Value -ErrorAction SilentlyContinue
        }
    }
}

# Update UDF Section
try {
    # Using Get-LocalGroupMember for consistency across the script
    $currentAdmins = Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue
    
    $adminList = @()
    $unwantedAdmin = $false

    foreach ($admin in $currentAdmins) {
        $nameOnly = $admin.Name -split '\\' | Select-Object -Last 1
        
        # Check if the account is enabled before flagging
        $userDetail = Get-LocalUser -Name $nameOnly -ErrorAction SilentlyContinue
        
        # Only process if user exists and is enabled
        if ($userDetail -and $userDetail.Enabled) {
            if ($allowList -notcontains $nameOnly.ToLower()) {
                $unwantedAdmin = $true
            }
            $adminList += $nameOnly
        }
    }

    $adminAccounts = $adminList -join ", "
    $checkResult = if($unwantedAdmin) { "Fail: $adminAccounts" } else { "Pass: $adminAccounts" }

} catch {
    $checkResult = "Info: ERROR $($_.Exception.Message)"
}

# Apply findings to Action1 UDF
Action1-Set-CustomAttribute "Local Administrators" $checkResult;