$allowList = @("lucid")

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