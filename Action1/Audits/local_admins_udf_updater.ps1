$allowList = "admin", "administrator"

try {
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
            if ($allowList -contains $admin.Name.ToLower()) {
                $adminList += $admin.Name
            }
        }

        $adminAccounts = $adminList -join ", "
    }

    $checkResult = if($adminList.Count -gt 0) { "Fail" } else { "Pass" }

} catch {
    $checkResult = "Info"
}

# Apply findings to Action1 UDF
Action1-Set-CustomAttribute "Local Administrators" $checkResult;