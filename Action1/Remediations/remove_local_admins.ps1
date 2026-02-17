$allowList = "admin", "administrator", "lucid"
$deleteList # = "example", "test"
# all other accounts are demoted

$group = Get-CimInstance -ClassName Win32_Group -Filter "Name='Administrators' AND LocalAccount=True"
$query = "Associators of {Win32_Group.Domain='$($group.Domain)',Name='$($group.Name)'} Where AssocClass=Win32_GroupUser Role=GroupComponent ResultClass=Win32_UserAccount"
$localAdmins = Get-CimInstance -Query $query -ErrorAction SilentlyContinue

if (-not $localAdmins) {
    # Fallback for systems where the query returns null but members exist
    $localAdmins = Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue
}

if ($localAdmins) {
    foreach ($admin in $localAdmins) {
        if ($allowList -notcontains $admin.Name.ToLower()) {
            if ($deleteList -contains $admin.Name.ToLower()) {
                Remove-LocalUser -Name $admin.Name
            } else {
                Remove-LocalGroupMember -Group "Administrators" -Member $admin.Name
            }
        }
    }
}

# Apply findings to Action1 UDF
Action1-Set-CustomAttribute "Local Administrators" "Pass";