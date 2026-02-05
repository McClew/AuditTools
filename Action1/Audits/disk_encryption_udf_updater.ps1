$bitLockerStatus = Get-BitLockerVolume -ErrorAction SilentlyContinue

if ($bitLockerStatus) {
    foreach ($volume in $bitLockerStatus) {
        $checkResult = if ($volume.ProtectionStatus -eq 1) { "Pass" } else { "Fail" }

        # Apply findings to Action1 UDF
        Action1-Set-CustomAttribute "Full Disk Encryption" $checkResult;
    }
} else {
    # Apply findings to Action1 UDF
    Action1-Set-CustomAttribute "Full Disk Encryption" "Fail";
}