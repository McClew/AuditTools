$osInfo = Get-CimInstance Win32_OperatingSystem
$osCaption = $osInfo.Caption

# Define supported OS versions (example: Windows 10 and above)
$supportedOS = @("Windows 10", "Windows 11", "Windows Server 2016", "Windows Server 2019", "Windows Server 2022")

$checkResult = if ($supportedOS | Where-Object { $osCaption -like "*$_*" }) { "Pass" } else { "Fail" }

# Apply findings to Action1 UDF
Action1-Set-CustomAttribute "OS Supported" $checkResult