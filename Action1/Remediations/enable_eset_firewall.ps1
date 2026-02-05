# Check ESET CMD (ECMD) location
$ecmd = "C:\Program Files\ESET\ESET Security\ecmd.exe"

# Check if ECMD exists before attempting to enable firewall
if (Test-Path $ecmd) {
    # Attempt to enable the firewall
    & $ecmd /setfeature firewall enable

    if ($LASTEXITCODE -eq 0) {
        Write-Host "Successfully sent enable command to ESET Firewall." -ForegroundColor Green
    } else {
        Write-Warning "Failed to enable ESET Firewall. ESET Self-Defense or password protection may be active."
    }
} else {
    Write-Error "ESET command-line tool not found at $ecmd"
}

# Apply to Action1 UDF
Action1-Set-CustomAttribute "Firewall" "Pass";