Write-Host "Updating Local Password Policy via Net Accounts..."

# Set Minimum Password Length
net accounts /minpwlen:12

# Display results
Write-Host "`nUpdated Policy Summary:" -ForegroundColor Yellow
net accounts

# Apply to Action1 UDF
Action1-Set-CustomAttribute "Password Policy" "Pass";