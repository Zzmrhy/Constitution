# PowerShell script to test authenticated violations cleanup endpoint

param (
    [string]$email,
    [string]$password
)

if (-not $email -or -not $password) {
    Write-Host "Usage: .\test_cleanup_auth.ps1 -email 'user@example.com' -password 'yourpassword'"
    exit 1
}

function ConvertFrom-JsonSafe {
    param ([string]$jsonText)
    if ([string]::IsNullOrEmpty($jsonText)) { return $null }
    return $jsonText | ConvertFrom-Json
}

# Sign in and get cookies
Write-Host "Signing in user $email ..."
$signinBody = @{ email = $email; password = $password } | ConvertTo-Json
$response = Invoke-WebRequest -Uri http://localhost:4000/api/signin -Method POST -Body $signinBody -ContentType 'application/json' -SessionVariable session -ErrorAction Stop
if ($response.StatusCode -ne 200) {
    Write-Host "Sign in failed with status code $($response.StatusCode)"
    exit 1
}
Write-Host "Sign in succeeded."

# Extract cookies from session
$cookies = $session.Cookies.GetCookies("http://localhost")
$accessTokenCookie = $cookies | Where-Object { $_.Name -eq "accessToken" }
if (-not $accessTokenCookie) {
    Write-Host "Did not receive accessToken cookie."
    exit 1
}

# Make cleanup API call with cookies
Write-Host "Testing POST /api/violations/cleanup before allowed time (should fail or 400 if before Monday 1 PM)..."
$responseBefore = Invoke-WebRequest -Uri http://localhost:4000/api/violations/cleanup -Method POST -WebSession $session -ErrorAction SilentlyContinue

if ($responseBefore.StatusCode -eq 400) {
    Write-Host "PASS: Cleanup rejected before allowed time with 400"
} elseif ($responseBefore.StatusCode -eq 200) {
    Write-Host "Cleanup accepted before allowed time (unexpected)"
} else {
    Write-Host "Unexpected status code before allowed time: $($responseBefore.StatusCode)"
}

# Calculate last Monday 1:00 PM as timestamp
$now = Get-Date
$dayOfWeek = [int]$now.DayOfWeek
$daysSinceMonday = if ($dayOfWeek -eq 1) { if ($now.Hour -lt 13) { 0 } else { 7 } } else { ($dayOfWeek + 6) % 7 }
$lastMonday = $now.AddDays(-$daysSinceMonday)
$lastMonday = $lastMonday.Date.AddHours(13)  # sets to 1 PM

$lastResetTimestamp = [int64]($lastMonday.ToUniversalTime() - [datetime]'1970-01-01T00:00:00Z').TotalMilliseconds

Write-Host "Updating lastReset via API to last Monday 1 PM timestamp: $lastResetTimestamp"

$updateBody = @{ lastReset = $lastResetTimestamp } | ConvertTo-Json

$responseUpdate = Invoke-WebRequest -Uri http://localhost:4000/api/admin/update-lastReset -Method POST -Body $updateBody -ContentType 'application/json' -WebSession $session -ErrorAction SilentlyContinue

if ($responseUpdate.StatusCode -eq 200) {
    Write-Host "lastReset updated successfully via admin API"
} else {
    Write-Host "Failed to update lastReset via admin API. Status code: $($responseUpdate.StatusCode)"
    exit 1
}

Start-Sleep -Seconds 2

# Make cleanup API call after updating lastReset.json (should succeed)
Write-Host "Testing POST /api/violations/cleanup after allowed time..."
$responseAfter = Invoke-WebRequest -Uri http://localhost:4000/api/violations/cleanup -Method POST -WebSession $session -ErrorAction SilentlyContinue

if ($responseAfter.StatusCode -eq 200) {
    Write-Host "PASS: Cleanup accepted after allowed time with 200"
} else {
    Write-Host "Unexpected status code after allowed time: $($responseAfter.StatusCode)"
}
