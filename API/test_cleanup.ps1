echo '==== Testing violations cleanup endpoint before allowed Monday 1:00 PM time ===='
$responseBefore = curl.exe -s -o $null -w '%{http_code}' -X POST http://localhost:4000/api/violations/cleanup
Write-Host 'Response HTTP status code:' $responseBefore
if ($responseBefore -eq 400) { Write-Host 'PASS: Cleanup rejected before allowed time' } else { Write-Host 'FAIL: Cleanup should be rejected before allowed time' }

echo '==== Setting lastReset.json to last Monday 00:00 ===='
$lastMondayDate = (Get-Date).AddDays(- ((Get-Date).DayOfWeek.value__ + 6) % 7).Date
$lastMonday = New-Object DateTime $lastMondayDate.Year, $lastMondayDate.Month, $lastMondayDate.Day, 0, 0, 0, [DateTimeKind]::Local
$epochStart = [datetime]'1970-01-01'
$timeSpan = $lastMonday.ToUniversalTime() - $epochStart
$timestamp = [int64]$timeSpan.TotalMilliseconds
$content = '{\"lastReset\":' + $timestamp + '}'
Set-Content -Path './API/lastReset.json' -Value $content

echo '==== Testing violations cleanup endpoint after allowed Monday 1:00 PM time ===='
$responseAfter = curl.exe -s -o $null -w '%{http_code}' -X POST http://localhost:4000/api/violations/cleanup
Write-Host 'Response HTTP status code:' $responseAfter
if ($responseAfter -eq 200) { Write-Host 'PASS: Cleanup accepted after allowed time' } else { Write-Host 'FAIL: Cleanup should be accepted after allowed time' }

echo '==== Current lastReset.json contents ===='
Get-Content './API/lastReset.json'

echo '==== Current violations.json contents ===='
Get-Content './API/violations.json'
