$base = "http://127.0.0.1:5000"

Write-Host "Testing Ping..."
Invoke-RestMethod "$base/api/ping"

Write-Host "`nTesting paste_links..."
$body1 = @{
    username="Device-1"
    device_id="PC-TEST-001"
    device_name="MyPC"
    items=@(
        "https://youtube.com/watch?v=dQw4w9WgXcQ",
        "hello wrong text",
        "https://youtu.be/dQw4w9WgXcQ"
    )
} | ConvertTo-Json

Invoke-RestMethod "$base/api/report/paste_links" -Method POST -ContentType "application/json" -Body $body1


Write-Host "`nTesting scrape_done..."
$body2 = @{
    username="Device-1"
    device_id="PC-TEST-001"
    device_name="MyPC"
    count=5
} | ConvertTo-Json

Invoke-RestMethod "$base/api/report/scrape_done" -Method POST -ContentType "application/json" -Body $body2


Write-Host "`nTesting download_done..."
$body3 = @{
    username="Device-1"
    device_id="PC-TEST-001"
    device_name="MyPC"
    count=2
} | ConvertTo-Json

Invoke-RestMethod "$base/api/report/download_done" -Method POST -ContentType "application/json" -Body $body3


Write-Host "`nTesting session..."
$body4 = @{
    username="Device-1"
    device_id="PC-TEST-001"
    device_name="MyPC"
    seconds=120
} | ConvertTo-Json

Invoke-RestMethod "$base/api/report/session" -Method POST -ContentType "application/json" -Body $body4

Write-Host "`nExcel Download Link (open in browser after admin login):"
Write-Host "$base/admin/work/excel"
