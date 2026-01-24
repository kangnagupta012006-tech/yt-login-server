$URL = "https://yt-login-server-1.onrender.com/api/ping"

Write-Host "==============================="
Write-Host "Render Keep Alive Started..."
Write-Host "Pinging: $URL"
Write-Host "Press CTRL + C to stop"
Write-Host "==============================="

while ($true) {
    try {
        $res = Invoke-RestMethod -Uri $URL -Method GET -TimeoutSec 20
        $time = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        Write-Host "[$time] OK -> $($res.message)"
    }
    catch {
        $time = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        Write-Host "[$time] FAIL -> $($_.Exception.Message)"
    }

    Start-Sleep -Seconds 300   # 5 minutes
}
