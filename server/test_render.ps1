# ===============================
# Render API + Google Sheet Test
# ===============================

# 🔥 1) Paste your Render Base URL here (only once)
$BASE = "https://yt-login-server-1.onrender.com/"

# 🔥 2) Admin credentials (same as Render ENV)
$ADMIN_USER = "Mkloveinfinite@#"
$ADMIN_PASS = "Mkundefined@#"

# 🔥 3) Test Device Info
$DEVICE_ID = "DEV-001"
$DEVICE_NAME = "Test-PC"

Write-Host "===============================" -ForegroundColor Cyan
Write-Host "Starting Render Tests..." -ForegroundColor Cyan
Write-Host "BASE = $BASE" -ForegroundColor Yellow
Write-Host "===============================" -ForegroundColor Cyan


function POST-JSON($url, $obj) {
    $json = $obj | ConvertTo-Json -Depth 10
    return Invoke-RestMethod -Method Post -Uri $url -Body $json -ContentType "application/json"
}

# -----------------------------
# TEST 1: Ping
# -----------------------------
Write-Host "`n[TEST 1] PING..." -ForegroundColor Green
try {
    $ping = Invoke-RestMethod -Method Get -Uri "$BASE/api/ping"
    Write-Host "PING OK:" -ForegroundColor Green
    $ping | Format-List
} catch {
    Write-Host "PING FAILED ❌" -ForegroundColor Red
    Write-Host $_
    exit
}

# -----------------------------
# TEST 2: Login (Devices sheet update)
# -----------------------------
Write-Host "`n[TEST 2] LOGIN..." -ForegroundColor Green
try {
    $loginBody = @{
        username   = $ADMIN_USER
        password   = $ADMIN_PASS
        device_id  = $DEVICE_ID
        device_name= $DEVICE_NAME
    }

    $login = POST-JSON "$BASE/api/login" $loginBody
    Write-Host "LOGIN OK ✅" -ForegroundColor Green
    $login | Format-List
} catch {
    Write-Host "LOGIN FAILED ❌" -ForegroundColor Red
    Write-Host $_
}

# -----------------------------
# TEST 3: Paste Links (Work Report entry)
# -----------------------------
Write-Host "`n[TEST 3] PASTE LINKS..." -ForegroundColor Green
try {
    $pasteBody = @{
        username   = "test_user"
        device_id  = $DEVICE_ID
        device_name= $DEVICE_NAME
        items      = @(
            "hello",
            "https://youtube.com/watch?v=abc",
            "random text https://youtu.be/xyz"
        )
    }

    $paste = POST-JSON "$BASE/api/report/paste_links" $pasteBody
    Write-Host "PASTE LINKS OK ✅" -ForegroundColor Green
    $paste | Format-List
} catch {
    Write-Host "PASTE LINKS FAILED ❌" -ForegroundColor Red
    Write-Host $_
}

# -----------------------------
# TEST 4: Scrape Done
# -----------------------------
Write-Host "`n[TEST 4] SCRAPE DONE..." -ForegroundColor Green
try {
    $scrapeBody = @{
        username   = "test_user"
        device_id  = $DEVICE_ID
        device_name= $DEVICE_NAME
        count      = 12
    }

    $scrape = POST-JSON "$BASE/api/report/scrape_done" $scrapeBody
    Write-Host "SCRAPE DONE OK ✅" -ForegroundColor Green
    $scrape | Format-List
} catch {
    Write-Host "SCRAPE DONE FAILED ❌" -ForegroundColor Red
    Write-Host $_
}

# -----------------------------
# TEST 5: Download Done
# -----------------------------
Write-Host "`n[TEST 5] DOWNLOAD DONE..." -ForegroundColor Green
try {
    $downBody = @{
        username   = "test_user"
        device_id  = $DEVICE_ID
        device_name= $DEVICE_NAME
        count      = 7
    }

    $down = POST-JSON "$BASE/api/report/download_done" $downBody
    Write-Host "DOWNLOAD DONE OK ✅" -ForegroundColor Green
    $down | Format-List
} catch {
    Write-Host "DOWNLOAD DONE FAILED ❌" -ForegroundColor Red
    Write-Host $_
}

# -----------------------------
# TEST 6: Session Time
# -----------------------------
Write-Host "`n[TEST 6] SESSION..." -ForegroundColor Green
try {
    $sessBody = @{
        username   = "test_user"
        device_id  = $DEVICE_ID
        device_name= $DEVICE_NAME
        seconds    = 180
    }

    $sess = POST-JSON "$BASE/api/report/session" $sessBody
    Write-Host "SESSION OK ✅" -ForegroundColor Green
    $sess | Format-List
} catch {
    Write-Host "SESSION FAILED ❌" -ForegroundColor Red
    Write-Host $_
}

Write-Host "`n===============================" -ForegroundColor Cyan
Write-Host "ALL TESTS FINISHED ✅" -ForegroundColor Cyan
Write-Host "अब Google Sheet check करो:" -ForegroundColor Yellow
Write-Host "1) devices tab में DEV-001" -ForegroundColor Yellow
Write-Host "2) Work Report tab में paste_links/scrape_done/download_done/session entries" -ForegroundColor Yellow
Write-Host "===============================" -ForegroundColor Cyan
