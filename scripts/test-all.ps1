# PowerShell test script for Windows
# Test all gateway scenarios

$GATEWAY_URL = "http://localhost:8080"
$API_KEY = "demo-key-123"

Write-Host "=== Gateway Security Demo Tests ===" -ForegroundColor Cyan
Write-Host ""

# Test 1: Valid file
Write-Host "Test 1: Valid file upload" -ForegroundColor Green
try {
    $response = Invoke-RestMethod -Uri "$GATEWAY_URL/api/infer" `
        -Method Post `
        -Headers @{ "x-api-key" = $API_KEY } `
        -Form @{ file = Get-Item "demo-files/valid-image.png" }
    Write-Host "  ✓ Success: $($response.status)" -ForegroundColor Green
} catch {
    Write-Host "  ✗ Failed: $($_.Exception.Message)" -ForegroundColor Red
}
Write-Host ""

# Test 2: Rate limiting
Write-Host "Test 2: Rate limiting (6 requests, limit is 5)" -ForegroundColor Yellow
$blocked = $false
for ($i = 1; $i -le 6; $i++) {
    try {
        $response = Invoke-RestMethod -Uri "$GATEWAY_URL/api/infer" `
            -Method Post `
            -Headers @{ "x-api-key" = $API_KEY } `
            -Form @{ file = Get-Item "demo-files/valid-image.png" }
        Write-Host "  Request $i: Allowed" -ForegroundColor Green
    } catch {
        if ($_.Exception.Response.StatusCode.value__ -eq 429) {
            Write-Host "  Request $i: Blocked (429)" -ForegroundColor Red
            $blocked = $true
        }
    }
    Start-Sleep -Milliseconds 500
}
if ($blocked) {
    Write-Host "  ✓ Rate limiting working correctly" -ForegroundColor Green
}
Write-Host ""

# Test 3: Invalid API key
Write-Host "Test 3: Invalid API key" -ForegroundColor Yellow
try {
    $response = Invoke-RestMethod -Uri "$GATEWAY_URL/api/infer" `
        -Method Post `
        -Headers @{ "x-api-key" = "invalid-key" } `
        -Form @{ file = Get-Item "demo-files/valid-image.png" }
    Write-Host "  ✗ Should have been blocked" -ForegroundColor Red
} catch {
    if ($_.Exception.Response.StatusCode.value__ -eq 401) {
        Write-Host "  ✓ Correctly blocked (401)" -ForegroundColor Green
    }
}
Write-Host ""

# Test 4: Double extension
Write-Host "Test 4: Double extension file" -ForegroundColor Yellow
if (Test-Path "demo-files/fake-image.jpg.exe") {
    try {
        $response = Invoke-RestMethod -Uri "$GATEWAY_URL/api/infer" `
            -Method Post `
            -Headers @{ "x-api-key" = $API_KEY } `
            -Form @{ file = Get-Item "demo-files/fake-image.jpg.exe" }
        Write-Host "  ✗ Should have been blocked" -ForegroundColor Red
    } catch {
        if ($_.Exception.Response.StatusCode.value__ -eq 403) {
            Write-Host "  ✓ Correctly blocked (403)" -ForegroundColor Green
        }
    }
} else {
    Write-Host "  - Skipped (file not found)" -ForegroundColor Gray
}
Write-Host ""

Write-Host "=== Tests Complete ===" -ForegroundColor Cyan
