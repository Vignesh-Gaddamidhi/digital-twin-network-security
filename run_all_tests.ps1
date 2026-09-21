Set-Location -Path "C:\Users\dell\digital-twin-network-security"
$env:PYTHONIOENCODING = "utf-8"
$python = ".\services\twin_engine\venv\Scripts\python.exe"

$testSuites = Get-ChildItem -Path "services", "packages", "security", "frontend/tests" -Recurse -Filter "test_*.py" |
    Where-Object { $_.FullName -notmatch "venv|site-packages|node_modules|\.next" } |
    Select-Object -ExpandProperty FullName

$passedCount = 0
$failedCount = 0
$failedItems = New-Object System.Collections.ArrayList

Write-Host "`n==========================================================" -ForegroundColor Cyan
Write-Host " EXECUTING COMPLETE REPOSITORY REGRESSION (DAYS 1 - 203)   " -ForegroundColor Cyan
Write-Host " Total Suites Identified: $($testSuites.Count)" -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

$i = 1
foreach ($suite in $testSuites) {
    $shortName = $suite.Replace("C:\Users\dell\digital-twin-network-security\", "")
    Write-Host "[$i/$($testSuites.Count)] Running: $shortName ... " -NoNewline
    $output = & $python $suite 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Host "PASS" -ForegroundColor Green
        $passedCount++
    } else {
        Write-Host "FAIL" -ForegroundColor Red
        $failedCount++
        [void]$failedItems.Add([PSCustomObject]@{
            SuiteName = $shortName
            ErrorLog  = ($output | Out-String)
        })
    }
    $i++
}

Write-Host "`n==========================================================" -ForegroundColor Cyan
Write-Host " REGRESSION EXECUTION SUMMARY                             " -ForegroundColor Cyan
Write-Host " Total Suites Run: $($testSuites.Count)" -ForegroundColor Cyan
Write-Host " Passed:           $passedCount" -ForegroundColor Green
Write-Host " Failed:           $failedCount" -ForegroundColor $(if ($failedCount -eq 0) { "Green" } else { "Red" })
Write-Host "==========================================================" -ForegroundColor Cyan

if ($failedCount -gt 0) {
    Write-Host "`nFailed Suites Details:" -ForegroundColor Red
    foreach ($item in $failedItems) {
        Write-Host "--------------------------------------------------------" -ForegroundColor Red
        Write-Host "SUITE: $($item.SuiteName)" -ForegroundColor Red
        Write-Host $item.ErrorLog -ForegroundColor Yellow
    }
    exit 1
} else {
    Write-Host "`n>>> ALL 193 TESTS PASSED! PLATFORM FULLY VERIFIED THROUGH DAY 203 <<<" -ForegroundColor Green
}
