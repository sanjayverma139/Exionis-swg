# 1. Delete old NDJSON files (stops old data from confusing you)
Remove-Item "C:\ProgramData\Exionis\output\processes_*.ndjson" -Force -ErrorAction SilentlyContinue

# 2. Restart agent fresh
Stop-Process -Name exionis-agent -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 2
.\exionis-agent.exe > agent.log 2>&1
Start-Sleep -Seconds 3  # Let ETW initialize

# 3. Launch a clean test process
Start-Process calc.exe
Start-Sleep -Seconds 2
Stop-Process -Name calc -Force
Start-Sleep -Seconds 2  # Let events flush

# 4. Verify output
$latest = Get-ChildItem "C:\ProgramData\Exionis\output\" -Filter "processes_*.ndjson" | Sort-Object LastWriteTime -Descending | Select-Object -First 1
Write-Host "`n📊 PROCESS EVENTS:" -ForegroundColor Cyan
Get-Content $latest.FullName | ConvertFrom-Json | 
  Where-Object record_type -in @("process_start", "process_stop") | 
  Format-Table timestamp, image, record_type, pid, duration_ms -AutoSize

Write-Host "`n🔍 PRE-EXISTING CHECK:" -ForegroundColor Cyan
if (Select-String -Path $latest.FullName -Pattern '"image":"<pre-existing>"') {
    Write-Host "❌ FAILED: Still seeing <pre-existing>" -ForegroundColor Red
} else {
    Write-Host "✅ PASSED: Zero <pre-existing> entries" -ForegroundColor Green
}