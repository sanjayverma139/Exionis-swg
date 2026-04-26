$env:PATH='C:\msys64\ucrt64\bin;'+$env:PATH
$env:CGO_ENABLED='1'
$env:CC='gcc'
Set-Location 'D:\Project\Exionis-swg\agent'
Remove-Item -LiteralPath 'D:\Project\Exionis-swg\agent\admin-run.log','D:\Project\Exionis-swg\agent\admin-run.err' -ErrorAction SilentlyContinue
$p = Start-Process -FilePath 'D:\Project\Exionis-swg\agent\agent.exe' -WorkingDirectory 'D:\Project\Exionis-swg\agent' -RedirectStandardOutput 'D:\Project\Exionis-swg\agent\admin-run.log' -RedirectStandardError 'D:\Project\Exionis-swg\agent\admin-run.err' -PassThru
Start-Sleep -Seconds 12
if (-not $p.HasExited) { Stop-Process -Id $p.Id -Force }
[pscustomobject]@{
  IsAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
  ExitCode = $p.ExitCode
  Stdout = @((Get-Content -LiteralPath 'D:\Project\Exionis-swg\agent\admin-run.log' -ErrorAction SilentlyContinue))
  Stderr = @((Get-Content -LiteralPath 'D:\Project\Exionis-swg\agent\admin-run.err' -ErrorAction SilentlyContinue))
  OutputFiles = @(Get-ChildItem 'C:\ProgramData\Exionis\output\*.ndjson' | Sort-Object LastWriteTime -Descending | Select-Object -First 5 FullName,LastWriteTime,Length)
  LogFiles = @(Get-ChildItem 'C:\ProgramData\Exionis\logs\*.ndjson' | Sort-Object LastWriteTime -Descending | Select-Object -First 5 FullName,LastWriteTime,Length)
} | ConvertTo-Json -Depth 5 | Set-Content 'D:\Project\Exionis-swg\agent\admin-run-state.json'
