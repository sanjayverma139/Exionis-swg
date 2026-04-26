$env:PATH='C:\msys64\ucrt64\bin;'+$env:PATH
$env:CGO_ENABLED='1'
$env:CC='gcc'
Set-Location 'D:\Project\Exionis-swg\agent'
& 'C:\Program Files\Go\bin\go.exe' build ./cmd/agent
Start-Sleep -Seconds 1
$processFile = Get-ChildItem 'C:\ProgramData\Exionis\output\processes_*.ndjson' | Sort-Object LastWriteTime -Descending | Select-Object -First 1 -ExpandProperty FullName
$networkFile = Get-ChildItem 'C:\ProgramData\Exionis\output\network_*.ndjson' | Sort-Object LastWriteTime -Descending | Select-Object -First 1 -ExpandProperty FullName
$appFile = Get-ChildItem 'C:\ProgramData\Exionis\output\apps_*.ndjson' | Sort-Object LastWriteTime -Descending | Select-Object -First 1 -ExpandProperty FullName
$procBefore = (Get-Content -LiteralPath $processFile).Count
$netBefore = (Get-Content -LiteralPath $networkFile).Count
$logBefore = (Get-Content -LiteralPath 'C:\ProgramData\Exionis\logs\agent.ndjson').Count
$p = Start-Process -FilePath 'D:\Project\Exionis-swg\agent\agent.exe' -WorkingDirectory 'D:\Project\Exionis-swg\agent' -PassThru -WindowStyle Hidden
Start-Sleep -Seconds 4
$n = Start-Process -FilePath 'notepad.exe' -PassThru
Start-Sleep -Seconds 2
if (-not $n.HasExited) { Stop-Process -Id $n.Id -Force }
Start-Sleep -Seconds 10
if (-not $p.HasExited) { Stop-Process -Id $p.Id -Force }
$procAfter = Get-Content -LiteralPath $processFile
$netAfter = Get-Content -LiteralPath $networkFile
$logAfter = Get-Content -LiteralPath 'C:\ProgramData\Exionis\logs\agent.ndjson'
[pscustomobject]@{
  IsAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
  ProcessNewLines = ($procAfter.Count - $procBefore)
  NetworkNewLines = ($netAfter.Count - $netBefore)
  LogNewLines = ($logAfter.Count - $logBefore)
  ProcessTail = @($procAfter | Select-Object -Last ([Math]::Min(8, [Math]::Max(0, $procAfter.Count - $procBefore))))
  NetworkTail = @($netAfter | Select-Object -Last ([Math]::Min(8, [Math]::Max(0, $netAfter.Count - $netBefore))))
  LogTail = @($logAfter | Select-Object -Last ([Math]::Min(8, [Math]::Max(0, $logAfter.Count - $logBefore))))
} | ConvertTo-Json -Depth 4 | Set-Content 'D:\Project\Exionis-swg\agent\admin-verify.json'
