$env:PATH='C:\msys64\ucrt64\bin;'+$env:PATH
$env:CGO_ENABLED='1'
$env:CC='gcc'
Set-Location 'D:\Project\Exionis-swg\agent'
$processFile = Get-ChildItem 'C:\ProgramData\Exionis\output\processes_*.ndjson' | Sort-Object LastWriteTime -Descending | Select-Object -First 1 -ExpandProperty FullName
$networkFile = Get-ChildItem 'C:\ProgramData\Exionis\output\network_*.ndjson' | Sort-Object LastWriteTime -Descending | Select-Object -First 1 -ExpandProperty FullName
$procBefore = (Get-Content -LiteralPath $processFile).Count
$netBefore = (Get-Content -LiteralPath $networkFile).Count
$p = Start-Process -FilePath 'D:\Project\Exionis-swg\agent\agent.exe' -WorkingDirectory 'D:\Project\Exionis-swg\agent' -PassThru -WindowStyle Hidden
Start-Sleep -Seconds 25
$n = Start-Process -FilePath 'notepad.exe' -PassThru
Start-Sleep -Seconds 4
if (-not $n.HasExited) { Stop-Process -Id $n.Id -Force }
Start-Sleep -Seconds 25
if (-not $p.HasExited) { Stop-Process -Id $p.Id -Force }
$procNew = (Get-Content -LiteralPath $processFile | Select-Object -Last ((Get-Content -LiteralPath $processFile).Count - $procBefore)) | ForEach-Object { $_ | ConvertFrom-Json }
$netNew = (Get-Content -LiteralPath $networkFile | Select-Object -Last ((Get-Content -LiteralPath $networkFile).Count - $netBefore)) | ForEach-Object { $_ | ConvertFrom-Json }
[pscustomobject]@{
  IsAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
  ProcessNewCount = $procNew.Count
  ProcessTypes = (($procNew | Group-Object record_type | ForEach-Object { '{0}:{1}' -f $_.Name,$_.Count }) -join ', ')
  NetworkInProcessFile = ($procNew | Where-Object { $_.record_type -eq 'network_connection' }).Count
  StartCount = ($procNew | Where-Object { $_.record_type -eq 'process_start' }).Count
  StartWithImagePath = ($procNew | Where-Object { $_.record_type -eq 'process_start' -and $_.image_path }).Count
  StartWithHash = ($procNew | Where-Object { $_.record_type -eq 'process_start' -and $_.sha256_hash }).Count
  StartSamples = @($procNew | Where-Object { $_.record_type -eq 'process_start' } | Select-Object -First 5)
  NetworkNewCount = $netNew.Count
  NetworkMissingLocalIP = ($netNew | Where-Object { -not $_.local_ip }).Count
  NetworkMissingDirection = ($netNew | Where-Object { -not $_.direction }).Count
  NetworkSamples = @($netNew | Select-Object -First 5)
} | ConvertTo-Json -Depth 5 | Set-Content 'D:\Project\Exionis-swg\agent\admin-final-validate.json'
