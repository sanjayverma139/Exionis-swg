$ErrorActionPreference = 'Stop'
$env:PATH = 'C:\msys64\ucrt64\bin;' + $env:PATH
$root = 'D:\Project\Exionis-swg\agent'
$outDir = 'C:\ProgramData\Exionis\output'
$logDir = 'C:\ProgramData\Exionis\logs'
$today = Get-Date -Format 'yyyy-MM-dd'
$processFile = Get-ChildItem -Path $outDir -Filter "processes_*_$today.ndjson" | Sort-Object LastWriteTime -Descending | Select-Object -First 1
$networkFile = Get-ChildItem -Path $outDir -Filter "network_*_$today.ndjson" | Sort-Object LastWriteTime -Descending | Select-Object -First 1
$appsFile = Get-ChildItem -Path $outDir -Filter "apps_*_$today.ndjson" | Sort-Object LastWriteTime -Descending | Select-Object -First 1
$logFile = Join-Path $logDir 'agent.ndjson'
if (-not $processFile -or -not $networkFile -or -not $appsFile -or -not (Test-Path $logFile)) { throw 'Expected output files are missing.' }
$procBefore = (Get-Content $processFile.FullName).Count
$netBefore = (Get-Content $networkFile.FullName).Count
$appsBefore = (Get-Content $appsFile.FullName).Count
$logBefore = (Get-Content $logFile).Count
$stdoutPath = Join-Path $root 'admin-phase2-run.log'
$stderrPath = Join-Path $root 'admin-phase2-run.err'
if (Test-Path $stdoutPath) { Remove-Item $stdoutPath -Force }
if (Test-Path $stderrPath) { Remove-Item $stderrPath -Force }
$proc = Start-Process -FilePath (Join-Path $root 'agent.exe') -WorkingDirectory $root -RedirectStandardOutput $stdoutPath -RedirectStandardError $stderrPath -PassThru -WindowStyle Hidden
$deadline = (Get-Date).AddSeconds(90)
$started = $false
while ((Get-Date) -lt $deadline) {
  Start-Sleep -Seconds 3
  if (Test-Path $stdoutPath) {
    $stdout = Get-Content $stdoutPath -Raw
    if ($stdout -match 'Phase 2: Process \+ Network Telemetry Engine ACTIVE') {
      $started = $true
      break
    }
  }
  if ($proc.HasExited) { break }
}
$helperProc = $null
if ($started) {
  $helperProc = Start-Process -FilePath 'powershell.exe' -ArgumentList '-NoProfile','-Command','Start-Sleep -Seconds 20' -PassThru -WindowStyle Hidden
  try {
    Invoke-WebRequest -Uri 'https://example.com' -UseBasicParsing | Out-Null
  } catch {
  }
  Start-Sleep -Seconds 15
}
if ($helperProc -and -not $helperProc.HasExited) {
  Stop-Process -Id $helperProc.Id -Force
}
if (-not $proc.HasExited) {
  Stop-Process -Id $proc.Id -Force
  Start-Sleep -Seconds 2
}
$procNewLines = @(Get-Content $processFile.FullName | Select-Object -Skip $procBefore)
$netNewLines = @(Get-Content $networkFile.FullName | Select-Object -Skip $netBefore)
$appsNewLines = @(Get-Content $appsFile.FullName | Select-Object -Skip $appsBefore)
$logNewLines = @(Get-Content $logFile | Select-Object -Skip $logBefore)
$procRecords = @()
foreach ($line in $procNewLines) { if ($line.Trim()) { $procRecords += ($line | ConvertFrom-Json) } }
$netRecords = @()
foreach ($line in $netNewLines) { if ($line.Trim()) { $netRecords += ($line | ConvertFrom-Json) } }
$procTypeCounts = @{}
foreach ($rec in $procRecords) { $key = [string]$rec.record_type; if (-not $procTypeCounts.ContainsKey($key)) { $procTypeCounts[$key] = 0 }; $procTypeCounts[$key]++ }
$result = [ordered]@{
  IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
  AgentReachedPhase2 = $started
  ProcessFile = $processFile.FullName
  NetworkFile = $networkFile.FullName
  AppsFile = $appsFile.FullName
  ProcessNewCount = $procRecords.Count
  ProcessTypes = (($procTypeCounts.GetEnumerator() | Sort-Object Name | ForEach-Object { "{0}:{1}" -f $_.Name, $_.Value }) -join ', ')
  NetworkInProcessFile = (@($procRecords | Where-Object { $_.record_type -eq 'network_connection' })).Count
  EnrichmentUpdateCount = (@($procRecords | Where-Object { $_.record_type -eq 'process_enrichment_update' })).Count
  EnrichmentUpdatesWithPath = (@($procRecords | Where-Object { $_.record_type -eq 'process_enrichment_update' -and -not [string]::IsNullOrWhiteSpace($_.image_path) })).Count
  EnrichmentUpdatesWithHash = (@($procRecords | Where-Object { $_.record_type -eq 'process_enrichment_update' -and -not [string]::IsNullOrWhiteSpace($_.sha256_hash) })).Count
  StartCount = (@($procRecords | Where-Object { $_.record_type -eq 'process_start' })).Count
  StopCount = (@($procRecords | Where-Object { $_.record_type -eq 'process_stop' })).Count
  StartWithImagePath = (@($procRecords | Where-Object { $_.record_type -eq 'process_start' -and -not [string]::IsNullOrWhiteSpace($_.image_path) })).Count
  StartWithHash = (@($procRecords | Where-Object { $_.record_type -eq 'process_start' -and -not [string]::IsNullOrWhiteSpace($_.sha256_hash) })).Count
  NetworkNewCount = $netRecords.Count
  NetworkMissingLocalIP = (@($netRecords | Where-Object { [string]::IsNullOrWhiteSpace($_.local_ip) })).Count
  NetworkMissingDirection = (@($netRecords | Where-Object { [string]::IsNullOrWhiteSpace($_.direction) })).Count
  NetworkMissingLocalPort = (@($netRecords | Where-Object { $_.local_port -eq 0 })).Count
  AppsNewCount = $appsNewLines.Count
  LogNewCount = $logNewLines.Count
  SampleProcessRecords = @($procRecords | Select-Object -First 5)
  SampleNetworkRecords = @($netRecords | Select-Object -First 5)
}
$result | ConvertTo-Json -Depth 6 | Set-Content -Path (Join-Path $root 'admin-phase2-validate.json') -Encoding UTF8
