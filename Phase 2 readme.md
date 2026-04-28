# Exionis Agent - Phase 2

## Process and Network Telemetry

Status:

- implemented
- validated on Windows with Administrator runtime
- `process_start` and `process_stop` now emit correctly
- process stop fallback no longer leaves `unknown_process` rows in the latest validated process file

## What Phase 2 Does

Phase 2 converts raw Windows kernel ETW events into structured telemetry for:

- process lifecycle
- process genealogy
- process-to-network correlation
- NDJSON export for local analysis and cloud ingestion

It is built on the `NT Kernel Logger` session and captures:

- process start
- process stop
- TCP activity
- UDP activity

## Latest Verified Improvements

The most important validated fixes are:

1. `DC_START` and `DC_END` process opcodes are recognized in the native ETW bridge.
2. PID extraction in the C layer is version-aware.
3. process stop detail includes image data when ETW exposes it.
4. the Go ETW wrapper forwards only process lifecycle events into `events.ProcessChan`.
5. the correlation engine starts before ETW starts sending events.
6. the process-start deadlock in `HandleProcessStart()` is fixed.
7. aggregation was relaxed so startup bursts are not wrongly suppressed.
8. stop fallback now rebuilds context from ETW detail, PID caches, and snapshot state.

Those changes moved the agent from:

- zero real `process_start` output

to:

- stable `process_start`
- stable `process_stop`
- working parent-child correlation
- clean process and network output separation

## Process Genealogy

Phase 2 now emits genealogy context in the live structured event path.

Current runtime genealogy fields:

- `ppid`
- `parent_image`
- `grandparent_image`
- `chain`
- `depth`

Example chains now visible in the runtime output:

- `explorer.exe > Codex.exe > powershell.exe`
- `powershell.exe > Notepad.exe`
- `Codex.exe > powershell.exe > conhost.exe`

Why this matters:

- LOLBins
- macro malware
- script abuse
- lateral movement
- persistence chains
- ransomware execution trees

Important schema note:

- stdout and the in-memory structured event path carry the richer genealogy fields
- the persisted process NDJSON schema currently keeps `ppid` and `parent_image`, but not the full `chain` / `depth` set yet
- process and app outputs no longer include `is_signed`

So the genealogy logic is live, but the durable file schema still has room to grow.

## Runtime Architecture

The working order today is:

1. initialize device ID, sinks, and privileges
2. load network filtering config
3. build an initial process snapshot
4. start the correlation engine
5. start the ETW listener
6. receive native ETW callbacks in C
7. normalize events into Go structs
8. correlate, enrich, and emit process and network records

## Key Modules

Entry point:

- [D:\Project\Exionis-swg\agent\cmd\agent\main.go](D:/Project/Exionis-swg/agent/cmd/agent/main.go)

Native ETW layer:

- [D:\Project\Exionis-swg\agent\internal\etw\etw_bridge.c](D:/Project/Exionis-swg/agent/internal/etw/etw_bridge.c)
- [D:\Project\Exionis-swg\agent\internal\etw\etw_bridge.h](D:/Project/Exionis-swg/agent/internal/etw/etw_bridge.h)
- [D:\Project\Exionis-swg\agent\internal\etw\etw_native_engine.go](D:/Project/Exionis-swg/agent/internal/etw/etw_native_engine.go)

Correlation and lineage:

- [D:\Project\Exionis-swg\agent\internal\correlation\engine.go](D:/Project/Exionis-swg/agent/internal/correlation/engine.go)
- [D:\Project\Exionis-swg\agent\internal\correlation\lineage.go](D:/Project/Exionis-swg/agent/internal/correlation/lineage.go)
- [D:\Project\Exionis-swg\agent\internal\correlation\enrichment.go](D:/Project/Exionis-swg/agent/internal/correlation/enrichment.go)
- [D:\Project\Exionis-swg\agent\internal\correlation\emitters.go](D:/Project/Exionis-swg/agent/internal/correlation/emitters.go)
- [D:\Project\Exionis-swg\agent\internal\correlation\aggregation.go](D:/Project/Exionis-swg/agent/internal/correlation/aggregation.go)
- [D:\Project\Exionis-swg\agent\internal\correlation\maintenance.go](D:/Project/Exionis-swg/agent/internal/correlation/maintenance.go)
- [D:\Project\Exionis-swg\agent\internal\correlation\risk.go](D:/Project/Exionis-swg/agent/internal/correlation/risk.go)
- [D:\Project\Exionis-swg\agent\internal\correlation\models.go](D:/Project/Exionis-swg/agent/internal/correlation/models.go)

Process metadata:

- [D:\Project\Exionis-swg\agent\internal\process\collector.go](D:/Project/Exionis-swg/agent/internal/process/collector.go)

Output:

- [D:\Project\Exionis-swg\agent\internal\output\file_output.go](D:/Project/Exionis-swg/agent/internal/output/file_output.go)
- [D:\Project\Exionis-swg\agent\internal\logger\file_sink.go](D:/Project/Exionis-swg/agent/internal/logger/file_sink.go)

## Output Files

Process file:

- `C:\ProgramData\Exionis\output\processes_<device_id>_<date>.ndjson`

Network file:

- `C:\ProgramData\Exionis\output\network_<device_id>_<date>.ndjson`

Combined sink:

- `C:\ProgramData\Exionis\logs\agent.ndjson`

Current behavior:

- process events stay in the process file
- network events stay in the network file
- the combined sink holds mixed event types for debugging and export

## Build and Test

Use an Administrator PowerShell.

Build:

```powershell
cd D:\Project\Exionis-swg\agent

$env:PATH='C:\msys64\ucrt64\bin;'+$env:PATH
$env:CGO_ENABLED='1'
$env:CC='gcc'

go clean -cache
go build -o exionis-agent.exe ./cmd/agent/
```

Run:

```powershell
cd D:\Project\Exionis-swg\agent

Remove-Item .\output.log,.\debug.log -Force -ErrorAction SilentlyContinue
$env:EXIONIS_DEBUG='1'
.\exionis-agent.exe > output.log 2> debug.log
```

In another Administrator shell:

```powershell
Start-Process notepad.exe
Start-Process powershell.exe -ArgumentList "-NoProfile","-Command","Start-Sleep -Seconds 2"
```

Then stop the agent and inspect:

```powershell
Select-String -Path .\debug.log -Pattern "PROCESS_START","PROCESS_STOP"
Select-String -Path .\output.log -Pattern '"event_type":"process_start"','"event_type":"process_stop"'
Get-Content "C:\ProgramData\Exionis\output\processes_*.ndjson"
Get-Content "C:\ProgramData\Exionis\output\network_*.ndjson"
```

## What Good Output Looks Like

Good signs:

- `debug.log` shows `PROCESS_START` and `PROCESS_STOP`
- `output.log` shows `process_start` and `process_stop`
- the process NDJSON file contains the launched processes
- network records continue to flow
- process rows no longer fall back to `unknown_process`

## Known Boundaries

These are still worth keeping in view:

1. full durable lineage persistence is not complete yet because the process file schema does not yet store the entire runtime chain model
2. very short-lived processes can still have partial start-time enrichment
3. the correlation package is cleaner now, but long-term scale still points toward a dedicated lineage package
4. DNS is still enrichment-driven rather than full DNS-client ETW ingestion

## Best Next Architecture Move

For future scale, the strongest next step is a dedicated `lineage` package.

Recommended direction:

- move genealogy building out of `engine.go`
- key process instances by `PID + StartTime`
- reconstruct full ancestry on demand
- let future detection code consume lineage-aware process objects instead of flat event rows

That will support deeper chains such as:

- `winword.exe > cmd.exe > powershell.exe > certutil.exe`

with much better long-term fidelity.

## Mermaid Sources

Updated raw Mermaid source is here:

- [D:\Project\Exionis-swg\Architecutr_worflow\project_workflow.mmd](D:/Project/Exionis-swg/Architecutr_worflow/project_workflow.mmd)
- [D:\Project\Exionis-swg\Architecutr_worflow\process_genealogy.mmd](D:/Project/Exionis-swg/Architecutr_worflow/process_genealogy.mmd)

These files are stored without Markdown fences so they can be pasted directly into Mermaid editors.
