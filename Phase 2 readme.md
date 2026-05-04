# Exionis Agent - Phase 2

## Process and Network Telemetry

Status:

- implemented
- validated on Windows with Administrator runtime
- `process_start` and `process_stop` now emit correctly
- process stop fallback no longer leaves `unknown_process` rows in the latest validated process file
- telemetry modes now support `baseline` and `deep`

## What Phase 2 Does

Phase 2 converts raw Windows kernel ETW events into structured telemetry for:

- process lifecycle
- process genealogy
- process-to-network correlation
- summary-first NDJSON export for local analysis and cloud ingestion
- local forensic bundle capture in deep mode

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
- baseline summary shaping for lower-cost always-on collection
- deep local capture for short-lived investigations

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

- stdout and the in-memory structured event path still carry the richest event-by-event view
- baseline persistence now writes genealogy into `process_execution` rows with `parent_execution_id`, `root_execution_id`, `parent_image`, `grandparent_image`, `chain`, and `depth`
- legacy raw `processes_*.ndjson` and `network_*.ndjson` files are optional and disabled by default
- process and app outputs no longer include `is_signed`

## Runtime Architecture

The working order today is:

1. initialize device ID, sinks, and privileges
2. load network filtering config
3. build an initial process snapshot
4. seed the telemetry controller with already-running processes
5. start the correlation engine
6. start the ETW listener
7. receive native ETW callbacks in C
8. normalize events into Go structs
9. correlate, enrich, and emit process and network records
10. summarize them into baseline records or store them in a deep local capture bundle

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

Telemetry shaping:

- [D:\Project\Exionis-swg\agent\internal\telemetry\config.go](D:/Project/Exionis-swg/agent/internal/telemetry/config.go)
- [D:\Project\Exionis-swg\agent\internal\telemetry\controller.go](D:/Project/Exionis-swg/agent/internal/telemetry/controller.go)
- [D:\Project\Exionis-swg\agent\internal\telemetry\types.go](D:/Project/Exionis-swg/agent/internal/telemetry/types.go)

Output:

- [D:\Project\Exionis-swg\agent\internal\output\file_output.go](D:/Project/Exionis-swg/agent/internal/output/file_output.go)
- [D:\Project\Exionis-swg\agent\internal\logger\file_sink.go](D:/Project/Exionis-swg/agent/internal/logger/file_sink.go)

## Output Files

Baseline files:

- `C:\ProgramData\Exionis\output\process_execution_<device_id>_<date>.ndjson`
- `C:\ProgramData\Exionis\output\process_edge_<device_id>_<date>.ndjson`
- `C:\ProgramData\Exionis\output\network_rollup_<device_id>_<date>.ndjson`
- `C:\ProgramData\Exionis\output\telemetry_mode_<device_id>_<date>.ndjson`

Deep capture:

- `C:\ProgramData\Exionis\deep\deep_capture_<device_id>_<session>.ndjson.gz`

Combined sink:

- `C:\ProgramData\Exionis\logs\agent.ndjson`

Current behavior:

- baseline mode writes summary-first records only
- deep mode keeps the same baseline files and also writes a local gzip forensic bundle
- legacy raw process and network files are only written when `EXIONIS_WRITE_LEGACY_RAW=1`

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
$env:EXIONIS_TELEMETRY_MODE='baseline'
$env:EXIONIS_DEBUG='1'
.\exionis-agent.exe > output.log 2> debug.log
```

Deep mode:

```powershell
cd D:\Project\Exionis-swg\agent

Remove-Item .\output.log,.\debug.log -Force -ErrorAction SilentlyContinue
$env:EXIONIS_TELEMETRY_MODE='deep'
$env:EXIONIS_DEEP_DURATION_MINUTES='30'
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
Get-Content "C:\ProgramData\Exionis\output\process_execution_*.ndjson"
Get-Content "C:\ProgramData\Exionis\output\process_edge_*.ndjson"
Get-Content "C:\ProgramData\Exionis\output\network_rollup_*.ndjson"
```

## What Good Output Looks Like

Good signs:

- `debug.log` shows `PROCESS_START` and `PROCESS_STOP`
- `output.log` shows `process_start` and `process_stop`
- `process_execution_*.ndjson` contains finished process runs
- `process_edge_*.ndjson` contains parent-child edges
- network rollups continue to flow

## Known Boundaries

These are still worth keeping in view:

1. full durable lineage persistence is not complete yet because the process file schema does not yet store the entire runtime chain model
2. very short-lived processes can still have partial start-time enrichment
3. file-summary and DLP policy streams are future work
4. the correlation package is cleaner now, but long-term scale still points toward a dedicated lineage package
5. DNS is still enrichment-driven rather than full DNS-client ETW ingestion

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
