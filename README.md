# Exionis SWG Agent

## Overview

Exionis is a Windows telemetry agent built in Go with a CGO bridge to native C ETW capture.

It currently has two working layers:

- Phase 1: device shadowing and installed application inventory
- Phase 2: real-time process and network telemetry from the Windows kernel

The codebase is built around a simple split of responsibilities:

1. C handles ETW session management and ABI-sensitive callback parsing.
2. Go handles correlation, enrichment, output, and long-lived runtime state.
3. NDJSON is the transport format for stdout, local files, and later cloud ingestion.

## Current Status

The latest validated state is:

- ETW kernel session starts successfully
- network events flow correctly
- `process_start` and `process_stop` both flow correctly
- the process pipeline no longer loses starts behind non-process ETW traffic
- stop-only `unknown_process` noise was eliminated in the latest validated process file
- process genealogy is present in the live structured event path
- the `is_signed` feature has been removed from app and process outputs

The major fixes behind the current runtime are:

- `DC_START` and `DC_END` process opcodes are recognized in the C bridge
- version-aware PID extraction is used in ETW process parsing
- process stop detail now includes image data when ETW exposes it
- the Go ETW bridge forwards only `PROCESS_START` and `PROCESS_STOP` into `events.ProcessChan`
- the correlation engine starts before the ETW listener
- the process-start deadlock in `HandleProcessStart()` was removed
- startup aggregation was relaxed from a 2 second / second-event suppression pattern to a 30 second / 10+ burst threshold
- stop fallback now rebuilds process context from ETW detail, PID caches, and snapshots

## Phase 1

Phase 1 is the baseline host inventory layer.

It currently provides:

- stable device ID generation
- installed application inventory from registry hives
- publisher, version, install path, uninstall string, size, and source hints
- app-level risk heuristics
- NDJSON persistence for later upload or reconciliation

Main code paths:

- [D:\Project\Exionis-swg\agent\internal\utils\deviceid.go](D:/Project/Exionis-swg/agent/internal/utils/deviceid.go)
- [D:\Project\Exionis-swg\agent\internal\inventory\apps.go](D:/Project/Exionis-swg/agent/internal/inventory/apps.go)
- [D:\Project\Exionis-swg\agent\internal\output\file_output.go](D:/Project/Exionis-swg/agent/internal/output/file_output.go)
- [D:\Project\Exionis-swg\agent\internal\logger\file_sink.go](D:/Project/Exionis-swg/agent/internal/logger/file_sink.go)

## Phase 2

Phase 2 is the live telemetry layer.

It currently provides:

- native ETW kernel trace session management
- process start and stop telemetry
- TCP and UDP event capture
- process-to-network correlation
- process bootstrap for pre-existing processes
- best-effort process enrichment for path, hash, SID, username, and system classification
- follow-up `process_enrichment_update` events when metadata arrives after start
- stop fallback recovery using ETW detail, PID caches, and snapshots
- separated process and network NDJSON outputs

Main code paths:

- [D:\Project\Exionis-swg\agent\internal\etw\etw_bridge.c](D:/Project/Exionis-swg/agent/internal/etw/etw_bridge.c)
- [D:\Project\Exionis-swg\agent\internal\etw\etw_bridge.h](D:/Project/Exionis-swg/agent/internal/etw/etw_bridge.h)
- [D:\Project\Exionis-swg\agent\internal\etw\etw_native_engine.go](D:/Project/Exionis-swg/agent/internal/etw/etw_native_engine.go)
- [D:\Project\Exionis-swg\agent\internal\events\events.go](D:/Project/Exionis-swg/agent/internal/events/events.go)
- [D:\Project\Exionis-swg\agent\internal\correlation\engine.go](D:/Project/Exionis-swg/agent/internal/correlation/engine.go)
- [D:\Project\Exionis-swg\agent\internal\correlation\lineage.go](D:/Project/Exionis-swg/agent/internal/correlation/lineage.go)
- [D:\Project\Exionis-swg\agent\internal\correlation\enrichment.go](D:/Project/Exionis-swg/agent/internal/correlation/enrichment.go)
- [D:\Project\Exionis-swg\agent\internal\correlation\emitters.go](D:/Project/Exionis-swg/agent/internal/correlation/emitters.go)
- [D:\Project\Exionis-swg\agent\internal\correlation\aggregation.go](D:/Project/Exionis-swg/agent/internal/correlation/aggregation.go)
- [D:\Project\Exionis-swg\agent\internal\correlation\maintenance.go](D:/Project/Exionis-swg/agent/internal/correlation/maintenance.go)
- [D:\Project\Exionis-swg\agent\internal\correlation\risk.go](D:/Project/Exionis-swg/agent/internal/correlation/risk.go)
- [D:\Project\Exionis-swg\agent\internal\correlation\models.go](D:/Project/Exionis-swg/agent/internal/correlation/models.go)
- [D:\Project\Exionis-swg\agent\internal\process\collector.go](D:/Project/Exionis-swg/agent/internal/process/collector.go)

## Process Genealogy

Process genealogy is implemented now.

The current runtime genealogy model tracks:

- `ppid`
- `parent_image`
- `grandparent_image`
- `chain`
- `depth`
- internal `rootPID` tracking in the in-memory registry

That is enough to surface meaningful chains such as:

- `explorer.exe > Codex.exe > powershell.exe`
- `powershell.exe > Notepad.exe`
- `Codex.exe > powershell.exe > conhost.exe`

This is useful for:

- LOLBins
- macro malware
- script abuse
- lateral movement
- persistence chains
- ransomware execution trees

Important accuracy note:

- live structured events and stdout include richer genealogy fields such as `grandparent_image`, `chain`, and `depth`
- the persisted process NDJSON file currently stores `ppid` and `parent_image`, but not the full chain fields

## Working Runtime Flow

The current runtime order is:

1. `main.go` initializes device ID, sinks, config, and privileges.
2. Phase 1 inventory runs and writes app records.
3. the initial process table is populated from a live snapshot
4. the correlation engine starts before ETW
5. the C ETW bridge starts `NT Kernel Logger`
6. ETW callbacks are normalized and pushed into Go channels
7. the correlation engine emits structured process and network events
8. stdout, the combined sink, and dedicated NDJSON outputs receive the normalized records

## Output Files

Dedicated output files:

- `C:\ProgramData\Exionis\output\apps_<device_id>_<date>.ndjson`
- `C:\ProgramData\Exionis\output\processes_<device_id>_<date>.ndjson`
- `C:\ProgramData\Exionis\output\network_<device_id>_<date>.ndjson`

Combined operational sink:

- `C:\ProgramData\Exionis\logs\agent.ndjson`

Current output behavior:

- process records are written to the process file
- network records are written to the network file
- app inventory is written to the app file
- app and process outputs no longer include `is_signed`
- the combined sink carries mixed event types for local debugging and bulk export

## Build and Run

Requirements:

- Windows
- Go
- CGO enabled
- a working C compiler such as MSYS2 `gcc`
- Administrator shell

Recommended build:

```powershell
$env:PATH='C:\msys64\ucrt64\bin;'+$env:PATH
$env:CGO_ENABLED='1'
$env:CC='gcc'

cd D:\Project\Exionis-swg\agent
go clean -cache
go build -o exionis-agent.exe ./cmd/agent/
```

Recommended test run:

```powershell
cd D:\Project\Exionis-swg\agent

Remove-Item .\output.log,.\debug.log -Force -ErrorAction SilentlyContinue
$env:EXIONIS_DEBUG='1'
.\exionis-agent.exe > output.log 2> debug.log
```

After that, launch short-lived processes such as `notepad.exe` and `powershell.exe`, then stop the agent and inspect:

- [D:\Project\Exionis-swg\agent\output.log](D:/Project/Exionis-swg/agent/output.log)
- [D:\Project\Exionis-swg\agent\debug.log](D:/Project/Exionis-swg/agent/debug.log)
- `C:\ProgramData\Exionis\output\processes_*.ndjson`
- `C:\ProgramData\Exionis\output\network_*.ndjson`

## Repository Structure

The current layout is in a better place now:

- `cmd/agent` is split between orchestration, inventory scheduling, and output workers
- `internal/etw` isolates native ETW capture
- `internal/correlation` is split by responsibility instead of depending on one oversized file
- `internal/process` owns process metadata helpers
- `internal/output` and `internal/logger` own persistence paths
- `internal/inventory` owns app inventory

The key structure improvements already applied are:

- [D:\Project\Exionis-swg\agent\cmd\agent\main.go](D:/Project/Exionis-swg/agent/cmd/agent/main.go) is back to orchestration
- [D:\Project\Exionis-swg\agent\cmd\agent\inventory_runner.go](D:/Project/Exionis-swg/agent/cmd/agent/inventory_runner.go) owns the inventory flow
- [D:\Project\Exionis-swg\agent\cmd\agent\output_workers.go](D:/Project/Exionis-swg/agent/cmd/agent/output_workers.go) owns stdout and NDJSON writer loops
- the correlation package is split across lineage, enrichment, emitters, risk, aggregation, and maintenance files

## Recommended Scale-Up Direction

For future scale, the best next architecture is a dedicated lineage subsystem.

Recommended direction:

```text
agent/
  cmd/agent/
  internal/
    intake/etw/
    lineage/
    process/
    network/
    enrich/
    detect/
    sink/
    inventory/
    config/
```

The highest-value refactor would be:

1. create a dedicated `lineage` package
2. key process instances by `PID + StartTime`, not PID alone
3. reconstruct full ancestry on demand instead of relying mostly on prebuilt strings
4. move rule logic to a future `detect` layer that consumes lineage-aware process objects

That will scale better for:

- deep ancestry like `winword.exe > cmd.exe > powershell.exe > certutil.exe`
- durable lineage reconstruction
- detection content built on ancestry instead of flat rows

## Mermaid Sources

The updated Mermaid source files are stored here:

- [D:\Project\Exionis-swg\architecture.mmd](D:/Project/Exionis-swg/architecture.mmd)
- [D:\Project\Exionis-swg\Architecutr_worflow\project_workflow.mmd](D:/Project/Exionis-swg/Architecutr_worflow/project_workflow.mmd)
- [D:\Project\Exionis-swg\Architecutr_worflow\process_genealogy.mmd](D:/Project/Exionis-swg/Architecutr_worflow/process_genealogy.mmd)

These files are raw Mermaid source without Markdown fences so they can be pasted directly into Mermaid editors.
