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
- telemetry is now mode-aware with `baseline` and `deep` operating modes
- baseline mode writes summary-first records instead of raw lifecycle files by default
- deep mode writes a local gzip forensic capture bundle for later upload

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
- mode-aware summary output for baseline operations
- local deep capture bundles for targeted investigations

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
- [D:\Project\Exionis-swg\agent\internal\telemetry\config.go](D:/Project/Exionis-swg/agent/internal/telemetry/config.go)
- [D:\Project\Exionis-swg\agent\internal\telemetry\controller.go](D:/Project/Exionis-swg/agent/internal/telemetry/controller.go)
- [D:\Project\Exionis-swg\agent\internal\telemetry\types.go](D:/Project/Exionis-swg/agent/internal/telemetry/types.go)

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

- live structured events and stdout still carry the richest event-by-event genealogy view
- baseline persistence now stores genealogy on `process_execution` summary rows through fields such as `parent_image`, `grandparent_image`, `chain`, `depth`, `parent_execution_id`, and `root_execution_id`
- the old raw `processes_*.ndjson` file is now optional and intended mainly for deep or compatibility scenarios

## Working Runtime Flow

The current runtime order is:

1. `main.go` initializes device ID, sinks, config, and privileges.
2. Phase 1 inventory runs and writes app records.
3. the initial process table is populated from a live snapshot
4. the telemetry controller seeds an execution registry for already-running processes
5. the correlation engine starts before ETW
6. the C ETW bridge starts `NT Kernel Logger`
7. ETW callbacks are normalized and pushed into Go channels
8. the correlation engine emits structured process and network events
9. baseline mode summarizes them into durable execution, edge, and rollup records
10. deep mode additionally stores a local gzip forensic bundle for later upload

## Output Files

Dedicated output files:

- `C:\ProgramData\Exionis\output\apps_<device_id>_<date>.ndjson`
- `C:\ProgramData\Exionis\output\process_execution_<device_id>_<date>.ndjson`
- `C:\ProgramData\Exionis\output\process_edge_<device_id>_<date>.ndjson`
- `C:\ProgramData\Exionis\output\network_rollup_<device_id>_<date>.ndjson`
- `C:\ProgramData\Exionis\output\telemetry_mode_<device_id>_<date>.ndjson`

Combined operational sink:

- `C:\ProgramData\Exionis\logs\agent.ndjson`

Current output behavior:

- app inventory is written to the app file
- baseline mode writes summary-first process, edge, network rollup, and mode-audit records
- legacy raw `processes_*.ndjson` and `network_*.ndjson` are disabled by default and can be re-enabled with `EXIONIS_WRITE_LEGACY_RAW=1`
- deep mode writes a local `deep_capture_*.ndjson.gz` bundle under `C:\ProgramData\Exionis\deep` by default
- app and process outputs no longer include `is_signed`
- the combined sink is no longer the primary raw event store in baseline mode

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
$env:EXIONIS_TELEMETRY_MODE='baseline'
$env:EXIONIS_DEBUG='1'
.\exionis-agent.exe > output.log 2> debug.log
```

Deep-mode test run:

```powershell
cd D:\Project\Exionis-swg\agent

Remove-Item .\output.log,.\debug.log -Force -ErrorAction SilentlyContinue
$env:EXIONIS_TELEMETRY_MODE='deep'
$env:EXIONIS_DEEP_DURATION_MINUTES='30'
$env:EXIONIS_DEBUG='1'
.\exionis-agent.exe > output.log 2> debug.log
```

After that, launch short-lived processes such as `notepad.exe` and `powershell.exe`, then stop the agent and inspect:

- [D:\Project\Exionis-swg\agent\output.log](D:/Project/Exionis-swg/agent/output.log)
- [D:\Project\Exionis-swg\agent\debug.log](D:/Project/Exionis-swg/agent/debug.log)
- `C:\ProgramData\Exionis\output\process_execution_*.ndjson`
- `C:\ProgramData\Exionis\output\process_edge_*.ndjson`
- `C:\ProgramData\Exionis\output\network_rollup_*.ndjson`
- `C:\ProgramData\Exionis\deep\deep_capture_*.ndjson.gz`

## Repository Structure

The current layout is in a better place now:

- `cmd/agent` is split between orchestration, inventory scheduling, and output workers
- `internal/etw` isolates native ETW capture
- `internal/correlation` is split by responsibility instead of depending on one oversized file
- `internal/telemetry` now owns baseline/deep mode policy, execution summaries, and deep capture lifecycle
- `internal/process` owns process metadata helpers
- `internal/output` and `internal/logger` own persistence paths
- `internal/inventory` owns app inventory

The key structure improvements already applied are:

- [D:\Project\Exionis-swg\agent\cmd\agent\main.go](D:/Project/Exionis-swg/agent/cmd/agent/main.go) is back to orchestration
- [D:\Project\Exionis-swg\agent\cmd\agent\inventory_runner.go](D:/Project/Exionis-swg/agent/cmd/agent/inventory_runner.go) owns the inventory flow
- [D:\Project\Exionis-swg\agent\cmd\agent\output_workers.go](D:/Project/Exionis-swg/agent/cmd/agent/output_workers.go) owns the channel-to-telemetry routing loops
- the correlation package is split across lineage, enrichment, emitters, risk, aggregation, and maintenance files
- the telemetry package keeps summary shaping and deep forensic capture out of the ETW and correlation layers

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

## Roadmap

The current delivery roadmap is tracked here:

- [D:\Project\Exionis-swg\ROADMAP.md](D:/Project/Exionis-swg/ROADMAP.md)

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
