# Exionis SWG - Phase 1 and Phase 2 Working Guide

## Executive Summary

Exionis now has a working two-phase pipeline:

- Phase 1 builds host identity and application inventory
- Phase 2 captures live process and network telemetry from ETW

The current implementation is good enough to produce useful endpoint telemetry today, especially around:

- process lifecycle
- parent-child execution context
- process-to-network correlation
- NDJSON output for later backend ingestion
- summary-first baseline telemetry with optional deep local capture

## Phase 1

Phase 1 is the static host visibility layer.

What it does:

- generates a stable device ID
- enumerates installed applications from the registry
- extracts publisher, version, uninstall data, install location, and size hints
- applies app-level risk heuristics
- writes inventory records to `apps_<device>_<date>.ndjson`

Primary files:

- [D:\Project\Exionis-swg\agent\internal\utils\deviceid.go](D:/Project/Exionis-swg/agent/internal/utils/deviceid.go)
- [D:\Project\Exionis-swg\agent\internal\inventory\apps.go](D:/Project/Exionis-swg/agent/internal/inventory/apps.go)
- [D:\Project\Exionis-swg\agent\internal\output\file_output.go](D:/Project/Exionis-swg/agent/internal/output/file_output.go)

## Phase 2

Phase 2 is the live telemetry layer.

What it does:

- starts the `NT Kernel Logger`
- captures process start and stop ETW events
- captures TCP and UDP ETW events
- correlates process and network activity
- enriches processes with file and user metadata
- emits structured records to stdout
- summarizes them into baseline execution, edge, and network-rollup records
- optionally stores deep local forensic bundles

Primary files:

- [D:\Project\Exionis-swg\agent\internal\etw\etw_bridge.c](D:/Project/Exionis-swg/agent/internal/etw/etw_bridge.c)
- [D:\Project\Exionis-swg\agent\internal\etw\etw_native_engine.go](D:/Project/Exionis-swg/agent/internal/etw/etw_native_engine.go)
- [D:\Project\Exionis-swg\agent\internal\correlation\engine.go](D:/Project/Exionis-swg/agent/internal/correlation/engine.go)
- [D:\Project\Exionis-swg\agent\internal\process\collector.go](D:/Project/Exionis-swg/agent/internal/process/collector.go)

## What Was Fixed Recently

This part matters because it explains why the current process pipeline is now trustworthy.

The main repairs were:

1. native process decode in C now recognizes `DC_START` and `DC_END`
2. PID extraction became version-aware
3. process stop detail includes image data when ETW provides it
4. the Go ETW bridge stopped sending unrelated ETW traffic into the process channel
5. the correlation engine now starts before ETW starts sending events
6. the process-start deadlock in `HandleProcessStart()` was removed
7. aggressive spawn aggregation was relaxed
8. stop fallback was improved so process stop rows can recover image and parent context even when the process is already gone

## Process Genealogy

Yes, process genealogy is implemented now.

Current genealogy fields in the runtime event model:

- `ppid`
- `parent_image`
- `grandparent_image`
- `chain`
- `depth`

This is already useful for chains like:

- `explorer.exe > Codex.exe > powershell.exe`
- `powershell.exe > Notepad.exe`
- `Codex.exe > powershell.exe > conhost.exe`

That makes the agent much more useful for:

- LOLBins
- script abuse
- macro malware
- persistence chains
- lateral movement
- ransomware ancestry

Baseline durability now includes richer genealogy than before:

- `process_execution` rows store `parent_execution_id`, `root_execution_id`, `parent_image`, `grandparent_image`, `chain`, and `depth`
- `process_edge` rows store the durable parent -> child graph
- raw lifecycle files are now optional compatibility outputs instead of the default storage model

## Current Workflow

The live workflow is:

1. initialize device ID, sinks, and privileges
2. run app inventory
3. build the initial process table
4. seed the telemetry controller with already-running processes
5. start the correlation engine
6. start the ETW listener
7. receive ETW callbacks in C
8. translate them into Go events
9. correlate, enrich, and emit process and network telemetry
10. write baseline summaries or deep local capture artifacts depending on mode

## Output Files

Phase 1 output:

- `C:\ProgramData\Exionis\output\apps_<device_id>_<date>.ndjson`

Phase 2 output:

- `C:\ProgramData\Exionis\output\process_execution_<device_id>_<date>.ndjson`
- `C:\ProgramData\Exionis\output\process_edge_<device_id>_<date>.ndjson`
- `C:\ProgramData\Exionis\output\network_rollup_<device_id>_<date>.ndjson`
- `C:\ProgramData\Exionis\output\telemetry_mode_<device_id>_<date>.ndjson`

Deep mode output:

- `C:\ProgramData\Exionis\deep\deep_capture_<device_id>_<session>.ndjson.gz`

Combined sink:

- `C:\ProgramData\Exionis\logs\agent.ndjson`

## Current Architecture Assessment

The directory structure is acceptable for the current stage:

- `cmd/agent` as entrypoint
- `internal/etw` for native capture
- `internal/correlation` for runtime logic
- `internal/telemetry` for baseline/deep mode shaping and deep capture lifecycle
- `internal/process` for metadata helpers
- `internal/inventory` for Phase 1 inventory
- `internal/output` and `internal/logger` for persistence

The main thing that will hurt future scale is:

- [D:\Project\Exionis-swg\agent\internal\correlation\engine.go](D:/Project/Exionis-swg/agent/internal/correlation/engine.go)

That file currently owns too much of the system.

## Recommended Future Structure

For cleaner scale, move toward:

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

Best next refactor:

1. extract a dedicated `lineage` package
2. store process instances by `PID + StartTime`
3. reconstruct ancestry from registry state instead of relying mostly on flat strings
4. keep `detect` logic separate from capture and correlation

## Delivery Roadmap

The active delivery roadmap now lives in:

- [D:\Project\Exionis-swg\ROADMAP.md](D:/Project/Exionis-swg/ROADMAP.md)

That is the direction you want if the end goal is deep execution trees like:

- `winword.exe > cmd.exe > powershell.exe > certutil.exe`

## Mermaid Files

Updated raw Mermaid source is stored here:

- [D:\Project\Exionis-swg\architecture.mmd](D:/Project/Exionis-swg/architecture.mmd)
- [D:\Project\Exionis-swg\Architecutr_worflow\project_workflow.mmd](D:/Project/Exionis-swg/Architecutr_worflow/project_workflow.mmd)
- [D:\Project\Exionis-swg\Architecutr_worflow\process_genealogy.mmd](D:/Project/Exionis-swg/Architecutr_worflow/process_genealogy.mmd)

These are raw Mermaid files without code fences, so they work better with Mermaid live editors.
