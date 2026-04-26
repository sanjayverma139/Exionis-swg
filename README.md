# Exionis SWG Agent

## Overview

Exionis is a Windows telemetry agent built in Go with a native C ETW bridge.
It currently implements two practical layers:

- Phase 1: device shadowing and asset intelligence
- Phase 2: real-time process and network telemetry

The project is designed around one core principle:

1. Native Windows event capture happens in C where ETW ABI handling is reliable.
2. Correlation, enrichment, and output orchestration happen in Go.
3. Output is written as NDJSON so the same records can be used locally, piped to tooling, or shipped to a cloud backend.

This README is the master reference for how the working codebase behaves today.

## Phase Breakdown

### Phase 1: Device Shadowing and Asset Intelligence

Phase 1 is the baseline visibility layer. Its purpose is to describe the device itself before live telemetry is considered.

Phase 1 currently provides:

- a stable device identifier derived from host-specific components
- installed application inventory from Windows uninstall registry hives
- app metadata such as publisher, version, install location, uninstall string, estimated size, and actual size when available
- basic security classification for software such as signing state, source inference, and heuristic risk scoring
- persistent NDJSON output suitable for later cloud synchronization

Main code paths:

- [deviceid.go](D:/Project/Exionis-swg/agent/internal/utils/deviceid.go)
- [apps.go](D:/Project/Exionis-swg/agent/internal/inventory/apps.go)
- [file_output.go](D:/Project/Exionis-swg/agent/internal/output/file_output.go)
- [file_sink.go](D:/Project/Exionis-swg/agent/internal/logger/file_sink.go)

### Phase 2: Real-Time Process and Network Telemetry

Phase 2 is the live monitoring layer. Its purpose is to capture process lifecycle and network activity from the Windows kernel, enrich it, correlate it, and emit normalized records.

Phase 2 currently provides:

- native ETW kernel trace session management
- process start and process stop telemetry
- TCP and UDP event capture
- process-to-network correlation
- reverse-DNS enrichment cache
- process bootstrap so the engine understands already-running processes
- async enrichment for executable path, hash, SID, username, and system classification
- late process enrichment follow-up records when metadata arrives after the initial start event
- output separation between process records and network records

Main code paths:

- [etw_bridge.c](D:/Project/Exionis-swg/agent/internal/etw/etw_bridge.c)
- [etw_bridge.h](D:/Project/Exionis-swg/agent/internal/etw/etw_bridge.h)
- [etw_native_engine.go](D:/Project/Exionis-swg/agent/internal/etw/etw_native_engine.go)
- [events.go](D:/Project/Exionis-swg/agent/internal/events/events.go)
- [engine.go](D:/Project/Exionis-swg/agent/internal/correlation/engine.go)
- [models.go](D:/Project/Exionis-swg/agent/internal/correlation/models.go)
- [collector.go](D:/Project/Exionis-swg/agent/internal/process/collector.go)

## Working Architecture

The current runtime architecture is:

1. `main.go` initializes identity, sinks, privileges, and bootstrap state.
2. Phase 1 inventory runs once at startup and writes app records.
3. The native ETW bridge starts `NT Kernel Logger` and consumes kernel process and network events.
4. ETW callbacks enter Go through typed event channels.
5. The correlation engine turns raw events into structured process and network records.
6. When late process metadata becomes available, the engine can emit a follow-up `process_enrichment_update`.
7. Process and network outputs are written to separate NDJSON streams.
8. A combined NDJSON audit sink captures mixed event types for local troubleshooting and bulk ingestion.

## Module Responsibilities

### Bootstrap and Main Control

[main.go](D:/Project/Exionis-swg/agent/cmd/agent/main.go) is the orchestrator.

It is responsible for:

- signal handling and graceful shutdown
- device ID resolution
- initializing the combined rotating log sink
- initializing dedicated output writers
- enabling required Windows privileges
- loading internal network filtering rules
- building the initial process table snapshot
- running app inventory
- starting the ETW listener
- launching correlation and output goroutines
- printing lightweight process snapshot summaries to stdout

### Privilege Layer

[privilege.go](D:/Project/Exionis-swg/agent/internal/config/privilege.go) enables:

- `SeDebugPrivilege`
- `SeSystemProfilePrivilege`

Purpose:

- `SeDebugPrivilege` improves access to process metadata
- `SeSystemProfilePrivilege` is required for reliable kernel ETW usage

This module is necessary because Exionis touches both protected process metadata and kernel trace infrastructure.

### Network Filtering Configuration

[network.go](D:/Project/Exionis-swg/agent/internal/config/network.go) defines which IP ranges are considered internal.

Purpose:

- suppress internal-only traffic from the ETW network pipeline when desired
- reduce noise in the network event stream

Default ranges include:

- loopback
- RFC1918 private IPv4 ranges
- IPv6 loopback
- link-local

### Native ETW Bridge

[etw_bridge.c](D:/Project/Exionis-swg/agent/internal/etw/etw_bridge.c) is the low-level telemetry capture layer.

It is responsible for:

- allocating `EVENT_TRACE_PROPERTIES`
- starting the kernel trace session
- opening the real-time ETW consumer
- processing ETW event records
- parsing process start and stop details
- parsing TCP and UDP payloads
- filtering loopback and internal traffic
- calling back into Go with normalized fields

This file is where Windows-specific ABI-sensitive work happens.

[etw_native_engine.go](D:/Project/Exionis-swg/agent/internal/etw/etw_native_engine.go) is the Go-facing ETW wrapper.

It is responsible for:

- converting Windows timestamps into Go `time.Time`
- mapping raw native callback arguments into Go event structs
- pushing process and network events into shared channels
- exposing `StartETWListener` and `StopETWListener`

### Shared Event Layer

[events.go](D:/Project/Exionis-swg/agent/internal/events/events.go) defines the shared data model between ETW and correlation.

It provides:

- `EventInput` for process and thread related ETW events
- `NetworkEvent` for parsed network activity
- `NetworkOutputRecord` for the final network file-writing contract
- shared buffered channels used across modules

### Correlation Engine

[engine.go](D:/Project/Exionis-swg/agent/internal/correlation/engine.go) is the center of the runtime intelligence layer.

It is responsible for:

- bootstrapping the process table with already-running processes
- maintaining the in-memory process registry
- linking parent and child processes
- converting raw ETW events into structured process lifecycle records
- emitting late enrichment updates without mutating the original lifecycle record
- tracking network connections per process
- reverse-DNS enrichment
- spawn aggregation
- TTL cleanup for stale processes and connections
- best-effort start-time enrichment and fallback stop-time enrichment

[models.go](D:/Project/Exionis-swg/agent/internal/correlation/models.go) defines the in-memory process, enrichment, connection, and structured output models used by the engine.

### Process Metadata Helpers

[collector.go](D:/Project/Exionis-swg/agent/internal/process/collector.go) provides the process helper functions used throughout the codebase.

It is responsible for:

- process enumeration
- command line retrieval
- executable path lookup
- parent PID resolution
- username and SID lookup
- process start time resolution
- file metadata lookups
- orphan detection helpers
- process architecture checks

### Output Layer

[file_output.go](D:/Project/Exionis-swg/agent/internal/output/file_output.go) is the dedicated structured export layer.

It writes three daily NDJSON streams:

- `apps_<device>_<date>.ndjson`
- `processes_<device>_<date>.ndjson`
- `network_<device>_<date>.ndjson`

Purpose:

- make each stream cloud-ingestible on its own
- separate app inventory from process lifecycle and network telemetry
- preserve a stable schema for later ETL or SIEM ingestion

[file_sink.go](D:/Project/Exionis-swg/agent/internal/logger/file_sink.go) is the rotating combined log sink.

Purpose:

- preserve a single mixed audit stream
- keep local operational debugging simple
- support bulk NDJSON ingestion without losing event order

## Output Contracts

### Apps Output

File pattern:

- `C:\ProgramData\Exionis\output\apps_<device_id>_<date>.ndjson`

Contains:

- only `installed_app` records

Purpose:

- device software inventory
- software risk assessment
- asset visibility for cloud synchronization

### Process Output

File pattern:

- `C:\ProgramData\Exionis\output\processes_<device_id>_<date>.ndjson`

Contains:

- `process_start`
- `process_stop`
- `process_spawn_aggregate`
- `process_enrichment_update`

Purpose:

- process lifecycle history
- parent-child relationships
- command-line and executable context when available
- process forensic timeline reconstruction

Important current behavior:

- process and network records are now separated correctly
- the process file no longer receives `network_connection` records
- late enrichment can appear as a separate `process_enrichment_update` row when the initial start record did not yet have the final path or hash
- some start records still depend on Windows being ready to expose full metadata immediately, so path and hash enrichment is best-effort at start time and usually more complete by stop time

### Network Output

File pattern:

- `C:\ProgramData\Exionis\output\network_<device_id>_<date>.ndjson`

Contains:

- only `network_connection` records

Purpose:

- remote IP visibility
- local/remote port tracking
- TCP/UDP protocol classification
- per-process connection context
- reverse-DNS enrichment when available

Important current behavior:

- `local_ip`, `local_port`, and `direction` are now preserved in the output path
- TCP records usually have meaningful `state`
- UDP records are represented, but direction/state remain best-effort because UDP is connectionless

### Combined Log

File:

- `C:\ProgramData\Exionis\logs\agent.ndjson`

Contains:

- app inventory
- process lifecycle records
- network connection records

Purpose:

- single audit stream
- debugging
- broad NDJSON export

## Build and Run

This project requires:

- Windows
- Go
- CGO enabled
- an available C compiler such as MSYS2 `gcc`
- Administrator shell for correct runtime access to kernel ETW and output paths

Recommended build:

```powershell
$env:PATH='C:\msys64\ucrt64\bin;'+$env:PATH
$env:CGO_ENABLED='1'
$env:CC='gcc'
& 'C:\Program Files\Go\bin\go.exe' build ./cmd/agent
```

Recommended run:

```powershell
$env:PATH='C:\msys64\ucrt64\bin;'+$env:PATH
$env:CGO_ENABLED='1'
$env:CC='gcc'
& 'C:\Program Files\Go\bin\go.exe' run ./cmd/agent
```

The terminal should be launched as Administrator.

## Verified Runtime Behavior

The latest verified state is:

- process output is now process-only
- network output includes `local_ip`, `local_port`, and `direction`
- combined log carries full network records with remote/local addressing
- app inventory output is stable
- elevated build and elevated runtime were both executed successfully during validation

## Known Limitations

These are still important and should not be hidden:

1. DNS is currently enrichment-driven, not native DNS-client ETW provider ingestion.
2. Start-time process enrichment is best-effort. Very short-lived processes may still emit with partial metadata.
3. Signature detection for process telemetry is still simpler than the app inventory WinVerifyTrust path.
4. The network ETW parser is strongest for the currently implemented IPv4/TCP/UDP layouts and may need expansion for richer or alternate payload variants.
5. The combined log is intentionally noisy because it is a mixed operational stream.

## Next Recommended Engineering Steps

1. Add a dedicated `process_enrichment_update` record type if you want delayed enrichment to be persisted explicitly instead of only improving later stop records.
2. Move process signature verification to the same WinVerifyTrust-backed path used by app inventory.
3. Add native DNS-client ETW provider support for query-level telemetry instead of relying only on reverse lookup.
4. Add persistence and query support for long-term historical analysis.
5. Add policy and scoring on top of the normalized event streams.

## Mermaid Source

The working architecture Mermaid source is stored in:

- [architecture.mmd](D:/Project/Exionis-swg/architecture.mmd)
