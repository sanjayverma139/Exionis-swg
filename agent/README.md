# Exionis Agent - Phase 2 Core ETW Bridge

## Overview

Exionis Agent is a Windows telemetry engine built in Go with a native C ETW bridge.
The current implementation combines a stable process collector, runtime privilege elevation, and a real-time kernel ETW streaming core.

This branch moves the project beyond Phase 1 scaffolding by replacing direct Go-to-ETW struct handling with a native bridge that owns `StartTraceW`, `OpenTraceW`, `ProcessTrace`, and `ControlTraceW`.

## Current Architecture

```text
Windows OS
|
|-- Process Collector (Go + gopsutil)
|   `-- CPU / Memory / Path tracking
|
|-- Privilege Layer (SeDebugPrivilege)
|   `-- Enhanced process visibility
|
|-- ETW Layer (Go + native C bridge)
|   |-- Go EventChannel
|   |-- C session control (`StartTraceW` / `ControlTraceW`)
|   |-- C consumer loop (`OpenTraceW` / `ProcessTrace`)
|   `-- Go event normalization and console output
|
`-- Output Stream
    `-- Console telemetry logs
```

## What Is Working Now

### 1. Process Collector
- Real-time process enumeration
- PID tracking
- CPU usage approximation
- Memory usage tracking
- Executable path lookup when permitted

Status: `STABLE`

### 2. Privilege Layer
- Enables `SeDebugPrivilege` at runtime
- Enables `SeSystemProfilePrivilege` at runtime
- Improves visibility into protected processes

Status: `STABLE` (best results when run as administrator)

### 3. Native ETW Kernel Streaming Core
- Native C wrapper for `EVENT_TRACE_PROPERTIES`
- Native `StartTraceW` kernel-session bootstrap
- Native `OpenTraceW` real-time consumer
- Native `ProcessTrace` event loop
- Go callback bridge for normalized event delivery
- Event typing for process, thread, image-load, TCP, and UDP classes

Status: `WORKING CORE`

### 4. Go Telemetry Event Pipeline
- Buffered `EventChannel`
- Non-blocking event publishing to avoid stalling ETW callbacks
- Normalized event shape with provider, PID, TID, event ID, opcode, detail, and timestamp

Status: `WORKING`

## Files Added or Reworked

```text
agent/
|-- cmd/agent/main.go
`-- internal/etw/
    |-- etw_bridge.c
    |-- etw_bridge.h
    `-- etw_native_engine.go
```

## Important Behavior Changes

### The bad `StartTraceW` cast is gone
The previous implementation tried to cast Go-managed ETW pointers directly into Windows APIs. That was the root cause of the repeated `LPWSTR` / `WCHAR` failures and the broader ETW instability.

The ETW session lifecycle is now handled in native C where the Windows structs and callback ABI are defined correctly.

### Kernel session naming changed to the real logger
This implementation uses `NT Kernel Logger` (`KERNEL_LOGGER_NAMEW`) rather than a custom session name.
That is the correct session model for classic kernel trace flags such as:
- process
- thread
- image load
- TCP/IP

## Current Limitations

### 1. DNS events are not decoded yet
The kernel logger covers process, thread, image-load, and TCP/IP classes here.
DNS-client provider wiring and property decoding still need a separate manifest-based provider path.

### 2. Event payload decoding is still light
This core bridge classifies and streams real ETW events, but it does not yet fully decode rich payload fields such as command line, parent PID, or socket addresses.

### 3. `NT Kernel Logger` can already be in use
If another tool owns the kernel logger session, Exionis can attach to the live session, but event coverage depends on that session's enabled flags.

### 4. CGO and a Windows compiler are required
This ETW bridge requires:
- `CGO_ENABLED=1`
- a working Windows C compiler such as MSYS2 `gcc`

### 5. Elevated execution is still required for live kernel consumption
- `NT Kernel Logger` control and real-time consumption typically require an elevated Administrator shell
- The bridge now attempts both `SeDebugPrivilege` and `SeSystemProfilePrivilege`
- If the shell is not elevated enough, `OpenTraceW` / `ProcessTrace` can still fail with `Access is denied`

## Build and Run

```powershell
$env:PATH = 'C:\msys64\ucrt64\bin;' + $env:PATH
$env:CGO_ENABLED = '1'
$env:CC = 'gcc'
& 'C:\Program Files\Go\bin\go.exe' run ./cmd/agent
```

Run the terminal as Administrator for kernel ETW testing. The agent can now request both debug and system-profile privileges, but the final ETW access level still depends on the elevation of the parent shell.

## Current Status

| Component | Status |
| --- | --- |
| Process Collector | Stable |
| Privilege Layer | Stable |
| Native ETW session bootstrap | Working |
| Native real-time ETW consumer | Working, elevation dependent |
| Kernel process/thread/image/network stream | Working core |
| DNS provider support | Not complete |
| Rich payload decoding | Partial |
| Storage Layer | Not started |
| Policy Engine | Not started |

## Next Recommended Upgrades

1. Add manifest-provider support for DNS-client ETW.
2. Decode high-value payload fields with TDH or dedicated native structs.
3. Persist events into SQLite.
4. Add a policy/rule engine on top of the normalized stream.

## Note

This project is still an active systems-level development build and is not yet a production-ready security agent.
