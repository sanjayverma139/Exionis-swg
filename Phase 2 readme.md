# Exionis Agent — Phase 2
## Process Telemetry Engine

> **Status:** ✅ Complete  
> **Target OS:** Windows 10 / 11 (x64)  
> **Requires:** Administrator privileges

---

## What Phase 2 Does

Phase 2 transforms raw kernel ETW events into structured, enriched process intelligence. Every new process that starts on the machine is captured, correlated with its parent, enriched with file path and SHA256 hash, timed from start to stop, and emitted as clean JSON.

**Example output:**
```json
{
  "event_type": "process_start",
  "timestamp": "2026-04-22T23:49:10.672263+05:30",
  "pid": 19084,
  "ppid": 11344,
  "image": "Notepad.exe",
  "cmdline": "\"C:\\Program Files\\WindowsApps\\...\\Notepad.exe\"",
  "image_path": "C:\\Program Files\\WindowsApps\\...\\Notepad.exe",
  "resolved": true,
  "enrichment": {
    "ExecutablePath": "C:\\Program Files\\WindowsApps\\...\\Notepad.exe",
    "SHA256Hash": "c8e1425c88305f836c2eeb78f4318b6b9ff1672c2ed8dc11a61b0fa8520be2bf",
    "IsSigned": false,
    "IsSystem": false,
    "UserSID": ""
  }
}
```

```json
{
  "event_type": "process_stop",
  "timestamp": "2026-04-22T23:49:11.554+05:30",
  "pid": 19084,
  "image": "Notepad.exe",
  "duration_ms": 881,
  "resolved": true
}
```

---

## Architecture

```
Windows Kernel
      │
      │  NT Kernel Logger (ETW)
      │  Provider: {3D6FA8D0-FE05-11D0-9DDA-00C04FD7BA7C}
      │  Flags: PROCESS | THREAD | IMAGE_LOAD | NETWORK_TCPIP
      │
      ▼
┌─────────────────────────────────────────────────┐
│  C Bridge  (internal/etw/etw_bridge.c)          │
│                                                 │
│  StartTraceW  → NT Kernel Logger session        │
│  OpenTraceW   → attach consumer                 │
│  ProcessTraceW → event loop (blocking)          │
│                                                 │
│  Per event:                                     │
│   • classify opcode → PROCESS_START/STOP        │
│   • extract PPID from UserData offset 12        │
│   • extract ImageFileName after SID (offset 52) │
│   • drop DC_START / DC_END / opcode 11          │
│   • call exionis_go_emit_event() via CGO        │
└──────────────────┬──────────────────────────────┘
                   │ CGO callback
                   ▼
┌─────────────────────────────────────────────────┐
│  ETW Go Bridge  (internal/etw/etw_native_engine) │
│                                                 │
│  Converts C callback → Go Event struct          │
│  Publishes to EventChannel (buffered, 5000)     │
│  Non-blocking: drops on overflow                │
└──────────────────┬──────────────────────────────┘
                   │ chan Event
                   ▼
┌─────────────────────────────────────────────────┐
│  Privilege Layer  (internal/config/privilege.go) │
│                                                 │
│  SeDebugPrivilege         → access to protected │
│  SeSystemProfilePrivilege → ETW kernel session  │
│  (enabled once at startup via AdjustTokenPrivs) │
└─────────────────────────────────────────────────┘
                   │
                   ▼
┌─────────────────────────────────────────────────┐
│  Correlation Engine  (internal/correlation/)    │
│                                                 │
│  engine.go                                      │
│  ├── HandleProcessStart()                       │
│  │    • parse PPID + image from Detail string   │
│  │    • fallback: GetExecutablePath / GetCmdline│
│  │    • link parent pointer + children slice    │
│  │    • run enrichment (path, hash, flags)      │
│  │    • register in processTable                │
│  │    • emit process_start JSON                 │
│  │                                              │
│  ├── HandleProcessStop()                        │
│  │    • lookup processTable by PID              │
│  │    • calculate duration_ms                   │
│  │    • emit process_stop JSON                  │
│  │    • schedule deletion after 2 seconds       │
│  │                                              │
│  ├── cleanupStaleProcesses()                    │
│  │    • TTL: 5 minutes                          │
│  │    • ticker: every 1 minute                  │
│  │                                              │
│  ├── shouldAggregate()                          │
│  │    • 2-second window aggregator              │
│  │    • suppresses repeated spawns of same image│
│  │    • emits process_spawn_aggregate summary   │
│  │                                              │
│  └── isCriticalProcess()                        │
│       • bypass aggregation for sensitive images │
│                                                 │
│  models.go                                      │
│  ├── ProcessInfo      (in-memory process entry) │
│  ├── ProcessEnrichment(path, hash, flags)       │
│  ├── StructuredEvent  (JSON output shape)       │
│  ├── SpawnStats       (aggregation counters)    │
│  └── EventInput       (from ETW bridge)         │
└──────────────────┬──────────────────────────────┘
                   │ chan StructuredEvent (10000)
                   ▼
┌─────────────────────────────────────────────────┐
│  Process Collector  (internal/process/collector) │
│                                                 │
│  GetProcesses()          → gopsutil snapshot    │
│  GetCmdline(pid)         → full command line    │
│  GetExecutablePath(pid)  → full image path      │
│  GetExecutablePathWithRetry() → 3-attempt retry │
│  ComputeFileSHA256(path) → hex SHA256 string    │
│  IsProcessSigned(pid)    → stub (Phase 3)       │
└──────────────────┬──────────────────────────────┘
                   │
                   ▼
            stdout  (NDJSON)
     one JSON line per process event
```

---

## File Structure

```
agent/
│
├── cmd/
│   └── agent/
│       └── main.go                   Entry point. Wires all layers together.
│                                     Starts ETW, creates engine, tees events,
│                                     runs snapshot ticker.
│
├── internal/
│   │
│   ├── config/
│   │   └── privilege.go              Windows privilege escalation.
│   │                                 Enables SeDebugPrivilege and
│   │                                 SeSystemProfilePrivilege via
│   │                                 AdjustTokenPrivileges (pure syscall,
│   │                                 no CGO).
│   │
│   ├── etw/
│   │   ├── etw_bridge.h              CGO header. Declares C functions
│   │   │                             exported to Go and the Go callback
│   │   │                             signature for exionis_go_emit_event.
│   │   │
│   │   ├── etw_bridge.c              Native C ETW consumer. No TDH.
│   │   │                             Direct UserData parsing.
│   │   │                             Handles: session create, open,
│   │   │                             process event callback, detail
│   │   │                             formatting, session stop.
│   │   │
│   │   └── etw_native_engine.go      Go side of CGO bridge.
│   │                                 Exports exionis_go_emit_event to C.
│   │                                 Converts C callback → Go Event.
│   │                                 Publishes to EventChannel.
│   │
│   ├── correlation/
│   │   ├── engine.go                 Core process intelligence engine.
│   │   │                             All handlers, emitters, enrichment,
│   │   │                             aggregation, TTL cleanup, JSON output.
│   │   │
│   │   └── models.go                 All data types:
│   │                                 ProcessInfo, ProcessEnrichment,
│   │                                 StructuredEvent, SpawnStats,
│   │                                 EventInput, CorrelatedEvent.
│   │
│   └── process/
│       └── collector.go              Process data helpers.
│                                     Wraps gopsutil for snapshot, cmdline,
│                                     exe path, SHA256, retry logic.
│                                     IsProcessSigned stub for Phase 3.
│
├── go.mod                            Module: exionis
│                                     Go 1.21
│                                     Deps: gopsutil/v3, golang.org/x/sys
│
├── go.sum                            Dependency checksums
│
└── README.md                         This file
```

---

## Features

### 1. Real-Time Kernel ETW Ingestion
- Attaches to NT Kernel Logger (`\\KernelLogger`)
- Providers: Process, Thread, ImageLoad, TCP/IP
- Uses `StartTraceW` → `OpenTraceW` → `ProcessTraceW`
- Events arrive on a dedicated consumer thread in C
- Forwarded to Go via CGO callback into a buffered channel

### 2. Process Correlation Engine
- In-memory map: `map[uint32]*ProcessInfo`
- Protected by `sync.RWMutex` — safe for concurrent ETW ingestion
- On `PROCESS_START`: create entry, link parent, enrich, emit
- On `PROCESS_STOP`: calculate duration, emit, schedule cleanup

### 3. Lifecycle Tracking
- `StartTime` recorded from ETW event timestamp
- `EndTime` recorded from STOP event timestamp
- `DurationMs = EndTime - StartTime` in milliseconds
- Emitted in every `process_stop` event

### 4. Parent-Child Relationship Tracking
- `ProcessInfo.Parent` pointer to parent entry
- `ProcessInfo.Children` slice of child entries
- PPID extracted from raw ETW UserData (offset 12, version-safe)
- Parent image resolved from correlation table

### 5. Enrichment Pipeline
- Runs at `PROCESS_START` — before process can exit
- Collects: full exe path, SHA256 hash, cmdline, IsSystem flag
- Falls back to `GetExecutablePath` + `GetCmdline` if ETW detail is incomplete
- `IsSystem` heuristic: `pid < 100`

### 6. Short-Lived Process Handling
- Enrichment happens synchronously at START time
- Even a process that exits in < 100ms has its data captured
- `GetExecutablePathWithRetry` provides 3 attempts with 10ms delay

### 7. Fallback Resolution
- If ETW image name is missing or `<unknown>`:
  - Try `GetCmdline` → extract basename from first argument
  - Try `GetExecutablePath` → extract basename from full path
- Ensures minimal data even when ETW payload is incomplete

### 8. Process Table TTL Cleanup
- Stale entries removed after 5 minutes
- Cleanup runs every 1 minute via ticker goroutine
- Prevents memory growth from PID reuse or missed STOP events

### 9. Noise Reduction (Aggregation)
- Detects repeated spawning of the same child image within 2 seconds
- Suppresses individual events and emits a `process_spawn_aggregate` summary
- Critical processes (`lsass.exe`, `powershell.exe`, `cmd.exe`, etc.) bypass aggregation

### 10. Critical Process Tagging
- Hardcoded list of security-sensitive process names
- These always produce individual events regardless of spawn frequency
- List: `lsass.exe`, `csrss.exe`, `wininit.exe`, `services.exe`, `svchost.exe`, `explorer.exe`, `cmd.exe`, `powershell.exe`, `wscript.exe`, `mshta.exe`, `regsvr32.exe`, `rundll32.exe`

### 11. Structured NDJSON Output
- One JSON line per event to stdout
- Fields: `event_type`, `timestamp`, `pid`, `ppid`, `image`, `parent_image`, `cmdline`, `image_path`, `duration_ms`, `resolved`, `enrichment`
- Machine-readable — ready for log shipper, SIEM, or file sink

### 12. Thread-Safe Design
- `processTable` → `sync.RWMutex` (read-heavy optimized)
- `pendingEvents` → `sync.Mutex`
- `spawnAggregator` → `sync.Mutex`
- `sequenceCounter` → `sync.Mutex`
- All channel writes are non-blocking (`select / default`)

---

## Limitations

### 1. Already-Running Processes
**Impact: High**

ETW only fires `PROCESS_START` for processes created after the agent attaches. Processes already running when the agent starts are only visible when they stop.

What is missing for pre-existing processes:
- Real PPID (no parent info)
- Accurate start time (estimated as `stop_time - 1s`)
- Accurate duration
- Full spawn chain

**Workaround:** The STOP handler creates a minimal entry via fallback resolution so the stop event is not lost entirely.

**Fix in Phase 3:** Bootstrap the process table from a live snapshot on startup before ETW attaches.

### 2. `IsSigned` Always False
**Impact: Medium**

Signature verification requires `WinVerifyTrust` via `CryptoAPI`. This is deferred to Phase 3 to avoid CGO complexity in Phase 2. The field exists in all output but is always `false`.

### 3. `UserSID` Always Empty
**Impact: Low**

User identity resolution requires `OpenProcessToken` + `GetTokenInformation`. Stubbed for Phase 3. Field exists in output but is always `""`.

### 4. Enrichment Blocks ETW Goroutine
**Impact: Medium under heavy load**

`enrichProcessAtStart` calls `GetExecutablePath` and `GetCmdline` synchronously inside the event handler. For most processes this is fast, but under a burst of process creation (e.g. build system, installer) this can introduce latency in the ETW pipeline.

**Fix in Phase 3:** Run enrichment in a goroutine and update the ProcessInfo entry asynchronously.

### 5. No Persistent Storage
**Impact: High for forensics**

All data lives in memory only. Agent restart loses all history. No SQLite, no file sink, no log rotation.

**Fix in Phase 3/4:** Add storage layer.

### 6. No Network-to-Process Correlation
**Impact: Medium**

TCP/IP events are captured at the ETW layer but not correlated to processes in Phase 2. The network provider is enabled but its events are not forwarded to the correlation engine.

**Fix in Phase 3:** Add network event handler to correlation engine.

### 7. SHA256 Blocks on Large Files
**Impact: Low**

`computeFileSHA256` reads the entire file synchronously. For large executables this takes measurable time inside the START handler.

**Fix:** Move to goroutine with result written back to `ProcessInfo.Enrichment`.

---

## Build & Run

**Requirements:**
- Windows 10 / 11 (x64)
- Go 1.21+
- GCC via MSYS2 UCRT64 (`C:\msys64\ucrt64\bin`)
- Run as Administrator

```powershell
$env:PATH = 'C:\msys64\ucrt64\bin;' + $env:PATH
$env:CGO_ENABLED = '1'
$env:CC = 'gcc'
go run ./cmd/agent
```

**Expected startup output:**
```
[Exionis] SeDebugPrivilege enabled successfully
[Exionis] SeSystemProfilePrivilege enabled successfully
[Exionis-ETW] Starting native kernel ETW engine...
[Exionis] Phase 2: Process Telemetry Engine ACTIVE
[Exionis] Process Collector Running...
```

---

## Phase Roadmap

| Phase | Description | Status |
|---|---|---|
| 1 | Device + Process Collector | ✅ Complete |
| 2 | Kernel Telemetry + Process Intelligence | ✅ Complete |
| 3 | Enrichment (signatures, SID, network correlation, storage) | 🔲 Next |
| 4 | Policy Engine (detection rules, alerting) | 🔲 Planned |
| 5 | Enforcement (block / allow) | 🔲 Planned |

---

## Key Design Decisions

| Decision | Reason |
|---|---|
| ETW parsing in C, not Go | ABI safety — Windows calling conventions for ETW callbacks require C |
| No TDH | NT Kernel Logger uses MOF classic events — TDH is unreliable and slow for this provider |
| Direct UserData parsing | Fastest path — no API overhead, offsets verified from live hex dumps |
| ASCII image name (not UTF-16) | NT Kernel Logger stores `ImageFileName` as narrow ASCII after the inline SID |
| SID at offset 52 (v4) | Offsets 40-51 are a kernel pointer + padding — confirmed from runtime hex dumps |
| Enrichment at START | Process may exit before STOP fires — data must be captured immediately |
| Non-blocking channels | ETW callback must never stall — drops are preferable to deadlock |
