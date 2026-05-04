# Exionis Endpoint Roadmap

## Goal

Build Exionis into an endpoint-first DLP and execution-visibility platform with:

- low-cost always-on baseline telemetry
- short-lived deep forensic capture when needed
- durable process lineage for investigation and dashboard graphing
- future DLP enforcement and evidence workflows

## Current State

The capture core is already in place:

- Phase 1 installed-app inventory works
- ETW process and network capture works
- process genealogy is present in live events
- baseline and deep telemetry modes are now implemented
- baseline persistence is summary-first
- deep mode stores a local gzip capture bundle for later upload

## Delivery Phases

### Phase A - Stabilize the New Telemetry Modes

Status: in progress

Target:

- baseline mode is the default production path
- deep mode is reliable for short-lived investigations
- summary schemas are stable enough for backend ingestion

Deliverables:

- `process_execution`
- `process_edge`
- `network_rollup`
- `telemetry_mode`
- local `deep_capture_*.ndjson.gz`

Validation:

- `process_start` / `process_stop` still appear in `output.log`
- baseline files populate on a real admin run
- deep capture file is created and non-empty in deep mode
- legacy raw files only appear when explicitly enabled

### Phase B - Durable Lineage and Investigation UX

Status: next

Target:

- execution trees are durable in storage, not only reconstructable from raw logs
- admin can query a user/device/app and render a parent -> child execution flow

Deliverables:

- dedicated lineage package
- stronger execution identity using `PID + StartTime + BootID`
- graph query helpers for backend/dashboard
- richer root-chain reconstruction for long ancestry

Validation:

- dashboard can render chains such as `winword.exe > cmd.exe > powershell.exe > certutil.exe`
- process edges remain correct across long-lived parent processes and PID reuse

### Phase C - File and Destination Summaries

Status: planned

Target:

- baseline DLP-adjacent visibility without full raw file telemetry flood

Deliverables:

- `file_summary`
- path classification (`downloads`, `usb`, `network_share`, `cloud_sync`, `temp`)
- destination-aware upload summaries
- browser and sync-client attribution where feasible

Validation:

- meaningful file-write and upload stories can be reconstructed without raw file spam

### Phase D - Telemetry Control Plane

Status: planned

Target:

- admin can remotely switch telemetry levels by tenant, device, user, or app

Deliverables:

- policy model for `baseline`, `deep`
- time-bounded deep capture windows
- local retention and cleanup policy
- upload request / approval workflow for deep bundles

Validation:

- deep mode can be enabled for a single device or user for a fixed duration
- the agent falls back automatically to baseline when the window expires

### Phase E - DLP Engine

Status: future

Target:

- first real endpoint DLP enforcement and alerting workflows

Deliverables:

- policy engine
- content classification hooks
- USB / upload / cloud-sync policies
- alerting and response actions

Validation:

- policy hits produce durable evidence and operator-friendly incident trails

## Architectural Direction

The next structural split should move toward:

```text
agent/
  cmd/agent/
  internal/
    etw/
    telemetry/
    lineage/
    process/
    inventory/
    output/
    detect/
    policy/
```

Guiding rules:

1. keep ETW capture and telemetry shaping separate
2. keep baseline storage summary-first
3. keep deep mode local-first and time-bounded
4. avoid building future DLP logic directly inside correlation or ETW packages
5. keep upload, policy, and detection concerns separate from capture

## Near-Term Engineering Tasks

1. validate baseline files on a real admin ETW run:
   - `process_execution`
   - `process_edge`
   - `network_rollup`
2. improve graceful shutdown and service-mode stop handling
3. add periodic deep-capture manifest flushes
4. add file-summary scaffolding
5. add backend-ready schema docs for baseline records

## Success Criteria

We are in a good place when:

- baseline mode answers who ran what, what spawned what, and who talked where
- deep mode preserves richer local evidence without forcing continuous cloud storage
- process lineage is stable enough to power an admin execution-flow view
- the future DLP engine can plug into the same execution and file context instead of reinventing telemetry
