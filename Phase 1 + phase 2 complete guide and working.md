```mermaid
flowchart TD
    %% ===== PHASE 1: INITIALIZATION & ASSET INTELLIGENCE =====
    subgraph Phase1["🟦 Phase 1: Device Shadowing & Asset Intelligence"]
        A1["🚀 Start Agent"] --> A2["🔐 Enable Privileges\nSeSystemProfile\nSeDebug"]
        A2 --> A3["🆔 Generate Device ID\nMachine GUID + Disk Serial\nSHA256 → dev:xxxx"]
        A3 --> A4["📁 Initialize File Sink\nNDJSON rotation\n100MB/10 files"]
        A4 --> A5["🌐 Load Network Config\nInternal IP ranges\nRFC1918 + custom"]
        A5 --> A6["📦 Collect Installed Apps\nHKLM + HKCU + WoW64\nDeduplication"]
        A6 --> A6a["✅ Validate Paths\nos.Stat checks"]
        A6 --> A6b["📊 Calculate Sizes\nAsync directory walk"]
        A6 --> A6c["🔍 Detect Install Source\nMSI/EXE/InnoSetup"]
        A6 --> A7["🛡️ Apply Security Filters\nNoise removal\nRisk scoring\nCode signing check"]
        A7 --> A8["🔄 Bootstrap Process Table\nSnapshot running processes"]
        A8 --> P1_DONE["✅ Phase 1 Complete\nEmit device_inventory JSON"]
    end

    %% ===== PHASE 2: REAL-TIME ETW TELEMETRY =====
    subgraph Phase2["🟧 Phase 2: Real-time Process & Network Monitoring"]
        B1["🪟 Start ETW Kernel Session\nStartTraceW"] --> B2["📡 Attach Consumer\nOpenTraceW"]
        B2 --> B3["🔄 ProcessTraceW\nEvent Loop Running"]
        B3 --> B4{"❓ Event Type?"}
        
        B4 -->|PROCESS_START/STOP| B5["🔍 Parse PID/PPID/Image\nFrom ETW detail field"]
        B4 -->|TCP/UDP Network| B6["🌐 Parse IPs/Ports/Bytes\n20-byte IPv4 layout"]
        
        B5 --> B7["🔗 CGO Callback\nto Go Layer"]
        B6 --> B8["🚫 Filter: localhost +\nInternal IPs + Config"]
        B8 -->|External ✅| B7
        
        B7 --> C1["🐹 Go Bridge\netw_native_engine.go"]
        C1 --> C2["🔄 Convert C Event\n→ Go Struct"]
        C2 --> C3["📤 Publish to Channels\nProcessChan / NetworkChan"]
    end

    %% ===== CORRELATION ENGINE =====
    subgraph Correlation["🧠 Correlation Engine"]
        C3 --> D1{"🔀 Channel Router"}
        D1 -->|ProcessChan| D2["⚙️ HandleProcessStart\nHandleProcessStop"]
        D1 -->|NetworkChan| D3["🌐 forwardNetworkEvents"]
        
        D2 --> D4["🔎 Lookup PID in\nProcess Table"]
        D4 --> D5["🔗 Link Parent-Child\nRelationship"]
        D5 --> D6["✨ Async Enrichment\nPath/Hash/SID/Username"]
        D6 --> D7["💾 Register in\nProcess Table"]
        D7 --> D8["⏱️ Calculate duration_ms\non ProcessStop"]
        
        D3 --> D9["🌍 ResolveDomain\nAsync DNS + Cache"]
        D9 --> D10["🗺️ Map Opcode\n→ ConnectionState"]
        D10 --> D11["📦 Create ConnectionInfo\nwith state field"]
        D11 --> D12["🔄 UpsertConnection\nAggregate by IP:Port:Proto"]
    end

    %% ===== OUTPUT PIPELINE =====
    subgraph Output["📤 Output Pipeline"]
        D8 --> E1["📄 Emit process_stop JSON"]
        D12 --> E2["🌐 Emit network_connection JSON"]
        D7 --> E3["📄 Emit process_start JSON"]
        
        E1 --> E4["🔄 StructuredOutput Channel"]
        E2 --> E4
        E3 --> E4
        
        E4 --> E5{"🔀 Dual Output"}
        E5 -->|Local File| E6["📁 NDJSON Log Files\nC:\ProgramData\Exionis\logs\nRotating 100MB"]
        E5 -->|stdout| E7["☁️ Cloud Pipeline\nNDJSON Stream → findstr/SIEM"]
        
        E2 --> E2a["📁 NetworkOutputChan\n→ network_*.ndjson"]
        E1 & E3 --> E3a["📁 ProcessOutputChan\n→ processes_*.ndjson"]
        
        E6 & E2a & E3a --> E8["🛑 Graceful Shutdown\nSIGINT/SIGTERM\nFlush & Close"]
        E7 --> E8
    end

    %% ===== SUPPORTING MODULES =====
    subgraph Supporting["🔧 Supporting Modules"]
        F1["config/privilege.go"] -.-> A2
        F2["config/network.go"] -.-> A5
        F3["process/collector.go"] -.-> A8 & D6
        F4["utils/deviceid.go"] -.-> A3
        F5["inventory/apps.go"] -.-> A6
        F6["logger/file_sink.go"] -.-> A4 & E6
        F7["correlation/engine.go"] -.-> D1
        F8["output/file_output.go"] -.-> E2a & E3a
    end

    %% ===== EXTERNAL SYSTEMS =====
    subgraph External["🌐 External Systems"]
        G1["🪟 Windows Kernel\nETW Provider"] -.-> B1
        G2["💾 File System\nPath/Hash Lookup"] -.-> D6
        G3["🌍 DNS Resolver\nAsync Cache"] -.-> D9
        G4["☁️ Cloud SIEM\nNDJSON Consumer"] -.-> E7
    end

    %% ===== STYLING =====
    classDef phase1 fill:#e1f5ff,stroke:#0066cc,stroke-width:2px
    classDef phase2 fill:#fff4e1,stroke:#cc6600,stroke-width:2px
    classDef correlation fill:#f0e1ff,stroke:#6600cc,stroke-width:2px
    classDef output fill:#e1ffe1,stroke:#00cc00,stroke-width:2px
    classDef support fill:#ffe1e1,stroke:#cc0000,stroke-width:2px
    classDef external fill:#f5f5f5,stroke:#666,stroke-width:1px,stroke-dasharray:3
    
    class A1,A2,A3,A4,A5,A6,A6a,A6b,A6c,A7,A8,P1_DONE phase1
    class B1,B2,B3,B4,B5,B6,B7,B8,C1,C2,C3 phase2
    class D1,D2,D3,D4,D5,D6,D7,D8,D9,D10,D11,D12 correlation
    class E1,E2,E2a,E3,E3a,E4,E5,E6,E7,E8 output
    class F1,F2,F3,F4,F5,F6,F7,F8 support
    class G1,G2,G3,G4 external
    ```
