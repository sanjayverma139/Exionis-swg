# Exionis

# 🛡️ Exionis SWG AGENT — FULL ARCHITECTURE & DEVELOPMENT ROADMAP

---

# 🧠 PROJECT OVERVIEW

This project is a **Hybrid Secure Web Gateway (SWG) + Endpoint Agent** designed to provide:

* Device visibility (installed apps, processes)
* Network visibility (connections, DNS, traffic)
* Policy-based enforcement
* Threat intelligence integration
* Centralized cloud control

---

# 🏗️ SYSTEM ARCHITECTURE


```
👨‍💻 1. ADMIN PANEL (GitHub Pages UI)
   - Create policies
   - View devices
   - View logs
   - Trigger actions

            ↓ (API calls)

☁️ 2. DATABASE (Supabase / Backend)
   - Stores policies
   - Stores device state
   - Stores logs/events
   - Stores admin actions

            ↓ (sync or pull)

🧠 3. CORTEX (POLICY ENGINE - IMPORTANT LAYER)
   - Evaluates policies
   - Resolves conflicts
   - Adds threat intelligence logic
   - Converts rules → decisions

            ↓ (decision output)

💻 4. AGENT (Go on device)
   - Syncs policies
   - Applies enforcement
   - Blocks / allows traffic
   - Reports telemetry

            ↓

📊 5. BACK TO CLOUD
   - Logs sent back
   - UI updates dashboard


                ☁️ Cloud (Supabase)
        - Policies
        - Config
        - Logs
                 │
                 ▼
        ┌─────────────────────┐
        │   JS Policy Engine  │
        │  - Rules            │
        │  - Threat Intel     │
        └─────────┬───────────┘
                  │ IPC (HTTP / socket)
                  ▼
        ┌─────────────────────┐
        │      Go Agent       │
        │ - Process monitor   │
        │ - DNS interceptor   │
        │ - Proxy             │
        │ - Enforcement       │
        └─────────┬───────────┘
                  ▼
           💻 User Device
```

---

# 📁 PROJECT STRUCTURE

```
Exionis-swg/
│
├── agent/
│   ├── cmd/
│   │   └── agent/
│   │       └── main.go
│   │
│   ├── internal/
│   │   ├── dns/
│   │   ├── proxy/
│   │   ├── network/
│   │   ├── process/
│   │   ├── enforcement/
│   │   ├── bridge/
│   │   ├── config/
│   │   ├── logger/
│   │   └── utils/
│   │
│   ├── scripts/
│   ├── go.mod
│   └── go.sum
│
├── policy-engine/
├── shared/
├── cloud/
├── configs/
├── logs/
└── README.md
```

---

# 🗺️ FULL DEVELOPMENT ROADMAP (DETAILED)

---

# 🥇 PHASE 1: DEVICE SHADOWING (VISIBILITY CORE)

## 🎯 Objective:

Capture complete **application and process visibility**

---

## 🔹 1. Installed Applications Collection

### 📍 Source:

* Windows Registry:

  * HKLM\Software\Microsoft\Windows\CurrentVersion\Uninstall
  * HKCU\Software\Microsoft\Windows\CurrentVersion\Uninstall

---

### 📊 Data Fields to Extract:

| Field           | Description            |
| --------------- | ---------------------- |
| DisplayName     | Application name       |
| DisplayVersion  | Version                |
| Publisher       | Vendor                 |
| InstallLocation | Installation path      |
| InstallDate     | Installation timestamp |
| UninstallString | Uninstall command      |
| EstimatedSize   | App size (KB)          |
| SystemComponent | System app flag        |

---

### ⚙️ Subtasks:

* Registry traversal
* Filtering invalid entries
* Normalizing paths
* Deduplication

---

## 🔹 2. Running Process Monitoring

### 📊 Data Fields:

| Field           | Description      |
| --------------- | ---------------- |
| PID             | Process ID       |
| Name            | Process name     |
| Executable Path | Full binary path |
| Parent PID      | Parent process   |
| Username        | Running user     |
| Start Time      | Execution time   |

---

### ⚙️ Subtasks:

* Enumerate all processes
* Resolve executable path
* Build parent-child tree
* Detect orphan processes

---

## 🔹 3. Process Metadata Enrichment

### 📊 Data Fields:

| Field             | Description        |
| ----------------- | ------------------ |
| SHA256 Hash       | File fingerprint   |
| Digital Signature | Trusted / unsigned |
| File Size         | Binary size        |
| Creation Time     | File creation      |
| Last Modified     | Last update        |

---

### ⚙️ Subtasks:

* File hashing
* Signature verification
* Metadata extraction
* Cache results (performance optimization)

---

## 🔹 4. Output Structure

```
{
  "installed_apps": [...],
  "running_processes": [...],
  "metadata": [...]
}
```

---

## 🚀 Phase 1 Outcome:

✔ Full device inventory
✔ Real-time process tracking

---

# 🥈 PHASE 2: PROCESS → NETWORK MAPPING

---

## 🎯 Objective:

Map which application is communicating with which network endpoint

---

## 🔹 Data Collection:

| Field          | Description      |
| -------------- | ---------------- |
| PID            | Process ID       |
| Local IP       | Source IP        |
| Remote IP      | Destination IP   |
| Port           | Destination port |
| Protocol       | TCP/UDP          |
| Bytes Sent     | Upload           |
| Bytes Received | Download         |

---

## 🔹 Derived Data:

| Field            | Description           |
| ---------------- | --------------------- |
| Domain           | Reverse DNS lookup    |
| Connection State | Established/Listening |

---

## ⚙️ Subtasks:

* Fetch active connections
* Map PID → connection
* Perform reverse DNS
* Aggregate per-process traffic

---

## 🚀 Phase 2 Outcome:

✔ App → Domain mapping
✔ Data usage tracking per process

---

# 🥉 PHASE 3: DNS INTERCEPTION

---

## 🎯 Objective:

Control domain access system-wide

---

## 🔹 Features:

* Local DNS server
* Intercept all DNS queries
* Forward or block based on policy

---

## 🔹 Flow:

```
App → DNS Query → Agent → Policy Engine → Decision → Response
```

---

## ⚙️ Subtasks:

* DNS listener (UDP 53)
* Query parser
* Policy check integration
* Response manipulation

---

## 🚀 Phase 3 Outcome:

✔ Domain-level blocking

---

# 🏅 PHASE 4: POLICY ENGINE INTEGRATION

---

## 🎯 Objective:

Central decision-making system

---

## 🔹 Input:

```
{
  "domain": "example.com",
  "process": "chrome.exe",
  "ip": "1.2.3.4"
}
```

---

## 🔹 Output:

```
{
  "action": "BLOCK | ALLOW | ALERT"
}
```

---

## ⚙️ Subtasks:

* IPC server setup
* Request validation
* Response parsing

---

## 🚀 Phase 4 Outcome:

✔ Centralized intelligence layer

---

# 🧠 PHASE 5: PROCESS-LEVEL CONTROL

---

## 🎯 Objective:

Control application behavior

---

## 🔹 Capabilities:

* Kill process
* Block process network access
* Allow/deny execution (future)

---

## ⚙️ Subtasks:

* Process termination
* Firewall rule creation
* Rule cleanup

---

## 🚀 Phase 5 Outcome:

✔ Direct application control

---

# 🚀 PHASE 6: LOCAL PROXY (SWG CORE)

---

## 🎯 Objective:

Enable URL-level inspection

---

## 🔹 Features:

* HTTP proxy server
* Request interception
* URL parsing

---

## 🔹 Data Extracted:

* Full URL
* Method (GET/POST)
* Headers
* Request size

---

## ⚙️ Subtasks:

* Proxy routing
* Request handler
* Policy integration

---

## 🚀 Phase 6 Outcome:

✔ URL-level filtering

---

# 🔥 PHASE 7: ADVANCED NETWORK CONTROL

---

## 🎯 Objective:

Deep packet-level control

---

## 🔹 Tools:

* WinDivert
* Windows Filtering Platform (WFP)

---

## 🔹 Capabilities:

* Packet inspection
* Drop connections
* Traffic shaping

---

## 🚀 Phase 7 Outcome:

✔ Full network control

---

# ☁️ PHASE 8: CLOUD INTEGRATION

---

## 🎯 Objective:

Centralized management

---

## 🔹 Features:

* Policy sync
* Device registration
* Event logging

---

## 🚀 Phase 8 Outcome:

✔ Multi-device control

---

# ⚡ PHASE 9: INTELLIGENCE LAYER

---

## 🔹 Add:

* Threat intelligence feeds
* Reputation scoring
* Behavioral detection

---

# 🔁 FINAL DATA FLOW

```
Process starts
   ↓
Network request generated
   ↓
Intercepted (DNS / Proxy / Packet)
   ↓
Go Agent → JS Policy Engine
   ↓
Decision returned
   ↓
Enforcement applied
   ↓
Log sent to Cloud
```

---

# ⚠️ ENGINEERING RULES

* NEVER mix Go and JS logic
* ALWAYS define IPC schema early
* BUILD in phases
* OPTIMIZE performance continuously

---

# 🧩 FINAL RESULT

This system becomes:

✔ Endpoint Visibility Agent
✔ Secure Web Gateway
✔ Policy Enforcement Engine
✔ Cloud-controlled Security Platform

---

# 🚀 NEXT STEP

Start with:

👉 Phase 1 — Device Shadowing Implementation

---
