Build a professional enterprise admin dashboard for a product named Exionis.

Exionis is an endpoint visibility and DLP-oriented platform. The dashboard is for security administrators, SOC analysts, and IT operations users. The product is not a marketing site. The first screen must be a real working dashboard.

Design goals:
- quiet, operational, enterprise look
- dense but clean information layout
- strong alignment and spacing
- professional color usage with good contrast
- no oversized hero sections
- no decorative gradients or marketing cards
- tables, filters, search, side navigation, detail panes, and graph views should feel polished and production-ready

Preferred stack:
- Next.js
- TypeScript
- Tailwind CSS
- shadcn/ui
- TanStack Table
- Recharts for trend charts
- React Flow for execution tree and process graph visualization

Main navigation:
1. Overview
2. Devices
3. Users
4. Installed Apps
5. Process Explorer
6. Network Activity
7. Deep Capture
8. Settings

Core data model:
- installed_apps
- process_executions
- process_edges
- network_rollups
- telemetry_modes

Important identifiers:
- tenant_id
- device_id
- hostname
- execution_id
- parent_execution_id
- root_execution_id
- user_sid
- username

Key product behaviors to represent:
- baseline mode is the default always-on telemetry mode
- deep mode is a time-bounded forensic mode
- baseline stores summary-first telemetry
- deep mode stores a local forensic bundle that may later be uploaded
- admins should be able to filter by hostname, device_id, user, process image, and time range

Required pages and functionality:

Overview page:
- KPI strip for:
  - active devices
  - process executions today
  - network rollups today
  - deep mode sessions
  - high-risk executions
- charts for:
  - process volume over time
  - network rollup volume over time
  - top process images
  - top remote domains
- latest telemetry mode changes
- top risky devices and users

Devices page:
- searchable/filterable device table
- columns:
  - hostname
  - device_id
  - latest telemetry mode
  - last_seen
  - process count
  - deep capture status
- right-side detail drawer or page
- device detail tabs:
  - summary
  - installed apps
  - process executions
  - execution graph
  - network rollups
  - telemetry history

Users page:
- table by username
- columns:
  - username
  - device count
  - execution count
  - risky execution count
  - last activity
- user detail view showing devices, executions, and network activity

Installed Apps page:
- table for installed_apps
- filters:
  - hostname
  - publisher
  - risk score
  - system component yes/no
- support grouping by device and app name

Process Explorer page:
- table for process_executions
- filters:
  - hostname
  - device_id
  - username
  - image
  - risk_score
  - date range
- columns:
  - start_time
  - stop_time
  - hostname
  - username
  - image
  - parent_image
  - chain
  - depth
  - duration_ms
  - risk_score
- click a row to open a detailed side panel with:
  - process metadata
  - lineage chain
  - related process edges
  - related network rollups

Execution Graph page or tab:
- use React Flow
- render process_edges as parent-child graph
- graph must support zoom, pan, fit-to-view, node search, and node detail hover
- node labels should show:
  - image
  - hostname
  - username
  - start time
  - risk score
- include a compact timeline filter above the graph
- make the graph usable on large screens and still legible

Network Activity page:
- table for network_rollups
- filters:
  - hostname
  - process image
  - remote_ip
  - domain
  - protocol
  - time range
- columns:
  - window_start
  - hostname
  - image
  - remote_ip
  - remote_port
  - domain
  - protocol
  - connection_count
  - bytes_sent
  - bytes_recv
- charts for top domains, top remote IPs, and top talkers by bytes

Deep Capture page:
- show telemetry_modes where mode=deep
- show deep session start, expiry, reason, and deep_capture_path
- table columns:
  - hostname
  - device_id
  - timestamp
  - source
  - reason
  - expires_at
  - deep_capture_path
- add status badges:
  - active
  - expired
  - uploaded
  - pending

Settings page:
- telemetry mode policy controls UI mock
- baseline vs deep policy descriptions
- retention settings mock
- upload and archive settings mock

UX requirements:
- use a left sidebar and top utility bar
- top bar should include global search, date range picker, and tenant selector
- use segmented controls, toggles, compact filters, and drawers
- tables should have sticky headers and row hover states
- keep typography restrained and enterprise-grade
- use icons where appropriate but keep them subtle
- do not use visible explanatory marketing copy

Visual style:
- modern enterprise SaaS
- mostly neutral background
- restrained accent color
- excellent whitespace discipline
- cards only where appropriate
- page sections should not look like floating marketing panels

Implementation expectations:
- build mock data based on the following entities:
  - installed_apps
  - process_executions
  - process_edges
  - network_rollups
  - telemetry_modes
- include realistic example data with hostname and device_id
- create reusable components for:
  - KPI cards
  - filter bars
  - data tables
  - detail drawers
  - graph panels
  - status badges
- ensure responsive behavior on laptop and large desktop screens

Important:
- do not build a landing page
- build the actual admin console first
- make the interface feel like a real professional security product
