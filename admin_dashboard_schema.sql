-- Exionis baseline and deep-mode admin schema
-- PostgreSQL-flavored DDL

create extension if not exists pgcrypto;

create table if not exists tenants (
    tenant_id uuid primary key default gen_random_uuid(),
    name text not null,
    slug text unique,
    created_at timestamptz not null default now()
);

create table if not exists devices (
    device_pk uuid primary key default gen_random_uuid(),
    tenant_id uuid not null references tenants(tenant_id) on delete cascade,
    device_id text not null unique,
    hostname text not null,
    first_seen timestamptz not null default now(),
    last_seen timestamptz not null default now(),
    status text default 'active',
    os_name text,
    os_version text,
    domain_name text,
    last_user_sid text,
    last_username text
);

create index if not exists idx_devices_tenant_hostname on devices (tenant_id, hostname);

create table if not exists installed_apps (
    app_row_id bigserial primary key,
    tenant_id uuid not null references tenants(tenant_id) on delete cascade,
    device_id text not null,
    hostname text not null,
    scan_time timestamptz not null,
    display_name text not null,
    display_version text,
    publisher text,
    install_location text,
    install_date text,
    uninstall_string text,
    estimated_size_kb bigint,
    actual_size_kb bigint,
    is_system_component boolean not null default false,
    registry_source text,
    install_source text,
    file_hash text,
    risk_score integer default 0,
    ingested_at timestamptz not null default now()
);

create index if not exists idx_installed_apps_device_scan on installed_apps (tenant_id, device_id, scan_time desc);
create index if not exists idx_installed_apps_hostname on installed_apps (tenant_id, hostname);
create index if not exists idx_installed_apps_name on installed_apps (tenant_id, display_name);

create table if not exists process_executions (
    execution_id text primary key,
    tenant_id uuid not null references tenants(tenant_id) on delete cascade,
    device_id text not null,
    hostname text not null,
    boot_id text not null,
    parent_execution_id text,
    root_execution_id text,
    pid integer not null,
    ppid integer,
    image text not null,
    parent_image text,
    grandparent_image text,
    chain text,
    depth integer,
    full_path text,
    sha256_hash text,
    user_sid text,
    username text,
    start_time timestamptz not null,
    stop_time timestamptz,
    duration_ms bigint,
    is_system boolean not null default false,
    integrity_level text,
    elevation text,
    risk_score integer default 0,
    tags jsonb default '[]'::jsonb,
    command_line_present boolean not null default false,
    ingested_at timestamptz not null default now()
);

create index if not exists idx_process_exec_device_start on process_executions (tenant_id, device_id, start_time desc);
create index if not exists idx_process_exec_hostname_start on process_executions (tenant_id, hostname, start_time desc);
create index if not exists idx_process_exec_image on process_executions (tenant_id, image, start_time desc);
create index if not exists idx_process_exec_root on process_executions (tenant_id, root_execution_id);
create index if not exists idx_process_exec_parent on process_executions (tenant_id, parent_execution_id);
create index if not exists idx_process_exec_user on process_executions (tenant_id, username, start_time desc);

create table if not exists process_edges (
    edge_row_id bigserial primary key,
    tenant_id uuid not null references tenants(tenant_id) on delete cascade,
    device_id text not null,
    hostname text not null,
    timestamp timestamptz not null,
    edge_type text not null default 'spawn',
    parent_execution_id text,
    child_execution_id text not null,
    root_execution_id text,
    parent_pid integer,
    child_pid integer not null,
    parent_image text,
    child_image text not null,
    depth integer,
    ingested_at timestamptz not null default now()
);

create index if not exists idx_process_edges_device_time on process_edges (tenant_id, device_id, timestamp desc);
create index if not exists idx_process_edges_hostname_time on process_edges (tenant_id, hostname, timestamp desc);
create index if not exists idx_process_edges_parent on process_edges (tenant_id, parent_execution_id);
create index if not exists idx_process_edges_child on process_edges (tenant_id, child_execution_id);
create index if not exists idx_process_edges_root on process_edges (tenant_id, root_execution_id);

create table if not exists network_rollups (
    rollup_row_id bigserial primary key,
    tenant_id uuid not null references tenants(tenant_id) on delete cascade,
    device_id text not null,
    hostname text not null,
    timestamp timestamptz not null,
    window_start timestamptz not null,
    window_end timestamptz not null,
    execution_id text,
    root_execution_id text,
    pid integer not null,
    image text not null,
    local_ip inet,
    remote_ip inet,
    local_port integer,
    remote_port integer,
    protocol text not null,
    direction text,
    domain text,
    connection_count integer not null default 0,
    bytes_sent bigint not null default 0,
    bytes_recv bigint not null default 0,
    last_observed_state text,
    ingested_at timestamptz not null default now()
);

create index if not exists idx_network_rollups_device_window on network_rollups (tenant_id, device_id, window_start desc);
create index if not exists idx_network_rollups_hostname_window on network_rollups (tenant_id, hostname, window_start desc);
create index if not exists idx_network_rollups_exec on network_rollups (tenant_id, execution_id);
create index if not exists idx_network_rollups_remote on network_rollups (tenant_id, remote_ip, remote_port, window_start desc);
create index if not exists idx_network_rollups_domain on network_rollups (tenant_id, domain, window_start desc);

create table if not exists telemetry_modes (
    mode_row_id bigserial primary key,
    tenant_id uuid not null references tenants(tenant_id) on delete cascade,
    device_id text not null,
    hostname text not null,
    timestamp timestamptz not null,
    mode text not null,
    source text,
    reason text,
    expires_at timestamptz,
    deep_capture_path text,
    ingested_at timestamptz not null default now()
);

create index if not exists idx_telemetry_modes_device_time on telemetry_modes (tenant_id, device_id, timestamp desc);
create index if not exists idx_telemetry_modes_hostname_time on telemetry_modes (tenant_id, hostname, timestamp desc);

-- Helpful views for the admin panel

create or replace view latest_device_telemetry_mode as
select distinct on (tenant_id, device_id)
    tenant_id,
    device_id,
    hostname,
    mode,
    source,
    reason,
    expires_at,
    timestamp
from telemetry_modes
order by tenant_id, device_id, timestamp desc;

create or replace view process_graph_nodes as
select
    tenant_id,
    device_id,
    hostname,
    execution_id,
    parent_execution_id,
    root_execution_id,
    image,
    parent_image,
    grandparent_image,
    chain,
    depth,
    start_time,
    stop_time,
    duration_ms,
    risk_score,
    tags
from process_executions;
