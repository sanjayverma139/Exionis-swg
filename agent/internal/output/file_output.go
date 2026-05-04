//go:build windows
// +build windows

// Package output handles structured file output for cloud sync.
// Writes two separate NDJSON files:
//  1. apps_<deviceID>_<date>.ndjson     — installed applications snapshot
//  2. processes_<deviceID>_<date>.ndjson — real-time process events
//
// Each line is a self-contained JSON record ready for Supabase/cloud ingestion.
package output

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// ============================================================================
// CLOUD-READY RECORD TYPES
// These match the schema your cloud admin panel will consume.
// Each field maps to a database column.
// ============================================================================

// AppRecord is one row in the cloud `installed_apps` table.
type AppRecord struct {
	// Cloud sync metadata
	RecordType    string `json:"record_type"` // always "installed_app"
	DeviceID      string `json:"device_id"`   // hardware fingerprint
	Hostname      string `json:"hostname,omitempty"`
	AgentVersion  string `json:"agent_version"`
	ScanTime      string `json:"scan_time"`      // ISO8601 — when this scan ran
	SchemaVersion int    `json:"schema_version"` // for migration tracking

	// App identity
	DisplayName     string `json:"display_name"`
	DisplayVersion  string `json:"display_version,omitempty"`
	Publisher       string `json:"publisher,omitempty"`
	InstallLocation string `json:"install_location,omitempty"`
	InstallDate     string `json:"install_date,omitempty"`
	UninstallString string `json:"uninstall_string,omitempty"`

	// Size metrics
	EstimatedSizeKB uint64 `json:"estimated_size_kb,omitempty"`
	ActualSizeKB    uint64 `json:"actual_size_kb,omitempty"`

	// Classification
	IsSystemComponent bool   `json:"is_system_component"`
	RegistrySource    string `json:"registry_source"`          // HKLM, HKCU, HKLM_WoW64
	InstallSource     string `json:"install_source,omitempty"` // MSI, InnoSetup, EXE...

	// Security
	FileHash  string `json:"file_hash,omitempty"`
	RiskScore int    `json:"risk_score,omitempty"`
}

// ProcessRecord is one row in the cloud `process_events` table.
type ProcessRecord struct {
	// Cloud sync metadata
	RecordType    string `json:"record_type"` // "process_start" | "process_stop" | "process_aggregate"
	DeviceID      string `json:"device_id"`
	Hostname      string `json:"hostname,omitempty"`
	AgentVersion  string `json:"agent_version"`
	SchemaVersion int    `json:"schema_version"`

	// Event identity
	Timestamp string `json:"timestamp"` // ISO8601 nanosecond
	EventSeq  uint64 `json:"event_seq"` // monotonic sequence for ordering

	// Process identity
	PID         uint32 `json:"pid"`
	PPID        uint32 `json:"ppid,omitempty"`
	Image       string `json:"image"`
	ParentImage string `json:"parent_image,omitempty"`
	Cmdline     string `json:"cmdline,omitempty"`
	ImagePath   string `json:"image_path,omitempty"`

	// Lifecycle
	StartTime  string `json:"start_time,omitempty"`
	StopTime   string `json:"stop_time,omitempty"`
	DurationMs int64  `json:"duration_ms,omitempty"`
	IsAlive    bool   `json:"is_alive"`

	// Enrichment
	SHA256Hash string `json:"sha256_hash,omitempty"`
	IsSystem   bool   `json:"is_system"`
	UserSID    string `json:"user_sid,omitempty"`

	// Network summary (optional — filled if connections exist)
	ActiveConnections int    `json:"active_connections,omitempty"`
	TotalBytesSent    uint64 `json:"total_bytes_sent,omitempty"`
	TotalBytesRecv    uint64 `json:"total_bytes_recv,omitempty"`
}

// ProcessExecutionRecord is the compact baseline record for one real process run.
type ProcessExecutionRecord struct {
	RecordType         string   `json:"record_type"` // always "process_execution"
	DeviceID           string   `json:"device_id"`
	Hostname           string   `json:"hostname,omitempty"`
	AgentVersion       string   `json:"agent_version"`
	SchemaVersion      int      `json:"schema_version"`
	Timestamp          string   `json:"timestamp"`
	ExecutionID        string   `json:"execution_id"`
	ParentExecutionID  string   `json:"parent_execution_id,omitempty"`
	RootExecutionID    string   `json:"root_execution_id,omitempty"`
	BootID             string   `json:"boot_id"`
	PID                uint32   `json:"pid"`
	PPID               uint32   `json:"ppid,omitempty"`
	Image              string   `json:"image"`
	ParentImage        string   `json:"parent_image,omitempty"`
	GrandParentImage   string   `json:"grandparent_image,omitempty"`
	Chain              string   `json:"chain,omitempty"`
	Depth              int      `json:"depth,omitempty"`
	FullPath           string   `json:"full_path,omitempty"`
	SHA256Hash         string   `json:"sha256_hash,omitempty"`
	UserSID            string   `json:"user_sid,omitempty"`
	Username           string   `json:"username,omitempty"`
	StartTime          string   `json:"start_time,omitempty"`
	StopTime           string   `json:"stop_time,omitempty"`
	DurationMs         int64    `json:"duration_ms,omitempty"`
	Aggregated         bool     `json:"aggregated,omitempty"`
	ExecutionCount     int      `json:"execution_count,omitempty"`
	FirstSeen          string   `json:"first_seen,omitempty"`
	LastSeen           string   `json:"last_seen,omitempty"`
	FirstPID           uint32   `json:"first_pid,omitempty"`
	LastPID            uint32   `json:"last_pid,omitempty"`
	AvgDurationMs      int64    `json:"avg_duration_ms,omitempty"`
	MinDurationMs      int64    `json:"min_duration_ms,omitempty"`
	MaxDurationMs      int64    `json:"max_duration_ms,omitempty"`
	IsSystem           bool     `json:"is_system"`
	IntegrityLevel     string   `json:"integrity_level,omitempty"`
	Elevation          string   `json:"elevation,omitempty"`
	RiskScore          int      `json:"risk_score,omitempty"`
	Tags               []string `json:"tags,omitempty"`
	CommandLinePresent bool     `json:"command_line_present,omitempty"`
}

// ProcessEdgeRecord stores one durable parent -> child relationship for graph views.
type ProcessEdgeRecord struct {
	RecordType        string `json:"record_type"` // always "process_edge"
	DeviceID          string `json:"device_id"`
	Hostname          string `json:"hostname,omitempty"`
	AgentVersion      string `json:"agent_version"`
	SchemaVersion     int    `json:"schema_version"`
	Timestamp         string `json:"timestamp"`
	EdgeType          string `json:"edge_type"`
	ParentExecutionID string `json:"parent_execution_id,omitempty"`
	ChildExecutionID  string `json:"child_execution_id"`
	RootExecutionID   string `json:"root_execution_id,omitempty"`
	ParentPID         uint32 `json:"parent_pid,omitempty"`
	ChildPID          uint32 `json:"child_pid"`
	ParentImage       string `json:"parent_image,omitempty"`
	ChildImage        string `json:"child_image"`
	Depth             int    `json:"depth,omitempty"`
}

// NetworkRollupRecord stores summarized network activity for a process execution.
type NetworkRollupRecord struct {
	RecordType        string `json:"record_type"` // always "network_rollup"
	DeviceID          string `json:"device_id"`
	Hostname          string `json:"hostname,omitempty"`
	AgentVersion      string `json:"agent_version"`
	SchemaVersion     int    `json:"schema_version"`
	Timestamp         string `json:"timestamp"`
	WindowStart       string `json:"window_start"`
	WindowEnd         string `json:"window_end"`
	ExecutionID       string `json:"execution_id,omitempty"`
	RootExecutionID   string `json:"root_execution_id,omitempty"`
	PID               uint32 `json:"pid"`
	Image             string `json:"image"`
	LocalIP           string `json:"local_ip,omitempty"`
	RemoteIP          string `json:"remote_ip"`
	EndpointGroup     string `json:"endpoint_group,omitempty"`
	LocalPort         uint16 `json:"local_port,omitempty"`
	RemotePort        uint16 `json:"remote_port"`
	PortClass         string `json:"port_class,omitempty"`
	Protocol          string `json:"protocol"`
	Direction         string `json:"direction,omitempty"`
	Domain            string `json:"domain,omitempty"`
	IsInternal        bool   `json:"is_internal,omitempty"`
	ConnectionCount   int    `json:"connection_count"`
	BytesSent         uint64 `json:"bytes_sent,omitempty"`
	BytesRecv         uint64 `json:"bytes_recv,omitempty"`
	LastObservedState string `json:"last_observed_state,omitempty"`
}

// TelemetryModeRecord tracks changes between baseline and deep capture.
type TelemetryModeRecord struct {
	RecordType      string `json:"record_type"` // always "telemetry_mode"
	DeviceID        string `json:"device_id"`
	Hostname        string `json:"hostname,omitempty"`
	AgentVersion    string `json:"agent_version"`
	SchemaVersion   int    `json:"schema_version"`
	Timestamp       string `json:"timestamp"`
	Mode            string `json:"mode"`
	Source          string `json:"source,omitempty"`
	Reason          string `json:"reason,omitempty"`
	ExpiresAt       string `json:"expires_at,omitempty"`
	DeepCapturePath string `json:"deep_capture_path,omitempty"`
}

// NetworkRecord is one row in the cloud `network_events` table.
type NetworkRecord struct {
	RecordType    string `json:"record_type"` // always "network_connection"
	DeviceID      string `json:"device_id"`
	Hostname      string `json:"hostname,omitempty"`
	AgentVersion  string `json:"agent_version"`
	SchemaVersion int    `json:"schema_version"`

	Timestamp  string `json:"timestamp"`
	PID        uint32 `json:"pid"`
	Image      string `json:"image"`
	LocalIP    string `json:"local_ip"`
	RemoteIP   string `json:"remote_ip"`
	LocalPort  uint16 `json:"local_port"`
	RemotePort uint16 `json:"remote_port"`
	Protocol   string `json:"protocol"`
	Direction  string `json:"direction"`
	State      string `json:"state"`
	Domain     string `json:"domain,omitempty"`
	BytesSent  uint64 `json:"bytes_sent,omitempty"`
	BytesRecv  uint64 `json:"bytes_recv,omitempty"`
}

// ============================================================================
// WRITER — one writer per file type
// ============================================================================

// Writer writes NDJSON records to a dedicated file.
// Thread-safe. New file per day.
type Writer struct {
	mu         sync.Mutex
	dir        string
	prefix     string // "apps" or "processes" or "network"
	deviceID   string
	current    *os.File
	currentDay string // YYYY-MM-DD — used to detect day rollover
}

// NewWriter creates a Writer. dir must exist or be creatable.
func NewWriter(dir, prefix, deviceID string) (*Writer, error) {
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("create output dir %s: %w", dir, err)
	}
	return &Writer{dir: dir, prefix: prefix, deviceID: deviceID}, nil
}

func (w *Writer) filePath(day string) string {
	// Format: apps_dev-XXXXX_2026-04-24.ndjson
	safe := sanitizeDeviceID(w.deviceID)
	return filepath.Join(w.dir, fmt.Sprintf("%s_%s_%s.ndjson", w.prefix, safe, day))
}

func sanitizeDeviceID(id string) string {
	// Replace : with - for safe filenames (dev:abc → dev-abc)
	safe := ""
	for _, c := range id {
		if c == ':' {
			safe += "-"
		} else {
			safe += string(c)
		}
	}
	return safe
}

func (w *Writer) openFile() error {
	day := time.Now().Format("2006-01-02")
	f, err := os.OpenFile(w.filePath(day), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return fmt.Errorf("open %s output file: %w", w.prefix, err)
	}
	if w.current != nil {
		w.current.Close()
	}
	w.current = f
	w.currentDay = day
	return nil
}

// Write serialises v as one NDJSON line and appends it to the file.
// Automatically rolls to a new file at day boundary.
func (w *Writer) Write(v interface{}) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	// Day rollover check
	today := time.Now().Format("2006-01-02")
	if w.current == nil || today != w.currentDay {
		if err := w.openFile(); err != nil {
			return err
		}
	}

	b, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("marshal record: %w", err)
	}
	b = append(b, '\n')
	_, err = w.current.Write(b)
	return err
}

// Close flushes and closes the underlying file.
func (w *Writer) Close() {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.current != nil {
		w.current.Sync()
		w.current.Close()
		w.current = nil
	}
}

// ============================================================================
// OUTPUT MANAGER — holds one writer per stream
// ============================================================================

// Manager owns the three output writers (apps, processes, network).
// Create once in main.go; pass to wherever events are emitted.
type Manager struct {
	Apps              *Writer
	Processes         *Writer
	Network           *Writer
	ProcessExecutions *Writer
	ProcessEdges      *Writer
	NetworkRollups    *Writer
	TelemetryModes    *Writer
	DeviceID          string
	Hostname          string
	AgentVer          string
}

// NewManager creates all three writers under baseDir.
// Suggested baseDir: C:\ProgramData\Exionis\output
func NewManager(baseDir, deviceID, hostname, agentVersion string) (*Manager, error) {
	if err := archiveExistingOutputs(baseDir, deviceID); err != nil {
		return nil, err
	}
	apps, err := NewWriter(baseDir, "apps", deviceID)
	if err != nil {
		return nil, err
	}
	procs, err := NewWriter(baseDir, "processes", deviceID)
	if err != nil {
		apps.Close()
		return nil, err
	}
	net, err := NewWriter(baseDir, "network", deviceID)
	if err != nil {
		apps.Close()
		procs.Close()
		return nil, err
	}
	procExec, err := NewWriter(baseDir, "process_execution", deviceID)
	if err != nil {
		apps.Close()
		procs.Close()
		net.Close()
		return nil, err
	}
	procEdge, err := NewWriter(baseDir, "process_edge", deviceID)
	if err != nil {
		apps.Close()
		procs.Close()
		net.Close()
		procExec.Close()
		return nil, err
	}
	netRollup, err := NewWriter(baseDir, "network_rollup", deviceID)
	if err != nil {
		apps.Close()
		procs.Close()
		net.Close()
		procExec.Close()
		procEdge.Close()
		return nil, err
	}
	modeAudit, err := NewWriter(baseDir, "telemetry_mode", deviceID)
	if err != nil {
		apps.Close()
		procs.Close()
		net.Close()
		procExec.Close()
		procEdge.Close()
		netRollup.Close()
		return nil, err
	}
	return &Manager{
		Apps:              apps,
		Processes:         procs,
		Network:           net,
		ProcessExecutions: procExec,
		ProcessEdges:      procEdge,
		NetworkRollups:    netRollup,
		TelemetryModes:    modeAudit,
		DeviceID:          deviceID,
		Hostname:          hostname,
		AgentVer:          agentVersion,
	}, nil
}

// Close flushes and closes all writers.
func (m *Manager) Close() {
	m.Apps.Close()
	m.Processes.Close()
	m.Network.Close()
	m.ProcessExecutions.Close()
	m.ProcessEdges.Close()
	m.NetworkRollups.Close()
	m.TelemetryModes.Close()
}

// WriteApp writes one installed application record.
func (m *Manager) WriteApp(app AppRecord) error {
	app.RecordType = "installed_app"
	app.DeviceID = m.DeviceID
	app.Hostname = m.Hostname
	app.AgentVersion = m.AgentVer
	app.SchemaVersion = 1
	if app.ScanTime == "" {
		app.ScanTime = time.Now().Format(time.RFC3339Nano)
	}
	return m.Apps.Write(app)
}

// WriteProcess writes one process event record.
func (m *Manager) WriteProcess(proc ProcessRecord) error {
	proc.DeviceID = m.DeviceID
	proc.Hostname = m.Hostname
	proc.AgentVersion = m.AgentVer
	proc.SchemaVersion = 1
	return m.Processes.Write(proc)
}

// WriteNetwork writes one network connection record.
func (m *Manager) WriteNetwork(net NetworkRecord) error {
	net.RecordType = "network_connection"
	net.DeviceID = m.DeviceID
	net.Hostname = m.Hostname
	net.AgentVersion = m.AgentVer
	net.SchemaVersion = 1
	return m.Network.Write(net)
}

// WriteProcessExecution writes one summarized process execution record.
func (m *Manager) WriteProcessExecution(proc ProcessExecutionRecord) error {
	proc.RecordType = "process_execution"
	proc.DeviceID = m.DeviceID
	proc.Hostname = m.Hostname
	proc.AgentVersion = m.AgentVer
	proc.SchemaVersion = 1
	if proc.Timestamp == "" {
		proc.Timestamp = time.Now().Format(time.RFC3339Nano)
	}
	return m.ProcessExecutions.Write(proc)
}

// WriteProcessEdge writes one process lineage edge.
func (m *Manager) WriteProcessEdge(edge ProcessEdgeRecord) error {
	edge.RecordType = "process_edge"
	edge.DeviceID = m.DeviceID
	edge.Hostname = m.Hostname
	edge.AgentVersion = m.AgentVer
	edge.SchemaVersion = 1
	if edge.Timestamp == "" {
		edge.Timestamp = time.Now().Format(time.RFC3339Nano)
	}
	return m.ProcessEdges.Write(edge)
}

// WriteNetworkRollup writes one summarized network rollup record.
func (m *Manager) WriteNetworkRollup(rollup NetworkRollupRecord) error {
	rollup.RecordType = "network_rollup"
	rollup.DeviceID = m.DeviceID
	rollup.Hostname = m.Hostname
	rollup.AgentVersion = m.AgentVer
	rollup.SchemaVersion = 1
	if rollup.Timestamp == "" {
		rollup.Timestamp = time.Now().Format(time.RFC3339Nano)
	}
	return m.NetworkRollups.Write(rollup)
}

// WriteTelemetryMode writes one telemetry mode audit record.
func (m *Manager) WriteTelemetryMode(mode TelemetryModeRecord) error {
	mode.RecordType = "telemetry_mode"
	mode.DeviceID = m.DeviceID
	mode.Hostname = m.Hostname
	mode.AgentVersion = m.AgentVer
	mode.SchemaVersion = 1
	if mode.Timestamp == "" {
		mode.Timestamp = time.Now().Format(time.RFC3339Nano)
	}
	return m.TelemetryModes.Write(mode)
}

func archiveExistingOutputs(baseDir, deviceID string) error {
	if err := os.MkdirAll(baseDir, 0755); err != nil {
		return fmt.Errorf("create output dir %s: %w", baseDir, err)
	}

	safe := sanitizeDeviceID(deviceID)
	prefixes := []string{
		"apps",
		"processes",
		"network",
		"process_execution",
		"process_edge",
		"network_rollup",
		"telemetry_mode",
	}

	for _, prefix := range prefixes {
		pattern := filepath.Join(baseDir, fmt.Sprintf("%s_%s_*.ndjson", prefix, safe))
		matches, err := filepath.Glob(pattern)
		if err != nil {
			return fmt.Errorf("glob %s: %w", pattern, err)
		}
		for _, src := range matches {
			base := filepath.Base(src)
			if strings.HasPrefix(base, "Old_") {
				continue
			}
			dst := filepath.Join(baseDir, "Old_"+base)
			if _, err := os.Stat(dst); err == nil {
				dst = filepath.Join(baseDir, fmt.Sprintf("Old_%s_%d.ndjson", strings.TrimSuffix(base, ".ndjson"), time.Now().UnixNano()))
			}
			if err := os.Rename(src, dst); err != nil && !os.IsNotExist(err) {
				return fmt.Errorf("archive %s: %w", src, err)
			}
		}
	}
	return nil
}
