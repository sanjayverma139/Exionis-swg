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

// NetworkRecord is one row in the cloud `network_events` table.
type NetworkRecord struct {
	RecordType    string `json:"record_type"` // always "network_connection"
	DeviceID      string `json:"device_id"`
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
	w := &Writer{dir: dir, prefix: prefix, deviceID: deviceID}
	if err := w.openFile(); err != nil {
		return nil, err
	}
	return w, nil
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
	if today != w.currentDay {
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
	Apps      *Writer
	Processes *Writer
	Network   *Writer
	DeviceID  string
	AgentVer  string
}

// NewManager creates all three writers under baseDir.
// Suggested baseDir: C:\ProgramData\Exionis\output
func NewManager(baseDir, deviceID, agentVersion string) (*Manager, error) {
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
	return &Manager{
		Apps:      apps,
		Processes: procs,
		Network:   net,
		DeviceID:  deviceID,
		AgentVer:  agentVersion,
	}, nil
}

// Close flushes and closes all writers.
func (m *Manager) Close() {
	m.Apps.Close()
	m.Processes.Close()
	m.Network.Close()
}

// WriteApp writes one installed application record.
func (m *Manager) WriteApp(app AppRecord) error {
	app.RecordType = "installed_app"
	app.DeviceID = m.DeviceID
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
	proc.AgentVersion = m.AgentVer
	proc.SchemaVersion = 1
	return m.Processes.Write(proc)
}

// WriteNetwork writes one network connection record.
func (m *Manager) WriteNetwork(net NetworkRecord) error {
	net.RecordType = "network_connection"
	net.DeviceID = m.DeviceID
	net.AgentVersion = m.AgentVer
	net.SchemaVersion = 1
	return m.Network.Write(net)
}
