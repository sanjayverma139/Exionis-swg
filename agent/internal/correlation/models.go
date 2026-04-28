// Package correlation handles process lifecycle tracking and event correlation.
package correlation

import (
	"fmt"
	"sync"
	"time"
)

// ============================================================================
// CONNECTION STATE ENUM
// ============================================================================
type ConnectionState string

const (
	StateNew         ConnectionState = "new"
	StateEstablished                 = "established"
	StateClosing                     = "closing"
	StateClosed                      = "closed"
	StateUnknown                     = "unknown"
)

// ============================================================================
// PROCESS INFO (with genealogy + risk fields added)
// ============================================================================
type ProcessInfo struct {
	PID         uint32
	PPID        uint32
	Image       string
	Cmdline     string
	ImagePath   string
	StartTime   time.Time
	EndTime     time.Time
	IsAlive     bool
	IsOrphan    bool
	Username    string
	Parent      *ProcessInfo
	Children    []*ProcessInfo
	Enrichment  ProcessEnrichment
	Connections []*ConnectionInfo
	connMu      sync.RWMutex

	// === GENEALOGY FIELDS (Phase 1.5) ===
	ParentImage      string
	GrandParentImage string
	RootPID          uint32
	Depth            int
	Chain            string // "explorer.exe > cmd.exe > powershell.exe"

	// === RISK SCORING FIELDS (non-blocking, informational) ===
	RiskScore   int
	RiskReasons []string
}

// ============================================================================
// PROCESS ENRICHMENT (unchanged, just confirming fields)
// ============================================================================
type ProcessEnrichment struct {
	ExecutablePath string `json:"executable_path,omitempty"`
	SHA256Hash     string `json:"sha256_hash,omitempty"`
	IsSystem       bool   `json:"is_system"`
	UserSID        string `json:"user_sid,omitempty"`
	Username       string `json:"username,omitempty"`
	SizeBytes      int64  `json:"size_bytes,omitempty"`
	SizeKB         int64  `json:"size_kb,omitempty"`
	IsOrphan       bool   `json:"is_orphan,omitempty"`
}

// ============================================================================
// STRUCTURED EVENT (with genealogy + risk fields added)
// ============================================================================
type StructuredEvent struct {
	EventType        string            `json:"event_type"`
	Timestamp        time.Time         `json:"timestamp"`
	PID              uint32            `json:"pid"`
	PPID             uint32            `json:"ppid,omitempty"`
	Image            string            `json:"image"`
	ParentImage      string            `json:"parent_image,omitempty"`
	GrandParentImage string            `json:"grandparent_image,omitempty"`
	Chain            string            `json:"chain,omitempty"`
	Depth            int               `json:"depth,omitempty"`
	Cmdline          string            `json:"cmdline,omitempty"`
	ImagePath        string            `json:"image_path,omitempty"`
	DurationMs       int64             `json:"duration_ms,omitempty"`
	IsAlive          bool              `json:"is_alive"`
	Resolved         bool              `json:"resolved"`
	Enrichment       ProcessEnrichment `json:"enrichment,omitempty"`
	SequenceID       uint64            `json:"-"`

	// === RISK SCORING FIELDS (non-blocking, informational) ===
	RiskScore   int      `json:"risk_score,omitempty"`
	RiskReasons []string `json:"risk_reasons,omitempty"`
}

// ============================================================================
// CORRELATED EVENT (legacy format - unchanged)
// ============================================================================
type CorrelatedEvent struct {
	Type        string
	PID         uint32
	TID         uint32
	EventID     uint16
	Opcode      uint8
	Provider    string
	Detail      string
	Timestamp   time.Time
	ProcessName string
	ParentPID   uint32
	ParentName  string
	Summary     string
}

// ============================================================================
// SPAWN STATS (unchanged)
// ============================================================================
type SpawnStats struct {
	ParentImage string
	ChildImage  string
	FirstSeen   time.Time
	LastSeen    time.Time
	Count       int
	WindowStart time.Time
}

// ============================================================================
// CONNECTION INFO (unchanged)
// ============================================================================
type ConnectionInfo struct {
	RemoteIP   string          `json:"remote_ip"`
	RemotePort uint16          `json:"remote_port"`
	Protocol   string          `json:"protocol"`
	BytesSent  uint64          `json:"bytes_sent"`
	BytesRecv  uint64          `json:"bytes_recv"`
	FirstSeen  time.Time       `json:"first_seen"`
	LastSeen   time.Time       `json:"last_seen"`
	Domain     string          `json:"domain,omitempty"`
	State      ConnectionState `json:"state"`
}

// ============================================================================
// CONNECTION METHODS (unchanged - preserves existing behavior)
// ============================================================================

// UpsertConnection adds or updates a connection record with state merging
func (p *ProcessInfo) UpsertConnection(conn *ConnectionInfo) {
	p.connMu.Lock()
	defer p.connMu.Unlock()

	key := fmt.Sprintf("%s:%d:%s", conn.RemoteIP, conn.RemotePort, conn.Protocol)
	for _, existing := range p.Connections {
		existingKey := fmt.Sprintf("%s:%d:%s", existing.RemoteIP, existing.RemotePort, existing.Protocol)
		if existingKey == key {
			existing.BytesSent += conn.BytesSent
			existing.BytesRecv += conn.BytesRecv
			existing.LastSeen = conn.LastSeen
			if existing.Domain == "" && conn.Domain != "" {
				existing.Domain = conn.Domain
			}
			// Preserve state unless new state is more definitive
			if conn.State != StateUnknown && conn.State != existing.State {
				existing.State = conn.State
			}
			return
		}
	}
	newConn := *conn
	p.Connections = append(p.Connections, &newConn)
}

// GetConnections returns a safe copy of connections
func (p *ProcessInfo) GetConnections() []*ConnectionInfo {
	p.connMu.RLock()
	defer p.connMu.RUnlock()
	result := make([]*ConnectionInfo, len(p.Connections))
	copy(result, p.Connections)
	return result
}

// GetConnectionsByState filters connections by state (helper for queries)
func (p *ProcessInfo) GetConnectionsByState(state ConnectionState) []*ConnectionInfo {
	p.connMu.RLock()
	defer p.connMu.RUnlock()
	var filtered []*ConnectionInfo
	for _, conn := range p.Connections {
		if conn.State == state {
			cpy := *conn
			filtered = append(filtered, &cpy)
		}
	}
	return filtered
}
