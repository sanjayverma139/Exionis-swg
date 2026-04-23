// Package correlation handles process lifecycle tracking and event correlation.
package correlation

import (
	"sync"
	"time"
)

// ProcessInfo holds enriched process metadata
type ProcessInfo struct {
	PID         uint32
	PPID        uint32
	Image       string
	Cmdline     string
	ImagePath   string
	StartTime   time.Time
	EndTime     time.Time
	IsAlive     bool
	Parent      *ProcessInfo
	Children    []*ProcessInfo
	Enrichment  ProcessEnrichment
	Connections []*ConnectionInfo
	connMu      sync.RWMutex
}

// ProcessEnrichment holds async-resolved metadata
type ProcessEnrichment struct {
	ExecutablePath string `json:"executable_path,omitempty"`
	SHA256Hash     string `json:"sha256_hash,omitempty"`
	IsSigned       bool   `json:"is_signed"`
	IsSystem       bool   `json:"is_system"`
	UserSID        string `json:"user_sid,omitempty"`
}

// StructuredEvent is the unified output format
type StructuredEvent struct {
	EventType   string            `json:"event_type"`
	Timestamp   time.Time         `json:"timestamp"`
	PID         uint32            `json:"pid"`
	PPID        uint32            `json:"ppid,omitempty"`
	Image       string            `json:"image"`
	ParentImage string            `json:"parent_image,omitempty"`
	Cmdline     string            `json:"cmdline,omitempty"`
	ImagePath   string            `json:"image_path,omitempty"`
	DurationMs  int64             `json:"duration_ms,omitempty"`
	Resolved    bool              `json:"resolved"`
	Enrichment  ProcessEnrichment `json:"enrichment,omitempty"`
	SequenceID  uint64            `json:"-"`
}

// CorrelatedEvent is legacy format for backward compatibility
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

// SpawnStats tracks process spawn aggregation with eviction support
type SpawnStats struct {
	ParentImage string
	ChildImage  string
	FirstSeen   time.Time
	LastSeen    time.Time  // ← Critical for eviction
	Count       int
	WindowStart time.Time
}

// ConnectionInfo holds network connection metadata
type ConnectionInfo struct {
	RemoteIP   string    `json:"remote_ip"`
	RemotePort uint16    `json:"remote_port"`
	Protocol   string    `json:"protocol"`
	BytesSent  uint64    `json:"bytes_sent"`
	BytesRecv  uint64    `json:"bytes_recv"`
	FirstSeen  time.Time `json:"first_seen"`
	LastSeen   time.Time `json:"last_seen"`
	Domain     string    `json:"domain,omitempty"`
}

// UpsertConnection adds or updates a connection record
func (p *ProcessInfo) UpsertConnection(conn *ConnectionInfo) {
	p.connMu.Lock()
	defer p.connMu.Unlock()
	
	key := conn.RemoteIP + ":" + string(conn.RemotePort) + ":" + conn.Protocol
	for _, existing := range p.Connections {
		existingKey := existing.RemoteIP + ":" + string(existing.RemotePort) + ":" + existing.Protocol
		if existingKey == key {
			existing.BytesSent += conn.BytesSent
			existing.BytesRecv += conn.BytesRecv
			existing.LastSeen = conn.LastSeen
			if existing.Domain == "" && conn.Domain != "" {
				existing.Domain = conn.Domain
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