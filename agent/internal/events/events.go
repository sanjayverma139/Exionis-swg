// Package events holds shared event types and channels.
// This package breaks the circular dependency between etw and correlation.
package events

import "time"

// EventInput represents a raw process/thread event from the ETW bridge.

type EventInput struct {
	Type          string    `json:"type"`
	Provider      string    `json:"provider"`
	PID           uint32    `json:"pid"`
	TID           uint32    `json:"tid"`
	EventID       uint16    `json:"event_id"`
	Opcode        uint8     `json:"opcode"`
	Detail        string    `json:"detail"`
	Timestamp     time.Time `json:"timestamp"`
	DeviceID      string    `json:"device_id,omitempty"`      // ← NEW: Cloud sync
	AgentVersion  string    `json:"agent_version,omitempty"`  // ← NEW: Version tracking
	PolicyVersion string    `json:"policy_version,omitempty"` // ← NEW: Policy tracking
	Source        string    `json:"source,omitempty"`         // ← NEW: "etw" or "bootstrap"
}

// NetworkEvent represents a parsed TCP/UDP event from ETW.
type NetworkEvent struct {
	PID           uint32    `json:"pid"`
	LocalIP       string    `json:"local_ip"`
	RemoteIP      string    `json:"remote_ip"`
	LocalPort     uint16    `json:"local_port"`
	RemotePort    uint16    `json:"remote_port"`
	Protocol      string    `json:"protocol"`
	Direction     string    `json:"direction"`
	BytesSent     uint64    `json:"bytes_sent,omitempty"`
	BytesRecv     uint64    `json:"bytes_recv,omitempty"`
	Timestamp     time.Time `json:"timestamp"`
	Domain        string    `json:"domain,omitempty"`
	Opcode        uint8     `json:"opcode"`
	DeviceID      string    `json:"device_id,omitempty"`      // ← NEW: Cloud sync
	AgentVersion  string    `json:"agent_version,omitempty"`  // ← NEW: Version tracking
	PolicyVersion string    `json:"policy_version,omitempty"` // ← NEW: Policy tracking
}

// Global buffered channels for event distribution.
// Initialized at package load time. Thread-safe via Go channels.
var (
	ProcessChan       = make(chan EventInput, 10000)
	NetworkChan       = make(chan NetworkEvent, 10000)
	NetworkOutputChan = make(chan NetworkOutputRecord, 5000)
)

// NetworkOutputRecord is a simplified record for file writing
type NetworkOutputRecord struct {
	Timestamp  string `json:"timestamp"`
	PID        uint32 `json:"pid"`
	Image      string `json:"image"`
	LocalIP    string `json:"local_ip"`
	RemoteIP   string `json:"remote_ip"`
	LocalPort  uint16 `json:"local_port"`
	RemotePort uint16 `json:"remote_port"`
	Protocol   string `json:"protocol"`
	Direction  string `json:"direction"`
	Domain     string `json:"domain,omitempty"`
	BytesSent  uint64 `json:"bytes_sent,omitempty"`
	BytesRecv  uint64 `json:"bytes_recv,omitempty"`
	State      string `json:"state"`
}

// InferDirection converts ETW TCP/IP opcodes into a human-readable direction.
func InferDirection(opcode uint8, protocol string) string {
	if protocol != "TCP" {
		return "unknown"
	}
	switch opcode {
	case 10, 12, 13, 16: // Connect, Reconnect, Send, Retransmit
		return "outbound"
	case 11, 14: // Accept, Receive
		return "inbound"
	default:
		return "unknown"
	}
}
