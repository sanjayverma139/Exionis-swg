// Package events holds shared event types and channels.
// This package breaks the circular dependency between etw and correlation.
package events

import "time"

// EventInput represents a raw process/thread event from the ETW bridge.
type EventInput struct {
	Type      string    `json:"type"`
	Provider  string    `json:"provider"`
	PID       uint32    `json:"pid"`
	TID       uint32    `json:"tid"`
	EventID   uint16    `json:"event_id"`
	Opcode    uint8     `json:"opcode"`
	Detail    string    `json:"detail"`
	Timestamp time.Time `json:"timestamp"`
}

// NetworkEvent represents a parsed TCP/UDP event from ETW.
type NetworkEvent struct {
	PID        uint32    `json:"pid"`
	LocalIP    string    `json:"local_ip"`
	RemoteIP   string    `json:"remote_ip"`
	LocalPort  uint16    `json:"local_port"`
	RemotePort uint16    `json:"remote_port"`
	Protocol   string    `json:"protocol"`
	Direction  string    `json:"direction"`
	BytesSent  uint64    `json:"bytes_sent,omitempty"`
	BytesRecv  uint64    `json:"bytes_recv,omitempty"`
	Timestamp  time.Time `json:"timestamp"`
	Domain     string    `json:"domain,omitempty"`
}

// Global buffered channels for event distribution.
// Initialized at package load time. Thread-safe via Go channels.
var (
	ProcessChan = make(chan EventInput, 10000)
	NetworkChan = make(chan NetworkEvent, 10000)
)