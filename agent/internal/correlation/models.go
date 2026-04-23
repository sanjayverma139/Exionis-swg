// File: internal/correlation/models.go
package correlation

import "time"

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
}

type ProcessEnrichment struct {
	ExecutablePath string
	SHA256Hash     string
	IsSigned       bool
	IsSystem       bool
	UserSID        string
}

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

type SpawnStats struct {
	ParentImage string
	ChildImage  string
	FirstSeen   time.Time
	LastSeen    time.Time
	Count       int
	WindowStart time.Time
}

type EventInput struct {
	Type      string
	Provider  string
	PID       uint32
	TID       uint32
	EventID   uint16
	Opcode    uint8
	Detail    string
	Timestamp time.Time
}