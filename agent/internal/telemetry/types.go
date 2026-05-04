//go:build windows
// +build windows

package telemetry

import "time"

type executionState struct {
	ExecutionID        string
	ParentExecutionID  string
	RootExecutionID    string
	BootID             string
	PID                uint32
	PPID               uint32
	Image              string
	ParentImage        string
	GrandParentImage   string
	Chain              string
	Depth              int
	FullPath           string
	Cmdline            string
	SHA256Hash         string
	UserSID            string
	Username           string
	StartTime          time.Time
	StopTime           time.Time
	DurationMs         int64
	IsAlive            bool
	IsSystem           bool
	IntegrityLevel     string
	Elevation          string
	RiskScore          int
	Tags               []string
	CommandLinePresent bool
}

type processRollupState struct {
	Key             string
	WindowStart     time.Time
	WindowEnd       time.Time
	Sample          *executionState
	ExecutionCount  int
	FirstSeen       time.Time
	LastSeen        time.Time
	FirstPID        uint32
	LastPID         uint32
	MinDurationMs   int64
	MaxDurationMs   int64
	TotalDurationMs int64
}

type networkRollupState struct {
	Key               string
	WindowStart       time.Time
	WindowEnd         time.Time
	ExecutionID       string
	RootExecutionID   string
	PID               uint32
	Image             string
	LocalIP           string
	RemoteIP          string
	EndpointGroup     string
	LocalPort         uint16
	RemotePort        uint16
	PortClass         string
	Protocol          string
	Direction         string
	Domain            string
	IsInternal        bool
	ConnectionCount   int
	BytesSent         uint64
	BytesRecv         uint64
	LastObservedState string
}
