//go:build windows
// +build windows

package telemetry

import (
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"exionis/internal/config"
	"exionis/internal/correlation"
	"exionis/internal/events"
	"exionis/internal/logger"
	"exionis/internal/output"
	"exionis/internal/process"
)

type Controller struct {
	cfg           Config
	outMgr        *output.Manager
	logSink       *logger.FileSink
	deviceID      string
	hostname      string
	agentVersion  string
	policyVersion string
	bootID        string
	startedAt     time.Time
	deepStartedAt time.Time

	mu             sync.Mutex
	activeByPID    map[uint32]*executionState
	processRollups map[string]*processRollupState
	rollups        map[string]*networkRollupState
	deepWriter     *output.GzipNDJSONWriter
	deepExpires    time.Time
	deepPath       string
	flushStop      chan struct{}
	wg             sync.WaitGroup
}

func NewController(cfg Config, outMgr *output.Manager, logSink *logger.FileSink, deviceID, hostname, agentVersion, policyVersion, bootID string) (*Controller, error) {
	c := &Controller{
		cfg:            cfg,
		outMgr:         outMgr,
		logSink:        logSink,
		deviceID:       deviceID,
		hostname:       hostname,
		agentVersion:   agentVersion,
		policyVersion:  policyVersion,
		bootID:         bootID,
		startedAt:      time.Now(),
		activeByPID:    make(map[uint32]*executionState, 1024),
		processRollups: make(map[string]*processRollupState, 256),
		rollups:        make(map[string]*networkRollupState, 4096),
		flushStop:      make(chan struct{}),
	}
	if err := c.startDeepCaptureIfNeeded(); err != nil {
		return nil, err
	}
	return c, nil
}

func (c *Controller) Start() {
	c.wg.Add(1)
	go c.flushLoop()
	c.emitModeAudit("startup", "agent_start")
}

func (c *Controller) Shutdown() {
	close(c.flushStop)
	c.wg.Wait()

	c.mu.Lock()
	rollups := make([]*networkRollupState, 0, len(c.rollups))
	processRollups := make([]*processRollupState, 0, len(c.processRollups))
	for key, rollup := range c.rollups {
		rollups = append(rollups, rollup)
		delete(c.rollups, key)
	}
	for key, rollup := range c.processRollups {
		processRollups = append(processRollups, rollup)
		delete(c.processRollups, key)
	}
	c.mu.Unlock()

	for _, rollup := range rollups {
		c.writeNetworkRollup(rollup)
	}
	for _, rollup := range processRollups {
		c.writeProcessExecutionRollup(rollup)
	}
	c.stopDeepCapture("shutdown", "agent_stop")
	c.emitModeAudit("shutdown", "agent_stop")
}

// SeedFromLiveProcesses builds an in-memory execution map for already-running processes
// so parent-child edges and network rollups stay meaningful across agent startup.
func (c *Controller) SeedFromLiveProcesses() {
	procs := process.GetProcesses()
	seeded := make(map[uint32]*executionState, len(procs))

	for _, procInfo := range procs {
		pid := uint32(procInfo.PID)
		start := process.GetProcessStartTime(pid)
		if start.IsZero() {
			start = c.startedAt
		}
		ppid := process.GetParentPID(pid)
		username := process.GetProcessUsername(pid)
		userSID := process.GetProcessUserSID(pid)
		exec := &executionState{
			ExecutionID:        buildExecutionID(c.deviceID, c.bootID, pid, start),
			BootID:             c.bootID,
			PID:                pid,
			PPID:               ppid,
			Image:              procInfo.Name,
			FullPath:           procInfo.Path,
			StartTime:          start,
			IsAlive:            true,
			UserSID:            userSID,
			Username:           username,
			IsSystem:           isSystemPath(procInfo.Path),
			Tags:               classifyTags(procInfo.Name, procInfo.Path, ""),
			CommandLinePresent: false,
		}
		seeded[pid] = exec
	}

	for _, exec := range seeded {
		if exec.PPID == 0 {
			exec.RootExecutionID = exec.ExecutionID
			exec.Depth = 1
			exec.Chain = exec.Image
			continue
		}
		parent, ok := seeded[exec.PPID]
		if !ok {
			exec.RootExecutionID = exec.ExecutionID
			exec.Depth = 1
			exec.Chain = exec.Image
			continue
		}
		exec.ParentExecutionID = parent.ExecutionID
		exec.ParentImage = parent.Image
		exec.Depth = parent.Depth + 1
		if exec.Depth == 1 {
			exec.Depth = 2
		}
		if parent.ParentImage != "" {
			exec.GrandParentImage = parent.ParentImage
		}
		if parent.RootExecutionID != "" {
			exec.RootExecutionID = parent.RootExecutionID
		} else {
			exec.RootExecutionID = parent.ExecutionID
		}
		if parent.Chain != "" {
			exec.Chain = parent.Chain + " > " + exec.Image
		} else {
			exec.Chain = parent.Image + " > " + exec.Image
		}
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	for pid, exec := range seeded {
		if exec.RootExecutionID == "" {
			exec.RootExecutionID = exec.ExecutionID
		}
		if exec.Depth == 0 {
			exec.Depth = 1
		}
		if exec.Chain == "" {
			exec.Chain = exec.Image
		}
		c.activeByPID[pid] = exec
	}
}

func (c *Controller) HandleProcessEvent(evt correlation.StructuredEvent) {
	c.captureDeepRecord("process_event", evt.Timestamp, evt)

	switch evt.EventType {
	case "process_start":
		c.handleProcessStart(evt)
	case "process_enrichment_update":
		c.handleProcessEnrichment(evt)
	case "process_stop":
		c.handleProcessStop(evt)
	}
}

func (c *Controller) HandleNetworkRecord(rec events.NetworkOutputRecord) {
	ts, err := time.Parse(time.RFC3339Nano, rec.Timestamp)
	if err != nil {
		ts = time.Now()
	}

	c.captureDeepRecord("network_event", ts, rec)

	windowStart := ts.Truncate(c.cfg.NetworkRollupWindow)
	windowEnd := windowStart.Add(c.cfg.NetworkRollupWindow)
	direction := normalizeDirection(rec.Protocol, rec.Direction)
	endpointGroup, isInternal := deriveEndpointGroup(rec.RemoteIP, rec.Domain)
	portClass := derivePortClass(rec.Protocol, rec.RemotePort)

	c.mu.Lock()
	c.expireDeepCaptureLocked(time.Now(), "timer", "deep_expired")

	exec := c.activeByPID[rec.PID]
	executionID := ""
	rootExecutionID := ""
	imageName := rec.Image
	if exec != nil {
		executionID = exec.ExecutionID
		rootExecutionID = exec.RootExecutionID
		if imageName == "" {
			imageName = exec.Image
		}
	}

	key := fmt.Sprintf("%s|%s|%s|%s|%s", imageName, windowStart.UTC().Format(time.RFC3339), endpointGroup, rec.Protocol, portClass)
	rollup, ok := c.rollups[key]
	if !ok {
		rollup = &networkRollupState{
			Key:             key,
			WindowStart:     windowStart,
			WindowEnd:       windowEnd,
			ExecutionID:     executionID,
			RootExecutionID: rootExecutionID,
			PID:             rec.PID,
			Image:           imageName,
			LocalIP:         rec.LocalIP,
			RemoteIP:        rec.RemoteIP,
			EndpointGroup:   endpointGroup,
			LocalPort:       rec.LocalPort,
			RemotePort:      rec.RemotePort,
			PortClass:       portClass,
			Protocol:        rec.Protocol,
			Direction:       direction,
			Domain:          rec.Domain,
			IsInternal:      isInternal,
		}
		c.rollups[key] = rollup
	} else {
		if rollup.ExecutionID != executionID {
			rollup.ExecutionID = ""
		}
		if rollup.RootExecutionID != rootExecutionID {
			rollup.RootExecutionID = ""
		}
		if rollup.RemoteIP != rec.RemoteIP && rollup.EndpointGroup != "" {
			rollup.RemoteIP = rollup.EndpointGroup
		}
		if rollup.LocalIP != rec.LocalIP {
			rollup.LocalIP = ""
		}
		if rollup.Direction != direction {
			rollup.Direction = "bidirectional"
		}
	}
	rollup.ConnectionCount++
	rollup.BytesSent += rec.BytesSent
	rollup.BytesRecv += rec.BytesRecv
	rollup.LastObservedState = rec.State
	if rollup.Image == "" {
		rollup.Image = imageName
	}
	c.mu.Unlock()
}

func (c *Controller) handleProcessStart(evt correlation.StructuredEvent) {
	var edge output.ProcessEdgeRecord
	shouldWriteEdge := false

	c.mu.Lock()
	c.expireDeepCaptureLocked(time.Now(), "timer", "deep_expired")

	parentExecID := ""
	rootExecID := ""
	if parent, ok := c.activeByPID[evt.PPID]; ok {
		parentExecID = parent.ExecutionID
		if parent.RootExecutionID != "" {
			rootExecID = parent.RootExecutionID
		} else {
			rootExecID = parent.ExecutionID
		}
	}

	startTime := evt.Timestamp
	if startTime.IsZero() {
		startTime = time.Now()
	}
	execID := buildExecutionID(c.deviceID, c.bootID, evt.PID, startTime)
	state := &executionState{
		ExecutionID:        execID,
		ParentExecutionID:  parentExecID,
		RootExecutionID:    rootExecID,
		BootID:             c.bootID,
		PID:                evt.PID,
		PPID:               evt.PPID,
		Image:              evt.Image,
		ParentImage:        evt.ParentImage,
		GrandParentImage:   evt.GrandParentImage,
		Chain:              evt.Chain,
		Depth:              evt.Depth,
		FullPath:           evt.ImagePath,
		Cmdline:            evt.Cmdline,
		SHA256Hash:         evt.Enrichment.SHA256Hash,
		UserSID:            evt.Enrichment.UserSID,
		Username:           firstNonEmpty(evt.Enrichment.Username, evt.Enrichment.UserSID),
		StartTime:          startTime,
		IsAlive:            true,
		IsSystem:           evt.Enrichment.IsSystem,
		RiskScore:          evt.RiskScore,
		Tags:               classifyTags(evt.Image, evt.ImagePath, evt.Cmdline),
		CommandLinePresent: evt.Cmdline != "",
	}
	if state.RootExecutionID == "" {
		state.RootExecutionID = state.ExecutionID
	}
	if state.Depth == 0 {
		if state.ParentExecutionID != "" {
			state.Depth = 2
		} else {
			state.Depth = 1
		}
	}
	if state.Chain == "" {
		if state.ParentImage != "" {
			state.Chain = state.ParentImage + " > " + state.Image
		} else {
			state.Chain = state.Image
		}
	}
	if state.Username == state.UserSID {
		state.Username = ""
	}

	c.activeByPID[evt.PID] = state

	if parentExecID != "" {
		edge = output.ProcessEdgeRecord{
			Timestamp:         startTime.Format(time.RFC3339Nano),
			EdgeType:          "spawn",
			ParentExecutionID: parentExecID,
			ChildExecutionID:  state.ExecutionID,
			RootExecutionID:   state.RootExecutionID,
			ParentPID:         evt.PPID,
			ChildPID:          evt.PID,
			ParentImage:       state.ParentImage,
			ChildImage:        state.Image,
			Depth:             state.Depth,
		}
		shouldWriteEdge = true
	}
	c.mu.Unlock()

	if shouldWriteEdge && c.outMgr != nil {
		_ = c.outMgr.WriteProcessEdge(edge)
	}
}

func (c *Controller) handleProcessEnrichment(evt correlation.StructuredEvent) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.expireDeepCaptureLocked(time.Now(), "timer", "deep_expired")
	state, ok := c.activeByPID[evt.PID]
	if !ok {
		return
	}
	if evt.ImagePath != "" {
		state.FullPath = evt.ImagePath
	}
	if evt.Enrichment.SHA256Hash != "" {
		state.SHA256Hash = evt.Enrichment.SHA256Hash
	}
	if evt.Enrichment.UserSID != "" {
		state.UserSID = evt.Enrichment.UserSID
	}
	if evt.Enrichment.Username != "" {
		state.Username = evt.Enrichment.Username
	}
	state.IsSystem = evt.Enrichment.IsSystem
	if evt.Cmdline != "" {
		state.Cmdline = evt.Cmdline
		state.CommandLinePresent = true
	}
	if evt.RiskScore > 0 {
		state.RiskScore = evt.RiskScore
	}
	state.Tags = classifyTags(firstNonEmpty(evt.Image, state.Image), firstNonEmpty(evt.ImagePath, state.FullPath), firstNonEmpty(evt.Cmdline, state.Cmdline))
}

func (c *Controller) handleProcessStop(evt correlation.StructuredEvent) {
	var state *executionState

	c.mu.Lock()
	c.expireDeepCaptureLocked(time.Now(), "timer", "deep_expired")

	if existing, ok := c.activeByPID[evt.PID]; ok {
		state = existing
		delete(c.activeByPID, evt.PID)
	} else {
		stopTime := evt.Timestamp
		if stopTime.IsZero() {
			stopTime = time.Now()
		}
		state = &executionState{
			ExecutionID:      buildExecutionID(c.deviceID, c.bootID, evt.PID, stopTime),
			RootExecutionID:  buildExecutionID(c.deviceID, c.bootID, evt.PID, stopTime),
			BootID:           c.bootID,
			PID:              evt.PID,
			PPID:             evt.PPID,
			Image:            evt.Image,
			ParentImage:      evt.ParentImage,
			GrandParentImage: evt.GrandParentImage,
			Chain:            evt.Chain,
			Depth:            evt.Depth,
			IsSystem:         evt.Enrichment.IsSystem,
			UserSID:          evt.Enrichment.UserSID,
			Username:         evt.Enrichment.Username,
			SHA256Hash:       evt.Enrichment.SHA256Hash,
			RiskScore:        evt.RiskScore,
			Tags:             classifyTags(evt.Image, evt.ImagePath, evt.Cmdline),
		}
	}
	c.mu.Unlock()

	stopTime := evt.Timestamp
	if stopTime.IsZero() {
		stopTime = time.Now()
	}
	state.StopTime = stopTime
	state.DurationMs = evt.DurationMs
	if state.DurationMs <= 0 && !state.StartTime.IsZero() && state.StopTime.After(state.StartTime) {
		state.DurationMs = state.StopTime.Sub(state.StartTime).Milliseconds()
	}
	if state.DurationMs == 0 && state.StartTime.IsZero() {
		state.DurationMs = -1
	}
	state.IsAlive = false
	if evt.Image != "" {
		state.Image = evt.Image
	}
	if evt.ParentImage != "" {
		state.ParentImage = evt.ParentImage
	}
	if evt.GrandParentImage != "" {
		state.GrandParentImage = evt.GrandParentImage
	}
	if evt.Chain != "" {
		state.Chain = evt.Chain
	}
	if evt.Depth > 0 {
		state.Depth = evt.Depth
	}
	if evt.ImagePath != "" {
		state.FullPath = evt.ImagePath
	}
	if evt.Enrichment.SHA256Hash != "" {
		state.SHA256Hash = evt.Enrichment.SHA256Hash
	}
	if evt.Enrichment.UserSID != "" {
		state.UserSID = evt.Enrichment.UserSID
	}
	if evt.Enrichment.Username != "" {
		state.Username = evt.Enrichment.Username
	}
	state.IsSystem = evt.Enrichment.IsSystem
	if evt.RiskScore > 0 {
		state.RiskScore = evt.RiskScore
	}
	if len(state.Tags) == 0 {
		state.Tags = classifyTags(state.Image, state.FullPath, state.Cmdline)
	}

	if c.shouldRollupProcessExecution(state) {
		c.queueProcessExecutionRollup(state)
	} else {
		c.writeProcessExecution(state)
	}
	c.flushRollupsForExecution(state.ExecutionID)
}

func (c *Controller) flushLoop() {
	defer c.wg.Done()
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-c.flushStop:
			return
		case now := <-ticker.C:
			c.flushStaleRollups(now)
		}
	}
}

func (c *Controller) flushStaleRollups(now time.Time) {
	var stale []*networkRollupState
	var staleProcess []*processRollupState

	c.mu.Lock()
	c.expireDeepCaptureLocked(now, "timer", "deep_expired")
	for key, rollup := range c.rollups {
		if !rollup.WindowEnd.After(now) {
			stale = append(stale, rollup)
			delete(c.rollups, key)
		}
	}
	for key, rollup := range c.processRollups {
		if !rollup.WindowEnd.After(now) {
			staleProcess = append(staleProcess, rollup)
			delete(c.processRollups, key)
		}
	}
	c.mu.Unlock()

	for _, rollup := range stale {
		c.writeNetworkRollup(rollup)
	}
	for _, rollup := range staleProcess {
		c.writeProcessExecutionRollup(rollup)
	}
}

func (c *Controller) flushRollupsForExecution(executionID string) {
	if executionID == "" {
		return
	}

	var matched []*networkRollupState
	c.mu.Lock()
	for key, rollup := range c.rollups {
		if rollup.ExecutionID == executionID {
			matched = append(matched, rollup)
			delete(c.rollups, key)
		}
	}
	c.mu.Unlock()

	for _, rollup := range matched {
		c.writeNetworkRollup(rollup)
	}
}

func (c *Controller) shouldRollupProcessExecution(state *executionState) bool {
	if state == nil {
		return false
	}
	if state.Image == "" || state.ParentImage == "" {
		return false
	}
	if state.DurationMs < 0 || state.DurationMs > 2000 {
		return false
	}
	if state.RiskScore > 0 {
		return false
	}
	for _, tag := range state.Tags {
		switch tag {
		case "powershell", "lolbin", "script_host", "office":
			return false
		}
	}
	return true
}

func (c *Controller) queueProcessExecutionRollup(state *executionState) {
	if state == nil {
		return
	}

	windowStart := state.StopTime.Truncate(c.cfg.ProcessRollupWindow)
	windowEnd := windowStart.Add(c.cfg.ProcessRollupWindow)
	key := fmt.Sprintf("%s|%s|%s|%s|%s", firstNonEmpty(state.Username, state.UserSID), state.ParentImage, state.Image, state.FullPath, windowStart.UTC().Format(time.RFC3339))

	c.mu.Lock()
	defer c.mu.Unlock()

	rollup, ok := c.processRollups[key]
	if !ok {
		sample := *state
		rollup = &processRollupState{
			Key:             key,
			WindowStart:     windowStart,
			WindowEnd:       windowEnd,
			Sample:          &sample,
			ExecutionCount:  1,
			FirstSeen:       sample.StopTime,
			LastSeen:        sample.StopTime,
			FirstPID:        sample.PID,
			LastPID:         sample.PID,
			MinDurationMs:   sample.DurationMs,
			MaxDurationMs:   sample.DurationMs,
			TotalDurationMs: positiveDuration(sample.DurationMs),
		}
		if !sample.StartTime.IsZero() {
			rollup.FirstSeen = sample.StartTime
		}
		c.processRollups[key] = rollup
		return
	}

	rollup.ExecutionCount++
	if !state.StartTime.IsZero() && (rollup.FirstSeen.IsZero() || state.StartTime.Before(rollup.FirstSeen)) {
		rollup.FirstSeen = state.StartTime
	}
	if state.StopTime.After(rollup.LastSeen) {
		rollup.LastSeen = state.StopTime
	}
	rollup.LastPID = state.PID
	if state.DurationMs >= 0 {
		if rollup.MinDurationMs < 0 || state.DurationMs < rollup.MinDurationMs {
			rollup.MinDurationMs = state.DurationMs
		}
		if state.DurationMs > rollup.MaxDurationMs {
			rollup.MaxDurationMs = state.DurationMs
		}
		rollup.TotalDurationMs += state.DurationMs
	}
	if rollup.Sample != nil {
		rollup.Sample.StopTime = rollup.LastSeen
		if !state.StartTime.IsZero() && (rollup.Sample.StartTime.IsZero() || state.StartTime.Before(rollup.Sample.StartTime)) {
			rollup.Sample.StartTime = state.StartTime
		}
	}
}

func (c *Controller) writeProcessExecution(state *executionState) {
	if c.outMgr == nil || state == nil {
		return
	}
	startTime := ""
	if !state.StartTime.IsZero() {
		startTime = state.StartTime.Format(time.RFC3339Nano)
	}
	stopTime := ""
	if !state.StopTime.IsZero() {
		stopTime = state.StopTime.Format(time.RFC3339Nano)
	}
	_ = c.outMgr.WriteProcessExecution(output.ProcessExecutionRecord{
		Timestamp:          stopTime,
		ExecutionID:        state.ExecutionID,
		ParentExecutionID:  state.ParentExecutionID,
		RootExecutionID:    state.RootExecutionID,
		BootID:             state.BootID,
		PID:                state.PID,
		PPID:               state.PPID,
		Image:              state.Image,
		ParentImage:        state.ParentImage,
		GrandParentImage:   state.GrandParentImage,
		Chain:              state.Chain,
		Depth:              state.Depth,
		FullPath:           state.FullPath,
		SHA256Hash:         state.SHA256Hash,
		UserSID:            state.UserSID,
		Username:           state.Username,
		StartTime:          startTime,
		StopTime:           stopTime,
		DurationMs:         state.DurationMs,
		IsSystem:           state.IsSystem,
		IntegrityLevel:     state.IntegrityLevel,
		Elevation:          state.Elevation,
		RiskScore:          state.RiskScore,
		Tags:               state.Tags,
		CommandLinePresent: state.CommandLinePresent,
	})
}

func (c *Controller) writeProcessExecutionRollup(rollup *processRollupState) {
	if rollup == nil || rollup.Sample == nil {
		return
	}
	if rollup.ExecutionCount <= 1 {
		c.writeProcessExecution(rollup.Sample)
		return
	}

	sample := *rollup.Sample
	sample.ExecutionID = fmt.Sprintf("agg|%s|%s|%s|%s", c.deviceID, sample.ParentImage, sample.Image, rollup.WindowStart.UTC().Format("20060102T150405"))
	sample.ParentExecutionID = ""
	sample.RootExecutionID = ""
	sample.PID = rollup.FirstPID
	sample.PPID = 0
	sample.StartTime = rollup.FirstSeen
	sample.StopTime = rollup.LastSeen
	sample.DurationMs = avgDuration(rollup.TotalDurationMs, rollup.ExecutionCount)

	startTime := ""
	if !sample.StartTime.IsZero() {
		startTime = sample.StartTime.Format(time.RFC3339Nano)
	}
	stopTime := ""
	if !sample.StopTime.IsZero() {
		stopTime = sample.StopTime.Format(time.RFC3339Nano)
	}

	_ = c.outMgr.WriteProcessExecution(output.ProcessExecutionRecord{
		Timestamp:          stopTime,
		ExecutionID:        sample.ExecutionID,
		BootID:             sample.BootID,
		PID:                sample.PID,
		Image:              sample.Image,
		ParentImage:        sample.ParentImage,
		GrandParentImage:   sample.GrandParentImage,
		Chain:              sample.Chain,
		Depth:              sample.Depth,
		FullPath:           sample.FullPath,
		SHA256Hash:         sample.SHA256Hash,
		UserSID:            sample.UserSID,
		Username:           sample.Username,
		StartTime:          startTime,
		StopTime:           stopTime,
		DurationMs:         sample.DurationMs,
		Aggregated:         true,
		ExecutionCount:     rollup.ExecutionCount,
		FirstSeen:          startTime,
		LastSeen:           stopTime,
		FirstPID:           rollup.FirstPID,
		LastPID:            rollup.LastPID,
		AvgDurationMs:      avgDuration(rollup.TotalDurationMs, rollup.ExecutionCount),
		MinDurationMs:      rollup.MinDurationMs,
		MaxDurationMs:      rollup.MaxDurationMs,
		IsSystem:           sample.IsSystem,
		IntegrityLevel:     sample.IntegrityLevel,
		Elevation:          sample.Elevation,
		RiskScore:          sample.RiskScore,
		Tags:               sample.Tags,
		CommandLinePresent: sample.CommandLinePresent,
	})
}

func (c *Controller) writeNetworkRollup(rollup *networkRollupState) {
	if c.outMgr == nil || rollup == nil {
		return
	}
	_ = c.outMgr.WriteNetworkRollup(output.NetworkRollupRecord{
		Timestamp:         rollup.WindowEnd.Format(time.RFC3339Nano),
		WindowStart:       rollup.WindowStart.Format(time.RFC3339Nano),
		WindowEnd:         rollup.WindowEnd.Format(time.RFC3339Nano),
		ExecutionID:       rollup.ExecutionID,
		RootExecutionID:   rollup.RootExecutionID,
		PID:               rollup.PID,
		Image:             rollup.Image,
		LocalIP:           rollup.LocalIP,
		RemoteIP:          rollup.RemoteIP,
		EndpointGroup:     rollup.EndpointGroup,
		LocalPort:         rollup.LocalPort,
		RemotePort:        rollup.RemotePort,
		PortClass:         rollup.PortClass,
		Protocol:          rollup.Protocol,
		Direction:         rollup.Direction,
		Domain:            rollup.Domain,
		IsInternal:        rollup.IsInternal,
		ConnectionCount:   rollup.ConnectionCount,
		BytesSent:         rollup.BytesSent,
		BytesRecv:         rollup.BytesRecv,
		LastObservedState: rollup.LastObservedState,
	})
}

func (c *Controller) emitModeAudit(source, reason string) {
	if c.outMgr == nil {
		return
	}
	record := output.TelemetryModeRecord{
		Timestamp:       time.Now().Format(time.RFC3339Nano),
		Mode:            string(c.cfg.Mode),
		Source:          source,
		Reason:          reason,
		DeepCapturePath: c.deepPath,
	}
	if !c.deepExpires.IsZero() {
		record.ExpiresAt = c.deepExpires.Format(time.RFC3339Nano)
	}
	_ = c.outMgr.WriteTelemetryMode(record)
	if c.logSink != nil {
		_ = c.logSink.WriteEvent(map[string]interface{}{
			"event_type":        "telemetry_mode",
			"timestamp":         record.Timestamp,
			"mode":              record.Mode,
			"source":            source,
			"reason":            reason,
			"expires_at":        record.ExpiresAt,
			"deep_capture_path": record.DeepCapturePath,
			"device_id":         c.deviceID,
			"hostname":          c.hostname,
			"agent_version":     c.agentVersion,
			"policy_version":    c.policyVersion,
		})
	}
}

func buildExecutionID(deviceID, bootID string, pid uint32, startedAt time.Time) string {
	return fmt.Sprintf("%s|%s|%d|%d", deviceID, bootID, pid, startedAt.UTC().UnixNano())
}

func classifyTags(image, fullPath, cmdline string) []string {
	lowerImage := strings.ToLower(image)
	lowerPath := strings.ToLower(fullPath)
	lowerCmd := strings.ToLower(cmdline)

	seen := make(map[string]struct{})
	add := func(tag string) {
		if tag == "" {
			return
		}
		seen[tag] = struct{}{}
	}

	switch {
	case strings.Contains(lowerImage, "powershell"):
		add("powershell")
	case strings.Contains(lowerImage, "cmd.exe"):
		add("shell")
	case strings.Contains(lowerImage, "wscript") || strings.Contains(lowerImage, "cscript"):
		add("script_host")
	case strings.Contains(lowerImage, "winword") || strings.Contains(lowerImage, "excel") || strings.Contains(lowerImage, "powerpnt"):
		add("office")
	case strings.Contains(lowerImage, "chrome") || strings.Contains(lowerImage, "msedge") || strings.Contains(lowerImage, "firefox"):
		add("browser")
	}

	for _, lolbin := range []string{"certutil", "bitsadmin", "rundll32", "regsvr32", "mshta"} {
		if strings.Contains(lowerImage, lolbin) || strings.Contains(lowerCmd, lolbin) {
			add("lolbin")
		}
	}

	for _, riskyPath := range []string{`\\users\\public\\`, `\\appdata\\local\\temp`, `\\downloads\\`} {
		if strings.Contains(lowerPath, riskyPath) {
			add("user_space")
			break
		}
	}

	tags := make([]string, 0, len(seen))
	for tag := range seen {
		tags = append(tags, tag)
	}
	return tags
}

func isSystemPath(path string) bool {
	lower := strings.ToLower(path)
	return strings.Contains(lower, `\windows\system32\`) || strings.Contains(lower, `\windows\syswow64\`)
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func positiveDuration(v int64) int64 {
	if v < 0 {
		return 0
	}
	return v
}

func avgDuration(total int64, count int) int64 {
	if count <= 0 {
		return 0
	}
	return total / int64(count)
}

func normalizeDirection(protocol, direction string) string {
	direction = strings.ToLower(strings.TrimSpace(direction))
	if protocol == "UDP" && (direction == "" || direction == "unknown") {
		return "connectionless"
	}
	if direction == "" {
		return "unknown"
	}
	return direction
}

func derivePortClass(protocol string, port uint16) string {
	switch {
	case protocol == "UDP" && port == 53:
		return "dns"
	case port == 80 || port == 443:
		return "web"
	case port == 445 || port == 139:
		return "smb"
	case port == 25 || port == 465 || port == 587 || port == 993 || port == 995:
		return "mail"
	default:
		return fmt.Sprintf("%s:%d", protocol, port)
	}
}

func deriveEndpointGroup(remoteIP, domain string) (string, bool) {
	cleanDomain := strings.ToLower(strings.TrimSpace(domain))
	if cleanDomain != "" && !looksLikeHostSpecificPTR(cleanDomain) {
		return cleanDomain, false
	}
	if remoteIP == "" {
		return "", false
	}
	if config.IsInternalIP(remoteIP) {
		return ipSubnetGroup(remoteIP), true
	}
	if cleanDomain != "" {
		return ipSubnetGroup(remoteIP), false
	}
	return ipSubnetGroup(remoteIP), false
}

func ipSubnetGroup(ipStr string) string {
	ip := net.ParseIP(strings.TrimSpace(ipStr))
	if ip == nil {
		return ipStr
	}
	if v4 := ip.To4(); v4 != nil {
		return fmt.Sprintf("%d.%d.%d.0/24", v4[0], v4[1], v4[2])
	}
	mask := net.CIDRMask(64, 128)
	return (&net.IPNet{IP: ip.Mask(mask), Mask: mask}).String()
}

func looksLikeHostSpecificPTR(domain string) bool {
	if domain == "" {
		return false
	}
	if strings.Contains(domain, "in-addr.arpa") || strings.Contains(domain, "ip6.arpa") {
		return true
	}
	firstLabel := domain
	if idx := strings.Index(domain, "."); idx > 0 {
		firstLabel = domain[:idx]
	}
	if strings.Count(firstLabel, "-") >= 3 && strings.IndexFunc(firstLabel, func(r rune) bool {
		return (r < '0' || r > '9') && r != '-'
	}) == -1 {
		return true
	}
	digits := 0
	for _, r := range firstLabel {
		if r >= '0' && r <= '9' {
			digits++
		}
	}
	return digits >= 6
}

func (c *Controller) captureDeepRecord(kind string, ts time.Time, payload interface{}) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.expireDeepCaptureLocked(time.Now(), "timer", "deep_expired")
	if c.deepWriter == nil {
		return
	}
	if !ts.IsZero() && !c.deepStartedAt.IsZero() && ts.Before(c.deepStartedAt) {
		return
	}

	record := map[string]interface{}{
		"record_type":    "deep_capture_event",
		"kind":           kind,
		"timestamp":      ts.Format(time.RFC3339Nano),
		"device_id":      c.deviceID,
		"hostname":       c.hostname,
		"agent_version":  c.agentVersion,
		"policy_version": c.policyVersion,
		"telemetry_mode": string(c.cfg.Mode),
		"payload":        payload,
	}
	_ = c.deepWriter.Write(record)
}

func (c *Controller) startDeepCaptureIfNeeded() error {
	if c.cfg.Mode != ModeDeep {
		return nil
	}
	c.deepStartedAt = time.Now()
	c.deepExpires = c.deepStartedAt.Add(c.cfg.DeepDuration)
	path := output.DeepCaptureFilePath(c.cfg.DeepCaptureDir, c.deviceID, c.deepStartedAt)
	writer, err := output.NewGzipNDJSONWriter(path)
	if err != nil {
		return err
	}
	c.deepWriter = writer
	c.deepPath = path
	_ = c.deepWriter.Write(map[string]interface{}{
		"record_type":    "deep_capture_started",
		"timestamp":      c.deepStartedAt.Format(time.RFC3339Nano),
		"device_id":      c.deviceID,
		"hostname":       c.hostname,
		"agent_version":  c.agentVersion,
		"policy_version": c.policyVersion,
		"mode":           string(c.cfg.Mode),
		"expires_at":     c.deepExpires.Format(time.RFC3339Nano),
	})
	return nil
}

func (c *Controller) stopDeepCapture(source, reason string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.stopDeepCaptureLocked(source, reason)
}

func (c *Controller) stopDeepCaptureLocked(source, reason string) {
	if c.deepWriter == nil {
		return
	}
	stoppedAt := time.Now()
	manifest := map[string]interface{}{
		"record_type":     "deep_capture_manifest",
		"timestamp":       stoppedAt.Format(time.RFC3339Nano),
		"device_id":       c.deviceID,
		"hostname":        c.hostname,
		"agent_version":   c.agentVersion,
		"policy_version":  c.policyVersion,
		"mode":            string(c.cfg.Mode),
		"capture_started": c.deepStartedAt.Format(time.RFC3339Nano),
		"capture_expires": c.deepExpires.Format(time.RFC3339Nano),
		"capture_stopped": stoppedAt.Format(time.RFC3339Nano),
		"reason":          reason,
	}
	_ = c.deepWriter.Write(manifest)
	_ = c.deepWriter.Flush()
	_ = c.deepWriter.Close()
	c.deepWriter = nil
}

func (c *Controller) expireDeepCaptureLocked(now time.Time, source, reason string) {
	if c.deepWriter == nil || c.deepExpires.IsZero() {
		return
	}
	if now.Before(c.deepExpires) {
		return
	}
	c.stopDeepCaptureLocked(source, reason)
	c.emitModeAudit(source, reason)
}

// MarshalState returns a compact JSON summary of active executions for troubleshooting.
func (c *Controller) MarshalState() ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	snapshot := make(map[uint32]string, len(c.activeByPID))
	for pid, exec := range c.activeByPID {
		snapshot[pid] = exec.ExecutionID
	}
	return json.Marshal(snapshot)
}
