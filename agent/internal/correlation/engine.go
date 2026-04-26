// Package correlation handles process lifecycle tracking and event correlation.
package correlation

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"syscall"
	"time"

	"exionis/internal/events"
	"exionis/internal/process"
)

// PIDHistoryEntry uniquely identifies a process instance by PID + StartTime.
// Prevents PID reuse confusion (e.g., chrome.exe exits, malware.exe reuses same PID).
type PIDHistoryEntry struct {
	Name      string
	StartTime time.Time
	UpdatedAt time.Time
}

// ============================================================================
// GLOBAL STATE & CONCURRENCY CONTROLS
// ============================================================================
var (
	processTable    = make(map[uint32]*ProcessInfo)
	tableMu         sync.RWMutex
	pendingEvents   = make(map[uint32][]events.EventInput)
	pendingMu       sync.Mutex
	spawnAggregator = make(map[string]*SpawnStats)
	aggMu           sync.Mutex
	sequenceCounter uint64
	seqMu           sync.Mutex
	StructuredOutput = make(chan StructuredEvent, 10000)
	aggregationWindow = 2 * time.Second

	// processTTL controls how long DEAD (IsAlive=false) process records are
	// retained in the table before being evicted by the maintenance ticker.
	// Only dead records are evicted — alive processes are never pruned by TTL.
	processTTL = 10 * time.Minute

	connectionTable = make(map[uint32][]*ConnectionInfo)
	connTableMu     sync.RWMutex
	dnsCache        = make(map[string]dnsCacheEntry)
	dnsCacheMu      sync.RWMutex
	dnsCacheTTL     = 10 * time.Minute
	hashCache       = make(map[string]string)
	hashCacheMu     sync.RWMutex
	hashCacheLimit  = 10000

	// enrichSem limits concurrent background enrichment goroutines (hash + path).
	enrichSem = make(chan struct{}, 32)
	// hashSem limits concurrent file-open operations for SHA256 computation.
	hashSem = make(chan struct{}, 10)

	// legacyOutput is the package-level channel used by emitLegacyOutput.
	legacyOutput   chan CorrelatedEvent
	legacyOutputMu sync.RWMutex

	// PID history cache for resolving process names after exit (PID reuse protection).
	pidHistory   = make(map[uint32]PIDHistoryEntry)
	pidHistoryMu sync.RWMutex
)

type dnsCacheEntry struct {
	domain  string
	expires time.Time
}

// Engine is the main correlation processor.
type Engine struct {
	Output chan CorrelatedEvent
	mu     sync.RWMutex
}

// New creates a new Engine instance and registers its Output channel globally.
func New() *Engine {
	e := &Engine{Output: make(chan CorrelatedEvent, 5000)}
	legacyOutputMu.Lock()
	legacyOutput = e.Output
	legacyOutputMu.Unlock()
	go e.cleanupAggregator()
	return e
}

// RegistrySize returns current process table size (thread-safe).
func (e *Engine) RegistrySize() int {
	tableMu.RLock()
	defer tableMu.RUnlock()
	return len(processTable)
}

// GetActiveConnectionCount returns active connection count (thread-safe).
func GetActiveConnectionCount() int {
	connTableMu.RLock()
	defer connTableMu.RUnlock()
	count := 0
	for _, conns := range connectionTable {
		count += len(conns)
	}
	return count
}

// ============================================================================
// PID HISTORY CACHE HELPERS (PID Reuse Protection)
// ============================================================================

func rememberPIDName(pid uint32, name string, start time.Time) {
	if pid == 0 || name == "" || name == "unknown" {
		return
	}
	pidHistoryMu.Lock()
	pidHistory[pid] = PIDHistoryEntry{
		Name:      name,
		StartTime: start,
		UpdatedAt: time.Now(),
	}
	pidHistoryMu.Unlock()
}

func getRememberedPIDName(pid uint32) string {
	pidHistoryMu.RLock()
	defer pidHistoryMu.RUnlock()
	entry, ok := pidHistory[pid]
	if !ok {
		return ""
	}
	// Reject stale cache entries (PID may have been reused by Windows)
	if time.Since(entry.UpdatedAt) > 30*time.Minute {
		return ""
	}
	return entry.Name
}

func cleanupPIDHistory() {
	pidHistoryMu.Lock()
	defer pidHistoryMu.Unlock()
	now := time.Now()
	for pid, entry := range pidHistory {
		if now.Sub(entry.UpdatedAt) > 1*time.Hour {
			delete(pidHistory, pid)
		}
	}
}

// ============================================================================
// BOOTSTRAP: populate table with already-running processes before ETW fires
// ============================================================================

// PopulateInitialProcessTable bootstraps the process table before ETW starts.
// Called once from main.go before StartETWListener().
func PopulateInitialProcessTable() {
	procs := process.GetProcesses()
	livePIDs := process.BuildLivePIDSet()

	tableMu.Lock()
	defer tableMu.Unlock()

	for _, p := range procs {
		if _, exists := processTable[uint32(p.PID)]; exists {
			continue
		}
		startTime := process.GetProcessStartTime(uint32(p.PID))
		if startTime.IsZero() {
			startTime = time.Now().Add(-1 * time.Hour)
		}
		username := process.GetProcessUsername(uint32(p.PID))
		isOrphan := process.IsOrphanProcess(uint32(p.PID), livePIDs)

		proc := &ProcessInfo{
			PID:       uint32(p.PID),
			Image:     p.Name,
			ImagePath: p.Path,
			StartTime: startTime,
			IsAlive:   true,
			IsOrphan:  isOrphan,
			Username:  username,
			Enrichment: ProcessEnrichment{
				IsSystem: isSystemProcess(p.Path),
				Username: username,
				IsOrphan: isOrphan,
			},
		}
		if parentPID := process.GetParentPID(uint32(p.PID)); parentPID > 0 {
			proc.PPID = parentPID
			if parent, ok := processTable[parentPID]; ok {
				proc.Parent = parent
				parent.Children = append(parent.Children, proc)
			}
		}
		go enrichProcessAsync(proc, p.Name)
		processTable[uint32(p.PID)] = proc
		// BUG 3 + PID REUSE FIX: Cache name at bootstrap
		rememberPIDName(uint32(p.PID), p.Name, startTime)
	}
}

// ============================================================================
// ENGINE MAIN LOOP
// ============================================================================

// Run starts the main event processing loop. Blocks until src is closed.
func (e *Engine) Run(src <-chan events.EventInput) {
	go runPendingResolver()
	go runMaintenanceTicker()
	go e.forwardNetworkEvents()

	for ev := range src {
		switch ev.Type {
		case "PROCESS_START":
			e.HandleProcessStart(ev)
		case "PROCESS_STOP":
			e.HandleProcessStop(ev)
		}
	}
}

// ============================================================================
// MAINTENANCE
// ============================================================================

func runMaintenanceTicker() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		cleanupStaleProcesses()
		cleanupStaleConnections()
		cleanupDNSCache()
		cleanupHashCache()
		cleanupSpawnAggregator()
	}
}

func (e *Engine) forwardNetworkEvents() {
	for netEvt := range events.NetworkChan {
		if netEvt.RemoteIP != "" && netEvt.Protocol == "TCP" {
			go func(ip string, evt *events.NetworkEvent) {
				if domain := ResolveDomain(ip); domain != "" {
					evt.Domain = domain
				}
			}(netEvt.RemoteIP, &netEvt)
		}

		tableMu.RLock()
		proc, exists := processTable[netEvt.PID]
		tableMu.RUnlock()

		if exists && proc.IsAlive {
			conn := &ConnectionInfo{
				RemoteIP:   netEvt.RemoteIP,
				RemotePort: netEvt.RemotePort,
				Protocol:   netEvt.Protocol,
				BytesSent:  netEvt.BytesSent,
				BytesRecv:  netEvt.BytesRecv,
				FirstSeen:  netEvt.Timestamp,
				LastSeen:   netEvt.Timestamp,
				Domain:     netEvt.Domain,
				State:      mapOpcodeToConnectionState(uint8(netEvt.Opcode), netEvt.Protocol),
			}
			proc.UpsertConnection(conn)
			connTableMu.Lock()
			connectionTable[netEvt.PID] = append(connectionTable[netEvt.PID], conn)
			connTableMu.Unlock()
		}

		// BUG 2 FIX: Ensure direction and local_ip are never empty
		if netEvt.Direction == "" && netEvt.Protocol == "TCP" {
			netEvt.Direction = mapOpcodeToDirection(netEvt.Opcode, netEvt.Protocol)
		}
		if netEvt.Direction == "" {
			netEvt.Direction = "unknown"
		}
		if netEvt.LocalIP == "" {
			netEvt.LocalIP = "0.0.0.0"
		}
		if netEvt.LocalPort == 0 {
			netEvt.LocalPort = 0
		}

		emitNetworkEvent(netEvt, proc)
	}
}

// ============================================================================
// PROCESS START HANDLER
// ============================================================================

func (e *Engine) HandleProcessStart(ev events.EventInput) {
	seqMu.Lock()
	seq := sequenceCounter
	sequenceCounter++
	seqMu.Unlock()

	ppid, imageName := parseProcessDetail(ev.Detail)
	if imageName == "" || imageName == "<unknown>" {
		imageName = resolveProcessImage(ev.PID)
	}
	cmdline := process.GetCmdline(ev.PID)
	initialEnrichment := enrichProcessAtStart(ev.PID, imageName)

	tableMu.Lock()
	if existing, ok := processTable[ev.PID]; ok && existing.IsAlive {
		if existing.Image == "" && imageName != "" {
			existing.Image = imageName
		}
		if existing.Cmdline == "" {
			existing.Cmdline = cmdline
		}
		if existing.Enrichment.ExecutablePath == "" && initialEnrichment.ExecutablePath != "" {
			existing.Enrichment = initialEnrichment
			existing.ImagePath = initialEnrichment.ExecutablePath
		}
		tableMu.Unlock()
		return
	}

	proc := &ProcessInfo{
		PID:        ev.PID,
		PPID:       ppid,
		Image:      imageName,
		Cmdline:    cmdline,
		ImagePath:  initialEnrichment.ExecutablePath,
		StartTime:  ev.Timestamp,
		IsAlive:    true,
		Enrichment: initialEnrichment,
	}
	if ppid > 0 {
		if parent, ok := processTable[ppid]; ok && parent.IsAlive {
			proc.Parent = parent
			parent.Children = append(parent.Children, proc)
		}
	}
	processTable[ev.PID] = proc
	// BUG 3 + PID REUSE FIX: Cache name at start event
	rememberPIDName(ev.PID, imageName, ev.Timestamp)
	tableMu.Unlock()

	go e.enrichAsync(ev.PID, imageName)
	resolvePendingChildren(ev.PID)
	emitProcessStart(proc, seq)
}

// ============================================================================
// PROCESS STOP HANDLER
// ============================================================================

func (e *Engine) HandleProcessStop(ev events.EventInput) {
	tableMu.Lock()
	proc, exists := processTable[ev.PID]

	if !exists {
		// BUG 3 + PID REUSE FIX: Multi-stage name resolution with cache age check
		resolvedName := process.GetProcessNameByPID(ev.PID)

		if resolvedName == "" {
			resolvedName = process.GetProcessNameFromSnapshot(ev.PID)
		}

		if resolvedName == "" {
			resolvedName = getRememberedPIDName(ev.PID)
		}

		if resolvedName == "" {
			resolvedName = "<pre-existing>"
		}

		proc = &ProcessInfo{
			PID:       ev.PID,
			Image:     resolvedName,
			StartTime: ev.Timestamp.Add(-1 * time.Second),
			EndTime:   ev.Timestamp,
			IsAlive:   false,
		}
		processTable[ev.PID] = proc
		tableMu.Unlock()
		emitProcessStop(proc)
		return
	}

	proc.EndTime = ev.Timestamp
	proc.IsAlive = false
	if proc.Image == "" || proc.Image == "unknown" {
		proc.Image = resolveProcessImage(ev.PID)
	}
	tableMu.Unlock()

	if proc.Enrichment.ExecutablePath == "" {
		go e.tryFallbackEnrichment(ev.PID, proc)
	}

	emitProcessStop(proc)

	go func(pid uint32) {
		time.Sleep(2 * time.Second)
		deleteProcessSafe(pid)
	}(ev.PID)
}

// ============================================================================
// ASYNC ENRICHMENT
// ============================================================================

func (e *Engine) enrichAsync(pid uint32, imageName string) {
	go func() {
		enrichSem <- struct{}{}
		defer func() { <-enrichSem }()

		exePath := e.retryResolvePath(pid, 5, 20*time.Millisecond)
		if exePath == "" || exePath == "unknown" {
			exePath = parseExecutablePathFromCmdline(process.GetCmdline(pid))
		}
		if exePath == "" || exePath == "unknown" {
			return
		}

		var hash string
		if stat, err := os.Stat(exePath); err == nil && stat.Size() <= 100<<20 {
			hash = computeSHA256Safe(exePath)
		}

		tableMu.Lock()
		if proc, ok := processTable[pid]; ok && proc.IsAlive {
			changed := false
			if proc.Enrichment.ExecutablePath != exePath || proc.ImagePath != exePath {
				proc.Enrichment.ExecutablePath = exePath
				proc.ImagePath = exePath
				changed = true
			}
			if hash != "" && proc.Enrichment.SHA256Hash != hash {
				proc.Enrichment.SHA256Hash = hash
				changed = true
			}
			isSystem := isSystemProcess(exePath)
			if proc.Enrichment.IsSystem != isSystem {
				proc.Enrichment.IsSystem = isSystem
				changed = true
			}
			isSigned := process.IsProcessSigned(pid)
			if proc.Enrichment.IsSigned != isSigned {
				proc.Enrichment.IsSigned = isSigned
				changed = true
			}
			snapshot := *proc
			tableMu.Unlock()
			if changed {
				emitProcessEnrichmentUpdate(&snapshot)
			}
			return
		}
		tableMu.Unlock()
	}()
}

func (e *Engine) retryResolvePath(pid uint32, attempts int, delay time.Duration) string {
	for i := 0; i < attempts; i++ {
		if path := process.GetExecutablePath(pid); path != "" && path != "unknown" {
			return path
		}
		if i < attempts-1 {
			time.Sleep(delay)
		}
	}
	return ""
}

func enrichProcessAsync(proc *ProcessInfo, imageName string) {
	enrichment := enrichProcessAtStart(proc.PID, imageName)
	tableMu.Lock()
	if p, ok := processTable[proc.PID]; ok && p.IsAlive {
		p.Enrichment = enrichment
		if enrichment.ExecutablePath != "" {
			p.ImagePath = enrichment.ExecutablePath
		}
	}
	tableMu.Unlock()
}

func enrichProcessAtStart(pid uint32, imageName string) ProcessEnrichment {
	enrich := ProcessEnrichment{IsSystem: false}
	if exePath := process.GetExecutablePathWithRetry(pid, 10); exePath != "" && exePath != "unknown" {
		enrich.ExecutablePath = exePath
		enrich.IsSystem = isSystemProcess(exePath)
	}
	if enrich.ExecutablePath == "" {
		if exePath := parseExecutablePathFromCmdline(process.GetCmdline(pid)); exePath != "" {
			enrich.ExecutablePath = exePath
			enrich.IsSystem = isSystemProcess(exePath)
		}
	}
	if enrich.ExecutablePath != "" {
		if hash, err := computeFileSHA256(enrich.ExecutablePath); err == nil {
			enrich.SHA256Hash = hash
		}
	}
	enrich.IsSigned = process.IsProcessSigned(pid)
	enrich.Username = process.GetProcessUsername(pid)
	enrich.UserSID = process.GetProcessUserSID(pid)
	return enrich
}

func parseExecutablePathFromCmdline(cmdline string) string {
	cmdline = strings.TrimSpace(cmdline)
	if cmdline == "" {
		return ""
	}
	var candidate string
	if strings.HasPrefix(cmdline, `"`) {
		trimmed := strings.TrimPrefix(cmdline, `"`)
		if idx := strings.Index(trimmed, `"`); idx >= 0 {
			candidate = trimmed[:idx]
		}
	} else {
		candidate = strings.Fields(cmdline)[0]
	}
	candidate = strings.TrimSpace(candidate)
	if candidate == "" {
		return ""
	}
	if _, err := os.Stat(candidate); err != nil {
		return ""
	}
	return candidate
}

func (e *Engine) tryFallbackEnrichment(pid uint32, proc *ProcessInfo) {
	path := process.GetExecutablePath(pid)
	if path == "" || path == "unknown" {
		path = parseExecutablePathFromCmdline(proc.Cmdline)
	}
	if path == "" || path == "unknown" {
		return
	}
	hash := computeSHA256Safe(path)
	tableMu.Lock()
	if p, ok := processTable[pid]; ok {
		if p.Enrichment.ExecutablePath == "" {
			p.Enrichment.ExecutablePath = path
			p.ImagePath = path
			p.Enrichment.SHA256Hash = hash
			p.Enrichment.IsSystem = isSystemProcess(path)
		}
		snap := *p
		tableMu.Unlock()
		emitProcessEnrichmentUpdate(&snap)
		return
	}
	tableMu.Unlock()
}

// ============================================================================
// EVENT EMITTERS
// ============================================================================

func emitProcessStart(proc *ProcessInfo, seq uint64) {
	parentImage := ""
	if proc.Parent != nil && proc.Parent.Image != "" {
		parentImage = proc.Parent.Image
	} else if proc.PPID > 0 {
		tableMu.RLock()
		if parent, ok := processTable[proc.PPID]; ok {
			parentImage = parent.Image
		}
		tableMu.RUnlock()
	}
	evt := StructuredEvent{
		EventType:   "process_start",
		Timestamp:   proc.StartTime,
		PID:         proc.PID,
		PPID:        proc.PPID,
		Image:       proc.Image,
		ParentImage: parentImage,
		Cmdline:     proc.Cmdline,
		ImagePath:   proc.Enrichment.ExecutablePath,
		IsAlive:     true,
		Resolved:    true,
		Enrichment:  proc.Enrichment,
		SequenceID:  seq,
	}
	if shouldAggregate(evt) {
		return
	}
	nonBlockingEmit(evt)
}

func emitProcessStop(proc *ProcessInfo) {
	duration := int64(-1)
	if !proc.StartTime.IsZero() && !proc.EndTime.IsZero() && proc.EndTime.After(proc.StartTime) {
		duration = proc.EndTime.Sub(proc.StartTime).Milliseconds()
	}
	evt := StructuredEvent{
		EventType:  "process_stop",
		Timestamp:  proc.EndTime,
		PID:        proc.PID,
		Image:      proc.Image,
		DurationMs: duration,
		IsAlive:    false,
		Resolved:   true,
		Enrichment: proc.Enrichment,
	}
	nonBlockingEmit(evt)
}

func emitProcessEnrichmentUpdate(proc *ProcessInfo) {
	parentImage := ""
	if proc.Parent != nil && proc.Parent.Image != "" {
		parentImage = proc.Parent.Image
	} else if proc.PPID > 0 {
		tableMu.RLock()
		if parent, ok := processTable[proc.PPID]; ok {
			parentImage = parent.Image
		}
		tableMu.RUnlock()
	}
	nonBlockingEmit(StructuredEvent{
		EventType:   "process_enrichment_update",
		Timestamp:   time.Now(),
		PID:         proc.PID,
		PPID:        proc.PPID,
		Image:       proc.Image,
		ParentImage: parentImage,
		Cmdline:     proc.Cmdline,
		ImagePath:   proc.ImagePath,
		IsAlive:     proc.IsAlive,
		Resolved:    true,
		Enrichment:  proc.Enrichment,
	})
}

// BUG 1 FIX: emitNetworkEvent ONLY prints to stdout and sends to events.NetworkOutputChan
func emitNetworkEvent(evt events.NetworkEvent, proc *ProcessInfo) {
	imageName := "unknown"
	if proc != nil && proc.Image != "" {
		imageName = proc.Image
	} else if resolved := process.GetProcessNameByPID(evt.PID); resolved != "" {
		imageName = resolved
	}

	output := map[string]interface{}{
		"event_type":  "network_connection",
		"timestamp":   evt.Timestamp.Format(time.RFC3339Nano),
		"pid":         evt.PID,
		"image":       imageName,
		"local_ip":    evt.LocalIP,
		"remote_ip":   evt.RemoteIP,
		"local_port":  evt.LocalPort,
		"remote_port": evt.RemotePort,
		"protocol":    evt.Protocol,
		"direction":   evt.Direction,
	}
	if evt.Domain != "" {
		output["domain"] = evt.Domain
	}
	if evt.BytesSent > 0 {
		output["bytes_sent"] = evt.BytesSent
	}
	if evt.BytesRecv > 0 {
		output["bytes_recv"] = evt.BytesRecv
	}
	jsonBytes, err := json.Marshal(output)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[Exionis] JSON marshal error: %v\n", err)
		return
	}
	fmt.Printf("%s\n", string(jsonBytes))

	select {
	case events.NetworkOutputChan <- events.NetworkOutputRecord{
		Timestamp:  evt.Timestamp.Format(time.RFC3339Nano),
		PID:        evt.PID,
		Image:      imageName,
		LocalIP:    evt.LocalIP,
		RemoteIP:   evt.RemoteIP,
		LocalPort:  evt.LocalPort,
		RemotePort: evt.RemotePort,
		Protocol:   evt.Protocol,
		Direction:  evt.Direction,
		Domain:     evt.Domain,
		BytesSent:  evt.BytesSent,
		BytesRecv:  evt.BytesRecv,
		State:      string(mapOpcodeToConnectionState(evt.Opcode, evt.Protocol)),
	}:
	default:
	}
	syscall.FlushFileBuffers(syscall.Handle(os.Stdout.Fd()))
}

func nonBlockingEmit(evt StructuredEvent) {
	if jsonBytes, err := json.Marshal(evt); err == nil {
		fmt.Printf("%s\n", string(jsonBytes))
	}
	emitLegacyOutput(evt)
	select {
	case StructuredOutput <- evt:
	default:
	}
}

func emitLegacyOutput(evt StructuredEvent) {
	legacyOutputMu.RLock()
	out := legacyOutput
	legacyOutputMu.RUnlock()
	if out == nil {
		return
	}
	legacy := CorrelatedEvent{
		Type:        evt.EventType,
		PID:         evt.PID,
		Timestamp:   evt.Timestamp,
		ProcessName: evt.Image,
		ParentPID:   evt.PPID,
		ParentName:  evt.ParentImage,
		Summary:     fmt.Sprintf("%s (PID %d)", evt.Image, evt.PID),
	}
	select {
	case out <- legacy:
	default:
	}
}

// ============================================================================
// PENDING CHILD RESOLUTION
// ============================================================================

func resolvePendingChildren(parentPID uint32) {
	pendingMu.Lock()
	children, ok := pendingEvents[parentPID]
	if !ok {
		pendingMu.Unlock()
		return
	}
	delete(pendingEvents, parentPID)
	pendingMu.Unlock()

	tableMu.RLock()
	_, parentExists := processTable[parentPID]
	tableMu.RUnlock()
	if !parentExists {
		return
	}
	for _, childEv := range children {
		HandleProcessStartWrapper(childEv)
	}
}

func HandleProcessStartWrapper(ev events.EventInput) {
	e := &Engine{}
	e.HandleProcessStart(ev)
}

func runPendingResolver() {
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	for range ticker.C {
		pendingMu.Lock()
		var toResolve []uint32
		tableMu.RLock()
		for ppid := range pendingEvents {
			if par, ok := processTable[ppid]; ok && par.IsAlive {
				toResolve = append(toResolve, ppid)
			}
		}
		tableMu.RUnlock()
		pendingMu.Unlock()

		for _, ppid := range toResolve {
			resolvePendingChildren(ppid)
		}
	}
}

// ============================================================================
// AGGREGATION
// ============================================================================

func shouldAggregate(evt StructuredEvent) bool {
	if evt.EventType != "process_start" {
		return false
	}
	key := fmt.Sprintf("%s:%s", evt.ParentImage, evt.Image)
	if isCriticalProcess(evt.Image) {
		return false
	}

	aggMu.Lock()
	defer aggMu.Unlock()

	stats, exists := spawnAggregator[key]
	now := time.Now()

	if !exists {
		spawnAggregator[key] = &SpawnStats{
			ParentImage: evt.ParentImage,
			ChildImage:  evt.Image,
			FirstSeen:   now,
			LastSeen:    now,
			Count:       1,
			WindowStart: now,
		}
		return false
	}

	if now.Sub(stats.WindowStart) < aggregationWindow {
		stats.Count++
		stats.LastSeen = now
		return true
	}

	emitAggregationSummary(stats)
	stats.Count = 1
	stats.FirstSeen = now
	stats.LastSeen = now
	stats.WindowStart = now
	return false
}

func emitAggregationSummary(stats *SpawnStats) {
	nonBlockingEmit(StructuredEvent{
		EventType:   "process_spawn_aggregate",
		Timestamp:   stats.LastSeen,
		Image:       stats.ChildImage,
		ParentImage: stats.ParentImage,
		Resolved:    true,
		Enrichment: ProcessEnrichment{
			SHA256Hash: fmt.Sprintf("count:%d", stats.Count),
		},
	})
}

func (e *Engine) cleanupAggregator() {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		aggMu.Lock()
		now := time.Now()
		for key, stats := range spawnAggregator {
			if now.Sub(stats.LastSeen) > 2*aggregationWindow {
				delete(spawnAggregator, key)
			}
		}
		aggMu.Unlock()
	}
}

func isCriticalProcess(image string) bool {
	critical := map[string]bool{
		"lsass.exe": true, "csrss.exe": true, "wininit.exe": true,
		"services.exe": true, "svchost.exe": true, "explorer.exe": true,
		"cmd.exe": true, "powershell.exe": true, "wscript.exe": true,
		"mshta.exe": true, "regsvr32.exe": true, "rundll32.exe": true,
	}
	return critical[strings.ToLower(image)]
}

// ============================================================================
// HELPERS
// ============================================================================

func parseProcessDetail(detail string) (ppid uint32, imageName string) {
	for _, tok := range strings.Fields(detail) {
		if strings.HasPrefix(tok, "PPID:") {
			fmt.Sscanf(tok, "PPID:%d", &ppid)
		}
		if strings.HasPrefix(tok, "Image:") {
			imageName = strings.TrimPrefix(tok, "Image:")
		}
	}
	return
}

func resolveProcessImage(pid uint32) string {
	if cmdline := process.GetCmdline(pid); cmdline != "" {
		parts := strings.Fields(cmdline)
		if len(parts) > 0 {
			path := parts[0]
			if idx := strings.LastIndexAny(path, `\/`); idx != -1 {
				return path[idx+1:]
			}
			return path
		}
	}
	if exePath := process.GetExecutablePathWithRetry(pid, 5); exePath != "" && exePath != "unknown" {
		if idx := strings.LastIndexAny(exePath, `\/`); idx != -1 {
			return exePath[idx+1:]
		}
		return exePath
	}
	if name := process.GetProcessNameByPID(pid); name != "" {
		return name
	}
	return "unknown"
}

func ResolveDomain(ip string) string {
	if ip == "" {
		return ""
	}
	dnsCacheMu.RLock()
	if entry, ok := dnsCache[ip]; ok && time.Now().Before(entry.expires) {
		dnsCacheMu.RUnlock()
		return entry.domain
	}
	dnsCacheMu.RUnlock()

	done := make(chan string, 1)
	go func() {
		names, err := net.LookupAddr(ip)
		if err != nil || len(names) == 0 {
			done <- ""
			return
		}
		done <- strings.TrimSuffix(names[0], ".")
	}()
	select {
	case domain := <-done:
		dnsCacheMu.Lock()
		dnsCache[ip] = dnsCacheEntry{domain: domain, expires: time.Now().Add(dnsCacheTTL)}
		if len(dnsCache) > 5000 {
			count := 0
			for k := range dnsCache {
				delete(dnsCache, k)
				if count++; count >= 500 {
					break
				}
			}
		}
		dnsCacheMu.Unlock()
		return domain
	case <-time.After(500 * time.Millisecond):
		return ""
	}
}

// ============================================================================
// SHA256
// ============================================================================

func computeSHA256Safe(path string) string {
	hashSem <- struct{}{}
	defer func() { <-hashSem }()

	file, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer file.Close()

	stat, err := file.Stat()
	if err != nil || stat.Size() > 100<<20 {
		return ""
	}

	hasher := sha256.New()
	if _, err := io.Copy(hasher, file); err != nil {
		return ""
	}
	return hex.EncodeToString(hasher.Sum(nil))
}

func computeFileSHA256(path string) (string, error) {
	hashCacheMu.RLock()
	if h, ok := hashCache[path]; ok {
		hashCacheMu.RUnlock()
		return h, nil
	}
	hashCacheMu.RUnlock()

	file, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("open %s: %w", path, err)
	}
	defer file.Close()

	stat, err := file.Stat()
	if err != nil {
		return "", fmt.Errorf("stat %s: %w", path, err)
	}
	if stat.Size() > 100<<20 {
		return "", fmt.Errorf("file too large: %d bytes", stat.Size())
	}

	hasher := sha256.New()
	if _, err := io.Copy(hasher, file); err != nil {
		return "", fmt.Errorf("hash %s: %w", path, err)
	}
	hash := hex.EncodeToString(hasher.Sum(nil))

	hashCacheMu.Lock()
	hashCache[path] = hash
	if len(hashCache) > hashCacheLimit {
		count := 0
		for k := range hashCache {
			delete(hashCache, k)
			if count++; count >= hashCacheLimit/10 {
				break
			}
		}
	}
	hashCacheMu.Unlock()
	return hash, nil
}

// ============================================================================
// CLEANUP
// ============================================================================

func cleanupStaleProcesses() {
	tableMu.Lock()
	defer tableMu.Unlock()
	now := time.Now()
	for pid, proc := range processTable {
		if !proc.IsAlive && now.Sub(proc.EndTime) > processTTL {
			delete(processTable, pid)
		}
	}
	// PID REUSE FIX: Clean up stale PID history entries
	cleanupPIDHistory()
}

func cleanupStaleConnections() {
	connTableMu.Lock()
	defer connTableMu.Unlock()
	now := time.Now()
	for pid, conns := range connectionTable {
		var kept []*ConnectionInfo
		for _, conn := range conns {
			if now.Sub(conn.LastSeen) < 10*time.Minute {
				kept = append(kept, conn)
			}
		}
		if len(kept) == 0 {
			delete(connectionTable, pid)
		} else {
			connectionTable[pid] = kept
		}
	}
}

func cleanupDNSCache() {
	dnsCacheMu.Lock()
	defer dnsCacheMu.Unlock()
	now := time.Now()
	for ip, entry := range dnsCache {
		if now.After(entry.expires) {
			delete(dnsCache, ip)
		}
	}
}

func cleanupHashCache() {
	hashCacheMu.Lock()
	defer hashCacheMu.Unlock()
	if len(hashCache) > hashCacheLimit*8/10 {
		count := 0
		for k := range hashCache {
			delete(hashCache, k)
			if count++; count >= hashCacheLimit/5 {
				break
			}
		}
	}
}

func cleanupSpawnAggregator() {
	aggMu.Lock()
	defer aggMu.Unlock()
	now := time.Now()
	for key, stats := range spawnAggregator {
		if now.Sub(stats.LastSeen) > 2*aggregationWindow {
			delete(spawnAggregator, key)
		}
	}
}

// Thread-safe process table accessors.
func getProcessSafe(pid uint32) (*ProcessInfo, bool) {
	tableMu.RLock()
	defer tableMu.RUnlock()
	p, ok := processTable[pid]
	return p, ok
}

func setProcessSafe(pid uint32, proc *ProcessInfo) {
	tableMu.Lock()
	defer tableMu.Unlock()
	processTable[pid] = proc
}

func deleteProcessSafe(pid uint32) {
	tableMu.Lock()
	defer tableMu.Unlock()
	delete(processTable, pid)
}

func resolveProcessSID(pid uint32) string { return "" }

// ============================================================================
// SYSTEM PROCESS DETECTION
// ============================================================================

func isSystemProcess(imagePath string) bool {
	if imagePath == "" {
		return false
	}
	normalized := strings.ToLower(strings.ReplaceAll(imagePath, "/", `\`))
	return strings.Contains(normalized, `c:\windows\system32`) ||
		strings.Contains(normalized, `c:\windows\syswow64`) ||
		strings.Contains(normalized, `\systemroot\`)
}

// ============================================================================
// CONNECTION STATE MAPPING
// ============================================================================

func mapOpcodeToConnectionState(opcode uint8, protocol string) ConnectionState {
	if protocol != "TCP" {
		return StateUnknown
	}
	const (
		opcodeConnect    = 10
		opcodeAccept     = 11
		opcodeReconnect  = 12
		opcodeSend       = 13
		opcodeReceive    = 14
		opcodeDisconnect = 15
		opcodeRetransmit = 16
	)
	switch opcode {
	case opcodeConnect, opcodeAccept, opcodeReconnect, opcodeSend, opcodeReceive, opcodeRetransmit:
		return StateEstablished
	case opcodeDisconnect:
		return StateClosed
	default:
		return StateNew
	}
}

// BUG 2 FIX: Helper to map opcode to direction for TCP events (uint8 signature)
func mapOpcodeToDirection(opcode uint8, protocol string) string {
	if protocol != "TCP" {
		return "unknown"
	}
	const (
		opcodeConnect uint8 = 10
		opcodeAccept  uint8 = 11
	)
	switch opcode {
	case opcodeConnect:
		return "outbound"
	case opcodeAccept:
		return "inbound"
	default:
		return "unknown"
	}
}