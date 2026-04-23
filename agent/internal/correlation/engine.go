// File: internal/correlation/engine.go
package correlation

import (
	"crypto/sha256"  // ✅ ADD THIS
	"encoding/hex"   // ✅ ADD THIS
	"encoding/json"
	"fmt"
	"io"            // ✅ ADD THIS
	"os"            // ✅ ADD THIS
	"strings"
	"sync"
	"time"

	"exionis/internal/process"
)

// ============================================================================
// GLOBAL STATE - THREAD-SAFE
// ============================================================================

var (
	processTable    = make(map[uint32]*ProcessInfo)
	tableMu         sync.RWMutex
	pendingEvents   = make(map[uint32][]EventInput)
	pendingMu       sync.Mutex
	spawnAggregator = make(map[string]*SpawnStats)
	aggMu           sync.Mutex
	sequenceCounter uint64
	seqMu           sync.Mutex
	StructuredOutput = make(chan StructuredEvent, 10000)
	aggregationWindow = 2 * time.Second
	processTTL        = 5 * time.Minute
)

// ============================================================================
// ENGINE STRUCT
// ============================================================================

type Engine struct {
	Output chan CorrelatedEvent
}

func New() *Engine {
	return &Engine{
		Output: make(chan CorrelatedEvent, 5000),
	}
}

func (e *Engine) RegistrySize() int {
	tableMu.RLock()
	defer tableMu.RUnlock()
	return len(processTable)
}

// ============================================================================
// THREAD-SAFE HELPERS
// ============================================================================

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

func cleanupStaleProcesses() {
	tableMu.Lock()
	defer tableMu.Unlock()
	now := time.Now()
	for pid, proc := range processTable {
		if !proc.IsAlive && now.Sub(proc.EndTime) > processTTL {
			delete(processTable, pid)
		} else if proc.IsAlive && now.Sub(proc.StartTime) > processTTL {
			proc.IsAlive = false
			proc.EndTime = now
			emitProcessStop(proc)
			delete(processTable, pid)
		}
	}
}

// ============================================================================
// ENGINE RUN METHOD
// ============================================================================

func (e *Engine) Run(src <-chan EventInput) {
	go runPendingResolver()
	
	// ✅ FIX: Proper goroutine syntax with braces
	go func() {
		ticker := time.NewTicker(1 * time.Minute)
		defer ticker.Stop()
		for range ticker.C {
			cleanupStaleProcesses()
		}
	}()
	
	go e.forwardToLegacyOutput()

	for ev := range src {
		switch ev.Type {
		case "PROCESS_START":
			HandleProcessStart(ev)
		case "PROCESS_STOP":
			HandleProcessStop(ev)
		}
	}
}

func (e *Engine) forwardToLegacyOutput() {
	for evt := range StructuredOutput {
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
		case e.Output <- legacy:
		default:
		}
	}
}

// ============================================================================
// EVENT HANDLERS
// ============================================================================

func HandleProcessStart(ev EventInput) {
	seqMu.Lock()
	seq := sequenceCounter
	sequenceCounter++
	seqMu.Unlock()

	ppid, imageName := parseProcessDetail(ev.Detail)

	if imageName == "" || imageName == "<unknown>" {
		imageName = resolveProcessImage(ev.PID)
	}

	enrichment := enrichProcessAtStart(ev.PID, imageName)

	tableMu.Lock()
	if existing, ok := processTable[ev.PID]; ok && existing.IsAlive {
		if existing.Image == "" && imageName != "" {
			existing.Image = imageName
		}
		if existing.Cmdline == "" {
			existing.Cmdline = process.GetCmdline(ev.PID)
		}
		if existing.Enrichment.ExecutablePath == "" {
			existing.Enrichment = enrichment
		}
		tableMu.Unlock()
		return
	}

	proc := &ProcessInfo{
		PID:          ev.PID,
		PPID:         ppid,
		Image:        imageName,
		Cmdline:      process.GetCmdline(ev.PID),
		StartTime:    ev.Timestamp,
		IsAlive:      true,
		Enrichment:   enrichment,
	}

	if ppid > 0 {
		if parent, ok := processTable[ppid]; ok && parent.IsAlive {
			proc.Parent = parent
			parent.Children = append(parent.Children, proc)
		}
	}

	processTable[ev.PID] = proc
	tableMu.Unlock()

	resolvePendingChildren(ev.PID)
	emitProcessStart(proc, seq)
}

func HandleProcessStop(ev EventInput) {
	tableMu.Lock()
	proc, exists := processTable[ev.PID]

	if !exists {
	imageName := resolveProcessImage(ev.PID)
	
	// Mark pre-existing processes differently
	if imageName == "unknown" {
		imageName = "<pre-existing>"
	}
	
	proc = &ProcessInfo{
		PID:        ev.PID,
		Image:      imageName,
		StartTime:  ev.Timestamp.Add(-1 * time.Second),
		EndTime:    ev.Timestamp,
		IsAlive:    false,
		Enrichment: enrichProcessAtStart(ev.PID, imageName),
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

	if proc.Enrichment.ExecutablePath == "" {
		proc.Enrichment = enrichProcessAtStart(ev.PID, proc.Image)
	}

	tableMu.Unlock()
	emitProcessStop(proc)

	go func(pid uint32) {
		time.Sleep(2 * time.Second)
		deleteProcessSafe(pid)
	}(ev.PID)
}

// ============================================================================
// EVENT EMITTERS - ✅ FIXED SYNTAX
// ============================================================================

func emitProcessStart(proc *ProcessInfo, seq uint64) {
	parentImage := ""
	if proc.Parent != nil && proc.Parent.Image != "" {
		parentImage = proc.Parent.Image
	}

	// ✅ FIX: Proper struct initialization INSIDE function
	evt := StructuredEvent{
		EventType:   "process_start",
		Timestamp:   proc.StartTime,
		PID:         proc.PID,
		PPID:        proc.PPID,
		Image:       proc.Image,
		ParentImage: parentImage,
		Cmdline:     proc.Cmdline,
		ImagePath:   proc.Enrichment.ExecutablePath,
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
	if !proc.StartTime.IsZero() && !proc.EndTime.IsZero() {
		if proc.EndTime.After(proc.StartTime) {
			duration = proc.EndTime.Sub(proc.StartTime).Milliseconds()
		}
	}

	// ✅ FIX: Proper struct initialization INSIDE function
	evt := StructuredEvent{
		EventType:  "process_stop",
		Timestamp:  proc.EndTime,
		PID:        proc.PID,
		Image:      proc.Image,
		DurationMs: duration,
		Resolved:   true,
		Enrichment: proc.Enrichment,
	}

	nonBlockingEmit(evt)
}

func nonBlockingEmit(evt StructuredEvent) {
	select {
	case StructuredOutput <- evt:
		if jsonBytes, err := json.Marshal(evt); err == nil {
			fmt.Printf("%s\n", string(jsonBytes))
		}
	default:
	}
}

// ============================================================================
// PARENT RESOLUTION
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
		HandleProcessStart(childEv)
	}
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
// NOISE REDUCTION
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
	summary := StructuredEvent{
		EventType:   "process_spawn_aggregate",
		Timestamp:   stats.LastSeen,
		Image:       stats.ChildImage,
		ParentImage: stats.ParentImage,
		Resolved:    true,
		Enrichment: ProcessEnrichment{
			SHA256Hash: fmt.Sprintf("count:%d", stats.Count),
		},
	}
	nonBlockingEmit(summary)
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
// DETAIL PARSER
// ============================================================================

func parseProcessDetail(detail string) (ppid uint32, imageName string) {
	tokens := strings.Fields(detail)
	for _, tok := range tokens {
		if strings.HasPrefix(tok, "PPID:") {
			fmt.Sscanf(tok, "PPID:%d", &ppid)
		} else if strings.HasPrefix(tok, "Image:") {
			imageName = strings.TrimPrefix(tok, "Image:")
		}
	}
	return
}

// ============================================================================
// FALLBACK RESOLVER
// ============================================================================

func resolveProcessImage(pid uint32) string {
	cmdline := process.GetCmdline(pid)
	if cmdline != "" {
		parts := strings.Fields(cmdline)
		if len(parts) > 0 {
			path := parts[0]
			if idx := strings.LastIndexAny(path, `\/`); idx != -1 {
				return path[idx+1:]
			}
			return path
		}
	}

	exePath := process.GetExecutablePath(pid)
	if exePath != "" && exePath != "unknown" {
		if idx := strings.LastIndexAny(exePath, `\/`); idx != -1 {
			return exePath[idx+1:]
		}
		return exePath
	}

	return "unknown"
}

// ============================================================================
// ENRICHMENT PIPELINE
// ============================================================================

func enrichProcessAtStart(pid uint32, imageName string) ProcessEnrichment {
	enrich := ProcessEnrichment{
		IsSystem: pid < 100,
	}

	if exePath := process.GetExecutablePath(pid); exePath != "" && exePath != "unknown" {
		enrich.ExecutablePath = exePath
	}

	if enrich.ExecutablePath != "" {
		if hash, err := computeFileSHA256(enrich.ExecutablePath); err == nil {
			enrich.SHA256Hash = hash
		}
	}

	enrich.IsSigned = process.IsProcessSigned(pid)
	enrich.UserSID = resolveProcessSID(pid)

	return enrich
}

func computeFileSHA256(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()

	hasher := sha256.New()
	if _, err := io.Copy(hasher, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(hasher.Sum(nil)), nil
}

func resolveProcessSID(pid uint32) string {
	// TODO: Implement using Windows API in Phase 3
	return ""
}

// ============================================================================
// LEGACY TYPES
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