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
	"time"

	"exionis/internal/events"
	"exionis/internal/process"
)

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
	processTTL        = 5 * time.Minute
	connectionTable   = make(map[uint32][]*ConnectionInfo)
	connTableMu       sync.RWMutex
	dnsCache          = make(map[string]dnsCacheEntry)
	dnsCacheMu        sync.RWMutex
	dnsCacheTTL       = 10 * time.Minute
	hashCache         = make(map[string]string)
	hashCacheMu       sync.RWMutex
	hashCacheLimit    = 10000
	
	// ✅ FIX 1: Async enrichment semaphore (limits concurrent hash ops)
	enrichSem = make(chan struct{}, 32)
	// ✅ FIX 5: Hash computation semaphore (limits FD usage)
	hashSem = make(chan struct{}, 10)
)

type dnsCacheEntry struct {
	domain  string
	expires time.Time
}

// Engine is the main correlation processor
type Engine struct {
	Output chan CorrelatedEvent
	mu     sync.RWMutex
}

// New creates a new Engine instance
func New() *Engine {
	e := &Engine{Output: make(chan CorrelatedEvent, 5000)}
	go e.cleanupAggregator() // ✅ FIX 4: Start aggregator eviction
	return e
}

// RegistrySize returns current process table size (thread-safe)
func (e *Engine) RegistrySize() int {
	tableMu.RLock()
	defer tableMu.RUnlock()
	return len(processTable)
}

// GetActiveConnectionCount returns active connection count (thread-safe)
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
// ✅ FIX 2: BOOTSTRAP PRE-EXISTING PROCESSES
// ============================================================================
// PopulateInitialProcessTable bootstraps the process table before ETW starts
func PopulateInitialProcessTable() {
	procs := process.GetProcesses()
	tableMu.Lock()
	defer tableMu.Unlock()
	
	for _, p := range procs {
		if _, exists := processTable[uint32(p.PID)]; exists {
			continue
		}
		proc := &ProcessInfo{
			PID:       uint32(p.PID),
			Image:     p.Name,
			ImagePath: p.Path,
			StartTime: time.Now().Add(-1 * time.Hour), // Approximate
			IsAlive:   true,
			Enrichment: ProcessEnrichment{
				IsSystem: isSystemProcess(p.Path), // ✅ FIX 3: Correct system detection
			},
		}
		if parentPID := process.GetParentPID(uint32(p.PID)); parentPID > 0 {
			proc.PPID = parentPID
			if parent, ok := processTable[parentPID]; ok {
				proc.Parent = parent
				parent.Children = append(parent.Children, proc)
			}
		}
		// Async enrichment for bootstrap processes
		go enrichProcessAsync(proc, p.Name)
		processTable[uint32(p.PID)] = proc
	}
}

// Run starts the main event processing loop
func (e *Engine) Run(src <-chan events.EventInput) {
	go runPendingResolver()
	go runMaintenanceTicker()
	go e.forwardToLegacyOutput()
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
// MAINTENANCE & CLEANUP
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
	State:      mapOpcodeToConnectionState(uint8(netEvt.Opcode), netEvt.Protocol), // ✅ NEW
}
			proc.UpsertConnection(conn)
			connTableMu.Lock()
			connectionTable[netEvt.PID] = append(connectionTable[netEvt.PID], conn)
			connTableMu.Unlock()
		}
		emitNetworkEvent(netEvt, proc)
	}
}

// ============================================================================
// ✅ FIX 1: ASYNC ENRICHMENT PIPELINE
// ============================================================================
// HandleProcessStart processes PROCESS_START events
func (e *Engine) HandleProcessStart(ev events.EventInput) {
	seqMu.Lock()
	seq := sequenceCounter
	sequenceCounter++
	seqMu.Unlock()

	ppid, imageName := parseProcessDetail(ev.Detail)
	if imageName == "" || imageName == "<unknown>" {
		imageName = resolveProcessImage(ev.PID)
	}

	tableMu.Lock()
	// Check if process already exists and is alive
	if existing, ok := processTable[ev.PID]; ok && existing.IsAlive {
		if existing.Image == "" && imageName != "" {
			existing.Image = imageName
		}
		if existing.Cmdline == "" {
			existing.Cmdline = process.GetCmdline(ev.PID)
		}
		tableMu.Unlock()
		return
	}

	// Create new process record (Stage 1: Fast, minimal)
	proc := &ProcessInfo{
		PID:       ev.PID,
		PPID:      ppid,
		Image:     imageName,
		StartTime: ev.Timestamp,
		IsAlive:   true,
		Enrichment: ProcessEnrichment{
			IsSystem: false, // Will be corrected async
		},
	}
	
	// Link to parent if known
	if ppid > 0 {
		if parent, ok := processTable[ppid]; ok && parent.IsAlive {
			proc.Parent = parent
			parent.Children = append(parent.Children, proc)
		}
	}
	processTable[ev.PID] = proc
	tableMu.Unlock()

	// ✅ FIX 1: Async enrichment (non-blocking)
	go e.enrichAsync(ev.PID, imageName)
	
	resolvePendingChildren(ev.PID)
	emitProcessStart(proc, seq)
}

// HandleProcessStop processes PROCESS_STOP events
func (e *Engine) HandleProcessStop(ev events.EventInput) {
	tableMu.Lock()
	proc, exists := processTable[ev.PID]
	
	if !exists {
		// Pre-existing process that we missed
		imageName := resolveProcessImage(ev.PID)
		if imageName == "unknown" {
			imageName = "<pre-existing>"
		}
		proc = &ProcessInfo{
			PID:       ev.PID,
			Image:     imageName,
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
	
	// ✅ FIX 6: Stop-time fallback enrichment
	if proc.Enrichment.ExecutablePath == "" {
		go e.tryFallbackEnrichment(ev.PID, proc)
	}
	
	emitProcessStop(proc)
	
	// Schedule cleanup after delay
	go func(pid uint32) {
		time.Sleep(2 * time.Second)
		deleteProcessSafe(pid)
	}(ev.PID)
}

// ============================================================================
// ✅ FIX 1: ASYNC ENRICHMENT WORKERS
// ============================================================================
// enrichAsync performs background enrichment with retry logic
func (e *Engine) enrichAsync(pid uint32, imageName string) {
	enrichSem <- struct{}{} // Acquire semaphore
	go func() {
		defer func() { <-enrichSem }() // Release semaphore

		// Retry resolution (process may not be ready yet)
		exePath := e.retryResolvePath(pid, 5, 20*time.Millisecond)
		if exePath == "" || exePath == "unknown" {
			return // Give up if still not resolvable
		}

		// Safe hash with size guard and FD throttling
		var hash string
		if stat, err := os.Stat(exePath); err == nil && stat.Size() <= 100<<20 {
			hash = computeSHA256Safe(exePath)
		}

		// Update process record atomically
		tableMu.Lock()
		if proc, ok := processTable[pid]; ok && proc.IsAlive {
			proc.Enrichment.ExecutablePath = exePath
			proc.Enrichment.SHA256Hash = hash
			proc.Enrichment.IsSystem = isSystemProcess(exePath) // ✅ FIX 3
			proc.Enrichment.IsSigned = process.IsProcessSigned(pid)
		}
		tableMu.Unlock()
	}()
}

// retryResolvePath attempts to resolve executable path with retries
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

// enrichProcessAsync is the legacy helper (kept for bootstrap compatibility)
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

// enrichProcessAtStart performs synchronous enrichment (legacy, for bootstrap only)
func enrichProcessAtStart(pid uint32, imageName string) ProcessEnrichment {
	enrich := ProcessEnrichment{IsSystem: false}
	if exePath := process.GetExecutablePathWithRetry(pid, 3); exePath != "" && exePath != "unknown" {
		enrich.ExecutablePath = exePath
		enrich.IsSystem = isSystemProcess(exePath) // ✅ FIX 3
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

// ============================================================================
// ✅ FIX 6: FALLBACK ENRICHMENT ON STOP
// ============================================================================
// tryFallbackEnrichment attempts enrichment when process is stopping
func (e *Engine) tryFallbackEnrichment(pid uint32, proc *ProcessInfo) {
	if path := process.GetExecutablePath(pid); path != "" && path != "unknown" {
		hash := computeSHA256Safe(path)
		
		tableMu.Lock()
		if p, ok := processTable[pid]; ok {
			if p.Enrichment.ExecutablePath == "" {
				p.Enrichment.ExecutablePath = path
				p.Enrichment.SHA256Hash = hash
				p.Enrichment.IsSystem = isSystemProcess(path) // ✅ FIX 3
			}
		}
		tableMu.Unlock()
	}
}

// ============================================================================
// EVENT EMITTERS
// ============================================================================
func emitProcessStart(proc *ProcessInfo, seq uint64) {
	parentImage := ""
	if proc.Parent != nil && proc.Parent.Image != "" {
		parentImage = proc.Parent.Image
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
		Resolved:   true,
		Enrichment: proc.Enrichment,
	}
	nonBlockingEmit(evt)
}

func emitNetworkEvent(evt events.NetworkEvent, proc *ProcessInfo) {
	imageName := "unknown"
	if proc != nil && proc.Image != "" {
		imageName = proc.Image
	}
	output := map[string]interface{}{
		"event_type":  "network_connection",
		"timestamp":   evt.Timestamp.Format(time.RFC3339Nano),
		"pid":         evt.PID,
		"image":       imageName,
		"remote_ip":   evt.RemoteIP,
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
	select {
	case StructuredOutput <- StructuredEvent{
		EventType: "network_connection",
		Timestamp: evt.Timestamp,
		PID:       evt.PID,
		Image:     imageName,
		Resolved:  true,
	}:
	default:
	}
	fmt.Printf("%s\n", string(jsonBytes))
}

func nonBlockingEmit(evt StructuredEvent) {
	select {
	case StructuredOutput <- evt:
		if jsonBytes, err := json.Marshal(evt); err == nil {
			fmt.Printf("%s\n", string(jsonBytes))
		}
	default:
		// Log drop if needed for debugging
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

// HandleProcessStartWrapper allows external calls to HandleProcessStart
func HandleProcessStartWrapper(ev events.EventInput) {
	// Create a dummy engine for standalone calls
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
// ✅ FIX 4: AGGREGATION WITH EVICTION
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
			LastSeen:    now,  // ← Critical for eviction
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

// ✅ FIX 4: Aggregator cleanup goroutine
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
// HELPER FUNCTIONS
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
		dnsCache[ip] = dnsCacheEntry{
			domain:  domain,
			expires: time.Now().Add(dnsCacheTTL),
		}
		if len(dnsCache) > 5000 {
			count := 0
			for k := range dnsCache {
				delete(dnsCache, k)
				count++
				if count >= 500 {
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

// ============================================================================
// ✅ FIX 5: SAFE SHA256 WITH FD THROTTLING
// ============================================================================
func computeSHA256Safe(path string) string {
	hashSem <- struct{}{} // Acquire semaphore
	defer func() { <-hashSem }() // Release semaphore

	file, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer file.Close()

	stat, err := file.Stat()
	if err != nil {
		return ""
	}
	if stat.Size() > 100<<20 {
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
			count++
			if count >= hashCacheLimit/10 {
				break
			}
		}
	}
	hashCacheMu.Unlock()

	return hash, nil
}

func cleanupHashCache() {
	hashCacheMu.Lock()
	defer hashCacheMu.Unlock()
	if len(hashCache) > hashCacheLimit*8/10 {
		count := 0
		for k := range hashCache {
			delete(hashCache, k)
			count++
			if count >= hashCacheLimit/5 {
				break
			}
		}
	}
}

// ============================================================================
// ✅ FIX 3: CORRECT SYSTEM PROCESS DETECTION
// ============================================================================
func isSystemProcess(imagePath string) bool {
	if imagePath == "" {
		return false
	}
	// Normalize path separators for reliable matching
	normalized := strings.ToLower(strings.ReplaceAll(imagePath, "/", "\\"))
	
	// Check for Windows system directories (case-insensitive)
	return strings.Contains(normalized, `c:\windows\system32`) ||
		   strings.Contains(normalized, `c:\windows\syswow64`) ||
		   strings.Contains(normalized, `\systemroot\`)
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

// Thread-safe process table accessors
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

func resolveProcessSID(pid uint32) string {
	return ""
}

// ============================================================================
// ✅ CONNECTION STATE MAPPING HELPER
// ============================================================================
// mapOpcodeToConnectionState maps ETW opcodes to our ConnectionState enum
func mapOpcodeToConnectionState(opcode uint8, protocol string) ConnectionState {
	if protocol != "TCP" {
		return StateUnknown // UDP is connectionless
	}
	
	// ETW opcode constants (from evntcons.h)
	const (
		EVENT_TRACE_TYPE_CONNECT    = 10
		EVENT_TRACE_TYPE_ACCEPT     = 11
		EVENT_TRACE_TYPE_RECONNECT  = 12
		EVENT_TRACE_TYPE_SEND       = 13
		EVENT_TRACE_TYPE_RECEIVE    = 14
		EVENT_TRACE_TYPE_DISCONNECT = 15
		EVENT_TRACE_TYPE_RETRANSMIT = 16
	)
	
	switch opcode {
	case EVENT_TRACE_TYPE_CONNECT, EVENT_TRACE_TYPE_ACCEPT, EVENT_TRACE_TYPE_RECONNECT:
		return StateEstablished
	case EVENT_TRACE_TYPE_DISCONNECT:
		return StateClosed
	case EVENT_TRACE_TYPE_SEND, EVENT_TRACE_TYPE_RECEIVE, EVENT_TRACE_TYPE_RETRANSMIT:
		return StateEstablished // Active data transfer
	default:
		return StateNew
	}
}