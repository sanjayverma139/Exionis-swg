package correlation

import (
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"exionis/internal/events"
	"exionis/internal/process"
)

var (
	processTable      = make(map[uint32]*ProcessInfo)
	tableMu           sync.RWMutex
	pendingEvents     = make(map[uint32][]events.EventInput)
	pendingMu         sync.Mutex
	spawnAggregator   = make(map[string]*SpawnStats)
	aggMu             sync.Mutex
	sequenceCounter   uint64
	seqMu             sync.Mutex
	StructuredOutput  = make(chan StructuredEvent, 10000)
	aggregationWindow = 30 * time.Second
	processTTL        = 10 * time.Minute

	connectionTable = make(map[uint32][]*ConnectionInfo)
	connTableMu     sync.RWMutex
	dnsCache        = make(map[string]dnsCacheEntry)
	dnsCacheMu      sync.RWMutex
	dnsCacheTTL     = 10 * time.Minute
	hashCache       = make(map[string]string)
	hashCacheMu     sync.RWMutex
	hashCacheLimit  = 10000

	enrichSem = make(chan struct{}, 32)
	hashSem   = make(chan struct{}, 10)

	legacyOutput   chan CorrelatedEvent
	legacyOutputMu sync.RWMutex

	pidHistory   = make(map[uint32]PIDHistoryEntry)
	pidHistoryMu sync.RWMutex

	debugMode = os.Getenv("EXIONIS_DEBUG") == "1"
)

type dnsCacheEntry struct {
	domain  string
	expires time.Time
}

// PIDHistoryEntry uniquely identifies a process instance by PID and start time.
type PIDHistoryEntry struct {
	Name      string
	StartTime time.Time
	UpdatedAt time.Time
}

// Engine is the main correlation processor.
type Engine struct {
	Output chan CorrelatedEvent
	mu     sync.RWMutex
}

func New() *Engine {
	e := &Engine{Output: make(chan CorrelatedEvent, 5000)}
	legacyOutputMu.Lock()
	legacyOutput = e.Output
	legacyOutputMu.Unlock()
	go e.cleanupAggregator()
	return e
}

func (e *Engine) RegistrySize() int {
	tableMu.RLock()
	defer tableMu.RUnlock()
	return len(processTable)
}

func GetActiveConnectionCount() int {
	connTableMu.RLock()
	defer connTableMu.RUnlock()
	count := 0
	for _, conns := range connectionTable {
		count += len(conns)
	}
	return count
}

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
	if time.Since(entry.UpdatedAt) > 30*time.Minute {
		return ""
	}
	if time.Since(entry.StartTime) > time.Hour {
		return ""
	}
	return entry.Name
}

func cleanupPIDHistory() {
	pidHistoryMu.Lock()
	defer pidHistoryMu.Unlock()
	now := time.Now()
	for pid, entry := range pidHistory {
		if now.Sub(entry.UpdatedAt) > time.Hour {
			delete(pidHistory, pid)
		}
	}
}

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
			Depth:     1,
			RootPID:   uint32(p.PID),
			Chain:     p.Name,
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
				proc.ParentImage = parent.Image
				parent.Children = append(parent.Children, proc)
				proc.Depth = parent.Depth + 1
				proc.RootPID = parent.RootPID
				proc.Chain = parent.Chain + " > " + p.Name
			}
		}
		go enrichProcessAsync(proc, p.Name)
		processTable[uint32(p.PID)] = proc
		rememberPIDName(uint32(p.PID), p.Name, startTime)
	}
}

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

		if netEvt.Direction == "" && netEvt.Protocol == "TCP" {
			netEvt.Direction = mapOpcodeToDirection(netEvt.Opcode, netEvt.Protocol)
		}
		if netEvt.Direction == "" {
			netEvt.Direction = "unknown"
		}
		if netEvt.LocalIP == "" {
			netEvt.LocalIP = "0.0.0.0"
		}

		emitNetworkEvent(netEvt, proc)
	}
}

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
	if debugMode {
		fmt.Fprintf(os.Stderr, "[CORR] HANDLE_START pid=%d ppid=%d image=%q detail=%q\n", ev.PID, ppid, imageName, ev.Detail)
	}

	tableMu.Lock()
	if existing, ok := processTable[ev.PID]; ok && existing.IsAlive {
		if existing.Image == "" && imageName != "" {
			existing.Image = imageName
		}
		if existing.Cmdline == "" {
			existing.Cmdline = cmdline
		}
		snap := *existing
		tableMu.Unlock()
		emitProcessStart(&snap, seq)
		return
	}
	tableMu.Unlock()

	parentImg, grandParentImg, chain, depth, rootPID := buildGenealogyChain(ev.PID, imageName, ppid)

	proc := &ProcessInfo{
		PID:              ev.PID,
		PPID:             ppid,
		Image:            imageName,
		Cmdline:          cmdline,
		StartTime:        ev.Timestamp,
		IsAlive:          true,
		ParentImage:      parentImg,
		GrandParentImage: grandParentImg,
		Chain:            chain,
		Depth:            depth,
		RootPID:          rootPID,
	}

	tableMu.Lock()
	if ppid > 0 {
		if parent, ok := processTable[ppid]; ok && parent.IsAlive {
			proc.Parent = parent
			parent.Children = append(parent.Children, proc)
		}
	}

	processTable[ev.PID] = proc
	rememberPIDName(ev.PID, imageName, ev.Timestamp)
	tableMu.Unlock()

	go e.enrichAsync(ev.PID, imageName)
	resolvePendingChildren(ev.PID)
	emitProcessStart(proc, seq)
}

func (e *Engine) HandleProcessStop(ev events.EventInput) {
	tableMu.Lock()
	proc, exists := processTable[ev.PID]
	if exists {
		proc.EndTime = ev.Timestamp
		proc.IsAlive = false
		tableMu.Unlock()
		emitProcessStop(proc)
		return
	}
	tableMu.Unlock()

	ppid, detailImage := parseProcessDetail(ev.Detail)
	resolvedName := detailImage
	if resolvedName == "" || resolvedName == "<unknown>" || resolvedName == "unknown" {
		resolvedName = process.GetProcessNameByPID(ev.PID)
	}
	if resolvedName == "" || resolvedName == "<unknown>" || resolvedName == "unknown" {
		resolvedName = process.GetProcessNameFromSnapshot(ev.PID)
	}
	if resolvedName == "" || resolvedName == "<unknown>" || resolvedName == "unknown" {
		resolvedName = getRememberedPIDName(ev.PID)
	}
	if resolvedName == "" || resolvedName == "<unknown>" || resolvedName == "unknown" {
		if cmd := process.GetCmdline(ev.PID); cmd != "" {
			parts := strings.Fields(cmd)
			if len(parts) > 0 {
				binary := parts[0]
				if idx := strings.LastIndexAny(binary, `\/`); idx != -1 {
					resolvedName = binary[idx+1:]
				} else {
					resolvedName = binary
				}
			}
		}
	}
	if resolvedName == "" || resolvedName == "<unknown>" || resolvedName == "unknown" {
		resolvedName = "unknown_process"
	}

	parentImg, grandParentImg, chain, depth, rootPID := buildGenealogyChain(ev.PID, resolvedName, ppid)
	if rootPID == 0 {
		rootPID = ev.PID
	}

	proc = &ProcessInfo{
		PID:              ev.PID,
		PPID:             ppid,
		Image:            resolvedName,
		StartTime:        ev.Timestamp.Add(-1 * time.Second),
		EndTime:          ev.Timestamp,
		IsAlive:          false,
		ParentImage:      parentImg,
		GrandParentImage: grandParentImg,
		Depth:            depth,
		RootPID:          rootPID,
		Chain:            chain,
	}

	tableMu.Lock()
	processTable[ev.PID] = proc
	tableMu.Unlock()
	emitProcessStop(proc)
}

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
