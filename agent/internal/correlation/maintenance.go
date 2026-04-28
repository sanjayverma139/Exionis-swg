package correlation

import (
	"fmt"
	"os"
	"time"
)

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

func cleanupStaleProcesses() {
	tableMu.Lock()
	defer tableMu.Unlock()

	now := time.Now()
	cleaned := 0

	for pid, proc := range processTable {
		if !proc.IsAlive &&
			!proc.EndTime.IsZero() &&
			now.Sub(proc.EndTime) > processTTL {
			delete(processTable, pid)
			cleaned++
		}
	}

	if debugMode && cleaned > 0 {
		fmt.Fprintf(os.Stderr, "[cleanup] removed %d stale processes\n", cleaned)
	}
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
