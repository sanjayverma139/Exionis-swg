package correlation

import (
	"strings"
	"time"
)

func shouldAggregate(evt StructuredEvent) bool {
	if evt.EventType != "process_start" {
		return false
	}
	if isCriticalProcess(evt.Image) {
		return false
	}

	key := strings.ToLower(evt.ParentImage + "->" + evt.Image)
	now := time.Now()

	aggMu.Lock()
	defer aggMu.Unlock()

	stats, exists := spawnAggregator[key]
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
		return stats.Count > 10
	}

	if stats.Count > 1 {
		emitAggregationSummary(stats)
	}

	stats.ParentImage = evt.ParentImage
	stats.ChildImage = evt.Image
	stats.FirstSeen = now
	stats.LastSeen = now
	stats.Count = 1
	stats.WindowStart = now
	return false
}

func emitAggregationSummary(stats *SpawnStats) {
	now := time.Now()
	nonBlockingEmit(StructuredEvent{
		EventType:   "process_spawn_aggregate",
		Timestamp:   now,
		Image:       stats.ChildImage,
		ParentImage: stats.ParentImage,
		DurationMs:  now.Sub(stats.FirstSeen).Milliseconds(),
		Resolved:    true,
		RiskScore:   0,
		RiskReasons: nil,
	})
}

func (e *Engine) cleanupAggregator() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		cleanupSpawnAggregator()
	}
}

func isCriticalProcess(image string) bool {
	switch strings.ToLower(image) {
	case "system", "smss.exe", "csrss.exe", "wininit.exe", "services.exe",
		"lsass.exe", "svchost.exe", "winlogon.exe", "fontdrvhost.exe",
		"dwm.exe", "audiodg.exe", "conhost.exe", "searchindexer.exe",
		"runtimebroker.exe", "taskhostw.exe", "sihost.exe":
		return true
	default:
		return false
	}
}
