//go:build windows
// +build windows

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"exionis/internal/config"
	"exionis/internal/correlation"
	"exionis/internal/etw"
	"exionis/internal/events"
	"exionis/internal/inventory"
	"exionis/internal/logger"
	"exionis/internal/process"
	"exionis/internal/utils"
)

func main() {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// 🔹 PHASE 1: Generate device ID for cloud sync
	deviceID, err := utils.GetDeviceID()
	if err != nil {
		fmt.Printf("[Warn] Device ID: %v\n", err)
		deviceID = "unknown"
	}
	agentVersion := "2.1.0" // Set from build flags in production
	policyVersion := "initial" // Will be synced from cloud

	// 🔹 PHASE 1: Initialize local log sink (Netskope-style)
	logSink, err := logger.NewFileSink(
		`C:\ProgramData\Exionis\logs`, // Windows standard location
		"agent", 
		100,  // 100MB max per file
		10,   // Keep last 10 files
	)
	if err != nil {
		fmt.Printf("[Warn] Local logging: %v\n", err)
	}
	defer logSink.Close()

	fmt.Println("[Exionis] Initializing privileges...")
	if err := config.EnableAllPrivileges(); err != nil {
		fmt.Printf("[Exionis] Privilege warning: %v\n", err)
	}

	// ✅ Initialize network filtering config
	fmt.Println("[Exionis] Loading network filtering config...")
	if err := config.InitNetworkConfig(config.DefaultInternalRanges()); err != nil {
		fmt.Printf("[Exionis] Network config warning: %v\n", err)
	}

	// ✅ FIX 2: Bootstrap pre-existing processes BEFORE ETW starts
	fmt.Println("[Exionis] Building initial process snapshot...")
	correlation.PopulateInitialProcessTable()
	fmt.Println("[Exionis] Snapshot complete.")

	// 🔹 PHASE 1: Emit installed apps snapshot (one-time)
	if apps := inventory.CollectInstalledApps(); len(apps) > 0 {
		snapshot := map[string]interface{}{
			"event_type":     "device_inventory",
			"timestamp":      time.Now().Format(time.RFC3339Nano),
			"device_id":      deviceID,
			"agent_version":  agentVersion,
			"policy_version": policyVersion,
			"installed_apps": apps,
		}
		// Write to local log
		if logSink != nil {
			logSink.WriteEvent(snapshot)
		}
		// Also emit to stdout for cloud pipeline (NDJSON)
		jsonBytes, _ := json.Marshal(snapshot)
		fmt.Printf("%s\n", jsonBytes)
	}

	fmt.Println("[Exionis] Starting ETW kernel listener...")
	if err := etw.StartETWListener(); err != nil {
		fmt.Printf("[Exionis] ETW startup error: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("[Exionis] Phase 2: Process + Network Telemetry Engine ACTIVE")

	corrEngine := correlation.New()

	go corrEngine.Run(events.ProcessChan)

	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			fmt.Printf("[STATS] Live processes: %d | Active connections: %d\n",
				corrEngine.RegistrySize(),
				correlation.GetActiveConnectionCount())
		}
	}()

		// 🔹 PHASE 1: Wrap StructuredOutput to also write to file sink
	go func() {
		for evt := range correlation.StructuredOutput {
			// Add cloud fields
			evtMap := structToMap(evt)
			evtMap["device_id"] = deviceID
			evtMap["agent_version"] = agentVersion
			evtMap["policy_version"] = policyVersion
			
			// Write to local log
			if logSink != nil {
				logSink.WriteEvent(evtMap)
			}
			// Keep existing stdout emission (cloud pipeline)
			jsonBytes, _ := json.Marshal(evtMap)
			fmt.Printf("%s\n", jsonBytes)
		}
	}()

	fmt.Println("[Exionis] Process Collector Running...")
	snapshotTicker := time.NewTicker(5 * time.Second)
	defer snapshotTicker.Stop()

	for {
		select {
		case <-sigChan:
			fmt.Println("\n[Exionis] Shutdown signal received, cleaning up...")
			etw.StopETWListener()
			if logSink != nil {
				logSink.Close()
			}
			fmt.Println("[Exionis] Graceful shutdown complete")
			return
		case <-snapshotTicker.C:
			procs := process.GetProcesses()
			fmt.Printf("[SNAPSHOT] Total: %d | Sample: ", len(procs))
			for i, p := range procs {
				if i >= 3 {
					break
				}
				fmt.Printf("%s(PID:%d) ", p.Name, p.PID)
			}
			fmt.Println()
		}
	}
}

// Helper: convert StructuredEvent to map for field injection
func structToMap(evt correlation.StructuredEvent) map[string]interface{} {
	return map[string]interface{}{
		"event_type":   evt.EventType,
		"timestamp":    evt.Timestamp.Format(time.RFC3339Nano),
		"pid":          evt.PID,
		"ppid":         evt.PPID,
		"image":        evt.Image,
		"parent_image": evt.ParentImage,
		"cmdline":      evt.Cmdline,
		"image_path":   evt.ImagePath,
		"duration_ms":  evt.DurationMs,
		"resolved":     evt.Resolved,
		"enrichment":   evt.Enrichment,
	}
}