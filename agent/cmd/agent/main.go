// File: cmd/agent/main.go
//go:build windows
// +build windows

package main

import (
	
	"fmt"
	"time"

	"exionis/internal/config"
	"exionis/internal/correlation"
	"exionis/internal/etw"
	"exionis/internal/process"
)

func main() {
	// Enable debug privileges for ETW kernel tracing
	if err := config.EnableSeDebugPrivilege(); err != nil {
		fmt.Printf("[Exionis] SeDebugPrivilege warning: %v\n", err)
	}

	// ---------------------------------------------------------------
	// 1. Start ETW kernel listener
	// ---------------------------------------------------------------
	etw.StartETWListener()
	fmt.Println("[Exionis] Phase 2: Process Telemetry Engine ACTIVE")
	fmt.Println("[Exionis] Enrichment: path|hash|signature|SID | Correlation: START↔STOP | TTL: 5m")
	fmt.Println("[Exionis] ETW kernel listener started")

	// ---------------------------------------------------------------
	// 2. Create Process Intelligence Engine
	// ---------------------------------------------------------------
	corrEngine := correlation.New()

	// ---------------------------------------------------------------
	// 3. Tee: etw.EventChannel → corrInput (process events only)
	// ---------------------------------------------------------------
	corrInput := make(chan correlation.EventInput, 5000)

	go func() {
		for event := range etw.EventChannel {
			// Skip kernel-context events
			if event.PID == 0 || event.PID == 0xFFFFFFFF {
				continue
			}
			// Forward only process events to correlation engine
			if event.Type == "PROCESS_START" || event.Type == "PROCESS_STOP" {
				select {
				case corrInput <- correlation.EventInput{
					Type:      event.Type,
					Provider:  event.Provider,
					PID:       event.PID,
					TID:       event.TID,
					EventID:   event.EventID,
					Opcode:    event.Opcode,
					Detail:    event.Detail,
					Timestamp: event.Timestamp,
				}:
				default:
					// Backpressure: drop if channel full
				}
			}
		}
	}()

	// ---------------------------------------------------------------
	// 4. Start the correlation engine
	// ---------------------------------------------------------------
	go corrEngine.Run(corrInput)

	

	// ---------------------------------------------------------------
	// 6. [OPTIONAL] Legacy stats ticker (uses new processTable)
	// ---------------------------------------------------------------
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			fmt.Printf("[STATS] Live processes: %d\n", corrEngine.RegistrySize())
		}
	}()

	// ---------------------------------------------------------------
	// 7. Process snapshot collector (existing functionality)
	// ---------------------------------------------------------------
	fmt.Println("[Exionis] Process Collector Running...")
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
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