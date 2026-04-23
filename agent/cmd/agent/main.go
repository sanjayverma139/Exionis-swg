//go:build windows
// +build windows

package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"exionis/internal/config"
	"exionis/internal/correlation"
	"exionis/internal/etw"
	"exionis/internal/events"
	"exionis/internal/process"
)

func main() {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

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

	fmt.Println("[Exionis] Process Collector Running...")
	snapshotTicker := time.NewTicker(5 * time.Second)
	defer snapshotTicker.Stop()

	for {
		select {
		case <-sigChan:
			fmt.Println("\n[Exionis] Shutdown signal received, cleaning up...")
			etw.StopETWListener()
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