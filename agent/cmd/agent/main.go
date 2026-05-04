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
	"exionis/internal/logger"
	"exionis/internal/output"
	"exionis/internal/process"
	"exionis/internal/telemetry"
	"exionis/internal/utils"
)

const (
	agentVersion     = "2.1.0"
	policyVersion    = "initial"
	appInventoryHour = 2
)

func main() {
	sigChan := make(chan os.Signal, 1)
	shutdown := make(chan struct{})
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	deviceID, err := utils.GetDeviceID()
	if err != nil {
		fmt.Printf("[Warn] Device ID: %v\n", err)
		deviceID = "unknown"
	}
	hostname, err := os.Hostname()
	if err != nil || hostname == "" {
		hostname = "unknown-host"
	}

	telemetryCfg := telemetry.LoadConfig()
	bootID := telemetry.BuildBootID()

	logSink, err := logger.NewFileSink(`C:\ProgramData\Exionis\logs`, "agent", 100, 10)
	if err != nil {
		fmt.Printf("[Warn] Log sink: %v\n", err)
	}
	defer func() {
		if logSink != nil {
			logSink.Close()
		}
	}()

	outMgr, err := output.NewManager(telemetryCfg.BaselineDir, deviceID, hostname, agentVersion)
	if err != nil {
		fmt.Printf("[Warn] Output manager: %v\n", err)
	}
	defer func() {
		if outMgr != nil {
			outMgr.Close()
		}
	}()

	fmt.Println("[Exionis] Initializing privileges...")
	if err := config.EnableAllPrivileges(); err != nil {
		fmt.Printf("[Exionis] Privilege warning: %v\n", err)
	}

	fmt.Println("[Exionis] Loading network filtering config...")
	if err := config.InitNetworkConfig(config.DefaultInternalRanges()); err != nil {
		fmt.Printf("[Exionis] Network config warning: %v\n", err)
	}

	fmt.Println("[Exionis] Building initial process snapshot...")
	correlation.PopulateInitialProcessTable()
	fmt.Println("[Exionis] Snapshot complete.")

	telemetryController, err := telemetry.NewController(telemetryCfg, outMgr, logSink, deviceID, hostname, agentVersion, policyVersion, bootID)
	if err != nil {
		fmt.Printf("[Warn] Telemetry controller: %v\n", err)
	}
	if telemetryController != nil {
		telemetryController.SeedFromLiveProcesses()
		telemetryController.Start()
		defer telemetryController.Shutdown()
	}

	corrEngine := correlation.New()
	go corrEngine.Run(events.ProcessChan)

	scanTime := time.Now().Format(time.RFC3339Nano)
	runAppInventory(outMgr, logSink, deviceID, hostname, scanTime)
	go scheduleDailyAppInventory(outMgr, logSink, deviceID, hostname, shutdown)

	fmt.Println("[Exionis] Starting ETW kernel listener...")
	if err := etw.StartETWListener(); err != nil {
		fmt.Printf("[Exionis] ETW startup error: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("[Exionis] Phase 2: Process + Network Telemetry Engine ACTIVE")

	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			fmt.Printf("[STATS] Live processes: %d | Active connections: %d\n",
				corrEngine.RegistrySize(),
				correlation.GetActiveConnectionCount())
		}
	}()

	startTelemetryWorkers(telemetryController, outMgr, logSink, deviceID, hostname, telemetryCfg)

	fmt.Println("[Exionis] Process Collector Running...")
	snapshotTicker := time.NewTicker(5 * time.Second)
	defer snapshotTicker.Stop()

	for {
		select {
		case <-sigChan:
			close(shutdown)
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
