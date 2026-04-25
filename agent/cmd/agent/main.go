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
	"exionis/internal/output"
	"exionis/internal/process"
	"exionis/internal/utils"
)

func main() {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	deviceID, err := utils.GetDeviceID()
	if err != nil {
		fmt.Printf("[Warn] Device ID: %v\n", err)
		deviceID = "unknown"
	}
	agentVersion  := "2.1.0"
	policyVersion := "initial"

	// Combined log sink (existing)
	logSink, err := logger.NewFileSink(
		`C:\ProgramData\Exionis\logs`,
		"agent", 100, 10,
	)
	if err != nil {
		fmt.Printf("[Warn] Log sink: %v\n", err)
	}
	defer func() {
		if logSink != nil {
			logSink.Close()
		}
	}()

	// NEW: Separate output files for cloud sync
	outMgr, err := output.NewManager(
		`C:\ProgramData\Exionis\output`,
		deviceID,
		agentVersion,
	)
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

	// Apps inventory → stdout + combined log + APPS FILE
	scanTime := time.Now().Format(time.RFC3339Nano)
	if apps := inventory.CollectInstalledApps(); len(apps) > 0 {
		snapshot := map[string]interface{}{
			"event_type":     "device_inventory",
			"timestamp":      scanTime,
			"device_id":      deviceID,
			"agent_version":  agentVersion,
			"policy_version": policyVersion,
			"installed_apps": apps,
		}
		if logSink != nil {
			logSink.WriteEvent(snapshot)
		}
		jsonBytes, _ := json.Marshal(snapshot)
		fmt.Printf("%s\n", jsonBytes)

		// Write one record per app to dedicated apps file
		if outMgr != nil {
			for _, app := range apps {
				rec := output.AppRecord{
					ScanTime:          scanTime,
					DisplayName:       app.Name,
					DisplayVersion:    app.Version,
					Publisher:         app.Publisher,
					InstallLocation:   app.InstallLocation,
					InstallDate:       app.InstallDate,
					UninstallString:   app.UninstallString,
					EstimatedSizeKB:   app.SizeKB,
					ActualSizeKB:      app.ActualSizeKB,
					IsSystemComponent: app.IsSystem,
					RegistrySource:    app.Source,
					InstallSource:     app.InstallSource,
					IsSigned:          app.IsSigned,
					RiskScore:         app.RiskScore,
				}
				outMgr.WriteApp(rec)
			}
		}
	}

	fmt.Println("[Exionis] Starting ETW kernel listener...")
	if err := etw.StartETWListener(); err != nil {
		fmt.Printf("[Exionis] ETW startup error: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("[Exionis] Phase 2: Process + Network Telemetry Engine ACTIVE")

	corrEngine := correlation.New()
	go corrEngine.Run(events.ProcessChan)

	// Stats ticker
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			fmt.Printf("[STATS] Live processes: %d | Active connections: %d\n",
				corrEngine.RegistrySize(),
				correlation.GetActiveConnectionCount())
		}
	}()

	// FIX: StructuredOutput consumer writes to FILE ONLY (no stdout — engine already printed)
	var seq uint64
	go func() {
		for evt := range correlation.StructuredOutput {
			seq++
			// Write to combined log file
			evtMap := map[string]interface{}{
				"event_type":     evt.EventType,
				"timestamp":      evt.Timestamp.Format(time.RFC3339Nano),
				"pid":            evt.PID,
				"ppid":           evt.PPID,
				"image":          evt.Image,
				"parent_image":   evt.ParentImage,
				"cmdline":        evt.Cmdline,
				"image_path":     evt.ImagePath,
				"duration_ms":    evt.DurationMs,
				"resolved":       evt.Resolved,
				"enrichment":     evt.Enrichment,
				"device_id":      deviceID,
				"agent_version":  agentVersion,
				"policy_version": policyVersion,
			}
			if logSink != nil {
				logSink.WriteEvent(evtMap)
			}
			// Write to dedicated process file
			if outMgr != nil {
				rec := output.ProcessRecord{
					RecordType:  evt.EventType,
					Timestamp:   evt.Timestamp.Format(time.RFC3339Nano),
					EventSeq:    seq,
					PID:         evt.PID,
					PPID:        evt.PPID,
					Image:       evt.Image,
					ParentImage: evt.ParentImage,
					Cmdline:     evt.Cmdline,
					ImagePath:   evt.ImagePath,
					DurationMs:  evt.DurationMs,
					IsAlive:     evt.EventType == "process_start",
					SHA256Hash:  evt.Enrichment.SHA256Hash,
					IsSigned:    evt.Enrichment.IsSigned,
					IsSystem:    evt.Enrichment.IsSystem,
					UserSID:     evt.Enrichment.UserSID,
				}
				outMgr.WriteProcess(rec)
			}
		}
	}()

	// Network output file writer
	go func() {
		for rec := range events.NetworkOutputChan {
			if outMgr != nil {
				outMgr.WriteNetwork(output.NetworkRecord{
					Timestamp:  rec.Timestamp,
					PID:        rec.PID,
					Image:      rec.Image,
					RemoteIP:   rec.RemoteIP,
					RemotePort: rec.RemotePort,
					Protocol:   rec.Protocol,
					Domain:     rec.Domain,
					BytesSent:  rec.BytesSent,
					BytesRecv:  rec.BytesRecv,
					State:      rec.State,
				})
			}
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