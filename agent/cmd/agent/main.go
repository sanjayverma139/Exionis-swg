//go:build windows
// +build windows

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"strings"
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

const (
	agentVersion  = "2.1.0"
	policyVersion = "initial"

	// appInventoryHour is the local hour (0-23) at which the daily app
	// inventory rescan runs when the agent is installed as a background service.
	// 2 AM is chosen because:
	//   - Very low user activity → minimal CPU contention.
	//   - Registry reads are the only I/O involved, no heavy disk work.
	//   - Results are available in the admin panel by the start of the work day.
	appInventoryHour = 2
)

func main() {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	deviceID, err := utils.GetDeviceID()
	if err != nil {
		fmt.Printf("[Warn] Device ID: %v\n", err)
		deviceID = "unknown"
	}

	// ── Combined rotating log sink ─────────────────────────────────────────
	logSink, err := logger.NewFileSink(`C:\ProgramData\Exionis\logs`, "agent", 100, 10)
	if err != nil {
		fmt.Printf("[Warn] Log sink: %v\n", err)
	}
	defer func() {
		if logSink != nil {
			logSink.Close()
		}
	}()

	// ── Per-stream cloud-sync output files ────────────────────────────────
	outMgr, err := output.NewManager(`C:\ProgramData\Exionis\output`, deviceID, agentVersion)
	if err != nil {
		fmt.Printf("[Warn] Output manager: %v\n", err)
	}
	defer func() {
		if outMgr != nil {
			outMgr.Close()
		}
	}()

	// ── Privileges ────────────────────────────────────────────────────────
	fmt.Println("[Exionis] Initializing privileges...")
	if err := config.EnableAllPrivileges(); err != nil {
		fmt.Printf("[Exionis] Privilege warning: %v\n", err)
	}

	// ── Network filtering config ──────────────────────────────────────────
	fmt.Println("[Exionis] Loading network filtering config...")
	if err := config.InitNetworkConfig(config.DefaultInternalRanges()); err != nil {
		fmt.Printf("[Exionis] Network config warning: %v\n", err)
	}

	// ── Bootstrap: snapshot pre-existing processes before ETW fires ───────
	fmt.Println("[Exionis] Building initial process snapshot...")
	correlation.PopulateInitialProcessTable()
	fmt.Println("[Exionis] Snapshot complete.")

	// ── App inventory: run once at startup, then daily at appInventoryHour ─
	// Running at startup ensures the admin panel has data immediately after
	// the agent is installed. The daily rescan keeps data fresh without
	// requiring a reinstall or manual trigger.
	scanTime := time.Now().Format(time.RFC3339Nano)
	runAppInventory(outMgr, logSink, deviceID, scanTime)

	go scheduleDailyAppInventory(outMgr, logSink, deviceID, sigChan)

	// ── ETW kernel listener ───────────────────────────────────────────────
	fmt.Println("[Exionis] Starting ETW kernel listener...")
	if err := etw.StartETWListener(); err != nil {
		fmt.Printf("[Exionis] ETW startup error: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("[Exionis] Phase 2: Process + Network Telemetry Engine ACTIVE")

	// ── Correlation engine ────────────────────────────────────────────────
	corrEngine := correlation.New()
	go corrEngine.Run(events.ProcessChan)

	// ── Stats ticker ──────────────────────────────────────────────────────
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			fmt.Printf("[STATS] Live processes: %d | Active connections: %d\n",
				corrEngine.RegistrySize(),
				correlation.GetActiveConnectionCount())
		}
	}()

	// ── StructuredOutput → file writer (stdout already done in engine) ────
	var seq uint64
	go func() {
		for evt := range correlation.StructuredOutput {
			seq++
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
				"is_alive":       evt.IsAlive,
				"resolved":       evt.Resolved,
				"enrichment":     evt.Enrichment,
				"device_id":      deviceID,
				"agent_version":  agentVersion,
				"policy_version": policyVersion,
			}
			if logSink != nil {
				logSink.WriteEvent(evtMap)
			}
			if outMgr != nil && isProcessRecordType(evt.EventType) {
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
					IsAlive:     evt.IsAlive,
					SHA256Hash:  evt.Enrichment.SHA256Hash,
					IsSigned:    evt.Enrichment.IsSigned,
					IsSystem:    evt.Enrichment.IsSystem,
					UserSID:     evt.Enrichment.UserSID,
				}
				if evt.EventType == "process_start" {
					rec.StartTime = evt.Timestamp.Format(time.RFC3339Nano)
				}
				if evt.EventType == "process_stop" {
					rec.StopTime = evt.Timestamp.Format(time.RFC3339Nano)
				}
				outMgr.WriteProcess(rec)
			}
		}
	}()

	// ── Network output file writer ────────────────────────────────────────
	go func() {
		for rec := range events.NetworkOutputChan {
			if logSink != nil {
				logSink.WriteEvent(map[string]interface{}{
					"event_type":     "network_connection",
					"timestamp":      rec.Timestamp,
					"pid":            rec.PID,
					"image":          rec.Image,
					"local_ip":       rec.LocalIP,
					"remote_ip":      rec.RemoteIP,
					"local_port":     rec.LocalPort,
					"remote_port":    rec.RemotePort,
					"protocol":       rec.Protocol,
					"direction":      rec.Direction,
					"domain":         rec.Domain,
					"bytes_sent":     rec.BytesSent,
					"bytes_recv":     rec.BytesRecv,
					"state":          rec.State,
					"device_id":      deviceID,
					"agent_version":  agentVersion,
					"policy_version": policyVersion,
				})
			}
			if outMgr != nil {
				outMgr.WriteNetwork(output.NetworkRecord{
					Timestamp:  rec.Timestamp,
					PID:        rec.PID,
					Image:      rec.Image,
					LocalIP:    rec.LocalIP,
					RemoteIP:   rec.RemoteIP,
					LocalPort:  rec.LocalPort,
					RemotePort: rec.RemotePort,
					Protocol:   rec.Protocol,
					Direction:  rec.Direction,
					Domain:     rec.Domain,
					BytesSent:  rec.BytesSent,
					BytesRecv:  rec.BytesRecv,
					State:      rec.State,
				})
			}
		}
	}()

	// ── Snapshot ticker ───────────────────────────────────────────────────
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

// runAppInventory scans installed applications and writes them to all sinks.
// The scan is a pure registry read — no disk I/O beyond the registry hive.
// It takes ~200-400 ms on a typical Windows machine and causes no measurable
// CPU spike because gopsutil / registry APIs are non-blocking syscalls.
func runAppInventory(outMgr *output.Manager, logSink *logger.FileSink, deviceID, scanTime string) {
	apps := inventory.CollectInstalledApps()
	if len(apps) == 0 {
		return
	}

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

	if outMgr != nil {
		for _, app := range apps {
			outMgr.WriteApp(output.AppRecord{
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
			})
		}
	}
}

// scheduleDailyAppInventory fires runAppInventory once per day at appInventoryHour.
//
// Strategy for background MSI service:
//   - Sleep until the next occurrence of appInventoryHour (2 AM by default).
//   - Run the scan, then sleep until the next day's occurrence.
//   - The scan itself is lightweight (~200 ms, registry reads only).
//   - We do NOT use a time.Ticker(24h) because that drifts from wall-clock time
//     (e.g. if the machine was asleep). Instead we recompute "time until next 2 AM"
//     after each run, which is always accurate regardless of sleep/hibernate gaps.
//
// CPU impact: negligible. Registry reads are kernel calls, no user-space spin.
// The goroutine sleeps the rest of the time — zero CPU when idle.
func scheduleDailyAppInventory(
	outMgr *output.Manager,
	logSink *logger.FileSink,
	deviceID string,
	stop <-chan os.Signal,
) {
	for {
		now := time.Now()
		// Next occurrence of appInventoryHour today.
		next := time.Date(now.Year(), now.Month(), now.Day(), appInventoryHour, 0, 0, 0, now.Location())
		// If that time has already passed today, schedule for tomorrow.
		if !now.Before(next) {
			next = next.Add(24 * time.Hour)
		}

		waitDuration := time.Until(next)
		fmt.Printf("[Exionis] Next app inventory scan scheduled in %v (at %s)\n",
			waitDuration.Round(time.Minute), next.Format("2006-01-02 15:04:05"))

		timer := time.NewTimer(waitDuration)
		select {
		case <-timer.C:
			scanTime := time.Now().Format(time.RFC3339Nano)
			fmt.Printf("[Exionis] Running scheduled app inventory scan at %s\n", scanTime)
			runAppInventory(outMgr, logSink, deviceID, scanTime)
		case <-stop:
			timer.Stop()
			return
		}
	}
}

func isProcessRecordType(eventType string) bool {
	return strings.HasPrefix(eventType, "process_")
}