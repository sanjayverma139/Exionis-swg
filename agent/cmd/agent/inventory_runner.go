//go:build windows
// +build windows

package main

import (
	"encoding/json"
	"fmt"
	"time"

	"exionis/internal/inventory"
	"exionis/internal/logger"
	"exionis/internal/output"
)

// runAppInventory scans installed applications and writes them to all sinks.
func runAppInventory(outMgr *output.Manager, logSink *logger.FileSink, deviceID, hostname, scanTime string) {
	apps := inventory.CollectInstalledApps()
	if len(apps) == 0 {
		return
	}

	snapshot := map[string]interface{}{
		"event_type":     "device_inventory",
		"timestamp":      scanTime,
		"device_id":      deviceID,
		"hostname":       hostname,
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
				RiskScore:         app.RiskScore,
			})
		}
	}
}

// scheduleDailyAppInventory fires runAppInventory once per day at appInventoryHour.
func scheduleDailyAppInventory(
	outMgr *output.Manager,
	logSink *logger.FileSink,
	deviceID string,
	hostname string,
	stop <-chan struct{},
) {
	for {
		now := time.Now()
		next := time.Date(now.Year(), now.Month(), now.Day(), appInventoryHour, 0, 0, 0, now.Location())
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
			runAppInventory(outMgr, logSink, deviceID, hostname, scanTime)
		case <-stop:
			timer.Stop()
			return
		}
	}
}
