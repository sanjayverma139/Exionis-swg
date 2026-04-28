//go:build windows
// +build windows

package main

import (
	"strings"
	"time"

	"exionis/internal/correlation"
	"exionis/internal/events"
	"exionis/internal/logger"
	"exionis/internal/output"
)

func startStructuredOutputWriter(outMgr *output.Manager, logSink *logger.FileSink, deviceID string) {
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
}

func startNetworkOutputWriter(outMgr *output.Manager, logSink *logger.FileSink, deviceID string) {
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
}

func isProcessRecordType(eventType string) bool {
	return strings.HasPrefix(eventType, "process_")
}
