package correlation

import (
	"encoding/json"
	"fmt"
	"os"
	"syscall"
	"time"

	"exionis/internal/events"
	"exionis/internal/process"
)

func emitProcessStart(proc *ProcessInfo, seq uint64) {
	parentImage := proc.ParentImage
	if parentImage == "" && proc.PPID > 0 {
		tableMu.RLock()
		if parent, ok := processTable[proc.PPID]; ok {
			parentImage = parent.Image
		}
		tableMu.RUnlock()
	}

	evt := StructuredEvent{
		EventType:        "process_start",
		Timestamp:        proc.StartTime,
		PID:              proc.PID,
		PPID:             proc.PPID,
		Image:            proc.Image,
		ParentImage:      parentImage,
		GrandParentImage: proc.GrandParentImage,
		Chain:            proc.Chain,
		Depth:            proc.Depth,
		Cmdline:          proc.Cmdline,
		ImagePath:        proc.Enrichment.ExecutablePath,
		IsAlive:          true,
		Resolved:         true,
		Enrichment:       proc.Enrichment,
		SequenceID:       seq,
	}

	score, reasons := computeRiskScore(evt, proc.Cmdline)
	evt.RiskScore = score
	evt.RiskReasons = reasons

	if shouldAggregate(evt) {
		return
	}

	nonBlockingEmit(evt)
}

func emitProcessStop(proc *ProcessInfo) {
	duration := int64(-1)
	if !proc.StartTime.IsZero() && !proc.EndTime.IsZero() && proc.EndTime.After(proc.StartTime) {
		duration = proc.EndTime.Sub(proc.StartTime).Milliseconds()
	}
	evt := StructuredEvent{
		EventType:   "process_stop",
		Timestamp:   proc.EndTime,
		PID:         proc.PID,
		Image:       proc.Image,
		ParentImage: proc.ParentImage,
		Chain:       proc.Chain,
		Depth:       proc.Depth,
		DurationMs:  duration,
		IsAlive:     false,
		Resolved:    true,
		Enrichment:  proc.Enrichment,
		RiskScore:   proc.RiskScore,
		RiskReasons: proc.RiskReasons,
	}
	nonBlockingEmit(evt)
}

func emitProcessEnrichmentUpdate(proc *ProcessInfo) {
	parentImage := proc.ParentImage
	if parentImage == "" && proc.PPID > 0 {
		tableMu.RLock()
		if parent, ok := processTable[proc.PPID]; ok {
			parentImage = parent.Image
		}
		tableMu.RUnlock()
	}
	nonBlockingEmit(StructuredEvent{
		EventType:   "process_enrichment_update",
		Timestamp:   time.Now(),
		PID:         proc.PID,
		PPID:        proc.PPID,
		Image:       proc.Image,
		ParentImage: parentImage,
		Cmdline:     proc.Cmdline,
		ImagePath:   proc.ImagePath,
		IsAlive:     proc.IsAlive,
		Resolved:    true,
		Enrichment:  proc.Enrichment,
		Chain:       proc.Chain,
		Depth:       proc.Depth,
		RiskScore:   proc.RiskScore,
		RiskReasons: proc.RiskReasons,
	})
}

func emitNetworkEvent(evt events.NetworkEvent, proc *ProcessInfo) {
	imageName := "unknown"
	if proc != nil && proc.Image != "" {
		imageName = proc.Image
	} else if resolved := process.GetProcessNameByPID(evt.PID); resolved != "" {
		imageName = resolved
	}

	output := map[string]interface{}{
		"event_type":  "network_connection",
		"timestamp":   evt.Timestamp.Format(time.RFC3339Nano),
		"pid":         evt.PID,
		"image":       imageName,
		"local_ip":    evt.LocalIP,
		"remote_ip":   evt.RemoteIP,
		"local_port":  evt.LocalPort,
		"remote_port": evt.RemotePort,
		"protocol":    evt.Protocol,
		"direction":   evt.Direction,
	}
	if evt.Domain != "" {
		output["domain"] = evt.Domain
	}
	if evt.BytesSent > 0 {
		output["bytes_sent"] = evt.BytesSent
	}
	if evt.BytesRecv > 0 {
		output["bytes_recv"] = evt.BytesRecv
	}
	jsonBytes, err := json.Marshal(output)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[Exionis] JSON marshal error: %v\n", err)
		return
	}
	fmt.Printf("%s\n", string(jsonBytes))

	events.NetworkOutputChan <- events.NetworkOutputRecord{
		Timestamp:  evt.Timestamp.Format(time.RFC3339Nano),
		PID:        evt.PID,
		Image:      imageName,
		LocalIP:    evt.LocalIP,
		RemoteIP:   evt.RemoteIP,
		LocalPort:  evt.LocalPort,
		RemotePort: evt.RemotePort,
		Protocol:   evt.Protocol,
		Direction:  evt.Direction,
		Domain:     evt.Domain,
		BytesSent:  evt.BytesSent,
		BytesRecv:  evt.BytesRecv,
		State:      string(mapOpcodeToConnectionState(uint8(evt.Opcode), evt.Protocol)),
	}
	if debugMode {
		syscall.FlushFileBuffers(syscall.Handle(os.Stdout.Fd()))
	}
}

func nonBlockingEmit(evt StructuredEvent) {
	if jsonBytes, err := json.Marshal(evt); err == nil {
		fmt.Printf("%s\n", string(jsonBytes))
	}
	emitLegacyOutput(evt)
	select {
	case StructuredOutput <- evt:
	default:
	}
	if debugMode {
		syscall.FlushFileBuffers(syscall.Handle(os.Stdout.Fd()))
	}
}

func emitLegacyOutput(evt StructuredEvent) {
	legacyOutputMu.RLock()
	out := legacyOutput
	legacyOutputMu.RUnlock()
	if out == nil {
		return
	}
	legacy := CorrelatedEvent{
		Type:        evt.EventType,
		PID:         evt.PID,
		Timestamp:   evt.Timestamp,
		ProcessName: evt.Image,
		ParentPID:   evt.PPID,
		ParentName:  evt.ParentImage,
		Summary:     fmt.Sprintf("%s (PID %d)", evt.Image, evt.PID),
	}
	select {
	case out <- legacy:
	default:
	}
}
