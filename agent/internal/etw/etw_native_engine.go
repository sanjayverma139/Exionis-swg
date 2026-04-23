//go:build windows

package etw

/*
#cgo LDFLAGS: -ladvapi32 -ltdh
#include "etw_bridge.h"
*/
import "C"

import (
	"fmt"
	"time"

	"golang.org/x/sys/windows"
)

const windowsEpochOffset100ns = 116444736000000000

// Event is the normalized telemetry shape emitted by the native ETW bridge.
type Event struct {
	Type      string
	Provider  string
	PID       uint32
	TID       uint32
	EventID   uint16
	Opcode    uint8
	Detail    string
	Timestamp time.Time
}

var EventChannel = make(chan Event, 5000)

func publishEvent(event Event) {
	select {
	case EventChannel <- event:
	default:
	}
}

func filetime100nsToTime(value uint64) time.Time {
	if value < windowsEpochOffset100ns {
		return time.Now()
	}

	return time.Unix(0, int64(value-windowsEpochOffset100ns)*100)
}

//export exionis_go_emit_event
func exionis_go_emit_event(pid C.uint, tid C.uint, eventID C.ushort, opcode C.uchar, timestamp100ns C.ulonglong, eventType *C.char, provider *C.char, detail *C.char) {
	kind := "KERNEL_EVENT"
	if eventType != nil {
		kind = C.GoString(eventType)
	}

	providerName := "kernel"
	if provider != nil {
		providerName = C.GoString(provider)
	}

	detailText := ""
	if detail != nil {
		detailText = C.GoString(detail)
	}

	publishEvent(Event{
		Type:      kind,
		Provider:  providerName,
		PID:       uint32(pid),
		TID:       uint32(tid),
		EventID:   uint16(eventID),
		Opcode:    uint8(opcode),
		Detail:    detailText,
		Timestamp: filetime100nsToTime(uint64(timestamp100ns)),
	})
}

// StartETWListener starts the native kernel trace bridge and streams events into EventChannel.
func StartETWListener() {
	fmt.Println("[Exionis-ETW] Starting native kernel ETW engine...")

	go func() {
		status := C.exionis_start_kernel_trace()
		if status != 0 {
			err := windows.Errno(status)
			fmt.Printf("[Exionis-ETW] StartTraceW failed: %v\n", err)
			publishEvent(Event{
				Type:      "ETW_ERROR",
				Provider:  "KernelTrace",
				Detail:    fmt.Sprintf("StartTraceW failed: %v", err),
				Timestamp: time.Now(),
			})
			return
		}

		publishEvent(Event{
			Type:      "ETW_STATUS",
			Provider:  "KernelTrace",
			Detail:    "NT Kernel Logger session active",
			Timestamp: time.Now(),
		})

		status = C.exionis_run_kernel_trace()
		if status != 0 {
			err := windows.Errno(status)
			detail := fmt.Sprintf(
				"ProcessTrace failed: %v (NT Kernel Logger consumption usually requires an elevated Administrator shell)",
				err,
			)
			fmt.Printf("[Exionis-ETW] %s\n", detail)
			publishEvent(Event{
				Type:      "ETW_ERROR",
				Provider:  "KernelTrace",
				Detail:    detail,
				Timestamp: time.Now(),
			})
		}
	}()
}

// StopETWListener tears down the trace session when this process owns it.
func StopETWListener() error {
	status := C.exionis_stop_kernel_trace()
	if status != 0 {
		return fmt.Errorf("ControlTraceW stop failed: %w", windows.Errno(status))
	}

	return nil
}
