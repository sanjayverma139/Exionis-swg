// Package etw provides the CGO bridge between Windows ETW C consumer and Go.
package etw

/*
#cgo LDFLAGS: -ladvapi32 -liphlpapi -lws2_32
#include "etw_bridge.h"
#include <stdlib.h>
*/
import "C"
import (
	"time"

	"exionis/internal/events"
)

// export exionis_go_emit_event is called from C when a process event occurs.
//export exionis_go_emit_event
func exionis_go_emit_event(
	pid C.uint,
	tid C.uint,
	eventID C.ushort,
	opcode C.uchar,
	timestamp C.ulonglong,
	eventType *C.char,
	provider *C.char,
	detail *C.char,
) {
	unixNano := int64(uint64(timestamp)-116444736000000000) * 100
	ts := time.Unix(0, unixNano)

	evt := events.EventInput{
		Type:      C.GoString(eventType),
		Provider:  C.GoString(provider),
		PID:       uint32(pid),
		TID:       uint32(tid),
		EventID:   uint16(eventID),
		Opcode:    uint8(opcode),
		Detail:    C.GoString(detail),
		Timestamp: ts,
	}

	select {
	case events.ProcessChan <- evt:
	default:
	}
}

// export exionis_go_emit_network_event is called from C when a network event occurs.
//export exionis_go_emit_network_event
func exionis_go_emit_network_event(
	pid C.uint,
	tid C.uint,
	opcode C.uchar,
	timestamp C.ulonglong,
	localIP *C.char,
	remoteIP *C.char,
	localPort C.ushort,
	remotePort C.ushort,
	protocol *C.char,
	bytesSent C.ulonglong,
	bytesRecv C.ulonglong,
) {
	unixNano := int64(uint64(timestamp)-116444736000000000) * 100
	ts := time.Unix(0, unixNano)

	evt := events.NetworkEvent{
		PID:        uint32(pid),
		LocalIP:    C.GoString(localIP),
		RemoteIP:   C.GoString(remoteIP),
		LocalPort:  uint16(localPort),
		RemotePort: uint16(remotePort),
		Protocol:   C.GoString(protocol),
		Direction:  mapOpcodeToDirection(uint8(opcode), C.GoString(protocol)),
		BytesSent:  uint64(bytesSent),
		BytesRecv:  uint64(bytesRecv),
		Timestamp:  ts,
	}

	select {
	case events.NetworkChan <- evt:
	default:
	}
}

func mapOpcodeToDirection(opcode uint8, protocol string) string {
	if protocol != "TCP" {
		return "unknown"
	}
	switch opcode {
	case 10, 12: return "outbound" // Connect, Send
	case 11, 13: return "inbound"  // Accept, Receive
	default:     return "unknown"
	}
}

// StartETWListener initializes and starts the ETW kernel trace session.
func StartETWListener() error {
	status := C.exionis_start_kernel_trace()
	if status != 0 && status != C.ERROR_ALREADY_EXISTS {
		return &ETWError{Code: int(status), Message: "failed to start kernel trace"}
	}
	go func() { C.exionis_run_kernel_trace() }()
	return nil
}

// StopETWListener gracefully stops the ETW kernel trace session.
func StopETWListener() error {
	status := C.exionis_stop_kernel_trace()
	if status != 0 {
		return &ETWError{Code: int(status), Message: "failed to stop kernel trace"}
	}
	return nil
}

type ETWError struct {
	Code    int
	Message string
}
func (e *ETWError) Error() string { return e.Message }