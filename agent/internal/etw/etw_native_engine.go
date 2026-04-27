package etw

/*
#cgo LDFLAGS: -ladvapi32 -liphlpapi -lws2_32
#include "etw_bridge.h"
#include <stdlib.h>
*/
import "C"
import (
	"fmt"
	"os"
	"time"

	"exionis/internal/config"
	"exionis/internal/events"
)


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
	eventTypeStr := C.GoString(eventType)
	if eventTypeStr != "PROCESS_START" && eventTypeStr != "PROCESS_STOP" {
		return
	}

	unixNano := int64(uint64(timestamp)-116444736000000000) * 100
	ts := time.Unix(0, unixNano)

	evt := events.EventInput{
		Type:      eventTypeStr,
		Provider:  C.GoString(provider),
		PID:       uint32(pid),
		TID:       uint32(tid),
		EventID:   uint16(eventID),
		Opcode:    uint8(opcode),
		Detail:    C.GoString(detail),
		Timestamp: ts,
	}

	// Send event — block briefly to avoid dropping startup events
	select {
	case events.ProcessChan <- evt:
	case <-time.After(250 * time.Millisecond):
		fmt.Fprintf(os.Stderr, "[ETW-GO] DROPPED: type=%s pid=%d\n", evt.Type, evt.PID)
	}
}

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

	proto := C.GoString(protocol)
	op := uint8(opcode)

	evt := events.NetworkEvent{
		PID:        uint32(pid),
		LocalIP:    C.GoString(localIP),
		RemoteIP:   C.GoString(remoteIP),
		LocalPort:  uint16(localPort),
		RemotePort: uint16(remotePort),
		Protocol:   proto,
		Direction:  mapOpcodeToDirection(op, proto),
		BytesSent:  uint64(bytesSent),
		BytesRecv:  uint64(bytesRecv),
		Timestamp:  ts,
		Opcode:     op,
	}

	select {
	case events.NetworkChan <- evt:
	default:
	}
}

//export go_is_internal_ip
func go_is_internal_ip(ip *C.char) C.int {
	if config.IsInternalIP(C.GoString(ip)) {
		return 1
	}
	return 0
}

// mapOpcodeToDirection converts an ETW TCP/IP opcode to a human-readable direction.
//
// ETW kernel TCP/IP provider opcodes (evntcons.h):
//   10 = Connect    — client initiates outbound connection
//   11 = Accept     — server accepts inbound connection
//   12 = Reconnect  — client reconnects (also outbound)
//   13 = Send       — local side is sending data (outbound)
//   14 = Receive    — local side is receiving data (inbound)
//   15 = Disconnect — connection torn down (direction not meaningful)
//   16 = Retransmit — retransmitting sent data (outbound)
//
// FIX: previous code had opcode 13 (Send) mapped to "inbound" and
// opcode 14 (Receive) falling through to "unknown". Both were wrong.
func mapOpcodeToDirection(opcode uint8, protocol string) string {
	if protocol != "TCP" {
		return "unknown"
	}
	switch opcode {
	case 10, 12, 13, 16: // Connect, Reconnect, Send, Retransmit
		return "outbound"
	case 11, 14: // Accept, Receive
		return "inbound"
	default:
		return "unknown"
	}
}

// StartETWListener initializes and starts the ETW kernel trace session.
func StartETWListener() error {
	if err := config.InitNetworkConfig(config.DefaultInternalRanges()); err != nil {
		return fmt.Errorf("failed to init network config: %w", err)
	}

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
