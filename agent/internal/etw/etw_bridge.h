#ifndef EXIONIS_ETW_BRIDGE_H
#define EXIONIS_ETW_BRIDGE_H

/* Prevent multiple inclusion */
#ifdef __cplusplus
extern "C" {
#endif

/* Windows headers must be included before this header when compiling C files */
#ifndef _WINDOWS_
#include <windows.h>
#endif
#include <evntrace.h>
#include <evntcons.h>

/* ============================================================================
 * Session Management API (C functions exported to Go via CGO)
 * ============================================================================*/
ULONG exionis_start_kernel_trace(void);
ULONG exionis_run_kernel_trace(void);
ULONG exionis_stop_kernel_trace(void);

/* ============================================================================
 * Go Callback Declarations (C calls these Go functions)
 * These are implemented in Go and exported via //export directive
 * ============================================================================*/

/* Process/Thread event callback */
extern void exionis_go_emit_event(
    unsigned int pid,
    unsigned int tid,
    unsigned short event_id,
    unsigned char opcode,
    unsigned long long timestamp_100ns,
    char* event_type,
    char* provider,
    char* detail
);

/* Network event callback */
extern void exionis_go_emit_network_event(
    unsigned int pid,
    unsigned int tid,
    unsigned char opcode,
    unsigned long long timestamp_100ns,
    char* local_ip,
    char* remote_ip,
    unsigned short local_port,
    unsigned short remote_port,
    char* protocol,
    unsigned long long bytes_sent,
    unsigned long long bytes_recv
);

#ifdef __cplusplus
}
#endif

#endif /* EXIONIS_ETW_BRIDGE_H */