#ifndef EXIONIS_ETW_BRIDGE_H
#define EXIONIS_ETW_BRIDGE_H

#include <windows.h>
#include <evntrace.h>
#include <evntcons.h>
#include <tdh.h>

ULONG exionis_start_kernel_trace(void);
ULONG exionis_run_kernel_trace(void);
ULONG exionis_stop_kernel_trace(void);

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

#endif
