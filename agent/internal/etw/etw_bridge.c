/* =========================================================================
 * Exionis ETW Bridge - C Consumer for Windows Kernel Events
 * 
 * IMPORTANT: Include order matters for Windows socket headers
 * winsock2.h MUST come before windows.h
 * =========================================================================*/

/* Prevent windows.h from pulling in winsock.h (we want winsock2.h) */
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

/* Socket headers FIRST */
#include <winsock2.h>
#include <ws2tcpip.h>
#include <in6addr.h>

/* Windows headers AFTER sockets */
#include <windows.h>
#include <evntrace.h>
#include <evntcons.h>
#include <tdh.h>

/* Standard C headers */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ============================================================================
 * Exionis Bridge Header - MUST be included after Windows headers
 * This declares the Go callback functions we call from C
 * ============================================================================*/
#include "etw_bridge.h"

/* ============================================================================
 * GUID Definitions for ETW Providers
 * ============================================================================*/
static const GUID EXIONIS_EVENT_TRACE_GUID =
    {0x68fdd900,0x4a3e,0x11d1,{0x84,0xf4,0x00,0x00,0xf8,0x04,0x64,0xe3}};
static const GUID EXIONIS_SYSTEM_TRACE_CONTROL_GUID =
    {0x9e814aad,0x3204,0x11d2,{0x9a,0x82,0x00,0x60,0x08,0xa8,0x69,0x39}};
static const GUID EXIONIS_PROCESS_GUID =
    {0x3d6fa8d0,0xfe05,0x11d0,{0x9d,0xda,0x00,0xc0,0x4f,0xd7,0xba,0x7c}};
static const GUID EXIONIS_THREAD_GUID =
    {0x3d6fa8d1,0xfe05,0x11d0,{0x9d,0xda,0x00,0x60,0x08,0xa8,0x69,0x39}};
static const GUID EXIONIS_IMAGE_LOAD_GUID =
    {0x2cb15d1d,0x5fc1,0x11d2,{0xab,0xe1,0x00,0xa0,0xc9,0x11,0xf5,0x18}};
static const GUID EXIONIS_TCPIP_GUID =
    {0x9a280ac0,0xc8e0,0x11d1,{0x84,0xe2,0x00,0xc0,0x4f,0xb9,0x98,0xa2}};
static const GUID EXIONIS_UDPIP_GUID =
    {0xbf3a50c5,0xa9c9,0x4988,{0xa0,0x05,0x2d,0xf0,0xb7,0xc8,0x0f,0x80}};

/* Global session state */
static TRACEHANDLE g_session_handle  = 0;
static TRACEHANDLE g_consumer_handle = 0;
static int         g_session_owned   = 0;
static const WCHAR g_session_name[]  = KERNEL_LOGGER_NAMEW;

#define EXIONIS_TRACE_BUFFER_SIZE 4096

/* ============================================================================
 * Helper: SID Length Calculation
 * ============================================================================*/
static ULONG exionis_sid_length(const BYTE* ptr, ULONG max_bytes) {
    if (max_bytes < 8) return 0;
    if (ptr[0] != 1) return 0;
    UCHAR sub = ptr[1];
    if (sub > 15) return 0;
    ULONG len = 8 + ((ULONG)sub * 4);
    return (len <= max_bytes) ? len : 0;
}

/* ============================================================================
 * Helper: Extract Parent PID from Process Event
 * ============================================================================*/
static ULONG exionis_extract_ppid(const BYTE* data, ULONG datalen, UCHAR version) {
    ULONG off = (version >= 3) ? 12 : 8;
    if (datalen < off + sizeof(ULONG)) return 0;
    ULONG ppid = 0;
    memcpy(&ppid, data + off, sizeof(ULONG));
    return ppid;
}

/* ============================================================================
 * Helper: Extract ImageFileName from PROCESS_START
 * ============================================================================*/
static void exionis_extract_image(const BYTE* data, ULONG datalen, UCHAR version, char* out, size_t out_size) {
    out[0] = '\0';
    if (out_size < 2) return;
    ULONG sid_offset, image_offset;
    int has_sid;
    if (version >= 4) { sid_offset = 52; has_sid = 1; }
    else if (version == 3) { sid_offset = 24; has_sid = 1; }
    else { sid_offset = 20; has_sid = 0; }
    if (datalen <= sid_offset) return;
    if (!has_sid) { image_offset = sid_offset; }
    else {
        ULONG sid_len = exionis_sid_length(data + sid_offset, datalen - sid_offset);
        image_offset = sid_offset + sid_len;
    }
    if (image_offset >= datalen) return;
    const char* src = (const char*)(data + image_offset);
    ULONG max_len = datalen - image_offset, nlen = 0;
    while (nlen < max_len && src[nlen] != '\0') nlen++;
    if (nlen == 0) return;
    ULONG copy = (nlen < (ULONG)(out_size - 1)) ? nlen : (ULONG)(out_size - 1);
    memcpy(out, src, copy);
    out[copy] = '\0';
}

/* ============================================================================
 * Network: Format IPv4 Address
 * ============================================================================*/
static void format_ipv4(const UCHAR* ip, char* out, size_t out_size) {
    if (out_size < 16) return;
    snprintf(out, out_size, "%u.%u.%u.%u", ip[0], ip[1], ip[2], ip[3]);
}

/* ============================================================================
 * Network: Format IPv6 Address
 * ============================================================================*/
static void format_ipv6(const UCHAR* ip, char* out, size_t out_size) {
    if (out_size < 40) return;
    struct in6_addr addr;
    memcpy(&addr, ip, 16);
    if (inet_ntop(AF_INET6, &addr, out, (socklen_t)out_size) == NULL) { out[0] = '\0'; }
}

/* ============================================================================
 * Network: Format IP Address (v4 or v6)
 * ============================================================================*/
static void format_ip(const UCHAR* ip, USHORT family, char* out, size_t out_size) {
    if (family == 2) { format_ipv4(ip, out, out_size); }
    else if (family == 23) { format_ipv6(ip, out, out_size); }
    else { out[0] = '\0'; }
}

/* ============================================================================
 * Network: Extract Fields from TCP/IP ETW Payload
 * ============================================================================*/
static int exionis_extract_network_fields(const BYTE* data, ULONG datalen, ULONG* pid,
    char* local_ip, size_t local_ip_size, char* remote_ip, size_t remote_ip_size,
    USHORT* local_port, USHORT* remote_port, USHORT* family, ULONGLONG* bytes) {
    if (datalen < 56) return 0;
    memcpy(pid, data, sizeof(ULONG));
    memcpy(family, data + 36, sizeof(USHORT));
    memcpy(local_port, data + 32, sizeof(USHORT));
    memcpy(remote_port, data + 34, sizeof(USHORT));
    *local_port = ntohs(*local_port);
    *remote_port = ntohs(*remote_port);
    format_ip(data + 40, *family, local_ip, local_ip_size);
    format_ip(data + 56, *family, remote_ip, remote_ip_size);
    if (bytes && datalen >= 28) { memcpy(bytes, data + 24, sizeof(ULONG)); }
    return 1;
}

/* ============================================================================
 * Provider/Event Name Helpers
 * ============================================================================*/
static const char* exionis_provider_name(const GUID* id) {
    if (IsEqualGUID(id, &EXIONIS_PROCESS_GUID)) return "Process";
    if (IsEqualGUID(id, &EXIONIS_THREAD_GUID)) return "Thread";
    if (IsEqualGUID(id, &EXIONIS_IMAGE_LOAD_GUID)) return "ImageLoad";
    if (IsEqualGUID(id, &EXIONIS_TCPIP_GUID)) return "TcpIp";
    if (IsEqualGUID(id, &EXIONIS_UDPIP_GUID)) return "UdpIp";
    if (IsEqualGUID(id, &EXIONIS_EVENT_TRACE_GUID)) return "EventTrace";
    if (IsEqualGUID(id, &EXIONIS_SYSTEM_TRACE_CONTROL_GUID)) return "KernelTrace";
    return "Unknown";
}

static const char* exionis_process_event_type(UCHAR opcode) {
    if (opcode == EVENT_TRACE_TYPE_START) return "PROCESS_START";
    if (opcode == EVENT_TRACE_TYPE_END) return "PROCESS_STOP";
    return NULL;
}

static const char* exionis_thread_event_type(UCHAR opcode) {
    switch (opcode) {
        case EVENT_TRACE_TYPE_START: case EVENT_TRACE_TYPE_DC_START: return "THREAD_START";
        case EVENT_TRACE_TYPE_END: case EVENT_TRACE_TYPE_DC_END: return "THREAD_STOP";
        default: return "THREAD_EVENT";
    }
}

static const char* exionis_network_event_type(UCHAR opcode, const GUID* id) {
    switch (opcode) {
        case EVENT_TRACE_TYPE_CONNECT: return "NETWORK_CONNECT";
        case EVENT_TRACE_TYPE_ACCEPT: return "NETWORK_ACCEPT";
        case EVENT_TRACE_TYPE_SEND: return "NETWORK_SEND";
        case EVENT_TRACE_TYPE_RECEIVE: return "NETWORK_RECEIVE";
        case EVENT_TRACE_TYPE_RECONNECT: return "NETWORK_RECONNECT";
        case EVENT_TRACE_TYPE_DISCONNECT: return "NETWORK_DISCONNECT";
        case EVENT_TRACE_TYPE_RETRANSMIT: return "NETWORK_RETRANSMIT";
        default: return IsEqualGUID(id, &EXIONIS_UDPIP_GUID) ? "UDP_EVENT" : "TCP_EVENT";
    }
}

static const char* exionis_event_type(const EVENT_RECORD* rec) {
    const GUID* id = &rec->EventHeader.ProviderId;
    const UCHAR opcode = rec->EventHeader.EventDescriptor.Opcode;
    if (IsEqualGUID(id, &EXIONIS_PROCESS_GUID)) return exionis_process_event_type(opcode);
    if (IsEqualGUID(id, &EXIONIS_THREAD_GUID)) return exionis_thread_event_type(opcode);
    if (IsEqualGUID(id, &EXIONIS_IMAGE_LOAD_GUID)) return "IMAGE_LOAD";
    if (IsEqualGUID(id, &EXIONIS_TCPIP_GUID) || IsEqualGUID(id, &EXIONIS_UDPIP_GUID))
        return exionis_network_event_type(opcode, id);
    if (IsEqualGUID(id, &EXIONIS_EVENT_TRACE_GUID)) return "TRACE_CONTROL";
    return "KERNEL_EVENT";
}

/* ============================================================================
 * Detail Formatter for Process Events
 * ============================================================================*/
static void exionis_format_detail(const EVENT_RECORD* rec, const char* provider_name, char* buf, size_t buf_size) {
    if (buf_size == 0) return;
    buf[0] = '\0';
    const GUID* id = &rec->EventHeader.ProviderId;
    const UCHAR opcode = rec->EventHeader.EventDescriptor.Opcode;
    const BYTE* data = (const BYTE*)rec->UserData;
    const ULONG datalen = (ULONG)rec->UserDataLength;
    const UCHAR version = rec->EventHeader.EventDescriptor.Version;
    if (IsEqualGUID(id, &EXIONIS_PROCESS_GUID)) {
        if (opcode == EVENT_TRACE_TYPE_START) {
            ULONG ppid = exionis_extract_ppid(data, datalen, version);
            char image[520];
            exionis_extract_image(data, datalen, version, image, sizeof(image));
            _snprintf(buf, buf_size, "PPID:%lu Image:%s", (unsigned long)ppid, image[0] ? image : "<unknown>");
            buf[buf_size - 1] = '\0';
            return;
        }
        if (opcode == EVENT_TRACE_TYPE_END) {
            ULONG ppid = exionis_extract_ppid(data, datalen, version);
            _snprintf(buf, buf_size, "PPID:%lu", (unsigned long)ppid);
            buf[buf_size - 1] = '\0';
            return;
        }
    }
    _snprintf(buf, buf_size, "provider=%s event_id=%u opcode=%u version=%u",
        provider_name, (unsigned int)rec->EventHeader.EventDescriptor.Id,
        (unsigned int)rec->EventHeader.EventDescriptor.Opcode,
        (unsigned int)rec->EventHeader.EventDescriptor.Version);
    buf[buf_size - 1] = '\0';
}

/* ============================================================================
 * ETW Event Callback - Main Entry Point
 * ============================================================================*/
static VOID WINAPI exionis_event_record_callback(PEVENT_RECORD record) {
    if (record == NULL) return;
    const GUID* provider_id = &record->EventHeader.ProviderId;
    const UCHAR opcode = record->EventHeader.EventDescriptor.Opcode;
    const BYTE* data = (const BYTE*)record->UserData;
    const ULONG datalen = (ULONG)record->UserDataLength;

    /* Process Events */
    if (IsEqualGUID(provider_id, &EXIONIS_PROCESS_GUID)) {
        const char* event_type = exionis_process_event_type(opcode);
        if (event_type == NULL) return;
        char detail[512];
        exionis_format_detail(record, "Process", detail, sizeof(detail));
        ULONG correct_pid = record->EventHeader.ProcessId;
        if (data != NULL && datalen >= 16) { memcpy(&correct_pid, data + 8, sizeof(ULONG)); }
        exionis_go_emit_event(correct_pid, record->EventHeader.ThreadId,
            record->EventHeader.EventDescriptor.Id, opcode,
            (unsigned long long)record->EventHeader.TimeStamp.QuadPart,
            (char*)event_type, (char*)"Process", detail);
        return;
    }

    /* TCP/IP Network Events */
    if (IsEqualGUID(provider_id, &EXIONIS_TCPIP_GUID) || IsEqualGUID(provider_id, &EXIONIS_UDPIP_GUID)) {
        const char* protocol = IsEqualGUID(provider_id, &EXIONIS_TCPIP_GUID) ? "TCP" : "UDP";
        if (opcode != EVENT_TRACE_TYPE_CONNECT && opcode != EVENT_TRACE_TYPE_ACCEPT &&
            opcode != EVENT_TRACE_TYPE_SEND && opcode != EVENT_TRACE_TYPE_RECEIVE) { return; }
        ULONG pid;
        char local_ip[40] = {0}, remote_ip[40] = {0};
        USHORT local_port = 0, remote_port = 0, family = 0;
        ULONGLONG bytes = 0;
        if (!exionis_extract_network_fields(data, datalen, &pid, local_ip, sizeof(local_ip),
                remote_ip, sizeof(remote_ip), &local_port, &remote_port, &family, &bytes)) { return; }
        if (strcmp(local_ip, "127.0.0.1") == 0 || strcmp(remote_ip, "127.0.0.1") == 0 ||
            strcmp(local_ip, "::1") == 0 || strcmp(remote_ip, "::1") == 0) { return; }
        exionis_go_emit_network_event(pid, record->EventHeader.ThreadId, opcode,
            (unsigned long long)record->EventHeader.TimeStamp.QuadPart,
            local_ip, remote_ip, local_port, remote_port, (char*)protocol,
            (opcode == EVENT_TRACE_TYPE_SEND || opcode == EVENT_TRACE_TYPE_CONNECT) ? bytes : 0,
            (opcode == EVENT_TRACE_TYPE_RECEIVE || opcode == EVENT_TRACE_TYPE_ACCEPT) ? bytes : 0);
        return;
    }

    /* Other Events */
    const char* event_type = exionis_event_type(record);
    if (event_type == NULL) return;
    const char* provider = exionis_provider_name(provider_id);
    char detail[512];
    exionis_format_detail(record, provider, detail, sizeof(detail));
    exionis_go_emit_event(record->EventHeader.ProcessId, record->EventHeader.ThreadId,
        record->EventHeader.EventDescriptor.Id, opcode,
        (unsigned long long)record->EventHeader.TimeStamp.QuadPart,
        (char*)event_type, (char*)provider, detail);
}

/* ============================================================================
 * Trace Session Properties Allocation
 * ============================================================================*/
static EVENT_TRACE_PROPERTIES* exionis_alloc_properties(void) {
    const size_t name_bytes = sizeof(g_session_name);
    size_t total = sizeof(EVENT_TRACE_PROPERTIES) + name_bytes;
    if (total < EXIONIS_TRACE_BUFFER_SIZE) total = EXIONIS_TRACE_BUFFER_SIZE;
    EVENT_TRACE_PROPERTIES* p = (EVENT_TRACE_PROPERTIES*)calloc(1, total);
    if (!p) return NULL;
    p->Wnode.BufferSize = (ULONG)total;
    p->Wnode.Guid = EXIONIS_SYSTEM_TRACE_CONTROL_GUID;
    p->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    p->Wnode.ClientContext = 2;
    p->LogFileMode = EVENT_TRACE_REAL_TIME_MODE | EVENT_TRACE_SYSTEM_LOGGER_MODE;
    p->EnableFlags = EVENT_TRACE_FLAG_PROCESS | EVENT_TRACE_FLAG_THREAD |
                     EVENT_TRACE_FLAG_IMAGE_LOAD | EVENT_TRACE_FLAG_NETWORK_TCPIP;
    p->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
    memcpy((BYTE*)p + p->LoggerNameOffset, g_session_name, name_bytes);
    return p;
}

/* ============================================================================
 * Public API: Start/Run/Stop Kernel Trace
 * ============================================================================*/
ULONG exionis_start_kernel_trace(void) {
    EVENT_TRACE_PROPERTIES* p = exionis_alloc_properties();
    if (!p) return ERROR_OUTOFMEMORY;
    ULONG status = StartTraceW(&g_session_handle, g_session_name, p);
    if (status == ERROR_SUCCESS) { g_session_owned = 1; }
    else if (status == ERROR_ALREADY_EXISTS) { g_session_owned = 0; status = ERROR_SUCCESS; }
    free(p);
    return status;
}

ULONG exionis_run_kernel_trace(void) {
    EVENT_TRACE_LOGFILEW lf;
    ZeroMemory(&lf, sizeof(lf));
    lf.LoggerName = (LPWSTR)g_session_name;
    lf.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
    lf.EventRecordCallback = exionis_event_record_callback;
    g_consumer_handle = OpenTraceW(&lf);
    if (g_consumer_handle == INVALID_PROCESSTRACE_HANDLE) { return GetLastError(); }
    ULONG status = ProcessTrace(&g_consumer_handle, 1, NULL, NULL);
    CloseTrace(g_consumer_handle);
    g_consumer_handle = 0;
    return status;
}

ULONG exionis_stop_kernel_trace(void) {
    ULONG status = ERROR_SUCCESS;
    if (g_consumer_handle != 0 && g_consumer_handle != INVALID_PROCESSTRACE_HANDLE) {
        CloseTrace(g_consumer_handle);
        g_consumer_handle = 0;
    }
    if (!g_session_owned) return status;
    EVENT_TRACE_PROPERTIES* p = exionis_alloc_properties();
    if (!p) return ERROR_OUTOFMEMORY;
    status = ControlTraceW(g_session_handle, g_session_name, p, EVENT_TRACE_CONTROL_STOP);
    free(p);
    g_session_handle = 0;
    g_session_owned = 0;
    return status;
}