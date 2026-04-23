#include "etw_bridge.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define EXIONIS_TRACE_BUFFER_SIZE 4096

static TRACEHANDLE g_session_handle  = 0;
static TRACEHANDLE g_consumer_handle = 0;
static int         g_session_owned   = 0;
static const WCHAR g_session_name[]  = KERNEL_LOGGER_NAMEW;

static const GUID EXIONIS_EVENT_TRACE_GUID =
    {0x68fdd900,0x4a3e,0x11d1,{0x84,0xf4,0x00,0x00,0xf8,0x04,0x64,0xe3}};
static const GUID EXIONIS_SYSTEM_TRACE_CONTROL_GUID =
    {0x9e814aad,0x3204,0x11d2,{0x9a,0x82,0x00,0x60,0x08,0xa8,0x69,0x39}};
static const GUID EXIONIS_PROCESS_GUID =
    {0x3d6fa8d0,0xfe05,0x11d0,{0x9d,0xda,0x00,0xc0,0x4f,0xd7,0xba,0x7c}};
static const GUID EXIONIS_THREAD_GUID =
    {0x3d6fa8d1,0xfe05,0x11d0,{0x9d,0xda,0x00,0xc0,0x4f,0xd7,0xba,0x7c}};
static const GUID EXIONIS_IMAGE_LOAD_GUID =
    {0x2cb15d1d,0x5fc1,0x11d2,{0xab,0xe1,0x00,0xa0,0xc9,0x11,0xf5,0x18}};
static const GUID EXIONIS_TCPIP_GUID =
    {0x9a280ac0,0xc8e0,0x11d1,{0x84,0xe2,0x00,0xc0,0x4f,0xb9,0x98,0xa2}};
static const GUID EXIONIS_UDPIP_GUID =
    {0xbf3a50c5,0xa9c9,0x4988,{0xa0,0x05,0x2d,0xf0,0xb7,0xc8,0x0f,0x80}};

/* =========================================================================
 * VERIFIED v4 (Windows 10/11 x64) PROCESS EVENT PAYLOAD LAYOUT
 * Cross-checked against two live hex dumps (agent.exe + audiodg.exe events).
 *
 *  offset  0   ULONG64  UniqueProcessKey
 *  offset  8   ULONG    ProcessId
 *  offset 12   ULONG    ParentId
 *  offset 16   ULONG    SessionId
 *  offset 20   LONG     ExitStatus
 *  offset 24   ULONG64  DirectoryTableBase
 *  offset 32   ULONG64  Flags
 *  offset 40   ULONG64  (kernel UserSID pointer — NOT the inline SID struct)
 *  offset 48   ULONG    (padding / alignment)
 *  offset 52   SID      UserSID inline  (variable: 8 + SubAuthorityCount*4 bytes)
 *  offset 52+sidlen
 *              char[]   ImageFileName   NARROW ASCII, null-terminated
 *  (after null) WCHAR[] CommandLine     UTF-16, null-terminated
 *
 *  Key finding: SID starts at offset 52, NOT 40.
 *  Offsets 40-51 are a kernel pointer + padding, NOT the SID struct.
 *
 *  PROCESS_STOP (opcode 2):
 *  The Windows kernel does NOT include ImageFileName in STOP payloads.
 *  Only PID (EventHeader.ProcessId) and ParentId (offset 12) are reliable.
 *  NEVER parse ImageFileName from STOP events.
 *
 *  v3 (Windows 7):
 *   offset 12  ULONG  ParentId
 *   offset 24  SID    (variable, starts here — no pointer prefix)
 *   offset 24+sidlen  char[]  ImageFileName
 *
 *  v1/v2 (pre-Vista):
 *   offset  8  ULONG  ParentId
 *   offset 20  char[] ImageFileName (no SID field at all)
 * =========================================================================*/

/* -------------------------------------------------------------------------
 * Returns the byte length of a Windows SID at ptr.
 * Returns 0 if the SID is absent, null, or invalid.
 * -------------------------------------------------------------------------*/
static ULONG exionis_sid_length(const BYTE* ptr, ULONG max_bytes)
{
    if (max_bytes < 8) return 0;
    if (ptr[0] != 1)   return 0;   /* Revision must be 1 */

    UCHAR sub = ptr[1];
    if (sub > 15) return 0;        /* max 15 sub-authorities per spec */

    ULONG len = 8 + ((ULONG)sub * 4);
    return (len <= max_bytes) ? len : 0;
}

/* -------------------------------------------------------------------------
 * Extract ParentId from a process event (START or STOP).
 * Uses fixed offsets only — no variable-length parsing.
 * -------------------------------------------------------------------------*/
static ULONG exionis_extract_ppid(const BYTE* data, ULONG datalen, UCHAR version)
{
    ULONG off = (version >= 3) ? 12 : 8;
    if (datalen < off + (ULONG)sizeof(ULONG)) return 0;

    ULONG ppid = 0;
    memcpy(&ppid, data + off, sizeof(ULONG));
    return ppid;
}

/* -------------------------------------------------------------------------
 * Extract ImageFileName from a PROCESS_START payload.
 * ONLY call this for opcode == EVENT_TRACE_TYPE_START.
 *
 * ImageFileName is a narrow (single-byte ASCII) null-terminated string.
 * It lives immediately after the inline SID struct.
 * No WideCharToMultiByte needed — ASCII is already valid UTF-8.
 *
 * SID offsets by version (confirmed from hex dumps):
 *   v4 (Win10/11 x64): SID at offset 52
 *   v3 (Win7):         SID at offset 24
 *   v1/v2:             No SID, image at offset 20
 * -------------------------------------------------------------------------*/
static void exionis_extract_image(
    const BYTE* data,
    ULONG       datalen,
    UCHAR       version,
    char*       out,
    size_t      out_size)
{
    out[0] = '\0';
    if (out_size < 2) return;

    ULONG sid_offset;
    int   has_sid;

    if (version >= 4) {
        sid_offset = 52;   /* verified: NOT 40 — bytes 40-51 are ptr+padding */
        has_sid    = 1;
    } else if (version == 3) {
        sid_offset = 24;
        has_sid    = 1;
    } else {
        sid_offset = 20;
        has_sid    = 0;
    }

    if (datalen <= sid_offset) return;

    ULONG image_offset;

    if (!has_sid) {
        image_offset = sid_offset;
    } else {
        ULONG sid_len = exionis_sid_length(data + sid_offset, datalen - sid_offset);
        /* sid_len == 0 → null/absent SID → image starts right at sid_offset */
        image_offset = sid_offset + sid_len;
    }

    if (image_offset >= datalen) return;

    /* ImageFileName: narrow ASCII string, copy directly */
    const char* src     = (const char*)(data + image_offset);
    ULONG       max_len = datalen - image_offset;
    ULONG       nlen    = 0;

    while (nlen < max_len && src[nlen] != '\0') nlen++;
    if (nlen == 0) return;

    ULONG copy = (nlen < (ULONG)(out_size - 1)) ? nlen : (ULONG)(out_size - 1);
    memcpy(out, src, copy);
    out[copy] = '\0';
}

/* =========================================================================
 * Provider / event-type name helpers
 * =========================================================================*/

static const char* exionis_provider_name(const GUID* id)
{
    if (IsEqualGUID(id, &EXIONIS_PROCESS_GUID))               return "Process";
    if (IsEqualGUID(id, &EXIONIS_THREAD_GUID))                return "Thread";
    if (IsEqualGUID(id, &EXIONIS_IMAGE_LOAD_GUID))            return "ImageLoad";
    if (IsEqualGUID(id, &EXIONIS_TCPIP_GUID))                 return "TcpIp";
    if (IsEqualGUID(id, &EXIONIS_UDPIP_GUID))                 return "UdpIp";
    if (IsEqualGUID(id, &EXIONIS_EVENT_TRACE_GUID))           return "EventTrace";
    if (IsEqualGUID(id, &EXIONIS_SYSTEM_TRACE_CONTROL_GUID))  return "KernelTrace";
    return "Unknown";
}

/* DC_START(3), DC_END(4), rundown(11) → NULL → dropped in callback */
static const char* exionis_process_event_type(UCHAR opcode)
{
    if (opcode == EVENT_TRACE_TYPE_START) return "PROCESS_START";
    if (opcode == EVENT_TRACE_TYPE_END)   return "PROCESS_STOP";
    return NULL;
}

static const char* exionis_thread_event_type(UCHAR opcode)
{
    switch (opcode) {
        case EVENT_TRACE_TYPE_START:
        case EVENT_TRACE_TYPE_DC_START: return "THREAD_START";
        case EVENT_TRACE_TYPE_END:
        case EVENT_TRACE_TYPE_DC_END:   return "THREAD_STOP";
        default:                        return "THREAD_EVENT";
    }
}

static const char* exionis_network_event_type(UCHAR opcode, const GUID* id)
{
    switch (opcode) {
        case EVENT_TRACE_TYPE_CONNECT:    return "NETWORK_CONNECT";
        case EVENT_TRACE_TYPE_ACCEPT:     return "NETWORK_ACCEPT";
        case EVENT_TRACE_TYPE_SEND:       return "NETWORK_SEND";
        case EVENT_TRACE_TYPE_RECEIVE:    return "NETWORK_RECEIVE";
        case EVENT_TRACE_TYPE_RECONNECT:  return "NETWORK_RECONNECT";
        case EVENT_TRACE_TYPE_DISCONNECT: return "NETWORK_DISCONNECT";
        case EVENT_TRACE_TYPE_RETRANSMIT: return "NETWORK_RETRANSMIT";
        default:
            return IsEqualGUID(id, &EXIONIS_UDPIP_GUID) ? "UDP_EVENT" : "TCP_EVENT";
    }
}

static const char* exionis_event_type(const EVENT_RECORD* rec)
{
    const GUID*  id     = &rec->EventHeader.ProviderId;
    const UCHAR  opcode = rec->EventHeader.EventDescriptor.Opcode;

    if (IsEqualGUID(id, &EXIONIS_PROCESS_GUID))    return exionis_process_event_type(opcode);
    if (IsEqualGUID(id, &EXIONIS_THREAD_GUID))     return exionis_thread_event_type(opcode);
    if (IsEqualGUID(id, &EXIONIS_IMAGE_LOAD_GUID)) return "IMAGE_LOAD";
    if (IsEqualGUID(id, &EXIONIS_TCPIP_GUID) ||
        IsEqualGUID(id, &EXIONIS_UDPIP_GUID))      return exionis_network_event_type(opcode, id);
    if (IsEqualGUID(id, &EXIONIS_EVENT_TRACE_GUID)) return "TRACE_CONTROL";
    return "KERNEL_EVENT";
}

/* =========================================================================
 * Detail formatter
 *
 *  PROCESS_START → "PPID:<n> Image:<name>"
 *  PROCESS_STOP  → "PPID:<n>"              (no image — Go cache resolves it)
 *  Everything else → generic field string
 * =========================================================================*/
static void exionis_format_detail(
    const EVENT_RECORD* rec,
    const char*         provider_name,
    char*               buf,
    size_t              buf_size)
{
    if (buf_size == 0) return;
    buf[0] = '\0';

    const GUID*  id      = &rec->EventHeader.ProviderId;
    const UCHAR  opcode  = rec->EventHeader.EventDescriptor.Opcode;
    const BYTE*  data    = (const BYTE*)rec->UserData;
    const ULONG  datalen = (ULONG)rec->UserDataLength;
    const UCHAR  version = rec->EventHeader.EventDescriptor.Version;

    if (IsEqualGUID(id, &EXIONIS_PROCESS_GUID)) {

        if (opcode == EVENT_TRACE_TYPE_START) {
            ULONG ppid = exionis_extract_ppid(data, datalen, version);
            char  image[520];
            exionis_extract_image(data, datalen, version, image, sizeof(image));

            _snprintf(buf, buf_size, "PPID:%lu Image:%s",
                      (unsigned long)ppid,
                      image[0] ? image : "<unknown>");
            buf[buf_size - 1] = '\0';
            return;
        }

        if (opcode == EVENT_TRACE_TYPE_END) {
            /* STOP: only PPID is reliable — no ImageFileName in kernel payload */
            ULONG ppid = exionis_extract_ppid(data, datalen, version);
            _snprintf(buf, buf_size, "PPID:%lu", (unsigned long)ppid);
            buf[buf_size - 1] = '\0';
            return;
        }
    }

    _snprintf(buf, buf_size,
        "provider=%s event_id=%u opcode=%u version=%u",
        provider_name,
        (unsigned int)rec->EventHeader.EventDescriptor.Id,
        (unsigned int)rec->EventHeader.EventDescriptor.Opcode,
        (unsigned int)rec->EventHeader.EventDescriptor.Version);
    buf[buf_size - 1] = '\0';
}

/* =========================================================================
 * ETW event callback — called by ProcessTrace on the consumer thread
 * =========================================================================*/
/* =========================================================================
 * ETW event callback — called by ProcessTrace on the consumer thread
 * =========================================================================*/
static VOID WINAPI exionis_event_record_callback(PEVENT_RECORD record)
{
    if (record == NULL) return;

    const char* event_type = exionis_event_type(record);
    if (event_type == NULL) return;   /* drop DC_START, DC_END, rundown */

    const char* provider = exionis_provider_name(&record->EventHeader.ProviderId);

    char detail[512];
    exionis_format_detail(record, provider, detail, sizeof(detail));

    /* =====================================================================
     * CRITICAL FIX: Kernel Process events report WRONG PID in EventHeader.ProcessId.
     * The TRUE PID lives at offset 8 in the UserData payload.
     * This patch extracts the correct PID for Process provider events only.
     * =====================================================================*/
    ULONG correct_pid = record->EventHeader.ProcessId;

    if (record->UserData != NULL && 
        record->UserDataLength >= 16 &&
        IsEqualGUID(&record->EventHeader.ProviderId, &EXIONIS_PROCESS_GUID)) 
    {
        // Extract PID from payload offset 8 (confirmed v3/v4 layout)
        memcpy(&correct_pid, (const BYTE*)record->UserData + 8, sizeof(ULONG));
    }

    exionis_go_emit_event(
        correct_pid,                  // ✅ Use payload PID, NOT header PID
        record->EventHeader.ThreadId,
        record->EventHeader.EventDescriptor.Id,
        record->EventHeader.EventDescriptor.Opcode,
        (unsigned long long)record->EventHeader.TimeStamp.QuadPart,
        (char*)event_type,
        (char*)provider,
        detail);
}

/* =========================================================================
 * Trace session management
 * =========================================================================*/
static EVENT_TRACE_PROPERTIES* exionis_alloc_properties(void)
{
    const size_t name_bytes = sizeof(g_session_name);
    size_t total = sizeof(EVENT_TRACE_PROPERTIES) + name_bytes;
    if (total < EXIONIS_TRACE_BUFFER_SIZE) total = EXIONIS_TRACE_BUFFER_SIZE;

    EVENT_TRACE_PROPERTIES* p = (EVENT_TRACE_PROPERTIES*)calloc(1, total);
    if (!p) return NULL;

    p->Wnode.BufferSize    = (ULONG)total;
    p->Wnode.Guid          = EXIONIS_SYSTEM_TRACE_CONTROL_GUID;
    p->Wnode.Flags         = WNODE_FLAG_TRACED_GUID;
    p->Wnode.ClientContext = 2;
    p->LogFileMode         = EVENT_TRACE_REAL_TIME_MODE | EVENT_TRACE_SYSTEM_LOGGER_MODE;
    p->EnableFlags         = EVENT_TRACE_FLAG_PROCESS      |
                             EVENT_TRACE_FLAG_THREAD        |
                             EVENT_TRACE_FLAG_IMAGE_LOAD    |
                             EVENT_TRACE_FLAG_NETWORK_TCPIP;
    p->LoggerNameOffset    = sizeof(EVENT_TRACE_PROPERTIES);
    memcpy((BYTE*)p + p->LoggerNameOffset, g_session_name, name_bytes);
    return p;
}

ULONG exionis_start_kernel_trace(void)
{
    EVENT_TRACE_PROPERTIES* p = exionis_alloc_properties();
    if (!p) return ERROR_OUTOFMEMORY;

    ULONG status = StartTraceW(&g_session_handle, g_session_name, p);
    if (status == ERROR_SUCCESS) {
        g_session_owned = 1;
    } else if (status == ERROR_ALREADY_EXISTS) {
        g_session_owned = 0;
        status = ERROR_SUCCESS;
    }
    free(p);
    return status;
}

ULONG exionis_run_kernel_trace(void)
{
    EVENT_TRACE_LOGFILEW lf;
    ZeroMemory(&lf, sizeof(lf));
    lf.LoggerName          = (LPWSTR)g_session_name;
    lf.ProcessTraceMode    = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
    lf.EventRecordCallback = exionis_event_record_callback;

    g_consumer_handle = OpenTraceW(&lf);
    if (g_consumer_handle == INVALID_PROCESSTRACE_HANDLE) return GetLastError();

    ULONG status = ProcessTrace(&g_consumer_handle, 1, NULL, NULL);
    CloseTrace(g_consumer_handle);
    g_consumer_handle = 0;
    return status;
}

ULONG exionis_stop_kernel_trace(void)
{
    ULONG status = ERROR_SUCCESS;

    if (g_consumer_handle != 0 &&
        g_consumer_handle != INVALID_PROCESSTRACE_HANDLE) {
        CloseTrace(g_consumer_handle);
        g_consumer_handle = 0;
    }

    if (!g_session_owned) return status;

    EVENT_TRACE_PROPERTIES* p = exionis_alloc_properties();
    if (!p) return ERROR_OUTOFMEMORY;

    status = ControlTraceW(g_session_handle, g_session_name, p,
                           EVENT_TRACE_CONTROL_STOP);
    free(p);
    g_session_handle = 0;
    g_session_owned  = 0;
    return status;
}