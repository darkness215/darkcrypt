#ifndef ONEDARK_H
#define ONEDARK_H

#include <windows.h>
#include <stdint.h>

/* Syscall number extraction from ntdll */
DWORD get_syscall_number(const char *func_name);

/* Create a 12-byte RWX syscall stub */
LPVOID create_syscall_stub(DWORD syscall_number);

/* Typedefs for syscall function pointers */

typedef LONG NTSTATUS;

typedef NTSTATUS (NTAPI *NtAllocateVirtualMemory_t)(
    HANDLE ProcessHandle,
    PVOID *BaseAddress,
    ULONG ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect
);

typedef NTSTATUS (NTAPI *NtWriteVirtualMemory_t)(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    SIZE_T NumberOfBytesToWrite,
    PSIZE_T NumberOfBytesWritten
);

typedef NTSTATUS (NTAPI *NtQueueApcThread_t)(
    HANDLE ThreadHandle,
    PVOID ApcRoutine,
    PVOID ApcArgument1,
    PVOID ApcArgument2,
    PVOID ApcArgument3
);

#endif
