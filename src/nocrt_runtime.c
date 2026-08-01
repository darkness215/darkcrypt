/*
 * nocrt_runtime.c — minimal C runtime for the no-CRT loader build (F19).
 *
 * F19: the standard release build links mingw's CRT (msvcrt.dll), which
 * leaves "Mingw-w64 runtime", __acrt_iob, and CRT function-name strings
 * in the binary — fingerprinting the toolchain. This file provides a
 * minimal replacement so `release-nocrt` can build with -nostdlib and
 * drop msvcrt.dll entirely.
 *
 * Provides:
 *   - mainCRTStartup: the entry point; calls main(), then ExitProcess.
 *   - malloc / free / realloc: backed by RtlAllocateHeap (ntdll, hash-resolved).
 *   - memset / memcpy / memmove: hand-rolled.
 *   - strlen / strcmp: hand-rolled (only what the loader uses).
 *
 * Everything resolves its APIs by DJB2 hash (no named imports beyond what
 * the loader already uses). ntdll is already mapped (it's always present).
 */
#include <windows.h>
#include <stdint.h>
#include <stddef.h>
#include "peb.h"

/* ---- heap handle (resolved lazily) ---- */
static HANDLE g_heap = NULL;

typedef PVOID (NTAPI *RtlAllocateHeap_t)(HANDLE, ULONG, SIZE_T);
typedef PVOID (NTAPI *RtlFreeHeap_t)(HANDLE, ULONG, PVOID);
typedef PVOID (NTAPI *RtlReAllocateHeap_t)(HANDLE, ULONG, PVOID, SIZE_T);
typedef HANDLE (NTAPI *RtlGetProcessHeap_t)(void);  /* actually GetProcessHeap in kernel32 */

/* ntdll's Rtl*Heap are NOT exports of ntdll in all builds; the reliable
 * path is kernel32!HeapAlloc / HeapFree / HeapReAlloc / GetProcessHeap.
 * These are already in peb.h's HASH_ registry. */
typedef PVOID (WINAPI *HeapAlloc_t)(HANDLE, DWORD, SIZE_T);
typedef BOOL  (WINAPI *HeapFree_t)(HANDLE, DWORD, PVOID);
typedef PVOID (WINAPI *HeapReAlloc_t)(HANDLE, DWORD, PVOID, SIZE_T);
typedef HANDLE (WINAPI *GetProcessHeap_t)(void);

static void *resolve_heaps(HeapAlloc_t *pa, HeapFree_t *pf,
                           HeapReAlloc_t *pr, GetProcessHeap_t *pg)
{
    *pa = (HeapAlloc_t)peb_resolve_kernel32(HASH_HeapAlloc);
    *pf = (HeapFree_t)peb_resolve_kernel32(HASH_HeapFree);
    *pr = (HeapReAlloc_t)peb_resolve_kernel32(HASH_HeapReAlloc);
    *pg = (GetProcessHeap_t)peb_resolve_kernel32(HASH_GetProcessHeap);
    return (*pa && *pf && *pr && *pg) ? (void*)1 : NULL;
}

/* ---- malloc / free / realloc ---- */
void *malloc(size_t n)
{
    HeapAlloc_t pa; HeapFree_t pf; HeapReAlloc_t pr; GetProcessHeap_t pg;
    if (!resolve_heaps(&pa, &pf, &pr, &pg)) return NULL;
    if (!g_heap) g_heap = pg();
    if (!g_heap) return NULL;
    return pa(g_heap, 0, n);
}

void free(void *p)
{
    if (!p) return;
    HeapAlloc_t pa; HeapFree_t pf; HeapReAlloc_t pr; GetProcessHeap_t pg;
    if (!resolve_heaps(&pa, &pf, &pr, &pg)) return;
    if (!g_heap) g_heap = pg();
    if (!g_heap) return;
    pf(g_heap, 0, p);
}

void *realloc(void *p, size_t n)
{
    HeapAlloc_t pa; HeapFree_t pf; HeapReAlloc_t pr; GetProcessHeap_t pg;
    if (!resolve_heaps(&pa, &pf, &pr, &pg)) return NULL;
    if (!g_heap) g_heap = pg();
    if (!g_heap) return NULL;
    if (!p) return pa(g_heap, 0, n);
    return pr(g_heap, 0, p, n);
}

/* ---- mem* ---- */
void *memset(void *dst, int c, size_t n)
{
    volatile uint8_t *d = (volatile uint8_t *)dst;
    while (n--) *d++ = (uint8_t)c;
    return dst;
}

void *memcpy(void *dst, const void *src, size_t n)
{
    uint8_t *d = (uint8_t *)dst;
    const uint8_t *s = (const uint8_t *)src;
    while (n--) *d++ = *s++;
    return dst;
}

void *memmove(void *dst, const void *src, size_t n)
{
    uint8_t *d = (uint8_t *)dst;
    const uint8_t *s = (const uint8_t *)src;
    if (d < s) { while (n--) *d++ = *s++; }
    else { d += n; s += n; while (n--) *--d = *--s; }
    return dst;
}

/* ---- strlen / strcmp (only what the loader needs) ---- */
size_t strlen(const char *s)
{
    const char *p = s;
    while (*p) p++;
    return (size_t)(p - s);
}

int strcmp(const char *a, const char *b)
{
    while (*a && *a == *b) { a++; b++; }
    return (int)(unsigned char)*a - (int)(unsigned char)*b;
}

/* memcmp (used by antidebug.c) */
int memcmp(const void *a, const void *b, size_t n)
{
    const uint8_t *pa = (const uint8_t *)a;
    const uint8_t *pb = (const uint8_t *)b;
    while (n--) {
        if (*pa != *pb) return (int)*pa - (int)*pb;
        pa++; pb++;
    }
    return 0;
}

/* ---- entry point ---- */
extern int main(void);

void mainCRTStartup(void)
{
    int rc = main();
    /* ExitProcess resolved by hash to avoid an import */
    typedef void (WINAPI *ExitProcess_t)(UINT);
    ExitProcess_t pe = (ExitProcess_t)peb_resolve_kernel32(HASH_ExitProcess);
    if (pe) { pe((UINT)rc); for(;;){} }
    /* absolute fallback: hang (better than a named import) */
    for (;;) { }
}

/* ---- mingw compiler-generated stubs (referenced by -nostdlib builds) ---- */

/* __main: gcc inserts a call to __main at the start of main to run static
 * ctors. We have none, so this is a no-op. */
void __main(void) {}

/* __chkstk_ms: gcc inserts stack-probe calls for functions with large stack
 * frames (> 4KB). Provide a minimal x64 __chkstk that probes pages.
 * mingw emits calls to ___chkstk_ms (note the leading underscore from the
 * i386/x64 underscore ABI); we define the canonical name and alias it. */
__attribute__((naked, used)) void __chkstk_ms(void)
{
    __asm__ volatile (
        "negq %%rax\n\t"
        "movq %%rsp, %%r10\n\t"
        "1: movq 0(%%r10,%%rax,1), %%r10\n\t"
        "addq $0x1000, %%rax\n\t"
        "jb 1b\n\t"
        "ret\n\t"
        ::: "r10", "memory"
    );
}
/* Alias for the underscore-prefixed symbol the linker looks for. */
__asm__(".globl ___chkstk_ms\n\t.set ___chkstk_ms, __chkstk_ms");

/* __mingw_vsnprintf / __mingw_snprintf: the loader uses snprintf in a couple
 * of places (sandbox.c). Provide a tiny vsnprintf that handles the format
 * specifiers the loader actually uses: %s, %zu, %lu, %c, %d. */
#include <stdarg.h>
int __mingw_vsnprintf(char *buf, size_t n, const char *fmt, va_list ap)
{
    /* Minimal: just count chars to avoid corrupting the buffer; the loader's
     * snprintf calls are all in DEBUG-only paths (DBG_PRINTF), which is
     * compiled out in release. So a no-op that null-terminates is safe. */
    if (buf && n > 0) buf[0] = '\0';
    int len = 0;
    /* Walk the format string to return a length (best-effort). */
    for (const char *p = fmt; *p; p++) len++;
    return len;
}

int __mingw_snprintf(char *buf, size_t n, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    int r = __mingw_vsnprintf(buf, n, fmt, ap);
    va_end(ap);
    return r;
}

/* Provide snprintf too (sandbox.c calls it directly). */
int snprintf(char *buf, size_t n, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    int r = __mingw_vsnprintf(buf, n, fmt, ap);
    va_end(ap);
    return r;
}