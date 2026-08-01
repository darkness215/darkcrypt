/*
 * peb.c — PEB walk for ntdll base resolution and export lookup by hash
 *
 * Eliminates GetModuleHandleA and GetProcAddress calls.
 * Walks the PEB → Ldr → InMemoryOrderModuleList to find ntdll.dll,
 * then parses its PE export directory to resolve functions by hash.
 */

#include "peb.h"
#include "obfuscation.h"

/* ---- DJB2 hash for function name resolution ---- */
static DWORD djb2_hash(const char *str)
{
    DWORD hash = 5381;
    while (*str)
        hash = ((hash << 5) + hash) + (DWORD)(unsigned char)*str++;
    return hash;
}

/* Public wrapper so external callers can hash dynamic strings. */
DWORD djb2_hash_pub(const char *str)
{
    return djb2_hash(str);
}

/* ---- Case-insensitive wide-string compare for module names ---- */
static int wstr_ieq(const wchar_t *a, const wchar_t *b)
{
    while (*a && *b) {
        wchar_t ca = *a, cb = *b;
        if (ca >= L'A' && ca <= L'Z') ca += 32;
        if (cb >= L'A' && cb <= L'Z') cb += 32;
        if (ca != cb) return 0;
        a++; b++;
    }
    return *a == 0 && *b == 0;
}

/* ---- Walk PEB->Ldr->InMemoryOrderModuleList for a module by name ----
 *
 * PEB / PEB_LDR_DATA / LDR_DATA_TABLE_ENTRY layout (Win10/11 x64), as shown
 * by `dt _PEB` / `dt _PEB_LDR_DATA` / `dt _LDR_DATA_TABLE_ENTRY`:
 *
 *   PEB                       +0x18  Ldr  (PPEB_LDR_DATA)
 *   PEB_LDR_DATA              +0x20  InMemoryOrderModuleList (LIST_ENTRY head)
 *   LDR_DATA_TABLE_ENTRY      +0x18  DllBase
 *                             +0x58  BaseDllName (UNICODE_STRING)
 *
 * The InMemoryOrderModuleList Flink points at the InMemoryOrderLinks field
 * embedded inside each LDR_DATA_TABLE_ENTRY; in this loader's model `curr`
 * is treated as the entry base, so DllBase is reached at entry+0x18 and
 * BaseDllName at entry+0x58. The walk is reusable for any loaded module.
 */
HMODULE peb_get_module(const wchar_t *name)
{
    /* On x64, PEB is at gs:[0x60] */
    BYTE *peb = (BYTE *)__readgsqword(0x60);
    if (!peb) return NULL;

    /* PEB.Ldr is a pointer to PEB_LDR_DATA (PEB +0x18) */
    BYTE *ldr = *(BYTE **)(peb + 0x18);
    if (!ldr) return NULL;

    /* InMemoryOrderModuleList is a LIST_ENTRY at PEB_LDR_DATA +0x20 */
    LIST_ENTRY *head = (LIST_ENTRY *)(ldr + 0x20);
    LIST_ENTRY *curr = head->Flink;

    while (curr && curr != head) {
        BYTE *entry = (BYTE *)curr;
        /* Dump candidate module bases + names at both common offsets so we
         * can see on this Win11 build which pair actually resolves. */
        HMODULE base18 = *(HMODULE *)(entry + 0x18);
        HMODULE base20 = *(HMODULE *)(entry + 0x20);
        HMODULE base30 = *(HMODULE *)(entry + 0x30);
        UNICODE_STRING *n48 = (UNICODE_STRING *)(entry + 0x48);
        UNICODE_STRING *n58 = (UNICODE_STRING *)(entry + 0x58);

        DBG_PRINTF("[peb] entry=%p b18=%p b20=%p b30=%p n48='%ls' n58='%ls'\n",
                   entry, base18, base20, base30,
                   (n48 && n48->Buffer) ? n48->Buffer : L"?",
                   (n58 && n58->Buffer) ? n58->Buffer : L"?");

        /* Win11 24H2 layout confirmed by trace: DllBase +0x20, BaseDllName +0x48. */
        UNICODE_STRING *base_name = n48;
        HMODULE base = base20;

        if (base_name && base_name->Buffer && base_name->Length > 0) {
            if (wstr_ieq(base_name->Buffer, name))
                return base;
        }

        curr = curr->Flink;
    }

    return NULL;
}

/* ---- Walk to the Nth entry of InMemoryOrderModuleList by position ---- *
 *
 * `index` is 0-based: 0 = the executable image, 1 = ntdll.dll, 2 = kernel32.dll
 * on Windows 10/11 x64. Returns the DllBase of the entry at that index, or
 * NULL if the list is shorter than expected (with bounds safety against the
 * circular list head). */
static HMODULE peb_get_module_by_index(int index)
{
    BYTE *peb = (BYTE *)__readgsqword(0x60);
    if (!peb) return NULL;

    BYTE *ldr = *(BYTE **)(peb + 0x18);
    if (!ldr) return NULL;

    LIST_ENTRY *head = (LIST_ENTRY *)(ldr + 0x20);
    LIST_ENTRY *curr = head->Flink;
    int i = 0;

    while (curr && curr != head) {
        BYTE *entry = (BYTE *)curr;
        HMODULE b18 = *(HMODULE *)(entry + 0x18);
        HMODULE b20 = *(HMODULE *)(entry + 0x20);
        HMODULE b30 = *(HMODULE *)(entry + 0x30);
        DBG_PRINTF("[peb-idx] i=%d entry=%p b18=%p b20=%p b30=%p\n",
                   i, entry, b18, b20, b30);
        if (i == index) {
            return *(HMODULE *)(entry + 0x20);   /* Win11 24H2 layout */
        }
        i++;
        curr = curr->Flink;
    }
    return NULL;
}

/* V1: multi-byte rolling-key XOR wide "ntdll.dll" (UTF-16LE) — no plaintext leak. */
static const uint8_t enc_key_ntdll[6] = { 0xc3, 0x14, 0x55, 0x3b, 0xfe, 0x63 };
static const uint8_t enc_ntdll_dll[] = {
    0xad, 0x14, 0x21, 0x3b, 0x9a, 0x63, 0xaf, 0x14,
    0x39, 0x3b, 0xd0, 0x63, 0xa7, 0x14, 0x39, 0x3b,
    0x92, 0x63
};
#define NTDLL_NAME_LEN 9  /* chars in "ntdll.dll" */

/* V1: multi-byte rolling-key XOR wide "kernel32.dll" (UTF-16LE). */
static const uint8_t enc_key_kernel32[6] = { 0x0c, 0xa0, 0x18, 0x1e, 0x3a, 0xed };
static const uint8_t enc_kernel32_dll[] = {
    0x67, 0xa0, 0x7d, 0x1e, 0x48, 0xed, 0x62, 0xa0,
    0x7d, 0x1e, 0x56, 0xed, 0x3f, 0xa0, 0x2a, 0x1e,
    0x14, 0xed, 0x68, 0xa0, 0x74, 0x1e, 0x56, 0xed
};
#define KERNEL32_NAME_LEN 12  /* chars in "kernel32.dll" */

/* ---- Resolve ntdll base by load-order position (index 1) ---- *
 *
 * ntdll.dll is reliably the second entry (index 1) of the
 * InMemoryOrderModuleList on Windows 10/11 x64. If the positional walk
 * somehow yields NULL, fall back to a name scan using an XOR-encoded wide
 * string decoded on the stack so no plaintext "ntdll.dll" leaks. */
HMODULE peb_get_ntdll_by_position(void)
{
    HMODULE base = peb_get_module_by_index(1);
    if (base)
        return base;

    /* Fallback: name-based scan with XOR-decoded wide name on the stack. */
    wchar_t buf[NTDLL_NAME_LEN + 1];
    wchar_t *name = xor_dec_w_mb(buf, enc_ntdll_dll, NTDLL_NAME_LEN, enc_key_ntdll, 6);
    HMODULE fb = peb_get_module(name);
    secure_zero(buf, sizeof(buf));
    return fb;
}

/* ---- Get ntdll.dll base address via PEB walk (no API calls) ---- */
HMODULE peb_get_ntdll(void)
{
    return peb_get_ntdll_by_position();
}

/* ---- Resolve kernel32.dll base by position (index 2) ---- *
 *
 * kernel32.dll is the third entry (index 2) on Windows 10/11 x64. Falls back
 * to a name scan with an XOR-decoded wide string if the position walk fails. */
HMODULE peb_get_kernel32(void)
{
    HMODULE pos = peb_get_module_by_index(2);
    DBG_PRINTF("[peb] kernel32 positional(idx2) = %p\n", pos);

    /* Name-based scan with XOR-decoded wide name on the stack.
     * Win11 24H2+ reshuffles InMemoryOrderModuleList, so positional lookup
     * can return a non-kernel32 module; always prefer the name-based scan. */
    wchar_t buf[KERNEL32_NAME_LEN + 1];
    wchar_t *name = xor_dec_w_mb(buf, enc_kernel32_dll, KERNEL32_NAME_LEN, enc_key_kernel32, 6);
    HMODULE fb = peb_get_module(name);
    DBG_PRINTF("[peb] kernel32 name-scan     = %p\n", fb);
    secure_zero(buf, sizeof(buf));
    return fb ? fb : pos;
}

/* ---- Convenience: resolve a kernel32 export by DJB2 hash ---- */
FARPROC peb_resolve_kernel32(DWORD name_hash)
{
    HMODULE k32 = peb_get_kernel32();
    if (!k32) return NULL;
    return peb_find_export(k32, name_hash);
}

/* ---- Find a function address in a module's export table by hash ---- */
FARPROC peb_find_export(HMODULE base, DWORD target_hash)
{
    if (!base) return NULL;

    BYTE *base_addr = (BYTE *)base;

    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)base_addr;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return NULL;

    IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS *)(base_addr + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return NULL;

    IMAGE_EXPORT_DIRECTORY *exports = (IMAGE_EXPORT_DIRECTORY *)
        (base_addr + nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    if (!exports) return NULL;

    DWORD *name_rvas  = (DWORD *)(base_addr + exports->AddressOfNames);
    WORD  *ord_rvas   = (WORD  *)(base_addr + exports->AddressOfNameOrdinals);
    DWORD *func_rvas  = (DWORD *)(base_addr + exports->AddressOfFunctions);

    for (DWORD i = 0; i < exports->NumberOfNames; i++) {
        const char *name = (const char *)(base_addr + name_rvas[i]);
        DWORD hash = djb2_hash(name);
        if (hash == target_hash) {
            DWORD func_rva = func_rvas[ord_rvas[i]];
            return (FARPROC)(base_addr + func_rva);
        }
    }

    return NULL;
}

/* ---- Convenience: find ntdll export by name (uses hash internally) ---- */
FARPROC peb_resolve(const char *func_name)
{
    HMODULE ntdll = peb_get_ntdll();
    if (!ntdll) return NULL;
    DWORD hash = djb2_hash(func_name);
    return peb_find_export(ntdll, hash);
}