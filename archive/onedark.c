#include "onedark.h"

DWORD get_syscall_number(const char *func_name)
{
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll)
        return 0;

    FARPROC addr = GetProcAddress(hNtdll, func_name);
    if (!addr)
        return 0;

    const uint8_t *bytes = (const uint8_t *)addr;

    /* Pattern: 4C 8B D1 B8 XX 00 00 00 (mov r10, rcx ; mov eax, SSN) */
    if (bytes[0] != 0x4C || bytes[1] != 0x8B || bytes[2] != 0xD1)
        return 0;
    if (bytes[3] != 0xB8)
        return 0;

    return (DWORD)bytes[4] | ((DWORD)bytes[5] << 8);
}

LPVOID create_syscall_stub(DWORD syscall_number)
{
    const SIZE_T stub_size = 12;
    LPVOID stub = VirtualAlloc(NULL, stub_size,
                               MEM_COMMIT | MEM_RESERVE,
                               PAGE_EXECUTE_READWRITE);
    if (!stub)
        return NULL;

    uint8_t *p = (uint8_t *)stub;

    /* mov r10, rcx */
    p[0] = 0x4C;
    p[1] = 0x8B;
    p[2] = 0xD1;

    /* mov eax, syscall_number */
    p[3] = 0xB8;
    p[4] = (uint8_t)(syscall_number & 0xFF);
    p[5] = (uint8_t)((syscall_number >> 8) & 0xFF);
    p[6] = 0x00;
    p[7] = 0x00;

    /* syscall */
    p[8] = 0x0F;
    p[9] = 0x05;

    /* ret */
    p[10] = 0xC3;

    return stub;
}
