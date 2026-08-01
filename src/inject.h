#ifndef INJECT_H
#define INJECT_H

#include <windows.h>
#include <stdint.h>
#include <stddef.h>

BOOL inject_shellcode(const uint8_t *shellcode, size_t len);

#endif
