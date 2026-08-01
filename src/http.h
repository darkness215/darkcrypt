#ifndef HTTP_H
#define HTTP_H

#include <windows.h>
#include <stdint.h>
#include <stddef.h>

BOOL http_download(const char *url, uint8_t **out_data, size_t *out_len);

#endif
