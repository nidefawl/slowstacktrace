// (c) Michael Hept 2022. See LICENSE.txt
#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>

void get_thread_stacktrace(char *out_buf, size_t out_buf_size);

#ifdef __cplusplus
}
#endif
