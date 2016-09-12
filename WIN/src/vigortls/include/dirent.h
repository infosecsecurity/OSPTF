/*
 * Copyright (c) 2015, Kurt Cancemi (kurt@x64architecture.com)
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#ifndef _WIN32
#include_next <dirent.h>
#else

#ifndef VIGORTLS_DIRENT_H
#define VIGORTLS_DIRENT_H

#if !defined(_68K_) && !defined(_MPPC_) && !defined(_X86_) && !defined(_IA64_) && !defined(_AMD64_) && defined(_M_IX86)
#define _X86_
#endif
#if !defined(_68K_) && !defined(_MPPC_) && !defined(_X86_) && !defined(_IA64_) && !defined(_AMD64_) && defined(_M_AMD64)
#define _AMD64_
#endif

#include <stdlib.h>
#include <windef.h>
#include <winbase.h>
#include <wchar.h>

#include <openssl/base.h>

struct dirent {
    unsigned int d_ino;
    char d_name[_MAX_PATH];
};

typedef struct {
    HANDLE h;
    WIN32_FIND_DATAA *fd;
    BOOL has_next;
    struct dirent entry;
} DIR;

VIGORTLS_EXPORT DIR *opendir(const char *name);
VIGORTLS_EXPORT struct dirent *readdir(DIR *dir);
VIGORTLS_EXPORT int closedir(DIR *dir);

#endif
#endif
