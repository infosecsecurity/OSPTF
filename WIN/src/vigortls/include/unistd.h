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

#if !defined(_WIN32)
#include_next <unistd.h>
#else

#ifndef VIGORTLS_UNISTD_H
#define VIGORTLS_UNISTD_H

#include <io.h>
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#define sleep(x) Sleep(1000 * x)
#define getpid() GetCurrentThreadId()

#define R_OK 4
#define X_OK 3
#define W_OK 2
#define F_OK 0

int issetugid(void);

#endif /* VIGORTLS_UNISTD_H */

#endif /* !defined(_WIN32) */
