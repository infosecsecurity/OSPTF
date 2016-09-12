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

#ifndef VIGORTLS_STDCOMPAT_H
#define VIGORTLS_STDCOMPAT_H

#include <openssl/base.h>

#include <stddef.h>
#include <stdarg.h>

#ifndef HAVE_ASPRINTF
VIGORTLS_EXPORT int asprintf(char **buf, const char *format, ...);
#endif

#ifndef HAVE_VASPRINTF
VIGORTLS_EXPORT int vasprintf(char **buf, const char *format, va_list args);
#endif

#ifndef HAVE_REALLOCARRAY
VIGORTLS_EXPORT void *reallocarray(void *ptr, size_t newmem, size_t size);
#endif

#ifndef HAVE_SNPRINTF
VIGORTLS_EXPORT int snprintf(char *buf, size_t n, const char *format, ...);
#endif

#ifndef HAVE_STRNDUP
VIGORTLS_EXPORT char *strndup(const char *buf, size_t size);
#endif

#ifndef HAVE_STRTONUM
VIGORTLS_EXPORT long long strtonum(const char *nptr, long long minval,
                                   long long maxval, const char **stnerr);
#endif

#ifndef HAVE_STRLCPY
VIGORTLS_EXPORT size_t strlcpy(char *dest, const char *src, size_t size);
#endif

#ifndef HAVE_STRLCAT
VIGORTLS_EXPORT size_t strlcat(char *dest, const char *src, size_t size);
#endif

#endif
