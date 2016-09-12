/*
 * Copyright (c) 2014 - 2015, Kurt Cancemi (kurt@x64architecture.com)
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

#if defined(_MSC_VER)
# define WIN32_LEAN_AND_MEAN
# include <windows.h>
#endif
#include <string.h>
#include <openssl/crypto.h>

void vigortls_zeroize(void *ptr, size_t len)
{
    if (ptr == NULL)
        return;
#if defined(_MSC_VER)
    SecureZeroMemory(ptr, len);
#else
    memset(ptr, 0, len);

/*
 * Try to prevent compiler optimizations
 */
    __asm__ volatile(
        ""
        :
        : "r"(ptr)
        : "memory"
    );
#endif
}

void OPENSSL_cleanse(void *ptr, size_t len)
{
    vigortls_zeroize(ptr, len);
}
