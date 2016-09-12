/*
 * Copyright (c) 2016, Kurt Cancemi (kurt@x64architecture.com)
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

#include <stdarg.h>
#include <stdint.h>

#include <openssl/crypto.h>
#include <openssl/opensslconf.h>

#include "cryptlib.h"

#if defined(VIGORTLS_X86) || defined(VIGORTLS_X86_64)

/*
 * This value must be initialized to zero in order to work around a 
 * bug in libtool or the linker on OS X.
 *
 * If not initialized or linked with the "-fno-common" flag the value 
 * becomes a "common symbol". In a library, linking on OS X will fail
 * to resolve common symbols. By initializing the value to zero, it
 * becomes a "data symbol", which isn't affected.
 */
unsigned int OPENSSL_ia32cap_P[4] = { 0 };
#endif

static void OPENSSL_showfatal(const char *fmta, ...)
{
    va_list ap;

    va_start(ap, fmta);
    vfprintf(stderr, fmta, ap);
    va_end(ap);
}

void OpenSSLDie(const char *file, int line, const char *assertion)
{
    OPENSSL_showfatal(
        "%s(%d): OpenSSL internal error, assertion failed: %s\n",
        file, line, assertion);
    abort();
}

const char *SSLeay_version(int unused)
{
    return "VigorTLS";
}

unsigned long SSLeay(void)
{
    return OPENSSL_VERSION_NUMBER;
}

/*
 * volatile uint8_t * pointers are there because
 * 1. Accessing a variable declared volatile via a pointer
 *    that lacks a volatile qualifier causes undefined behavior.
 * 2. When the variable itself is not volatile the compiler is
 *    not required to keep all those reads and can convert
 *    this into canonical memcmp() which doesn't read the whole block.
 * Pointers to volatile resolve the first problem fully. The second
 * problem cannot be resolved in any Standard-compliant way but this
 * works the problem around. Compilers typically react to
 * pointers to volatile by preserving the reads and writes through them.
 * The latter is not required by the Standard if the memory pointed to
 * is not volatile.
 * Pointers themselves are volatile in the function signature to work
 * around a subtle bug in gcc 4.6+ which causes writes through
 * pointers to volatile to not be emitted in some rare,
 * never needed in real life, pieces of code.
 */
int CRYPTO_memcmp(const volatile void * volatile in_a,
                  const volatile void * volatile in_b,
                  size_t len)
{
    size_t i;
    const volatile uint8_t *a = in_a;
    const volatile uint8_t *b = in_b;
    uint8_t x = 0;

    for (i = 0; i < len; i++)
        x |= a[i] ^ b[i];

    return x;
}
