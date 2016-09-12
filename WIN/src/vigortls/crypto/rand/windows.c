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

/*
 * We use RtlGenRandom here instead of CryptGenRandom due to 
 * the overhead of having to pull in the whole CryptoAPI. 
 */

#include <openssl/rand.h>

#include <limits.h>
#include <stdlib.h>
#include <windows.h>

#define SystemFunction036 NTAPI SystemFunction036
#include <NTSecAPI.h>
#undef SystemFunction036

void RAND_cleanup(void)
{
    return;
}

int CRYPTO_genrandom(uint8_t *buf, size_t requested)
{
    while (requested > 0) {
        unsigned long output_bytes;
        if (requested < ULONG_MAX) {
            output_bytes = requested;
        }
        if (RtlGenRandom(buf, output_bytes) == FALSE) {
            abort();
            return 0;
        }
        requested -= output_bytes;
        buf += output_bytes;
    }
    return 1;
}
