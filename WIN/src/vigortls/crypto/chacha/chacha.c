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

#include <openssl/opensslconf.h>

#ifndef OPENSSL_NO_CHACHA

#include <openssl/chacha.h>

#define U8TO32_LITTLE(p)         \
    (((uint32_t)(p)[0]      )  | \
     ((uint32_t)(p)[1] <<  8)  | \
     ((uint32_t)(p)[2] << 16)  | \
     ((uint32_t)(p)[3] << 24))

/*
 * ChaCha20_ctr32 encrypts/decrypts |len| bytes from |in| with the given
 * key and nonce and writes the result to |out|, which may be equal to
 * |in|. The |key| is not 32 bytes of verbatim key material though, the
 * key material is held in 8 32-bit elements in host byte order. The same
 * approach applies to the nonce, the |counter| argument is a pointer to
 * a concatenated nonce and counter values collected into 4 32-bit elements.
 * This method of collecting elements was used because passing crypto
 * material collected into 32-bit elements as opposed to passing verbatim
 * byte vectors is more efficient in multi-call scenarios.
 */
void ChaCha20_ctr32(uint8_t *out, const uint8_t *in,
                    size_t len, const uint32_t key[8],
                    const uint32_t counter[4]);

void CRYPTO_chacha_20(uint8_t *out, const uint8_t *in, size_t inlen,
                      const uint8_t key[32], const uint8_t nonce[12],
                      uint32_t counter)
{
    uint32_t k[8], ctr[4];

    k[0] = U8TO32_LITTLE(key + 0);
    k[1] = U8TO32_LITTLE(key + 4);
    k[2] = U8TO32_LITTLE(key + 8);
    k[3] = U8TO32_LITTLE(key + 12);
    k[4] = U8TO32_LITTLE(key + 16);
    k[5] = U8TO32_LITTLE(key + 20);
    k[6] = U8TO32_LITTLE(key + 24);
    k[7] = U8TO32_LITTLE(key + 28);

    ctr[0] = counter;
    ctr[1] = U8TO32_LITTLE(nonce + 0);
    ctr[2] = U8TO32_LITTLE(nonce + 4);
    ctr[3] = U8TO32_LITTLE(nonce + 8);

    ChaCha20_ctr32(out, in, inlen, k, ctr);
}

#endif /* !OPENSSL_NO_CHACHA */
