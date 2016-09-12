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

#include <assert.h>

#include <openssl/opensslconf.h>
#include <openssl/camellia.h>
#include <openssl/modes.h>

/* CBC Mode */

#if defined(OPENSSL_NO_ASM) || \
    (!defined(VIGORTLS_X86_64) && !defined(VIGORTLS_X86))

void Camellia_cbc_encrypt(const uint8_t *in, uint8_t *out, size_t len,
                          const CAMELLIA_KEY *key, uint8_t *ivec, const int enc)
{

    if (enc == CAMELLIA_ENCRYPT)
        CRYPTO_cbc128_encrypt(in, out, len, key, ivec, (block128_f)Camellia_encrypt);
    else /* enc == CAMELLIA_DECRYPT */
        CRYPTO_cbc128_decrypt(in, out, len, key, ivec, (block128_f)Camellia_decrypt);
}

#else

void asm_Camellia_cbc_encrypt(const uint8_t *in, uint8_t *out, size_t len,
                              const CAMELLIA_KEY *key, uint8_t *ivec,
                              const int enc);
void Camellia_cbc_encrypt(const uint8_t *in, uint8_t *out, size_t len,
                          const CAMELLIA_KEY *key, uint8_t *ivec, const int enc)
{
    asm_Camellia_cbc_encrypt(in, out, len, key, ivec, enc);
}

#endif /* OPENSSL_NO_ASM || (!VIGORTLS_X86_64 && !VIGORTLS_X86) */

/* CFB Mode */

/* The input and output encrypted as though 128bit cfb mode is being
 * used.  The extra state information to record how much of the
 * 128bit block we have used is contained in *num;
 */

void Camellia_cfb128_encrypt(const uint8_t *in, uint8_t *out,
                             size_t length, const CAMELLIA_KEY *key,
                             uint8_t *ivec, int *num, const int enc)
{

    CRYPTO_cfb128_encrypt(in, out, length, key, ivec, num, enc, (block128_f)Camellia_encrypt);
}

/* N.B. This expects the input to be packed, MSB first */
void Camellia_cfb1_encrypt(const uint8_t *in, uint8_t *out,
                           size_t length, const CAMELLIA_KEY *key,
                           uint8_t *ivec, int *num, const int enc)
{
    CRYPTO_cfb128_1_encrypt(in, out, length, key, ivec, num, enc, (block128_f)Camellia_encrypt);
}

void Camellia_cfb8_encrypt(const uint8_t *in, uint8_t *out,
                           size_t length, const CAMELLIA_KEY *key,
                           uint8_t *ivec, int *num, const int enc)
{
    CRYPTO_cfb128_8_encrypt(in, out, length, key, ivec, num, enc, (block128_f)Camellia_encrypt);
}

/* CTR Mode */

void Camellia_ctr128_encrypt(const uint8_t *in, uint8_t *out,
                             size_t length, const CAMELLIA_KEY *key,
                             uint8_t ivec[CAMELLIA_BLOCK_SIZE],
                             uint8_t ecount_buf[CAMELLIA_BLOCK_SIZE],
                             unsigned int *num)
{

    CRYPTO_ctr128_encrypt(in, out, length, key, ivec, ecount_buf, num, (block128_f)Camellia_encrypt);
}

/* ECB Mode */

void Camellia_ecb_encrypt(const uint8_t *in, uint8_t *out,
                          const CAMELLIA_KEY *key, const int enc)
{

    assert(in && out && key);
    assert((enc == CAMELLIA_ENCRYPT) || (enc == CAMELLIA_DECRYPT));

    if (CAMELLIA_ENCRYPT == enc)
        Camellia_encrypt(in, out, key);
    else /* enc == CAMELLIA_DECRYPT */
        Camellia_decrypt(in, out, key);
}

/* OFB Mode */

/* The input and output encrypted as though 128bit ofb mode is being
 * used.  The extra state information to record how much of the
 * 128bit block we have used is contained in *num;
 */
void Camellia_ofb128_encrypt(const uint8_t *in, uint8_t *out,
                             size_t length, const CAMELLIA_KEY *key,
                             uint8_t *ivec, int *num)
{
    CRYPTO_ofb128_encrypt(in, out, length, key, ivec, num, (block128_f)Camellia_encrypt);
}
