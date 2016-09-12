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
#include <openssl/aes.h>
#include <openssl/modes.h>

/* Modes wrapper for AES */

/* CBC Mode */

#if defined(OPENSSL_NO_ASM) || \
    (!defined(VIGORTLS_X86_64) && !defined(VIGORTLS_X86))
void AES_cbc_encrypt(const uint8_t *in, uint8_t *out, size_t len,
                     const AES_KEY *key, uint8_t *ivec, const int enc)
{
    if (enc == AES_ENCRYPT)
        CRYPTO_cbc128_encrypt(in, out, len, key, ivec, (block128_f)AES_encrypt);
    else /* enc == AES_DECRYPT */
        CRYPTO_cbc128_decrypt(in, out, len, key, ivec, (block128_f)AES_decrypt);
}
#else
void asm_AES_cbc_encrypt(const uint8_t *in, uint8_t *out, size_t len,
                         const AES_KEY *key, uint8_t *ivec, const int enc);
void AES_cbc_encrypt(const uint8_t *in, uint8_t *out, size_t len,
                     const AES_KEY *key, uint8_t *ivec, const int enc)
{
    asm_AES_cbc_encrypt(in, out, len, key, ivec, enc);
}
#endif /* OPENSSL_NO_ASM || (!VIGORTLS_X86_64 && !VIGORTLS_X86) */

/* CFB Mode */

void AES_cfb128_encrypt(const uint8_t *in, uint8_t *out, size_t length,
                        const AES_KEY *key, uint8_t *ivec, int *num, const int enc)
{
    CRYPTO_cfb128_encrypt(in, out, length, key, ivec, num, enc,
                          (block128_f)AES_encrypt);
}

/* N.B. This expects the input to be packed, MSB first */
void AES_cfb1_encrypt(const uint8_t *in, uint8_t *out, size_t length,
                      const AES_KEY *key, uint8_t *ivec, int *num, const int enc)
{
    CRYPTO_cfb128_1_encrypt(in, out, length, key, ivec, num, enc,
                            (block128_f)AES_encrypt);
}

void AES_cfb8_encrypt(const uint8_t *in, uint8_t *out, size_t length,
                      const AES_KEY *key, uint8_t *ivec, int *num, const int enc)
{
    CRYPTO_cfb128_8_encrypt(in, out, length, key, ivec, num, enc,
                            (block128_f)AES_encrypt);
}

/* CTR Mode */

void AES_ctr128_encrypt(const uint8_t *in, uint8_t *out, size_t length,
                        const AES_KEY *key, uint8_t ivec[AES_BLOCK_SIZE],
                        uint8_t ecount_buf[AES_BLOCK_SIZE], unsigned int *num)
{
    CRYPTO_ctr128_encrypt(in, out, length, key, ivec, ecount_buf, num,
                          (block128_f)AES_encrypt);
}

/* ECB Mode */

void AES_ecb_encrypt(const uint8_t *in, uint8_t *out, const AES_KEY *key,
                     const int enc)
{
    assert(in && out && key);
    assert((AES_ENCRYPT == enc) || (AES_DECRYPT == enc));

    if (enc == AES_ENCRYPT)
        AES_encrypt(in, out, key);
    else /* enc == AES_DECRYPT */
        AES_decrypt(in, out, key);
}

/* OFB Mode */

void AES_ofb128_encrypt(const uint8_t *in, uint8_t *out, size_t length,
                        const AES_KEY *key, uint8_t *ivec, int *num)
{
    CRYPTO_ofb128_encrypt(in, out, length, key, ivec, num, (block128_f)AES_encrypt);
}

/* Wrap Mode */

int AES_wrap_key(AES_KEY *key, const uint8_t *iv, uint8_t *out, const uint8_t *in,
                 unsigned int inlen)
{
    return CRYPTO_128_wrap(key, iv, out, in, inlen, (block128_f)AES_encrypt);
}

int AES_unwrap_key(AES_KEY *key, const uint8_t *iv, uint8_t *out, const uint8_t *in,
                   unsigned int inlen)
{
    return CRYPTO_128_unwrap(key, iv, out, in, inlen, (block128_f)AES_decrypt);
}
