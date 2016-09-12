/*
 * Copyright (c) 2014 - 2016, Kurt Cancemi (kurt@x64architecture.com)
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
 * Copyright 2014 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/opensslconf.h>

#ifndef OPENSSL_NO_CHACHA

#include <string.h>

#include <openssl/chacha.h>
#include <openssl/evp.h>
#include <openssl/objects.h>

#include "evp_locl.h"

#define CHACHA_BLK_SIZE 64

typedef struct {
    uint8_t buf[CHACHA_BLK_SIZE];
    uint32_t key[8];
    uint32_t counter[4];
    uint32_t partial_len;
    char pad[4]; /* Ensures sizeof(EVP_CHACHA_CTX) % 8 == 0 */
} EVP_CHACHA_CTX;

void ChaCha20_ctr32(uint8_t *out, const uint8_t *in,
                    size_t len, const uint32_t key[8],
                    const uint32_t counter[4]);


#define U8TO32_LITTLE(p)         \
    (((uint32_t)(p)[0]      )  | \
     ((uint32_t)(p)[1] <<  8)  | \
     ((uint32_t)(p)[2] << 16)  | \
     ((uint32_t)(p)[3] << 24))

static int chacha_init(EVP_CIPHER_CTX *ctx, const uint8_t *key,
                       const uint8_t *iv, int enc)
{
    EVP_CHACHA_CTX *chacha_ctx = (EVP_CHACHA_CTX *)ctx->cipher_data;

    if (key) {
        chacha_ctx->key[0] = U8TO32_LITTLE(key + 0);
        chacha_ctx->key[1] = U8TO32_LITTLE(key + 4);
        chacha_ctx->key[2] = U8TO32_LITTLE(key + 8);
        chacha_ctx->key[3] = U8TO32_LITTLE(key + 12);
        chacha_ctx->key[4] = U8TO32_LITTLE(key + 16);
        chacha_ctx->key[5] = U8TO32_LITTLE(key + 20);
        chacha_ctx->key[6] = U8TO32_LITTLE(key + 24);
        chacha_ctx->key[7] = U8TO32_LITTLE(key + 28);
    }

    if (iv) {
        chacha_ctx->counter[0] = U8TO32_LITTLE(iv + 0);
        chacha_ctx->counter[1] = U8TO32_LITTLE(iv + 4);
        chacha_ctx->counter[2] = U8TO32_LITTLE(iv + 8);
        chacha_ctx->counter[3] = U8TO32_LITTLE(iv + 12);
    }

    return 1;
}

static int chacha_cipher(EVP_CIPHER_CTX *ctx, uint8_t *out, const uint8_t *in,
                         size_t len)
{
    EVP_CHACHA_CTX *chacha_ctx = (EVP_CHACHA_CTX *)ctx->cipher_data;
    uint32_t n, rem, ctr32;

    if ((n = chacha_ctx->partial_len)) {
        while (len && n < CHACHA_BLK_SIZE) {
            *out++ = *in++ ^ chacha_ctx->buf[n++];
            len--;
        }
        chacha_ctx->partial_len = n;

        if (len == 0)
            return 1;

        if (n == CHACHA_BLK_SIZE) {
            chacha_ctx->partial_len = 0;
            chacha_ctx->counter[0]++;
            if (chacha_ctx->counter[0] == 0)
                chacha_ctx->counter[1]++;
        }
    }

    rem = (uint32_t)(len % CHACHA_BLK_SIZE);
    len -= rem;
    ctr32 = chacha_ctx->counter[0];
    while (len >= CHACHA_BLK_SIZE) {
        size_t blocks = len / CHACHA_BLK_SIZE;
        /*
         * 1<<28 is just a not-so-small yet not-so-large number...
         * Below condition is practically never met, but it has to
         * be checked for code correctness.
         */
        if (sizeof(size_t) > sizeof(uint32_t) && blocks > (1U << 28))
            blocks = (1U << 28);

        /*
         * As ChaCha20_ctr32 operates on 32-bit counter, caller
         * has to handle overflow. 'if' below detects the
         * overflow, which is then handled by limiting the
         * amount of blocks to the exact overflow point...
         */
        ctr32 += (uint32_t)blocks;
        if (ctr32 < blocks) {
            blocks -= ctr32;
            ctr32 = 0;
        }
        blocks *= CHACHA_BLK_SIZE;
        ChaCha20_ctr32(out, in, blocks, chacha_ctx->key, chacha_ctx->counter);
        len -= blocks;
        in += blocks;
        out += blocks;

        chacha_ctx->counter[0] = ctr32;
        if (ctr32 == 0)
            chacha_ctx->counter[1]++;
    }

    if (rem) {
        memset(chacha_ctx->buf, 0, sizeof(chacha_ctx->buf));
        ChaCha20_ctr32(chacha_ctx->buf, chacha_ctx->buf, CHACHA_BLK_SIZE,
                       chacha_ctx->key, chacha_ctx->counter);
        for (n = 0; n < rem; n++)
            out[n] = in[n] ^ chacha_ctx->buf[n];
        chacha_ctx->partial_len = rem;
    }

    return 1;
}

static const EVP_CIPHER chacha20_cipher = {
    .nid = NID_chacha20,
    .block_size = 1,
    .key_len = 32,
    .iv_len = 12,
    .flags = EVP_CIPH_STREAM_CIPHER,
    .init = chacha_init,
    .do_cipher = chacha_cipher,
    .ctx_size = sizeof(EVP_CHACHA_CTX)
};

const EVP_CIPHER *EVP_chacha20(void)
{
    return (&chacha20_cipher);
}

#endif
