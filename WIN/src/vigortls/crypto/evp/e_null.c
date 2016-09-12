/*
 * Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/objects.h>

static int null_init_key(EVP_CIPHER_CTX *ctx, const uint8_t *key,
                         const uint8_t *iv, int enc);
static int null_cipher(EVP_CIPHER_CTX *ctx, uint8_t *out,
                       const uint8_t *in, size_t inl);
static const EVP_CIPHER n_cipher = {
    .nid = NID_undef,
    .block_size = 1,
    .init = null_init_key,
    .do_cipher = null_cipher,
};

const EVP_CIPHER *EVP_enc_null(void)
{
    return (&n_cipher);
}

static int null_init_key(EVP_CIPHER_CTX *ctx, const uint8_t *key,
                         const uint8_t *iv, int enc)
{
    return 1;
}

static int null_cipher(EVP_CIPHER_CTX *ctx, uint8_t *out,
                       const uint8_t *in, size_t inl)
{
    if (in != out)
        memcpy((char *)out, (const char *)in, inl);
    return 1;
}
