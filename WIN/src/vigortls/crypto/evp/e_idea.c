/*
 * Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/opensslconf.h>

#ifndef OPENSSL_NO_IDEA

#include <stdio.h>

#include <openssl/evp.h>
#include <openssl/objects.h>
#include "evp_locl.h"
#include <openssl/idea.h>

static int idea_init_key(EVP_CIPHER_CTX *ctx, const uint8_t *key,
                         const uint8_t *iv, int enc);

/* NB idea_ecb_encrypt doesn't take an 'encrypt' argument so we treat it as a special
 * case
 */

static int idea_ecb_cipher(EVP_CIPHER_CTX *ctx, uint8_t *out,
                           const uint8_t *in, size_t inl)
{
    BLOCK_CIPHER_ecb_loop()
        idea_ecb_encrypt(in + i, out + i, ctx->cipher_data);
    return 1;
}

/* Can't use IMPLEMENT_BLOCK_CIPHER because idea_ecb_encrypt is different */

typedef struct
    {
    IDEA_KEY_SCHEDULE ks;
} EVP_IDEA_KEY;

BLOCK_CIPHER_func_cbc(idea, idea, EVP_IDEA_KEY, ks)
    BLOCK_CIPHER_func_ofb(idea, idea, 64, EVP_IDEA_KEY, ks)
        BLOCK_CIPHER_func_cfb(idea, idea, 64, EVP_IDEA_KEY, ks)

            BLOCK_CIPHER_defs(idea, IDEA_KEY_SCHEDULE, NID_idea, 8, 16, 8, 64,
                              0, idea_init_key, NULL,
                              EVP_CIPHER_set_asn1_iv, EVP_CIPHER_get_asn1_iv, NULL)

                static int idea_init_key(EVP_CIPHER_CTX *ctx, const uint8_t *key,
                                         const uint8_t *iv, int enc)
{
    if (!enc) {
        if (EVP_CIPHER_CTX_mode(ctx) == EVP_CIPH_OFB_MODE)
            enc = 1;
        else if (EVP_CIPHER_CTX_mode(ctx) == EVP_CIPH_CFB_MODE)
            enc = 1;
    }
    if (enc)
        idea_set_encrypt_key(key, ctx->cipher_data);
    else {
        IDEA_KEY_SCHEDULE tmp;

        idea_set_encrypt_key(key, &tmp);
        idea_set_decrypt_key(&tmp, ctx->cipher_data);
        vigortls_zeroize((uint8_t *)&tmp,
                         sizeof(IDEA_KEY_SCHEDULE));
    }
    return 1;
}

#endif
