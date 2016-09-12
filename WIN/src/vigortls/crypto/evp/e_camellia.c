/*
 * Copyright 2006-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/opensslconf.h>


#include <string.h>
#include <assert.h>

#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/camellia.h>

#include "evp_locl.h"

static int camellia_init_key(EVP_CIPHER_CTX *ctx, const uint8_t *key,
                             const uint8_t *iv, int enc);

/* Camellia subkey Structure */
typedef struct
    {
    CAMELLIA_KEY ks;
} EVP_CAMELLIA_KEY;

/* Attribute operation for Camellia */
#define data(ctx) EVP_C_DATA(EVP_CAMELLIA_KEY, ctx)

IMPLEMENT_BLOCK_CIPHER(camellia_128, ks, Camellia, EVP_CAMELLIA_KEY,
                       NID_camellia_128, 16, 16, 16, 128,
                       0, camellia_init_key, NULL,
                       EVP_CIPHER_set_asn1_iv,
                       EVP_CIPHER_get_asn1_iv,
                       NULL)
IMPLEMENT_BLOCK_CIPHER(camellia_192, ks, Camellia, EVP_CAMELLIA_KEY,
                       NID_camellia_192, 16, 24, 16, 128,
                       0, camellia_init_key, NULL,
                       EVP_CIPHER_set_asn1_iv,
                       EVP_CIPHER_get_asn1_iv,
                       NULL)
IMPLEMENT_BLOCK_CIPHER(camellia_256, ks, Camellia, EVP_CAMELLIA_KEY,
                       NID_camellia_256, 16, 32, 16, 128,
                       0, camellia_init_key, NULL,
                       EVP_CIPHER_set_asn1_iv,
                       EVP_CIPHER_get_asn1_iv,
                       NULL)

#define IMPLEMENT_CAMELLIA_CFBR(ksize, cbits) IMPLEMENT_CFBR(camellia, Camellia, EVP_CAMELLIA_KEY, ks, ksize, cbits, 16)

IMPLEMENT_CAMELLIA_CFBR(128, 1)
IMPLEMENT_CAMELLIA_CFBR(192, 1)
IMPLEMENT_CAMELLIA_CFBR(256, 1)

IMPLEMENT_CAMELLIA_CFBR(128, 8)
IMPLEMENT_CAMELLIA_CFBR(192, 8)
IMPLEMENT_CAMELLIA_CFBR(256, 8)

/* The subkey for Camellia is generated. */
static int camellia_init_key(EVP_CIPHER_CTX *ctx, const uint8_t *key,
                             const uint8_t *iv, int enc)
{
    int ret;

    ret = Camellia_set_key(key, ctx->key_len * 8, ctx->cipher_data);

    if (ret < 0) {
        EVPerr(EVP_F_CAMELLIA_INIT_KEY, EVP_R_CAMELLIA_KEY_SETUP_FAILED);
        return 0;
    }

    return 1;
}

