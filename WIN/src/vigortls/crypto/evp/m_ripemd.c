/*
 * Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OPENSSL_NO_RIPEMD

#include <openssl/ripemd.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/x509.h>
#include <openssl/rsa.h>
#include "evp_locl.h"

static int init(EVP_MD_CTX *ctx)
{
    return RIPEMD160_Init(ctx->md_data);
}

static int update(EVP_MD_CTX *ctx, const void *data, size_t count)
{
    return RIPEMD160_Update(ctx->md_data, data, count);
}

static int final(EVP_MD_CTX *ctx, uint8_t *md)
{
    return RIPEMD160_Final(md, ctx->md_data);
}

static const EVP_MD ripemd160_md = {
    .type = NID_ripemd160,
    .pkey_type = NID_ripemd160WithRSA,
    .md_size = RIPEMD160_DIGEST_LENGTH,
    .init = init,
    .update = update,
    .final = final,
#ifndef OPENSSL_NO_RSA
    .sign = (evp_sign_method *)RSA_sign,
    .verify = (evp_verify_method *)RSA_verify,
    .required_pkey_type = {
        EVP_PKEY_RSA, EVP_PKEY_RSA2, 0, 0,
    },
#endif
    .block_size = RIPEMD160_CBLOCK,
    .ctx_size = sizeof(EVP_MD *) + sizeof(RIPEMD160_CTX),
};

const EVP_MD *EVP_ripemd160(void)
{
    return (&ripemd160_md);
}
#endif
