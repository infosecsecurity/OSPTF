/*
 * Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/sha.h>
#ifndef OPENSSL_NO_DSA
#include <openssl/dsa.h>
#endif


static int init(EVP_MD_CTX *ctx)
{
    return SHA1_Init(ctx->md_data);
}

static int update(EVP_MD_CTX *ctx, const void *data, size_t count)
{
    return SHA1_Update(ctx->md_data, data, count);
}

static int final(EVP_MD_CTX *ctx, uint8_t *md)
{
    return SHA1_Final(md, ctx->md_data);
}

static const EVP_MD dsa_md = {
    .type = NID_dsaWithSHA,
    .pkey_type = NID_dsaWithSHA,
    .md_size = SHA_DIGEST_LENGTH,
    .flags = EVP_MD_FLAG_PKEY_DIGEST,
    .init = init,
    .update = update,
    .final = final,
    .copy = NULL,
    .cleanup = NULL,
#ifndef OPENSSL_NO_DSA
    .sign = (evp_sign_method *)DSA_sign,
    .verify = (evp_verify_method *)DSA_verify,
    .required_pkey_type = {
        EVP_PKEY_DSA, EVP_PKEY_DSA2, EVP_PKEY_DSA3, EVP_PKEY_DSA4, 0,
    },
#endif
    .block_size = SHA_CBLOCK,
    .ctx_size = sizeof(EVP_MD *) + sizeof(SHA_CTX),
};

const EVP_MD *EVP_dss(void)
{
    return (&dsa_md);
}
