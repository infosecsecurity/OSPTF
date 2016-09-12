/*
 * Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/x509.h>


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

static const EVP_MD ecdsa_md = {
    .type = NID_ecdsa_with_SHA1,
    .pkey_type = NID_ecdsa_with_SHA1,
    .md_size = SHA_DIGEST_LENGTH,
    .flags = EVP_MD_FLAG_PKEY_DIGEST,
    .init = init,
    .update = update,
    .final = final,
    .copy = NULL,
    .cleanup = NULL,
    .sign = (evp_sign_method *)ECDSA_sign,
    .verify = (evp_verify_method *)ECDSA_verify,
    .required_pkey_type = {
        EVP_PKEY_EC, 0, 0, 0,
    },
    .block_size = SHA_CBLOCK,
    .ctx_size = sizeof(EVP_MD *) + sizeof(SHA_CTX),
};

const EVP_MD *EVP_ecdsa(void)
{
    return (&ecdsa_md);
}
