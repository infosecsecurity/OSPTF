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
#include <openssl/md5.h>
#include <openssl/rsa.h>
#include "evp_locl.h"

static int init(EVP_MD_CTX *ctx)
{
    return MD5_Init(ctx->md_data);
}

static int update(EVP_MD_CTX *ctx, const void *data, size_t count)
{
    return MD5_Update(ctx->md_data, data, count);
}

static int final(EVP_MD_CTX *ctx, uint8_t *md)
{
    return MD5_Final(md, ctx->md_data);
}

static const EVP_MD md5_md = {
    .type = NID_md5,
    .pkey_type = NID_md5WithRSAEncryption,
    .md_size = MD5_DIGEST_LENGTH,
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
    .block_size = MD5_CBLOCK,
    .ctx_size = sizeof(EVP_MD *) + sizeof(MD5_CTX),
};

const EVP_MD *EVP_md5(void)
{
    return (&md5_md);
}
