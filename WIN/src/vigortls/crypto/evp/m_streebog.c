/*
 * Copyright (c) 2014 Dmitry Eremin-Solenikov <dbaryshkov@gmail.com>
 * Copyright (c) 2005-2006 Cryptocom LTD
 * Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/opensslconf.h>

#ifndef OPENSSL_NO_GOST

#include <openssl/evp.h>
#include <openssl/gost.h>
#include <openssl/objects.h>

static int init256(EVP_MD_CTX *ctx)
{
    return STREEBOG256_Init(ctx->md_data);
}

static int update256(EVP_MD_CTX *ctx, const void *data, size_t count)
{
    return STREEBOG256_Update(ctx->md_data, data, count);
}

static int final256(EVP_MD_CTX *ctx, uint8_t *md)
{
    return STREEBOG256_Final(md, ctx->md_data);
}

static int init512(EVP_MD_CTX *ctx)
{
    return STREEBOG512_Init(ctx->md_data);
}

static int update512(EVP_MD_CTX *ctx, const void *data, size_t count)
{
    return STREEBOG512_Update(ctx->md_data, data, count);
}

static int final512(EVP_MD_CTX *ctx, uint8_t *md)
{
    return STREEBOG512_Final(md, ctx->md_data);
}

static const EVP_MD streebog256_md = {
    .type = NID_id_tc26_gost3411_2012_256,
    .pkey_type = NID_undef,
    .md_size = STREEBOG256_LENGTH,
    .flags = EVP_MD_FLAG_PKEY_METHOD_SIGNATURE,
    .init = init256,
    .update = update256,
    .final = final256,
    .block_size = STREEBOG_CBLOCK,
    .ctx_size = sizeof(EVP_MD *) + sizeof(STREEBOG_CTX),
};

static const EVP_MD streebog512_md = {
    .type = NID_id_tc26_gost3411_2012_512,
    .pkey_type = NID_undef,
    .md_size = STREEBOG512_LENGTH,
    .flags = EVP_MD_FLAG_PKEY_METHOD_SIGNATURE,
    .init = init512,
    .update = update512,
    .final = final512,
    .block_size = STREEBOG_CBLOCK,
    .ctx_size = sizeof(EVP_MD *) + sizeof(STREEBOG_CTX),
};

const EVP_MD *EVP_streebog256(void)
{
    return (&streebog256_md);
}

const EVP_MD *EVP_streebog512(void)
{
    return (&streebog512_md);
}
#endif
