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

static int init(EVP_MD_CTX *ctx)
{
    return GOSTR341194_Init(ctx->md_data, NID_id_GostR3411_94_CryptoProParamSet);
}

static int update(EVP_MD_CTX *ctx, const void *data, size_t count)
{
    return GOSTR341194_Update(ctx->md_data, data, count);
}

static int final(EVP_MD_CTX *ctx, uint8_t *md)
{
    return GOSTR341194_Final(md, ctx->md_data);
}

static const EVP_MD gostr341194_md = {
    .type = NID_id_GostR3411_94,
    .pkey_type = NID_undef,
    .md_size = GOSTR341194_LENGTH,
    .flags = EVP_MD_FLAG_PKEY_METHOD_SIGNATURE,
    .init = init,
    .update = update,
    .final = final,
    .block_size = GOSTR341194_CBLOCK,
    .ctx_size = sizeof(EVP_MD *) + sizeof(GOSTR341194_CTX),
};

const EVP_MD *EVP_gostr341194(void)
{
    return (&gostr341194_md);
}
#endif
