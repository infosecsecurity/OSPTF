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
    return GOST2814789IMIT_Init(ctx->md_data,
                                NID_id_Gost28147_89_CryptoPro_A_ParamSet);
}

static int update(EVP_MD_CTX *ctx, const void *data, size_t count)
{
    return GOST2814789IMIT_Update(ctx->md_data, data, count);
}

static int final(EVP_MD_CTX *ctx, uint8_t *md)
{
    return GOST2814789IMIT_Final(md, ctx->md_data);
}

static int md_ctrl(EVP_MD_CTX *ctx, int cmd, int p1, void *p2)
{
    GOST2814789IMIT_CTX *gctx = ctx->md_data;

    switch (cmd) {
        case EVP_MD_CTRL_SET_KEY:
            return Gost2814789_set_key(&gctx->cipher, p2, p1);
        case EVP_MD_CTRL_GOST_SET_SBOX:
            return Gost2814789_set_sbox(&gctx->cipher, p1);
    }
    return -2;
}

static const EVP_MD gost2814789imit_md = {
    .type = NID_id_Gost28147_89_MAC,
    .pkey_type = NID_undef,
    .md_size = GOST2814789IMIT_LENGTH,
    .flags = 0,
    .init = init,
    .update = update,
    .final = final,
    .block_size = GOST2814789IMIT_CBLOCK,
    .ctx_size = sizeof(EVP_MD *) + sizeof(GOST2814789IMIT_CTX),
    .md_ctrl = md_ctrl,
};

const EVP_MD *EVP_gost2814789imit(void)
{
    return (&gost2814789imit_md);
}
#endif
