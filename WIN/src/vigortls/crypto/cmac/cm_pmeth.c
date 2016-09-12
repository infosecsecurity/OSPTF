/*
 * Copyright 2010-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <string.h>

#include <openssl/cmac.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include "internal/evp_int.h"

/* The context structure and "key" is simply a CMAC_CTX */

static int pkey_cmac_init(EVP_PKEY_CTX *ctx)
{
    ctx->data = CMAC_CTX_new();
    if (!ctx->data)
        return 0;
    ctx->keygen_info_count = 0;
    return 1;
}

static int pkey_cmac_copy(EVP_PKEY_CTX *dst, EVP_PKEY_CTX *src)
{
    if (!pkey_cmac_init(dst))
        return 0;
    if (!CMAC_CTX_copy(dst->data, src->data))
        return 0;
    return 1;
}

static void pkey_cmac_cleanup(EVP_PKEY_CTX *ctx)
{
    CMAC_CTX_free(ctx->data);
}

static int pkey_cmac_keygen(EVP_PKEY_CTX *ctx, EVP_PKEY *pkey)
{
    CMAC_CTX *cmkey = CMAC_CTX_new();
    CMAC_CTX *cmctx = ctx->data;
    if (!cmkey)
        return 0;
    if (!CMAC_CTX_copy(cmkey, cmctx)) {
        CMAC_CTX_free(cmkey);
        return 0;
    }
    EVP_PKEY_assign(pkey, EVP_PKEY_CMAC, cmkey);

    return 1;
}

static int int_update(EVP_MD_CTX *ctx, const void *data, size_t count)
{
    if (!CMAC_Update(ctx->pctx->data, data, count))
        return 0;
    return 1;
}

static int cmac_signctx_init(EVP_PKEY_CTX *ctx, EVP_MD_CTX *mctx)
{
    EVP_MD_CTX_set_flags(mctx, EVP_MD_CTX_FLAG_NO_INIT);
    mctx->update = int_update;
    return 1;
}

static int cmac_signctx(EVP_PKEY_CTX *ctx, uint8_t *sig, size_t *siglen,
                        EVP_MD_CTX *mctx)
{
    return CMAC_Final(ctx->data, sig, siglen);
}

static int pkey_cmac_ctrl(EVP_PKEY_CTX *ctx, int type, int p1, void *p2)
{
    CMAC_CTX *cmctx = ctx->data;
    switch (type) {

        case EVP_PKEY_CTRL_SET_MAC_KEY:
            if (!p2 || p1 < 0)
                return 0;
            if (!CMAC_Init(cmctx, p2, p1, NULL, NULL))
                return 0;
            break;

        case EVP_PKEY_CTRL_CIPHER:
            if (!CMAC_Init(cmctx, NULL, 0, p2, ctx->engine))
                return 0;
            break;

        case EVP_PKEY_CTRL_MD:
            if (ctx->pkey && !CMAC_CTX_copy(ctx->data, (CMAC_CTX *)ctx->pkey->pkey.ptr))
                return 0;
            if (!CMAC_Init(cmctx, NULL, 0, NULL, NULL))
                return 0;
            break;

        default:
            return -2;
    }
    return 1;
}

static int pkey_cmac_ctrl_str(EVP_PKEY_CTX *ctx,
                              const char *type, const char *value)
{
    if (!value) {
        return 0;
    }
    if (strcmp(type, "key") == 0) {
        void *p = (void *)value;
        return pkey_cmac_ctrl(ctx, EVP_PKEY_CTRL_SET_MAC_KEY,
                              strlen(p), p);
    }
    if (strcmp(type, "cipher") == 0) {
        const EVP_CIPHER *c;
        c = EVP_get_cipherbyname(value);
        if (!c)
            return 0;
        return pkey_cmac_ctrl(ctx, EVP_PKEY_CTRL_CIPHER, -1, (void *)c);
    }
    if (strcmp(type, "hexkey") == 0) {
        uint8_t *key;
        int r;
        long keylen;
        key = string_to_hex(value, &keylen);
        if (!key)
            return 0;
        r = pkey_cmac_ctrl(ctx, EVP_PKEY_CTRL_SET_MAC_KEY, keylen, key);
        free(key);
        return r;
    }
    return -2;
}

const EVP_PKEY_METHOD cmac_pkey_meth = {
    EVP_PKEY_CMAC,
    EVP_PKEY_FLAG_SIGCTX_CUSTOM,
    pkey_cmac_init,
    pkey_cmac_copy,
    pkey_cmac_cleanup,

    0, 0,

    0,
    pkey_cmac_keygen,

    0, 0,

    0, 0,

    0, 0,

    cmac_signctx_init,
    cmac_signctx,

    0, 0,

    0, 0,

    0, 0,

    0, 0,

    pkey_cmac_ctrl,
    pkey_cmac_ctrl_str

};
