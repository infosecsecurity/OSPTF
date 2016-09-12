/*
 * Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdlib.h>
#include <string.h>
#include <openssl/hmac.h>

int HMAC_Init_ex(HMAC_CTX *ctx, const void *key, int len,
                 const EVP_MD *md, ENGINE *impl)
{
    int i, j, reset = 0;
    uint8_t pad[HMAC_MAX_MD_CBLOCK];

    if (md != NULL) {
        reset = 1;
        ctx->md = md;
    } else if (ctx->md) {
        md = ctx->md;
    } else {
        return 0;
    }
    
    if (!ctx->key_init && key == NULL)
        return 0;

    if (key != NULL) {
        reset = 1;
        j = EVP_MD_block_size(md);
        OPENSSL_assert(j <= (int)sizeof(ctx->key));
        if (j < len) {
            if (!EVP_DigestInit_ex(&ctx->md_ctx, md, impl))
                goto err;
            if (!EVP_DigestUpdate(&ctx->md_ctx, key, len))
                goto err;
            if (!EVP_DigestFinal_ex(&(ctx->md_ctx), ctx->key,
                                    &ctx->key_length))
                goto err;
        } else {
            if (len < 0 || len > (int)sizeof(ctx->key))
                return 0;
            memcpy(ctx->key, key, len);
            ctx->key_length = len;
        }
        if (ctx->key_length != HMAC_MAX_MD_CBLOCK)
            memset(&ctx->key[ctx->key_length], 0,
                   HMAC_MAX_MD_CBLOCK - ctx->key_length);
        ctx->key_init = 1;
    }

    if (reset) {
        for (i = 0; i < HMAC_MAX_MD_CBLOCK; i++)
            pad[i] = 0x36 ^ ctx->key[i];
        if (!EVP_DigestInit_ex(&ctx->i_ctx, md, impl))
            goto err;
        if (!EVP_DigestUpdate(&ctx->i_ctx, pad, EVP_MD_block_size(md)))
            goto err;

        for (i = 0; i < HMAC_MAX_MD_CBLOCK; i++)
            pad[i] = 0x5c ^ ctx->key[i];
        if (!EVP_DigestInit_ex(&ctx->o_ctx, md, impl))
            goto err;
        if (!EVP_DigestUpdate(&ctx->o_ctx, pad, EVP_MD_block_size(md)))
            goto err;
    }
    if (!EVP_MD_CTX_copy_ex(&ctx->md_ctx, &ctx->i_ctx))
        goto err;
    return 1;
err:
    return 0;
}

int HMAC_Init(HMAC_CTX *ctx, const void *key, int len, const EVP_MD *md)
{
    if (key && md)
        HMAC_CTX_init(ctx);
    return HMAC_Init_ex(ctx, key, len, md, NULL);
}

int HMAC_Update(HMAC_CTX *ctx, const uint8_t *data, size_t len)
{
    if (!ctx->key_init)
        return 0;

    return EVP_DigestUpdate(&ctx->md_ctx, data, len);
}

int HMAC_Final(HMAC_CTX *ctx, uint8_t *md, unsigned int *len)
{
    unsigned int i;
    uint8_t buf[EVP_MAX_MD_SIZE];
    
    if (!ctx->key_init)
        goto err;

    if (!EVP_DigestFinal_ex(&ctx->md_ctx, buf, &i))
        goto err;
    if (!EVP_MD_CTX_copy_ex(&ctx->md_ctx, &ctx->o_ctx))
        goto err;
    if (!EVP_DigestUpdate(&ctx->md_ctx, buf, i))
        goto err;
    if (!EVP_DigestFinal_ex(&ctx->md_ctx, md, len))
        goto err;
    return 1;
err:
    return 0;
}

void HMAC_CTX_init(HMAC_CTX *ctx)
{
    EVP_MD_CTX_init(&ctx->i_ctx);
    EVP_MD_CTX_init(&ctx->o_ctx);
    EVP_MD_CTX_init(&ctx->md_ctx);
    ctx->key_init = 0;
    ctx->md = NULL;
}

int HMAC_CTX_copy(HMAC_CTX *dctx, HMAC_CTX *sctx)
{
    if (!EVP_MD_CTX_copy(&dctx->i_ctx, &sctx->i_ctx))
        goto err;
    if (!EVP_MD_CTX_copy(&dctx->o_ctx, &sctx->o_ctx))
        goto err;
    if (!EVP_MD_CTX_copy(&dctx->md_ctx, &sctx->md_ctx))
        goto err;
    dctx->key_init = sctx->key_init;
    if (sctx->key_init) {
        memcpy(dctx->key, sctx->key, HMAC_MAX_MD_CBLOCK);
        dctx->key_length = sctx->key_length;
    }
    dctx->md = sctx->md;
    return 1;
err:
    return 0;
}

void HMAC_CTX_cleanup(HMAC_CTX *ctx)
{
    EVP_MD_CTX_cleanup(&ctx->i_ctx);
    EVP_MD_CTX_cleanup(&ctx->o_ctx);
    EVP_MD_CTX_cleanup(&ctx->md_ctx);
    memset(ctx, 0, sizeof *ctx);
}

uint8_t *HMAC(const EVP_MD *evp_md, const void *key, int key_len,
                    const uint8_t *d, size_t n, uint8_t *md,
                    unsigned int *md_len)
{
    HMAC_CTX c;
    static uint8_t m[EVP_MAX_MD_SIZE];

    if (md == NULL)
        md = m;

    HMAC_CTX_init(&c);
    if (!HMAC_Init(&c, key, key_len, evp_md))
        goto err;
    if (!HMAC_Update(&c, d, n))
        goto err;
    if (!HMAC_Final(&c, md, md_len))
        goto err;

    HMAC_CTX_cleanup(&c);
    return md;

err:
    HMAC_CTX_cleanup(&c);
    return NULL;
}

void HMAC_CTX_set_flags(HMAC_CTX *ctx, unsigned long flags)
{
    EVP_MD_CTX_set_flags(&ctx->i_ctx, flags);
    EVP_MD_CTX_set_flags(&ctx->o_ctx, flags);
    EVP_MD_CTX_set_flags(&ctx->md_ctx, flags);
}
