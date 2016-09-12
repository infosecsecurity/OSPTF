/*
 * Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef HEADER_HMAC_H
#define HEADER_HMAC_H

#include <openssl/base.h>

#if defined(OPENSSL_NO_HMAC)
#error HMAC is disabled.
#endif

#include <openssl/evp.h>

#define HMAC_MAX_MD_CBLOCK 128 /* largest known is SHA512 */

#ifdef __cplusplus
extern "C" {
#endif

typedef struct hmac_ctx_st {
    const EVP_MD *md;
    EVP_MD_CTX md_ctx;
    EVP_MD_CTX i_ctx;
    EVP_MD_CTX o_ctx;
    unsigned int key_length;
    uint8_t key[HMAC_MAX_MD_CBLOCK];
    int key_init;
} HMAC_CTX;

#define HMAC_size(e) (EVP_MD_size((e)->md))

VIGORTLS_EXPORT void HMAC_CTX_init(HMAC_CTX *ctx);
VIGORTLS_EXPORT void HMAC_CTX_cleanup(HMAC_CTX *ctx);

#define HMAC_cleanup(ctx) HMAC_CTX_cleanup(ctx) /* deprecated */

VIGORTLS_EXPORT int HMAC_Init(HMAC_CTX *ctx, const void *key, int len,
                              const EVP_MD *md); /* deprecated */
VIGORTLS_EXPORT int HMAC_Init_ex(HMAC_CTX *ctx, const void *key, int len,
                                 const EVP_MD *md, ENGINE *impl);
VIGORTLS_EXPORT int HMAC_Update(HMAC_CTX *ctx, const uint8_t *data, size_t len);
VIGORTLS_EXPORT int HMAC_Final(HMAC_CTX *ctx, uint8_t *md, unsigned int *len);
VIGORTLS_EXPORT uint8_t *HMAC(const EVP_MD *evp_md, const void *key,
                              int key_len, const uint8_t *d, size_t n,
                              uint8_t *md, unsigned int *md_len);
VIGORTLS_EXPORT int HMAC_CTX_copy(HMAC_CTX *dctx, HMAC_CTX *sctx);

VIGORTLS_EXPORT void HMAC_CTX_set_flags(HMAC_CTX *ctx, unsigned long flags);

#ifdef __cplusplus
}
#endif

#endif
