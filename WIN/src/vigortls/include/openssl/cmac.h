/*
 * Copyright 2010-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef HEADER_CMAC_H
#define HEADER_CMAC_H

#include <openssl/base.h>
#include <openssl/evp.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Opaque */
typedef struct CMAC_CTX_st CMAC_CTX;

VIGORTLS_EXPORT CMAC_CTX *CMAC_CTX_new(void);
VIGORTLS_EXPORT void CMAC_CTX_cleanup(CMAC_CTX *ctx);
VIGORTLS_EXPORT void CMAC_CTX_free(CMAC_CTX *ctx);
VIGORTLS_EXPORT EVP_CIPHER_CTX *CMAC_CTX_get0_cipher_ctx(CMAC_CTX *ctx);
VIGORTLS_EXPORT int CMAC_CTX_copy(CMAC_CTX *out, const CMAC_CTX *in);

VIGORTLS_EXPORT int CMAC_Init(CMAC_CTX *ctx, const void *key, size_t keylen,
                              const EVP_CIPHER *cipher, ENGINE *impl);
VIGORTLS_EXPORT int CMAC_Update(CMAC_CTX *ctx, const void *data, size_t dlen);
VIGORTLS_EXPORT int CMAC_Final(CMAC_CTX *ctx, uint8_t *out, size_t *poutlen);
VIGORTLS_EXPORT int CMAC_resume(CMAC_CTX *ctx);

#ifdef __cplusplus
}
#endif
#endif
