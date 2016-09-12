/*
 * Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef HEADER_MD5_H
#define HEADER_MD5_H

#include <stddef.h>
#include <stdint.h>

#include <openssl/base.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
 * ! MD5_LONG has to be at least 32 bits wide. If it's wider, then !
 * ! MD5_LONG_LOG2 has to be defined along.               !
 * !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
 */

#define MD5_LONG unsigned int

#define MD5_CBLOCK 64
#define MD5_LBLOCK (MD5_CBLOCK / 4)
#define MD5_DIGEST_LENGTH 16

typedef struct MD5state_st {
    MD5_LONG A, B, C, D;
    MD5_LONG Nl, Nh;
    MD5_LONG data[MD5_LBLOCK];
    unsigned int num;
} MD5_CTX;

VIGORTLS_EXPORT int MD5_Init(MD5_CTX *ctx);
VIGORTLS_EXPORT int MD5_Update(MD5_CTX *ctx, const void *data, size_t len);
VIGORTLS_EXPORT int MD5_Final(uint8_t *md, MD5_CTX *ctx);
VIGORTLS_EXPORT uint8_t *MD5(const uint8_t *data, size_t len, uint8_t *out);
VIGORTLS_EXPORT void MD5_Transform(MD5_CTX *ctx, const uint8_t *b);
#ifdef __cplusplus
}
#endif

#endif
