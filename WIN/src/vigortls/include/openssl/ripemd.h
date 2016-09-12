/*
 * Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef HEADER_RIPEMD_H
#define HEADER_RIPEMD_H

#include <openssl/base.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifdef OPENSSL_NO_RIPEMD
#error RIPEMD is disabled.
#endif

#define RIPEMD160_LONG uint32_t

#define RIPEMD160_CBLOCK 64
#define RIPEMD160_LBLOCK (RIPEMD160_CBLOCK / 4)
#define RIPEMD160_DIGEST_LENGTH 20

typedef struct RIPEMD160state_st {
    uint32_t A, B, C, D, E;
    uint32_t Nl, Nh;
    uint32_t data[RIPEMD160_LBLOCK];
    unsigned int num;
} RIPEMD160_CTX;

VIGORTLS_EXPORT int RIPEMD160_Init(RIPEMD160_CTX *c);
VIGORTLS_EXPORT int RIPEMD160_Update(RIPEMD160_CTX *c, const void *data,
                                     size_t len);
VIGORTLS_EXPORT int RIPEMD160_Final(uint8_t *md, RIPEMD160_CTX *c);
VIGORTLS_EXPORT uint8_t *RIPEMD160(const uint8_t *d, size_t n, uint8_t *md);
VIGORTLS_EXPORT void RIPEMD160_Transform(RIPEMD160_CTX *c, const uint8_t *b);

#ifdef __cplusplus
}
#endif

#endif
