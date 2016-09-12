/*
 * Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef HEADER_SHA_H
#define HEADER_SHA_H

#include <openssl/base.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SHA_LONG uint32_t

#define SHA_LBLOCK 16
#define SHA_CBLOCK (SHA_LBLOCK * 4) /* SHA treats input data as a contiguous
                                     * array of 32 bit wide big-endian values.*/
#define SHA_LAST_BLOCK (SHA_CBLOCK - 8)
#define SHA_DIGEST_LENGTH 20

typedef struct SHAstate_st {
    uint32_t h0, h1, h2, h3, h4;
    uint32_t Nl, Nh;
    uint32_t data[SHA_LBLOCK];
    unsigned int num;
} SHA_CTX;

VIGORTLS_EXPORT int SHA1_Init(SHA_CTX *ctx);
VIGORTLS_EXPORT int SHA1_Update(SHA_CTX *ctx, const void *data, size_t len);
VIGORTLS_EXPORT int SHA1_Final(uint8_t *md, SHA_CTX *ctx);
VIGORTLS_EXPORT uint8_t *SHA1(const uint8_t *d, size_t n, uint8_t *md);
VIGORTLS_EXPORT void SHA1_Transform(SHA_CTX *ctx, const uint8_t *data);

#define SHA256_CBLOCK (SHA_LBLOCK * 4) /* SHA-256 treats input data as a
                                        * contiguous array of 32 bit wide
                                        * big-endian values. */
#define SHA224_DIGEST_LENGTH 28
#define SHA256_DIGEST_LENGTH 32

typedef struct SHA256state_st {
    uint32_t h[8];
    uint32_t Nl, Nh;
    uint32_t data[SHA_LBLOCK];
    unsigned int num, md_len;
} SHA256_CTX;

VIGORTLS_EXPORT int SHA224_Init(SHA256_CTX *c);
VIGORTLS_EXPORT int SHA224_Update(SHA256_CTX *c, const void *data, size_t len);
VIGORTLS_EXPORT int SHA224_Final(uint8_t *md, SHA256_CTX *c);
VIGORTLS_EXPORT uint8_t *SHA224(const uint8_t *d, size_t n, uint8_t *md);
VIGORTLS_EXPORT int SHA256_Init(SHA256_CTX *c);
VIGORTLS_EXPORT int SHA256_Update(SHA256_CTX *c, const void *data, size_t len);
VIGORTLS_EXPORT int SHA256_Final(uint8_t *md, SHA256_CTX *c);
VIGORTLS_EXPORT uint8_t *SHA256(const uint8_t *d, size_t n, uint8_t *md);
VIGORTLS_EXPORT void SHA256_Transform(SHA256_CTX *c, const uint8_t *data);

#define SHA384_DIGEST_LENGTH 48
#define SHA512_DIGEST_LENGTH 64

/*
 * Unlike 32-bit digest algorithms, SHA-512 *relies* on SHA_LONG64
 * being exactly 64-bit wide. See Implementation Notes in sha512.c
 * for further details.
 */
#define SHA512_CBLOCK                                  \
    (SHA_LBLOCK * 8) /* SHA-512 treats input data as a \
                      * contiguous array of 64 bit     \
                      * wide big-endian values. */

typedef struct SHA512state_st {
    uint64_t h[8];
    uint64_t Nl, Nh;
    union {
        uint64_t d[SHA_LBLOCK];
        uint8_t p[SHA512_CBLOCK];
    } u;
    unsigned int num, md_len;
} SHA512_CTX;

VIGORTLS_EXPORT int SHA384_Init(SHA512_CTX *c);
VIGORTLS_EXPORT int SHA384_Update(SHA512_CTX *c, const void *data, size_t len);
VIGORTLS_EXPORT int SHA384_Final(uint8_t *md, SHA512_CTX *c);
VIGORTLS_EXPORT uint8_t *SHA384(const uint8_t *d, size_t n, uint8_t *md);
VIGORTLS_EXPORT int SHA512_Init(SHA512_CTX *c);
VIGORTLS_EXPORT int SHA512_Update(SHA512_CTX *c, const void *data, size_t len);
VIGORTLS_EXPORT int SHA512_Final(uint8_t *md, SHA512_CTX *c);
VIGORTLS_EXPORT uint8_t *SHA512(const uint8_t *d, size_t n, uint8_t *md);
VIGORTLS_EXPORT void SHA512_Transform(SHA512_CTX *c, const uint8_t *data);

#ifdef __cplusplus
}
#endif

#endif
