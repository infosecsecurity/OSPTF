/*
 * Copyright 2006-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef HEADER_CAMELLIA_H
#define HEADER_CAMELLIA_H

#include <stddef.h>
#include <stdint.h>

#include <openssl/base.h>

#define CAMELLIA_ENCRYPT 1
#define CAMELLIA_DECRYPT 0

/* Because array size can't be a const in C, the following two are macros.
   Both sizes are in bytes. */

#ifdef __cplusplus
extern "C" {
#endif

/* This should be a hidden type, but EVP requires that the size be known */

#define CAMELLIA_BLOCK_SIZE 16
#define CAMELLIA_TABLE_BYTE_LEN 272
#define CAMELLIA_TABLE_WORD_LEN (CAMELLIA_TABLE_BYTE_LEN / 4)

typedef unsigned int
    KEY_TABLE_TYPE[CAMELLIA_TABLE_WORD_LEN]; /* to match with WORD */

struct camellia_key_st {
    union {
        double d; /* ensures 64-bit align */
        KEY_TABLE_TYPE rd_key;
    } u;
    int grand_rounds;
};
typedef struct camellia_key_st CAMELLIA_KEY;

VIGORTLS_EXPORT int Camellia_set_key(const uint8_t *userKey, const int bits,
                                     CAMELLIA_KEY *key);

VIGORTLS_EXPORT void Camellia_encrypt(const uint8_t *in, uint8_t *out,
                                      const CAMELLIA_KEY *key);
VIGORTLS_EXPORT void Camellia_decrypt(const uint8_t *in, uint8_t *out,
                                      const CAMELLIA_KEY *key);

VIGORTLS_EXPORT void Camellia_ecb_encrypt(const uint8_t *in, uint8_t *out,
                                          const CAMELLIA_KEY *key,
                                          const int enc);
VIGORTLS_EXPORT void Camellia_cbc_encrypt(const uint8_t *in, uint8_t *out,
                                          size_t length,
                                          const CAMELLIA_KEY *key,
                                          uint8_t *ivec, const int enc);
VIGORTLS_EXPORT void Camellia_cfb128_encrypt(const uint8_t *in, uint8_t *out,
                                             size_t length,
                                             const CAMELLIA_KEY *key,
                                             uint8_t *ivec, int *num,
                                             const int enc);
VIGORTLS_EXPORT void Camellia_cfb1_encrypt(const uint8_t *in, uint8_t *out,
                                           size_t length,
                                           const CAMELLIA_KEY *key,
                                           uint8_t *ivec, int *num,
                                           const int enc);
VIGORTLS_EXPORT void Camellia_cfb8_encrypt(const uint8_t *in, uint8_t *out,
                                           size_t length,
                                           const CAMELLIA_KEY *key,
                                           uint8_t *ivec, int *num,
                                           const int enc);
VIGORTLS_EXPORT void Camellia_ofb128_encrypt(const uint8_t *in, uint8_t *out,
                                             size_t length,
                                             const CAMELLIA_KEY *key,
                                             uint8_t *ivec, int *num);
VIGORTLS_EXPORT void Camellia_ctr128_encrypt(
    const uint8_t *in, uint8_t *out, size_t length, const CAMELLIA_KEY *key,
    uint8_t ivec[CAMELLIA_BLOCK_SIZE], uint8_t ecount_buf[CAMELLIA_BLOCK_SIZE],
    unsigned int *num);

#ifdef __cplusplus
}
#endif

#endif /* !HEADER_CAMELLIA_H */
