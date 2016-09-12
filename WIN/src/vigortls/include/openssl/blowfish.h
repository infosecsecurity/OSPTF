/*
 * Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef HEADER_BLOWFISH_H
#define HEADER_BLOWFISH_H

#include <stdint.h>

#include <openssl/base.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifdef OPENSSL_NO_BF
#error BF is disabled.
#endif

#define BF_ENCRYPT 1
#define BF_DECRYPT 0

/*
 * !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
 * ! BF_LONG has to be at least 32 bits wide. If it's wider, then !
 * ! BF_LONG_LOG2 has to be defined along.                        !
 * !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
 */

#define BF_LONG unsigned int

#define BF_ROUNDS 16
#define BF_BLOCK 8

typedef struct bf_key_st {
    BF_LONG P[BF_ROUNDS + 2];
    BF_LONG S[4 * 256];
} BF_KEY;

VIGORTLS_EXPORT void BF_set_key(BF_KEY *key, int len, const uint8_t *data);

VIGORTLS_EXPORT void BF_encrypt(BF_LONG *data, const BF_KEY *key);
VIGORTLS_EXPORT void BF_decrypt(BF_LONG *data, const BF_KEY *key);

VIGORTLS_EXPORT void BF_ecb_encrypt(const uint8_t *in, uint8_t *out,
                                    const BF_KEY *key, int enc);
VIGORTLS_EXPORT void BF_cbc_encrypt(const uint8_t *in, uint8_t *out,
                                    long length, const BF_KEY *schedule,
                                    uint8_t *ivec, int enc);
VIGORTLS_EXPORT void BF_cfb64_encrypt(const uint8_t *in, uint8_t *out,
                                      long length, const BF_KEY *schedule,
                                      uint8_t *ivec, int *num, int enc);
VIGORTLS_EXPORT void BF_ofb64_encrypt(const uint8_t *in, uint8_t *out,
                                      long length, const BF_KEY *schedule,
                                      uint8_t *ivec, int *num);
VIGORTLS_EXPORT const char *BF_options(void);

#ifdef __cplusplus
}
#endif

#endif
