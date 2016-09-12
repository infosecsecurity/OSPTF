/*
 * Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef HEADER_RC2_H
#define HEADER_RC2_H

#include <openssl/base.h>
#include <stdint.h>

#ifdef OPENSSL_NO_RC2
#error RC2 is disabled.
#endif

#define RC2_ENCRYPT 1
#define RC2_DECRYPT 0

#define RC2_BLOCK 8
#define RC2_KEY_LENGTH 16

#ifdef __cplusplus
extern "C" {
#endif

typedef struct rc2_key_st {
    uint32_t data[64];
} RC2_KEY;

VIGORTLS_EXPORT void RC2_set_key(RC2_KEY *key, int len, const uint8_t *data,
                                 int bits);
VIGORTLS_EXPORT void RC2_ecb_encrypt(const uint8_t *in, uint8_t *out,
                                     RC2_KEY *key, int enc);
VIGORTLS_EXPORT void RC2_encrypt(unsigned long *data, RC2_KEY *key);
VIGORTLS_EXPORT void RC2_decrypt(unsigned long *data, RC2_KEY *key);
VIGORTLS_EXPORT void RC2_cbc_encrypt(const uint8_t *in, uint8_t *out,
                                     long length, RC2_KEY *ks, uint8_t *iv,
                                     int enc);
VIGORTLS_EXPORT void RC2_cfb64_encrypt(const uint8_t *in, uint8_t *out,
                                       long length, RC2_KEY *schedule,
                                       uint8_t *ivec, int *num, int enc);
VIGORTLS_EXPORT void RC2_ofb64_encrypt(const uint8_t *in, uint8_t *out,
                                       long length, RC2_KEY *schedule,
                                       uint8_t *ivec, int *num);

#ifdef __cplusplus
}
#endif

#endif
