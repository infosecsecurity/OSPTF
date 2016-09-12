/*
 * Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef HEADER_IDEA_H
#define HEADER_IDEA_H

#include <openssl/base.h>
#include <stdint.h>

#ifdef OPENSSL_NO_IDEA
#error IDEA is disabled.
#endif

#define IDEA_ENCRYPT 1
#define IDEA_DECRYPT 0

#define IDEA_BLOCK 8
#define IDEA_KEY_LENGTH 16

#ifdef __cplusplus
extern "C" {
#endif

typedef struct idea_key_st {
    uint32_t data[9][6];
} IDEA_KEY_SCHEDULE;

VIGORTLS_EXPORT const char *idea_options(void);
VIGORTLS_EXPORT void idea_ecb_encrypt(const uint8_t *in, uint8_t *out,
                                      IDEA_KEY_SCHEDULE *ks);
VIGORTLS_EXPORT void idea_set_encrypt_key(const uint8_t *key,
                                          IDEA_KEY_SCHEDULE *ks);
VIGORTLS_EXPORT void idea_set_decrypt_key(IDEA_KEY_SCHEDULE *ek,
                                          IDEA_KEY_SCHEDULE *dk);
VIGORTLS_EXPORT void idea_cbc_encrypt(const uint8_t *in, uint8_t *out,
                                      long length, IDEA_KEY_SCHEDULE *ks,
                                      uint8_t *iv, int enc);
VIGORTLS_EXPORT void idea_cfb64_encrypt(const uint8_t *in, uint8_t *out,
                                        long length, IDEA_KEY_SCHEDULE *ks,
                                        uint8_t *iv, int *num, int enc);
VIGORTLS_EXPORT void idea_ofb64_encrypt(const uint8_t *in, uint8_t *out,
                                        long length, IDEA_KEY_SCHEDULE *ks,
                                        uint8_t *iv, int *num);
VIGORTLS_EXPORT void idea_encrypt(uint32_t *in, IDEA_KEY_SCHEDULE *ks);
#ifdef __cplusplus
}
#endif

#endif
