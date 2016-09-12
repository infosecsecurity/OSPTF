/*
 * Copyright 1998-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef HEADER_AES_H
#define HEADER_AES_H

#include <openssl/base.h>

#include <stddef.h>
#include <stdint.h>

#define AES_ENCRYPT 1
#define AES_DECRYPT 0

/* Because array size can't be a const in C, the following two are macros.
   Both sizes are in bytes. */
#define AES_MAXNR 14
#define AES_BLOCK_SIZE 16

#ifdef __cplusplus
extern "C" {
#endif

/* This should be a hidden type, but EVP requires that the size be known */
struct aes_key_st {
    unsigned int rd_key[4 * (AES_MAXNR + 1)];
    int rounds;
};
typedef struct aes_key_st AES_KEY;

VIGORTLS_EXPORT const char *AES_options(void);

VIGORTLS_EXPORT int AES_set_encrypt_key(const uint8_t *userKey, const int bits,
                                        AES_KEY *key);
VIGORTLS_EXPORT int AES_set_decrypt_key(const uint8_t *userKey, const int bits,
                                        AES_KEY *key);

VIGORTLS_EXPORT void AES_encrypt(const uint8_t *in, uint8_t *out,
                                 const AES_KEY *key);
VIGORTLS_EXPORT void AES_decrypt(const uint8_t *in, uint8_t *out,
                                 const AES_KEY *key);

VIGORTLS_EXPORT void AES_ecb_encrypt(const uint8_t *in, uint8_t *out,
                                     const AES_KEY *key, const int enc);
VIGORTLS_EXPORT void AES_cbc_encrypt(const uint8_t *in, uint8_t *out,
                                     size_t length, const AES_KEY *key,
                                     uint8_t *ivec, const int enc);
VIGORTLS_EXPORT void AES_cfb128_encrypt(const uint8_t *in, uint8_t *out,
                                        size_t length, const AES_KEY *key,
                                        uint8_t *ivec, int *num, const int enc);
VIGORTLS_EXPORT void AES_cfb1_encrypt(const uint8_t *in, uint8_t *out,
                                      size_t length, const AES_KEY *key,
                                      uint8_t *ivec, int *num, const int enc);
VIGORTLS_EXPORT void AES_cfb8_encrypt(const uint8_t *in, uint8_t *out,
                                      size_t length, const AES_KEY *key,
                                      uint8_t *ivec, int *num, const int enc);
VIGORTLS_EXPORT void AES_ofb128_encrypt(const uint8_t *in, uint8_t *out,
                                        size_t length, const AES_KEY *key,
                                        uint8_t *ivec, int *num);
VIGORTLS_EXPORT void AES_ctr128_encrypt(const uint8_t *in, uint8_t *out,
                                        size_t length, const AES_KEY *key,
                                        uint8_t ivec[AES_BLOCK_SIZE],
                                        uint8_t ecount_buf[AES_BLOCK_SIZE],
                                        unsigned int *num);
/* NB: the IV is _two_ blocks long */
VIGORTLS_EXPORT void AES_ige_encrypt(const uint8_t *in, uint8_t *out,
                                     size_t length, const AES_KEY *key,
                                     uint8_t *ivec, const int enc);

VIGORTLS_EXPORT int AES_wrap_key(AES_KEY *key, const uint8_t *iv, uint8_t *out,
                                 const uint8_t *in, unsigned int inlen);
VIGORTLS_EXPORT int AES_unwrap_key(AES_KEY *key, const uint8_t *iv,
                                   uint8_t *out, const uint8_t *in,
                                   unsigned int inlen);

#ifdef __cplusplus
}
#endif

#endif /* !HEADER_AES_H */
