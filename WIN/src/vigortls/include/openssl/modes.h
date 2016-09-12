/*
 * Copyright 2008-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stddef.h>
#include <stdint.h>

#include <openssl/base.h>

#ifdef  __cplusplus
extern "C" {
#endif

typedef void (*block128_f)(const uint8_t in[16], uint8_t out[16],
                           const void *key);

typedef void (*cbc128_f)(const uint8_t *in, uint8_t *out, size_t len,
                         const void *key, uint8_t ivec[16], int enc);

typedef void (*ctr128_f)(const uint8_t *in, uint8_t *out, size_t blocks,
                         const void *key, const uint8_t ivec[16]);

typedef void (*ccm128_f)(const uint8_t *in, uint8_t *out, size_t blocks,
                         const void *key, const uint8_t ivec[16],
                         uint8_t cmac[16]);

VIGORTLS_EXPORT void CRYPTO_cbc128_encrypt(const uint8_t *in, uint8_t *out,
                                           size_t len, const void *key,
                                           uint8_t ivec[16], block128_f block);
VIGORTLS_EXPORT void CRYPTO_cbc128_decrypt(const uint8_t *in, uint8_t *out,
                                           size_t len, const void *key,
                                           uint8_t ivec[16], block128_f block);

VIGORTLS_EXPORT void CRYPTO_ctr128_encrypt(const uint8_t *in, uint8_t *out,
                                           size_t len, const void *key,
                                           uint8_t ivec[16],
                                           uint8_t ecount_buf[16],
                                           unsigned int *num, block128_f block);

VIGORTLS_EXPORT void CRYPTO_ctr128_encrypt_ctr32(
    const uint8_t *in, uint8_t *out, size_t len, const void *key,
    uint8_t ivec[16], uint8_t ecount_buf[16], unsigned int *num, ctr128_f ctr);

VIGORTLS_EXPORT void CRYPTO_ofb128_encrypt(const uint8_t *in, uint8_t *out,
                                           size_t len, const void *key,
                                           uint8_t ivec[16], int *num,
                                           block128_f block);

VIGORTLS_EXPORT void CRYPTO_cfb128_encrypt(const uint8_t *in, uint8_t *out,
                                           size_t len, const void *key,
                                           uint8_t ivec[16], int *num, int enc,
                                           block128_f block);
VIGORTLS_EXPORT void CRYPTO_cfb128_8_encrypt(const uint8_t *in, uint8_t *out,
                                             size_t length, const void *key,
                                             uint8_t ivec[16], int *num,
                                             int enc, block128_f block);
VIGORTLS_EXPORT void CRYPTO_cfb128_1_encrypt(const uint8_t *in, uint8_t *out,
                                             size_t bits, const void *key,
                                             uint8_t ivec[16], int *num,
                                             int enc, block128_f block);

VIGORTLS_EXPORT size_t CRYPTO_cts128_encrypt_block(const uint8_t *in,
                                                   uint8_t *out, size_t len,
                                                   const void *key,
                                                   uint8_t ivec[16],
                                                   block128_f block);
VIGORTLS_EXPORT size_t CRYPTO_cts128_encrypt(const uint8_t *in, uint8_t *out,
                                             size_t len, const void *key,
                                             uint8_t ivec[16], cbc128_f cbc);
VIGORTLS_EXPORT size_t CRYPTO_cts128_decrypt_block(const uint8_t *in,
                                                   uint8_t *out, size_t len,
                                                   const void *key,
                                                   uint8_t ivec[16],
                                                   block128_f block);
VIGORTLS_EXPORT size_t CRYPTO_cts128_decrypt(const uint8_t *in, uint8_t *out,
                                             size_t len, const void *key,
                                             uint8_t ivec[16], cbc128_f cbc);

VIGORTLS_EXPORT size_t CRYPTO_nistcts128_encrypt_block(const uint8_t *in,
                                                       uint8_t *out, size_t len,
                                                       const void *key,
                                                       uint8_t ivec[16],
                                                       block128_f block);
VIGORTLS_EXPORT size_t CRYPTO_nistcts128_encrypt(const uint8_t *in,
                                                 uint8_t *out, size_t len,
                                                 const void *key,
                                                 uint8_t ivec[16],
                                                 cbc128_f cbc);
VIGORTLS_EXPORT size_t CRYPTO_nistcts128_decrypt_block(const uint8_t *in,
                                                       uint8_t *out, size_t len,
                                                       const void *key,
                                                       uint8_t ivec[16],
                                                       block128_f block);
VIGORTLS_EXPORT size_t CRYPTO_nistcts128_decrypt(const uint8_t *in,
                                                 uint8_t *out, size_t len,
                                                 const void *key,
                                                 uint8_t ivec[16],
                                                 cbc128_f cbc);

typedef struct gcm128_context GCM128_CONTEXT;

VIGORTLS_EXPORT GCM128_CONTEXT *CRYPTO_gcm128_new(void *key, block128_f block);
VIGORTLS_EXPORT void CRYPTO_gcm128_init(GCM128_CONTEXT *ctx, void *key,
                                        block128_f block);
VIGORTLS_EXPORT void CRYPTO_gcm128_setiv(GCM128_CONTEXT *ctx, const uint8_t *iv,
                                         size_t len);
VIGORTLS_EXPORT int CRYPTO_gcm128_aad(GCM128_CONTEXT *ctx, const uint8_t *aad,
                                      size_t len);
VIGORTLS_EXPORT int CRYPTO_gcm128_encrypt(GCM128_CONTEXT *ctx,
                                          const uint8_t *in, uint8_t *out,
                                          size_t len);
VIGORTLS_EXPORT int CRYPTO_gcm128_decrypt(GCM128_CONTEXT *ctx,
                                          const uint8_t *in, uint8_t *out,
                                          size_t len);
VIGORTLS_EXPORT int CRYPTO_gcm128_encrypt_ctr32(GCM128_CONTEXT *ctx,
                                                const uint8_t *in, uint8_t *out,
                                                size_t len, ctr128_f stream);
VIGORTLS_EXPORT int CRYPTO_gcm128_decrypt_ctr32(GCM128_CONTEXT *ctx,
                                                const uint8_t *in, uint8_t *out,
                                                size_t len, ctr128_f stream);
VIGORTLS_EXPORT int CRYPTO_gcm128_finish(GCM128_CONTEXT *ctx,
                                         const uint8_t *tag, size_t len);
VIGORTLS_EXPORT void CRYPTO_gcm128_tag(GCM128_CONTEXT *ctx, uint8_t *tag,
                                       size_t len);
VIGORTLS_EXPORT void CRYPTO_gcm128_release(GCM128_CONTEXT *ctx);

typedef struct ccm128_context CCM128_CONTEXT;

VIGORTLS_EXPORT void CRYPTO_ccm128_init(CCM128_CONTEXT *ctx, unsigned int M,
                                        unsigned int L, void *key,
                                        block128_f block);
VIGORTLS_EXPORT int CRYPTO_ccm128_setiv(CCM128_CONTEXT *ctx,
                                        const uint8_t *nonce, size_t nlen,
                                        size_t mlen);
VIGORTLS_EXPORT void CRYPTO_ccm128_aad(CCM128_CONTEXT *ctx, const uint8_t *aad,
                                       size_t alen);
VIGORTLS_EXPORT int CRYPTO_ccm128_encrypt(CCM128_CONTEXT *ctx,
                                          const uint8_t *inp, uint8_t *out,
                                          size_t len);
VIGORTLS_EXPORT int CRYPTO_ccm128_decrypt(CCM128_CONTEXT *ctx,
                                          const uint8_t *inp, uint8_t *out,
                                          size_t len);
VIGORTLS_EXPORT int CRYPTO_ccm128_encrypt_ccm64(CCM128_CONTEXT *ctx,
                                                const uint8_t *inp,
                                                uint8_t *out, size_t len,
                                                ccm128_f stream);
VIGORTLS_EXPORT int CRYPTO_ccm128_decrypt_ccm64(CCM128_CONTEXT *ctx,
                                                const uint8_t *inp,
                                                uint8_t *out, size_t len,
                                                ccm128_f stream);
VIGORTLS_EXPORT size_t CRYPTO_ccm128_tag(CCM128_CONTEXT *ctx, uint8_t *tag,
                                         size_t len);

typedef struct xts128_context XTS128_CONTEXT;

VIGORTLS_EXPORT int CRYPTO_xts128_encrypt(const XTS128_CONTEXT *ctx,
                                          const uint8_t iv[16],
                                          const uint8_t *inp, uint8_t *out,
                                          size_t len, int enc);

VIGORTLS_EXPORT size_t CRYPTO_128_wrap(void *key, const uint8_t *iv,
                                       uint8_t *out, const uint8_t *in,
                                       size_t inlen, block128_f block);

VIGORTLS_EXPORT size_t CRYPTO_128_unwrap(void *key, const uint8_t *iv,
                                         uint8_t *out, const uint8_t *in,
                                         size_t inlen, block128_f block);

#ifdef  __cplusplus
}
#endif