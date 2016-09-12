/*
 * Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <string.h>

#include <openssl/buffer.h>
#include <openssl/des.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/sha.h>
#include <openssl/rand.h>

#include "evp_locl.h"

typedef struct {
    union {
        double align;
        DES_key_schedule ks;
    } ks;
} EVP_DES_KEY;

#define ks1 ks.ks[0]
#define ks2 ks.ks[1]
#define ks3 ks.ks[2]

static int des_init_key(EVP_CIPHER_CTX *ctx, const uint8_t *key,
                        const uint8_t *iv, int enc)
{
    DES_cblock *deskey = (DES_cblock *)key;
    EVP_DES_KEY *dat = (EVP_DES_KEY *)ctx->cipher_data;

    DES_set_key(deskey, &dat->ks.ks);
    return 1;
}

static int des_cbc_cipher(EVP_CIPHER_CTX *ctx, uint8_t *out, const uint8_t *in,
                          size_t in_len)
{
    EVP_DES_KEY *dat = (EVP_DES_KEY *)ctx->cipher_data;

    DES_ncbc_encrypt(in, out, in_len, &dat->ks.ks, (DES_cblock *)ctx->iv,
                     ctx->encrypt);

    return 1;
}

static const EVP_CIPHER des_cbc = {
    .nid        = NID_des_cbc,
    .block_size = 8,
    .key_len    = 8,
    .iv_len     = 8,
    .ctx_size   = sizeof(EVP_DES_KEY),
    .flags      = EVP_CIPH_CBC_MODE,
    .init       = des_init_key,
    .do_cipher  = des_cbc_cipher,
};

const EVP_CIPHER *EVP_des_cbc(void)
{
    return &des_cbc;
}

typedef struct {
    union {
        double align;
        DES_key_schedule ks[3];
    } ks;
    union {
        void (*cbc) (const void *, void *, size_t,
                     const DES_key_schedule *, uint8_t *);
    } stream;
} DES_EDE_KEY;

static int des_ede3_init_key(EVP_CIPHER_CTX *ctx, const uint8_t *key,
                             const uint8_t *iv, int enc)
{
    DES_cblock *deskey = (DES_cblock *)key;
    DES_EDE_KEY *dat = (DES_EDE_KEY *)ctx->cipher_data;

    DES_set_key(&deskey[0], &dat->ks.ks[0]);
    DES_set_key(&deskey[1], &dat->ks.ks[1]);
    DES_set_key(&deskey[2], &dat->ks.ks[2]);

    return 1;
}

static int des_ede3_cbc_cipher(EVP_CIPHER_CTX *ctx, uint8_t *out,
                               const uint8_t *in, size_t in_len)
{
    DES_EDE_KEY *dat = (DES_EDE_KEY *)ctx->cipher_data;

    DES_ede3_cbc_encrypt(in, out, in_len, &dat->ks.ks[0], &dat->ks.ks[1],
                         &dat->ks.ks[2], (DES_cblock *)ctx->iv, ctx->encrypt);

    return 1;
}

static int des_ede_cbc_cipher(EVP_CIPHER_CTX *ctx, uint8_t *out,
                              const uint8_t *in, size_t inl)
{
    DES_EDE_KEY *dat = (DES_EDE_KEY *)ctx->cipher_data;

    if (dat->stream.cbc) {
        (*dat->stream.cbc) (in, out, inl, dat->ks.ks, ctx->iv);
        return 1;
    }

    while (inl >= EVP_MAXCHUNK) {
        DES_ede3_cbc_encrypt(in, out, (long)EVP_MAXCHUNK,
                             &dat->ks1, &dat->ks2, &dat->ks3,
                             (DES_cblock *)ctx->iv, ctx->encrypt);
        inl -= EVP_MAXCHUNK;
        in += EVP_MAXCHUNK;
        out += EVP_MAXCHUNK;
    }
    if (inl)
        DES_ede3_cbc_encrypt(in, out, (long)inl,
                             &dat->ks1, &dat->ks2, &dat->ks3,
                             (DES_cblock *)ctx->iv, ctx->encrypt);
    return 1;
}

static const EVP_CIPHER des3_cbc = {
    .nid        = NID_des_cbc,
    .block_size = 8,
    .key_len    = 24,
    .iv_len     = 8,
    .ctx_size   = sizeof(DES_EDE_KEY),
    .flags      = EVP_CIPH_CBC_MODE,
    .init       = des_ede3_init_key,
    .do_cipher  = des_ede3_cbc_cipher,
};

const EVP_CIPHER *EVP_des_ede3_cbc(void)
{
    return &des3_cbc;
}

static const uint8_t wrap_iv[8] = {
    0x4a, 0xdd, 0xa2, 0x2c, 0x79, 0xe8, 0x21, 0x05
};

static int des_ede3_unwrap(EVP_CIPHER_CTX *ctx, uint8_t *out, const uint8_t *in,
                           size_t inl)
{
    uint8_t icv[8], iv[8], sha1tmp[SHA_DIGEST_LENGTH];
    int rv = -1;

    if (inl < 24)
        return -1;
    if (out == NULL)
        return inl - 16;
    memcpy(ctx->iv, wrap_iv, 8);
    /* Decrypt first block which will end up as icv */
    des_ede_cbc_cipher(ctx, icv, in, 8);
    /* Decrypt central blocks */
    /*
     * If decrypting in place move whole output along a block
     * so the next des_ede_cbc_cipher is in place.
     */
    if (out == in) {
        memmove(out, out + 8, inl - 8);
        in -= 8;
    }
    des_ede_cbc_cipher(ctx, out, in + 8, inl - 16);
    /* Decrypt final block which will be IV */
    des_ede_cbc_cipher(ctx, iv, in + inl - 8, 8);
    /* Reverse order of everything */
    BUF_reverse(icv, NULL, 8);
    BUF_reverse(out, NULL, inl - 16);
    BUF_reverse(ctx->iv, iv, 8);
    /* Decrypt again using new IV */
    des_ede_cbc_cipher(ctx, out, out, inl - 16);
    des_ede_cbc_cipher(ctx, icv, icv, 8);
    /* Work out SHA1 hash of first portion */
    SHA1(out, inl - 16, sha1tmp);

    if (CRYPTO_memcmp(sha1tmp, icv, 8) == 0)
        rv = inl - 16;
    vigortls_zeroize(icv, 8);
    vigortls_zeroize(sha1tmp, SHA_DIGEST_LENGTH);
    vigortls_zeroize(iv, 8);
    vigortls_zeroize(ctx->iv, 8);
    if (rv == -1)
        vigortls_zeroize(out, inl - 16);

    return rv;
}

static int des_ede3_wrap(EVP_CIPHER_CTX *ctx, uint8_t *out, const uint8_t *in,
                         size_t inl)
{
    uint8_t sha1tmp[SHA_DIGEST_LENGTH];
    if (out == NULL)
        return inl + 16;
    /* Copy input to output buffer + 8 so we have space for IV */
    memmove(out + 8, in, inl);
    /* Work out ICV */
    SHA1(in, inl, sha1tmp);
    memcpy(out + inl + 8, sha1tmp, 8);
    vigortls_zeroize(sha1tmp, SHA_DIGEST_LENGTH);
    /* Generate random IV */
    if (RAND_bytes(ctx->iv, 8) <= 0)
        return -1;
    memcpy(out, ctx->iv, 8);
    /* Encrypt everything after IV in place */
    des_ede_cbc_cipher(ctx, out + 8, out + 8, inl + 8);
    BUF_reverse(out, NULL, inl + 16);
    memcpy(ctx->iv, wrap_iv, 8);
    des_ede_cbc_cipher(ctx, out, out, inl + 16);
    return inl + 16;
}

static int des_ede3_wrap_cipher(EVP_CIPHER_CTX *ctx, uint8_t *out,
                                const uint8_t *in, size_t inl)
{
    /*
     * Sanity check input length: we typically only wrap keys
     * so EVP_MAXCHUNK is more than will ever be needed. Also
     * input length must be a multiple of 8 bits.
     */
    if (inl >= EVP_MAXCHUNK || inl % 8)
        return -1;
    if (ctx->encrypt)
        return des_ede3_wrap(ctx, out, in, inl);
    else
        return des_ede3_unwrap(ctx, out, in, inl);
}

static const EVP_CIPHER des3_wrap = {
    .nid = NID_id_smime_alg_CMS3DESwrap,
    .block_size = 8,
    .key_len = 24,
    .flags = EVP_CIPH_WRAP_MODE | EVP_CIPH_CUSTOM_IV |
             EVP_CIPH_FLAG_CUSTOM_CIPHER | EVP_CIPH_FLAG_DEFAULT_ASN1,
    .init = des_ede3_init_key,
    .do_cipher = des_ede3_wrap_cipher,
    .ctx_size = sizeof(DES_EDE_KEY),
};

const EVP_CIPHER *EVP_des_ede3_wrap(void)
{
    return &des3_wrap;
}
