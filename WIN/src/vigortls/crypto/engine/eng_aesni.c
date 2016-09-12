/*
 * Copyright 2001-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/opensslconf.h>

#if !defined(OPENSSL_NO_HW) && !defined(OPENSSL_NO_HW_AES_NI) && !defined(OPENSSL_NO_AES)

#include <stdio.h>
#include <assert.h>
#include <openssl/dso.h>
#include <openssl/engine.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/err.h>

/* AES-NI is available *ONLY* on some x86 CPUs.  Not only that it
   doesn't exist elsewhere, but it even can't be compiled on other
   platforms! */
#undef COMPILE_HW_AESNI
#if (defined(VIGORTLS_X86_64 || defined(OPENSSL_IA32_SSE2)) && !defined(OPENSSL_NO_ASM) && !defined(VIGORTLS_X86)
#define COMPILE_HW_AESNI
#endif
static ENGINE *ENGINE_aesni(void);

void ENGINE_load_aesni(void)
{
/* On non-x86 CPUs it just returns. */
#ifdef COMPILE_HW_AESNI
    ENGINE *toadd = ENGINE_aesni();
    if (!toadd)
        return;
    ENGINE_add(toadd);
    ENGINE_register_complete(toadd);
    ENGINE_free(toadd);
    ERR_clear_error();
#endif
}

#ifdef COMPILE_HW_AESNI
int aesni_set_encrypt_key(const uint8_t *userKey, int bits,
                          AES_KEY *key);
int aesni_set_decrypt_key(const uint8_t *userKey, int bits,
                          AES_KEY *key);

void aesni_encrypt(const uint8_t *in, uint8_t *out,
                   const AES_KEY *key);
void aesni_decrypt(const uint8_t *in, uint8_t *out,
                   const AES_KEY *key);

void aesni_ecb_encrypt(const uint8_t *in, uint8_t *out,
                       size_t length, const AES_KEY *key, int enc);
void aesni_cbc_encrypt(const uint8_t *in, uint8_t *out,
                       size_t length, const AES_KEY *key, uint8_t *ivec, int enc);

/* Function for ENGINE detection and control */
static int aesni_init(ENGINE *e);

/* Cipher Stuff */
static int aesni_ciphers(ENGINE *e, const EVP_CIPHER **cipher,
                         const int **nids, int nid);

#define AESNI_MIN_ALIGN 16
#define AESNI_ALIGN(x) \
    ((void *)(((unsigned long)(x) + AESNI_MIN_ALIGN - 1) & ~(AESNI_MIN_ALIGN - 1)))

/* Engine names */
static const char aesni_id[] = "aesni",
                  aesni_name[] = "Intel AES-NI engine",
                  no_aesni_name[] = "Intel AES-NI engine (no-aesni)";

/* The input and output encrypted as though 128bit cfb mode is being
 * used.  The extra state information to record how much of the
 * 128bit block we have used is contained in *num;
 */
static void
aesni_cfb128_encrypt(const uint8_t *in, uint8_t *out,
                     unsigned int len, const void *key, uint8_t ivec[16], int *num,
                     int enc)
{
    unsigned int n;
    size_t l = 0;

    assert(in && out && key && ivec && num);

    n = *num;

    if (enc) {
#if !defined(OPENSSL_SMALL_FOOTPRINT)
        if (16 % sizeof(size_t) == 0)
            do { /* always true actually */
                while (n && len) {
                    *(out++) = ivec[n] ^= *(in++);
                    --len;
                    n = (n + 1) % 16;
                }
                while (len >= 16) {
                    aesni_encrypt(ivec, ivec, key);
                    for (n = 0; n < 16; n += sizeof(size_t)) {
                        *(size_t *)(out + n) = *(size_t *)(ivec + n) ^= *(size_t *)(in + n);
                    }
                    len -= 16;
                    out += 16;
                    in += 16;
                }
                n = 0;
                if (len) {
                    aesni_encrypt(ivec, ivec, key);
                    while (len--) {
                        out[n] = ivec[n] ^= in[n];
                        ++n;
                    }
                }
                *num = n;
                return;
            } while (0);
/* the rest would be commonly eliminated by x86* compiler */
#endif
        while (l < len) {
            if (n == 0) {
                aesni_encrypt(ivec, ivec, key);
            }
            out[l] = ivec[n] ^= in[l];
            ++l;
            n = (n + 1) % 16;
        }
        *num = n;
    } else {
#if !defined(OPENSSL_SMALL_FOOTPRINT)
        if (16 % sizeof(size_t) == 0)
            do { /* always true actually */
                while (n && len) {
                    uint8_t c;
                    *(out++) = ivec[n] ^ (c = *(in++));
                    ivec[n] = c;
                    --len;
                    n = (n + 1) % 16;
                }
                while (len >= 16) {
                    aesni_encrypt(ivec, ivec, key);
                    for (n = 0; n < 16; n += sizeof(size_t)) {
                        size_t t = *(size_t *)(in + n);
                        *(size_t *)(out + n) = *(size_t *)(ivec + n) ^ t;
                        *(size_t *)(ivec + n) = t;
                    }
                    len -= 16;
                    out += 16;
                    in += 16;
                }
                n = 0;
                if (len) {
                    aesni_encrypt(ivec, ivec, key);
                    while (len--) {
                        uint8_t c;
                        out[n] = ivec[n] ^ (c = in[n]);
                        ivec[n] = c;
                        ++n;
                    }
                }
                *num = n;
                return;
            } while (0);
/* the rest would be commonly eliminated by x86* compiler */
#endif
        while (l < len) {
            uint8_t c;
            if (n == 0) {
                aesni_encrypt(ivec, ivec, key);
            }
            out[l] = ivec[n] ^ (c = in[l]);
            ivec[n] = c;
            ++l;
            n = (n + 1) % 16;
        }
        *num = n;
    }
}

/* The input and output encrypted as though 128bit ofb mode is being
 * used.  The extra state information to record how much of the
 * 128bit block we have used is contained in *num;
 */
static void
aesni_ofb128_encrypt(const uint8_t *in, uint8_t *out,
                     unsigned int len, const void *key, uint8_t ivec[16], int *num)
{
    unsigned int n;
    size_t l = 0;

    assert(in && out && key && ivec && num);

    n = *num;

#if !defined(OPENSSL_SMALL_FOOTPRINT)
    if (16 % sizeof(size_t) == 0)
        do { /* always true actually */
            while (n && len) {
                *(out++) = *(in++) ^ ivec[n];
                --len;
                n = (n + 1) % 16;
            }
            while (len >= 16) {
                aesni_encrypt(ivec, ivec, key);
                for (n = 0; n < 16; n += sizeof(size_t))
                    *(size_t *)(out + n) = *(size_t *)(in + n) ^ *(size_t *)(ivec + n);
                len -= 16;
                out += 16;
                in += 16;
            }
            n = 0;
            if (len) {
                aesni_encrypt(ivec, ivec, key);
                while (len--) {
                    out[n] = in[n] ^ ivec[n];
                    ++n;
                }
            }
            *num = n;
            return;
        } while (0);
/* the rest would be commonly eliminated by x86* compiler */
#endif
    while (l < len) {
        if (n == 0) {
            aesni_encrypt(ivec, ivec, key);
        }
        out[l] = in[l] ^ ivec[n];
        ++l;
        n = (n + 1) % 16;
    }

    *num = n;
}
/* ===== Engine "management" functions ===== */

typedef uint64_t IA32CAP;

/* Prepare the ENGINE structure for registration */
static int
aesni_bind_helper(ENGINE *e)
{
    int engage;

    if (sizeof(OPENSSL_ia32cap_P) > 4) {
        engage = ((IA32CAP)OPENSSL_ia32cap_P >> 57) & 1;
    } else {
        IA32CAP OPENSSL_ia32_cpuid(void);
        engage = (OPENSSL_ia32_cpuid() >> 57) & 1;
    }

    /* Register everything or return with an error */
    if (!ENGINE_set_id(e, aesni_id) || !ENGINE_set_name(e, engage ? aesni_name : no_aesni_name) || !ENGINE_set_init_function(e, aesni_init) || (engage && !ENGINE_set_ciphers(e, aesni_ciphers)))
        return 0;

    /* Everything looks good */
    return 1;
}

/* Constructor */
static ENGINE *
ENGINE_aesni(void)
{
    ENGINE *eng = ENGINE_new();

    if (!eng) {
        return NULL;
    }

    if (!aesni_bind_helper(eng)) {
        ENGINE_free(eng);
        return NULL;
    }

    return eng;
}

/* Check availability of the engine */
static int
aesni_init(ENGINE *e)
{
    return 1;
}

#if defined(NID_aes_128_cfb128) && !defined(NID_aes_128_cfb)
#define NID_aes_128_cfb NID_aes_128_cfb128
#endif

#if defined(NID_aes_128_ofb128) && !defined(NID_aes_128_ofb)
#define NID_aes_128_ofb NID_aes_128_ofb128
#endif

#if defined(NID_aes_192_cfb128) && !defined(NID_aes_192_cfb)
#define NID_aes_192_cfb NID_aes_192_cfb128
#endif

#if defined(NID_aes_192_ofb128) && !defined(NID_aes_192_ofb)
#define NID_aes_192_ofb NID_aes_192_ofb128
#endif

#if defined(NID_aes_256_cfb128) && !defined(NID_aes_256_cfb)
#define NID_aes_256_cfb NID_aes_256_cfb128
#endif

#if defined(NID_aes_256_ofb128) && !defined(NID_aes_256_ofb)
#define NID_aes_256_ofb NID_aes_256_ofb128
#endif

/* List of supported ciphers. */
static int aesni_cipher_nids[] = {
    NID_aes_128_ecb,
    NID_aes_128_cbc,
    NID_aes_128_cfb,
    NID_aes_128_ofb,

    NID_aes_192_ecb,
    NID_aes_192_cbc,
    NID_aes_192_cfb,
    NID_aes_192_ofb,

    NID_aes_256_ecb,
    NID_aes_256_cbc,
    NID_aes_256_cfb,
    NID_aes_256_ofb,
};
static int aesni_cipher_nids_num = (sizeof(aesni_cipher_nids) / sizeof(aesni_cipher_nids[0]));

typedef struct {
    AES_KEY ks;
    unsigned int _pad1[3];
} AESNI_KEY;

static int
aesni_init_key(EVP_CIPHER_CTX *ctx, const uint8_t *user_key,
               const uint8_t *iv, int enc)
{
    int ret;
    AES_KEY *key = AESNI_ALIGN(ctx->cipher_data);

    if ((ctx->cipher->flags & EVP_CIPH_MODE) == EVP_CIPH_CFB_MODE || (ctx->cipher->flags & EVP_CIPH_MODE) == EVP_CIPH_OFB_MODE || enc)
        ret = aesni_set_encrypt_key(user_key, ctx->key_len * 8, key);
    else
        ret = aesni_set_decrypt_key(user_key, ctx->key_len * 8, key);

    if (ret < 0) {
        EVPerr(EVP_F_AESNI_INIT_KEY, EVP_R_AES_KEY_SETUP_FAILED);
        return 0;
    }

    return 1;
}

static int
aesni_cipher_ecb(EVP_CIPHER_CTX *ctx, uint8_t *out,
                 const uint8_t *in, size_t inl)
{
    AES_KEY *key = AESNI_ALIGN(ctx->cipher_data);

    aesni_ecb_encrypt(in, out, inl, key, ctx->encrypt);
    return 1;
}

static int
aesni_cipher_cbc(EVP_CIPHER_CTX *ctx, uint8_t *out,
                 const uint8_t *in, size_t inl)
{
    AES_KEY *key = AESNI_ALIGN(ctx->cipher_data);

    aesni_cbc_encrypt(in, out, inl, key, ctx->iv, ctx->encrypt);
    return 1;
}

static int
aesni_cipher_cfb(EVP_CIPHER_CTX *ctx, uint8_t *out,
                 const uint8_t *in, size_t inl)
{
    AES_KEY *key = AESNI_ALIGN(ctx->cipher_data);

    aesni_cfb128_encrypt(in, out, inl, key, ctx->iv, &ctx->num,
                         ctx->encrypt);
    return 1;
}

static int
aesni_cipher_ofb(EVP_CIPHER_CTX *ctx, uint8_t *out,
                 const uint8_t *in, size_t inl)
{
    AES_KEY *key = AESNI_ALIGN(ctx->cipher_data);

    aesni_ofb128_encrypt(in, out, inl, key, ctx->iv, &ctx->num);
    return 1;
}

#define AES_BLOCK_SIZE 16

#define EVP_CIPHER_block_size_ECB AES_BLOCK_SIZE
#define EVP_CIPHER_block_size_CBC AES_BLOCK_SIZE
#define EVP_CIPHER_block_size_OFB 1
#define EVP_CIPHER_block_size_CFB 1

/* Declaring so many ciphers by hand would be a pain.
   Instead introduce a bit of preprocessor magic :-) */
#define DECLARE_AES_EVP(ksize, lmode, umode)            \
    static const EVP_CIPHER aesni_##ksize##_##lmode = { \
        NID_aes_##ksize##_##lmode,                      \
        EVP_CIPHER_block_size_##umode,                  \
        ksize / 8,                                      \
        AES_BLOCK_SIZE,                                 \
        0 | EVP_CIPH_##umode##_MODE,                    \
        aesni_init_key,                                 \
        aesni_cipher_##lmode,                           \
        NULL,                                           \
        sizeof(AESNI_KEY),                              \
        EVP_CIPHER_set_asn1_iv,                         \
        EVP_CIPHER_get_asn1_iv,                         \
        NULL,                                           \
        NULL                                            \
    }

DECLARE_AES_EVP(128, ecb, ECB);
DECLARE_AES_EVP(128, cbc, CBC);
DECLARE_AES_EVP(128, cfb, CFB);
DECLARE_AES_EVP(128, ofb, OFB);

DECLARE_AES_EVP(192, ecb, ECB);
DECLARE_AES_EVP(192, cbc, CBC);
DECLARE_AES_EVP(192, cfb, CFB);
DECLARE_AES_EVP(192, ofb, OFB);

DECLARE_AES_EVP(256, ecb, ECB);
DECLARE_AES_EVP(256, cbc, CBC);
DECLARE_AES_EVP(256, cfb, CFB);
DECLARE_AES_EVP(256, ofb, OFB);

static int
aesni_ciphers(ENGINE *e, const EVP_CIPHER **cipher, const int **nids, int nid)
{
    /* No specific cipher => return a list of supported nids ... */
    if (!cipher) {
        *nids = aesni_cipher_nids;
        return aesni_cipher_nids_num;
    }

    /* ... or the requested "cipher" otherwise */
    switch (nid) {
        case NID_aes_128_ecb:
            *cipher = &aesni_128_ecb;
            break;
        case NID_aes_128_cbc:
            *cipher = &aesni_128_cbc;
            break;
        case NID_aes_128_cfb:
            *cipher = &aesni_128_cfb;
            break;
        case NID_aes_128_ofb:
            *cipher = &aesni_128_ofb;
            break;

        case NID_aes_192_ecb:
            *cipher = &aesni_192_ecb;
            break;
        case NID_aes_192_cbc:
            *cipher = &aesni_192_cbc;
            break;
        case NID_aes_192_cfb:
            *cipher = &aesni_192_cfb;
            break;
        case NID_aes_192_ofb:
            *cipher = &aesni_192_ofb;
            break;

        case NID_aes_256_ecb:
            *cipher = &aesni_256_ecb;
            break;
        case NID_aes_256_cbc:
            *cipher = &aesni_256_cbc;
            break;
        case NID_aes_256_cfb:
            *cipher = &aesni_256_cfb;
            break;
        case NID_aes_256_ofb:
            *cipher = &aesni_256_ofb;
            break;

        default:
            /* Sorry, we don't support this NID */
            *cipher = NULL;
            return 0;
    }
    return 1;
}

#endif /* COMPILE_HW_AESNI */
#endif /* !defined(OPENSSL_NO_HW) && !defined(OPENSSL_NO_HW_AESNI) && !defined(OPENSSL_NO_AES) */
