/*
 * Copyright 2000-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/* Macros to code block cipher wrappers */

/* Wrapper functions for each cipher mode */

#define BLOCK_CIPHER_ecb_loop()   \
    size_t i, bl;                 \
    bl = ctx->cipher->block_size; \
    if (inl < bl)                 \
        return 1;                 \
    inl -= bl;                    \
    for (i = 0; i <= inl; i += bl)

#define BLOCK_CIPHER_func_ecb(cname, cprefix, kstruct, ksched)       \
    static int cname##_ecb_cipher(EVP_CIPHER_CTX *ctx, uint8_t *out, \
                                  const uint8_t *in, size_t inl)     \
    {                                                                \
        BLOCK_CIPHER_ecb_loop() cprefix##_ecb_encrypt(               \
            in + i, out + i, &((kstruct *)ctx->cipher_data)->ksched, \
            ctx->encrypt);                                           \
        return 1;                                                    \
    }

#define EVP_MAXCHUNK ((size_t)1 << (sizeof(long) * 8 - 2))

#define BLOCK_CIPHER_func_ofb(cname, cprefix, cbits, kstruct, ksched)        \
    static int cname##_ofb_cipher(EVP_CIPHER_CTX *ctx, uint8_t *out,         \
                                  const uint8_t *in, size_t inl)             \
    {                                                                        \
        while (inl >= EVP_MAXCHUNK) {                                        \
            cprefix##_ofb##cbits##_encrypt(                                  \
                in, out, (long)EVP_MAXCHUNK,                                 \
                &((kstruct *)ctx->cipher_data)->ksched, ctx->iv, &ctx->num); \
            inl -= EVP_MAXCHUNK;                                             \
            in += EVP_MAXCHUNK;                                              \
            out += EVP_MAXCHUNK;                                             \
        }                                                                    \
        if (inl)                                                             \
            cprefix##_ofb##cbits##_encrypt(                                  \
                in, out, (long)inl, &((kstruct *)ctx->cipher_data)->ksched,  \
                ctx->iv, &ctx->num);                                         \
        return 1;                                                            \
    }

#define BLOCK_CIPHER_func_cbc(cname, cprefix, kstruct, ksched)            \
    static int cname##_cbc_cipher(EVP_CIPHER_CTX *ctx, uint8_t *out,      \
                                  const uint8_t *in, size_t inl)          \
    {                                                                     \
        while (inl >= EVP_MAXCHUNK) {                                     \
            cprefix##_cbc_encrypt(in, out, (long)EVP_MAXCHUNK,            \
                                  &((kstruct *)ctx->cipher_data)->ksched, \
                                  ctx->iv, ctx->encrypt);                 \
            inl -= EVP_MAXCHUNK;                                          \
            in += EVP_MAXCHUNK;                                           \
            out += EVP_MAXCHUNK;                                          \
        }                                                                 \
        if (inl)                                                          \
            cprefix##_cbc_encrypt(in, out, (long)inl,                     \
                                  &((kstruct *)ctx->cipher_data)->ksched, \
                                  ctx->iv, ctx->encrypt);                 \
        return 1;                                                         \
    }

#define BLOCK_CIPHER_func_cfb(cname, cprefix, cbits, kstruct, ksched)         \
    static int cname##_cfb##cbits##_cipher(EVP_CIPHER_CTX *ctx, uint8_t *out, \
                                           const uint8_t *in, size_t inl)     \
    {                                                                         \
        size_t chunk = EVP_MAXCHUNK;                                          \
        if (cbits == 1)                                                       \
            chunk >>= 3;                                                      \
        if (inl < chunk)                                                      \
            chunk = inl;                                                      \
        while (inl && inl >= chunk) {                                         \
            cprefix##_cfb##cbits##_encrypt(                                   \
                in, out,                                                      \
                (long)((cbits == 1)                                           \
                               && !(ctx->flags & EVP_CIPH_FLAG_LENGTH_BITS) ? \
                           inl * 8 :                                          \
                           inl),                                              \
                &((kstruct *)ctx->cipher_data)->ksched, ctx->iv, &ctx->num,   \
                ctx->encrypt);                                                \
            inl -= chunk;                                                     \
            in += chunk;                                                      \
            out += chunk;                                                     \
            if (inl < chunk)                                                  \
                chunk = inl;                                                  \
        }                                                                     \
        return 1;                                                             \
    }

#define BLOCK_CIPHER_all_funcs(cname, cprefix, cbits, kstruct, ksched) \
    BLOCK_CIPHER_func_cbc(cname, cprefix, kstruct, ksched)             \
        BLOCK_CIPHER_func_cfb(cname, cprefix, cbits, kstruct, ksched)  \
            BLOCK_CIPHER_func_ecb(cname, cprefix, kstruct, ksched)     \
                BLOCK_CIPHER_func_ofb(cname, cprefix, cbits, kstruct, ksched)

#define BLOCK_CIPHER_def1(cname, nmode, mode, MODE, kstruct, nid, block_size,  \
                          key_len, iv_len, flags, init_key, cleanup, set_asn1, \
                          get_asn1, ctrl)                                      \
    static const EVP_CIPHER cname##_##mode                                     \
        = { nid##_##nmode, block_size, key_len, iv_len,                        \
            flags | EVP_CIPH_##MODE##_MODE, init_key, cname##_##mode##_cipher, \
            cleanup, sizeof(kstruct), set_asn1, get_asn1, ctrl, NULL };        \
    const EVP_CIPHER *EVP_##cname##_##mode(void)                               \
    {                                                                          \
        return &cname##_##mode;                                                \
    }

#define BLOCK_CIPHER_def_cbc(cname, kstruct, nid, block_size, key_len, iv_len, \
                             flags, init_key, cleanup, set_asn1, get_asn1,     \
                             ctrl)                                             \
    BLOCK_CIPHER_def1(cname, cbc, cbc, CBC, kstruct, nid, block_size, key_len, \
                      iv_len, flags, init_key, cleanup, set_asn1, get_asn1,    \
                      ctrl)

#define BLOCK_CIPHER_def_cfb(cname, kstruct, nid, key_len, iv_len, cbits,  \
                             flags, init_key, cleanup, set_asn1, get_asn1, \
                             ctrl)                                         \
    BLOCK_CIPHER_def1(cname, cfb##cbits, cfb##cbits, CFB, kstruct, nid, 1, \
                      key_len, iv_len, flags, init_key, cleanup, set_asn1, \
                      get_asn1, ctrl)

#define BLOCK_CIPHER_def_ofb(cname, kstruct, nid, key_len, iv_len, cbits,    \
                             flags, init_key, cleanup, set_asn1, get_asn1,   \
                             ctrl)                                           \
    BLOCK_CIPHER_def1(cname, ofb##cbits, ofb, OFB, kstruct, nid, 1, key_len, \
                      iv_len, flags, init_key, cleanup, set_asn1, get_asn1,  \
                      ctrl)

#define BLOCK_CIPHER_def_ecb(cname, kstruct, nid, block_size, key_len, flags,  \
                             init_key, cleanup, set_asn1, get_asn1, ctrl)      \
    BLOCK_CIPHER_def1(cname, ecb, ecb, ECB, kstruct, nid, block_size, key_len, \
                      0, flags, init_key, cleanup, set_asn1, get_asn1, ctrl)

#define BLOCK_CIPHER_defs(cname, kstruct, nid, block_size, key_len, iv_len,    \
                          cbits, flags, init_key, cleanup, set_asn1, get_asn1, \
                          ctrl)                                                \
    BLOCK_CIPHER_def_cbc(cname, kstruct, nid, block_size, key_len, iv_len,     \
                         flags, init_key, cleanup, set_asn1, get_asn1, ctrl)   \
        BLOCK_CIPHER_def_cfb(cname, kstruct, nid, key_len, iv_len, cbits,      \
                             flags, init_key, cleanup, set_asn1, get_asn1,     \
                             ctrl)                                             \
            BLOCK_CIPHER_def_ofb(cname, kstruct, nid, key_len, iv_len, cbits,  \
                                 flags, init_key, cleanup, set_asn1, get_asn1, \
                                 ctrl)                                         \
                BLOCK_CIPHER_def_ecb(cname, kstruct, nid, block_size, key_len, \
                                     flags, init_key, cleanup, set_asn1,       \
                                     get_asn1, ctrl)

#define IMPLEMENT_BLOCK_CIPHER(cname, ksched, cprefix, kstruct, nid,           \
                               block_size, key_len, iv_len, cbits, flags,      \
                               init_key, cleanup, set_asn1, get_asn1, ctrl)    \
    BLOCK_CIPHER_all_funcs(cname, cprefix, cbits, kstruct, ksched)             \
        BLOCK_CIPHER_defs(cname, kstruct, nid, block_size, key_len, iv_len,    \
                          cbits, flags, init_key, cleanup, set_asn1, get_asn1, \
                          ctrl)

#define EVP_C_DATA(kstruct, ctx) ((kstruct *)(ctx)->cipher_data)

#define IMPLEMENT_CFBR(cipher, cprefix, kstruct, ksched, keysize, cbits,       \
                       iv_len)                                                 \
    BLOCK_CIPHER_func_cfb(cipher##_##keysize, cprefix, cbits, kstruct, ksched) \
        BLOCK_CIPHER_def_cfb(                                                  \
            cipher##_##keysize, kstruct, NID_##cipher##_##keysize,             \
            keysize / 8, iv_len, cbits, 0, cipher##_init_key, NULL,            \
            EVP_CIPHER_set_asn1_iv, EVP_CIPHER_get_asn1_iv, NULL)

void evp_pkey_set_cb_translate(BN_GENCB *cb, EVP_PKEY_CTX *ctx);

int PKCS5_v2_PBKDF2_keyivgen(EVP_CIPHER_CTX *ctx, const char *pass, int passlen,
                             ASN1_TYPE *param, const EVP_CIPHER *c,
                             const EVP_MD *md, int en_de);

/* EVP_AEAD represents a specific AEAD algorithm. */
struct evp_aead_st {
    uint8_t key_len;
    uint8_t nonce_len;
    uint8_t overhead;
    uint8_t max_tag_len;

    int (*init)(struct evp_aead_ctx_st *, const uint8_t *key, size_t key_len,
                size_t tag_len);
    void (*cleanup)(struct evp_aead_ctx_st *);

    int (*seal)(const struct evp_aead_ctx_st *ctx, uint8_t *out,
                size_t *out_len, size_t max_out_len, const uint8_t *nonce,
                size_t nonce_len, const uint8_t *in, size_t in_len,
                const uint8_t *ad, size_t ad_len);

    int (*open)(const struct evp_aead_ctx_st *ctx, uint8_t *out,
                size_t *out_len, size_t max_out_len, const uint8_t *nonce,
                size_t nonce_len, const uint8_t *in, size_t in_len,
                const uint8_t *ad, size_t ad_len);
};
