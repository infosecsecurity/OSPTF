/*
 * Copyright 2011-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/opensslconf.h>

#include <stdio.h>
#include <string.h>


#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/rc4.h>
#include <openssl/md5.h>

#ifndef EVP_CIPH_FLAG_AEAD_CIPHER
#define EVP_CIPH_FLAG_AEAD_CIPHER 0x200000
#define EVP_CTRL_AEAD_TLS1_AAD 0x16
#define EVP_CTRL_AEAD_SET_MAC_KEY 0x17
#endif

#define EVP_RC4_KEY_SIZE 16

typedef struct
    {
    RC4_KEY ks;
    MD5_CTX head, tail, md;
    size_t payload_length;
} EVP_RC4_HMAC_MD5;

#define NO_PAYLOAD_LENGTH ((size_t)-1)

void rc4_md5_enc(RC4_KEY *key, const void *in0, void *out,
                 MD5_CTX *ctx, const void *inp, size_t blocks);

#define data(ctx) ((EVP_RC4_HMAC_MD5 *)(ctx)->cipher_data)

static int rc4_hmac_md5_init_key(EVP_CIPHER_CTX *ctx,
                                 const uint8_t *inkey,
                                 const uint8_t *iv, int enc)
{
    EVP_RC4_HMAC_MD5 *key = data(ctx);

    RC4_set_key(&key->ks, EVP_CIPHER_CTX_key_length(ctx),
                inkey);

    MD5_Init(&key->head); /* handy when benchmarking */
    key->tail = key->head;
    key->md = key->head;

    key->payload_length = NO_PAYLOAD_LENGTH;

    return 1;
}

static int rc4_hmac_md5_cipher(EVP_CIPHER_CTX *ctx, uint8_t *out,
                               const uint8_t *in, size_t len)
{
    EVP_RC4_HMAC_MD5 *key = data(ctx);
    size_t plen = key->payload_length;

    if (plen != NO_PAYLOAD_LENGTH && len != (plen + MD5_DIGEST_LENGTH))
        return 0;

    if (ctx->encrypt) {
        if (plen == NO_PAYLOAD_LENGTH)
            plen = len;
        MD5_Update(&key->md, in, plen);

        if (plen != len) { /* "TLS" mode of operation */
            if (in != out)
                memcpy(out, in, plen);

            /* calculate HMAC and append it to payload */
            MD5_Final(out + plen, &key->md);
            key->md = key->tail;
            MD5_Update(&key->md, out + plen, MD5_DIGEST_LENGTH);
            MD5_Final(out + plen, &key->md);
            /* encrypt HMAC at once */
            RC4(&key->ks, len, out, out);
        } else {
            RC4(&key->ks, len, in, out);
        }
    } else {
        uint8_t mac[MD5_DIGEST_LENGTH];
        /* decrypt HMAC at once */
        RC4(&key->ks, len, in, out);
        if (plen != NO_PAYLOAD_LENGTH) { /* "TLS" mode of operation */
            MD5_Update(&key->md, out, plen);

            /* calculate HMAC and verify it */
            MD5_Final(mac, &key->md);
            key->md = key->tail;
            MD5_Update(&key->md, mac, MD5_DIGEST_LENGTH);
            MD5_Final(mac, &key->md);

            if (CRYPTO_memcmp(out + plen, mac, MD5_DIGEST_LENGTH) != 0)
                return 0;
        } else {
            MD5_Update(&key->md, out, len);
        }
    }

    key->payload_length = NO_PAYLOAD_LENGTH;

    return 1;
}

static int rc4_hmac_md5_ctrl(EVP_CIPHER_CTX *ctx, int type, int arg, void *ptr)
{
    EVP_RC4_HMAC_MD5 *key = data(ctx);

    switch (type) {
        case EVP_CTRL_AEAD_SET_MAC_KEY: {
            unsigned int i;
            uint8_t hmac_key[64];

            memset(hmac_key, 0, sizeof(hmac_key));

            if (arg > (int)sizeof(hmac_key)) {
                MD5_Init(&key->head);
                MD5_Update(&key->head, ptr, arg);
                MD5_Final(hmac_key, &key->head);
            } else {
                memcpy(hmac_key, ptr, arg);
            }

            for (i = 0; i < sizeof(hmac_key); i++)
                hmac_key[i] ^= 0x36; /* ipad */
            MD5_Init(&key->head);
            MD5_Update(&key->head, hmac_key, sizeof(hmac_key));

            for (i = 0; i < sizeof(hmac_key); i++)
                hmac_key[i] ^= 0x36 ^ 0x5c; /* opad */
            MD5_Init(&key->tail);
            MD5_Update(&key->tail, hmac_key, sizeof(hmac_key));

            return 1;
        }
        case EVP_CTRL_AEAD_TLS1_AAD: {
            uint8_t *p = ptr;
            unsigned int len;

            if (arg != EVP_AEAD_TLS1_AAD_LEN)
                return -1;

            len = p[arg - 2] << 8 | p[arg - 1];

            if (!ctx->encrypt) {
                len -= MD5_DIGEST_LENGTH;
                p[arg - 2] = len >> 8;
                p[arg - 1] = len;
            }
            key->payload_length = len;
            key->md = key->head;
            MD5_Update(&key->md, p, arg);

            return MD5_DIGEST_LENGTH;
        }
        default:
            return -1;
    }
}

static EVP_CIPHER r4_hmac_md5_cipher = {
#ifdef NID_rc4_hmac_md5
    NID_rc4_hmac_md5,
#else
    NID_undef,
#endif
    1, EVP_RC4_KEY_SIZE, 0,
    EVP_CIPH_STREAM_CIPHER | EVP_CIPH_VARIABLE_LENGTH | EVP_CIPH_FLAG_AEAD_CIPHER,
    rc4_hmac_md5_init_key,
    rc4_hmac_md5_cipher,
    NULL,
    sizeof(EVP_RC4_HMAC_MD5),
    NULL,
    NULL,
    rc4_hmac_md5_ctrl,
    NULL
};

const EVP_CIPHER *EVP_rc4_hmac_md5(void)
{
    return (&r4_hmac_md5_cipher);
}
