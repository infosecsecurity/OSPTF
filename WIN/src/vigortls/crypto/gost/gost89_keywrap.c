/*
 * Copyright (c) 2014 Dmitry Eremin-Solenikov <dbaryshkov@gmail.com>
 * Copyright (c) 2005-2006 Cryptocom LTD
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <string.h>

#include <openssl/opensslconf.h>

#ifndef OPENSSL_NO_GOST

#include <openssl/gost.h>

#include "gost_locl.h"

static void key_diversify_crypto_pro(GOST2814789_KEY *ctx,
                                     const uint8_t *inputKey,
                                     const uint8_t *ukm,
                                     uint8_t *outputKey)
{

    unsigned long k, s1, s2;
    int i, mask;
    uint8_t S[8];
    uint8_t *p;
    memcpy(outputKey, inputKey, 32);
    for (i = 0; i < 8; i++) {
        /* Make array of integers from key */
        /* Compute IV S */
        s1 = 0, s2 = 0;
        p = outputKey;
        for (mask = 1; mask < 256; mask <<= 1) {
            c2l(p, k);
            if (mask & ukm[i]) {
                s1 += k;
            } else {
                s2 += k;
            }
        }
        p = S;
        l2c(s1, p);
        l2c(s2, p);
        Gost2814789_set_key(ctx, outputKey, 256);
        mask = 0;
        Gost2814789_cfb64_encrypt(outputKey, outputKey, 32, ctx, S, &mask, 1);
    }
}

int gost_key_wrap_crypto_pro(int nid, const uint8_t *keyExchangeKey,
                             const uint8_t *ukm, const uint8_t *sessionKey,
                             uint8_t *wrappedKey)
{
    GOST2814789_KEY ctx;
    uint8_t kek_ukm[32];

    Gost2814789_set_sbox(&ctx, nid);
    key_diversify_crypto_pro(&ctx, keyExchangeKey, ukm, kek_ukm);
    Gost2814789_set_key(&ctx, kek_ukm, 256);
    memcpy(wrappedKey, ukm, 8);
    Gost2814789_encrypt(sessionKey + 0, wrappedKey + 8 + 0, &ctx);
    Gost2814789_encrypt(sessionKey + 8, wrappedKey + 8 + 8, &ctx);
    Gost2814789_encrypt(sessionKey + 16, wrappedKey + 8 + 16, &ctx);
    Gost2814789_encrypt(sessionKey + 24, wrappedKey + 8 + 24, &ctx);
    GOST2814789IMIT(sessionKey, 32, wrappedKey + 40, nid, kek_ukm, ukm);
    return 1;
}

int gost_key_unwrap_crypto_pro(int nid, const uint8_t *keyExchangeKey,
                               const uint8_t *wrappedKey,
                               uint8_t *sessionKey)
{
    uint8_t kek_ukm[32], cek_mac[4];
    GOST2814789_KEY ctx;

    Gost2814789_set_sbox(&ctx, nid);
    /* First 8 bytes of wrapped Key is ukm */
    key_diversify_crypto_pro(&ctx, keyExchangeKey, wrappedKey, kek_ukm);
    Gost2814789_set_key(&ctx, kek_ukm, 256);
    Gost2814789_decrypt(wrappedKey + 8 + 0, sessionKey + 0, &ctx);
    Gost2814789_decrypt(wrappedKey + 8 + 8, sessionKey + 8, &ctx);
    Gost2814789_decrypt(wrappedKey + 8 + 16, sessionKey + 16, &ctx);
    Gost2814789_decrypt(wrappedKey + 8 + 24, sessionKey + 24, &ctx);

    GOST2814789IMIT(sessionKey, 32, cek_mac, nid, kek_ukm, wrappedKey);
    if (memcmp(cek_mac, wrappedKey + 40, 4)) {
        printf("IMIT Mismatch!\n");
        return 0;
    }
    return 1;
}

#endif
