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
#include <openssl/err.h>
#include <openssl/gost.h>
#include "gost_locl.h"

/* Convert little-endian byte array into bignum */
BIGNUM *GOST_le2bn(const uint8_t *buf, size_t len, BIGNUM *bn)
{
    uint8_t temp[64];
    int i;
    if (len > 64)
        return NULL;

    for (i = 0; i < len; i++) {
        temp[len - 1 - i] = buf[i];
    }

    return BN_bin2bn(temp, len, bn);
}

int GOST_bn2le(BIGNUM *bn, uint8_t *buf, int len)
{
    uint8_t temp[64];
    int i, bytes;

    bytes = BN_num_bytes(bn);
    if (len > 64 || bytes > len)
        return 0;

    BN_bn2bin(bn, temp);

    for (i = 0; i < bytes; i++) {
        buf[bytes - 1 - i] = temp[i];
    }

    memset(buf + bytes, 0, len - bytes);

    return 1;
}

int gost2001_compute_public(GOST_KEY *ec)
{
    const EC_GROUP *group = GOST_KEY_get0_group(ec);
    EC_POINT *pub_key = NULL;
    const BIGNUM *priv_key = NULL;
    BN_CTX *ctx = NULL;
    int ok = 0;

    if (group == NULL) {
        GOSTerr(GOST_F_GOST2001_COMPUTE_PUBLIC, GOST_R_KEY_IS_NOT_INITIALIZED);
        return 0;
    }
    ctx = BN_CTX_new();
    if (ctx == NULL) {
        GOSTerr(GOST_F_GOST2001_COMPUTE_PUBLIC, ERR_R_MALLOC_FAILURE);
        return 0;
    }
    BN_CTX_start(ctx);
    if ((priv_key = GOST_KEY_get0_private_key(ec)) == NULL)
        goto err;

    pub_key = EC_POINT_new(group);
    if (pub_key == NULL)
        goto err;
    if (EC_POINT_mul(group, pub_key, priv_key, NULL, NULL, ctx) == 0)
        goto err;
    if (GOST_KEY_set_public_key(ec, pub_key) == 0)
        goto err;
    ok = 1;

err:
    if (ok == 0)
        GOSTerr(GOST_F_GOST2001_COMPUTE_PUBLIC, ERR_R_EC_LIB);
    EC_POINT_free(pub_key);
    BN_CTX_end(ctx);    
    BN_CTX_free(ctx);
    return ok;
}

ECDSA_SIG *gost2001_do_sign(BIGNUM *md, GOST_KEY *eckey)
{
    ECDSA_SIG *newsig = NULL;
    BIGNUM *order = NULL;
    const EC_GROUP *group;
    const BIGNUM *priv_key;
    BIGNUM *r = NULL, *s = NULL, *X = NULL, *tmp = NULL, *tmp2 = NULL, *k = NULL,
           *e = NULL;
    EC_POINT *C = NULL;
    BN_CTX *ctx = BN_CTX_new();
    int ok = 0;

    if (ctx == NULL) {
        GOSTerr(GOST_F_GOST2001_DO_SIGN, ERR_R_MALLOC_FAILURE);
        return NULL;
    }
    BN_CTX_start(ctx);
    newsig = ECDSA_SIG_new();
    if (newsig == NULL) {
        GOSTerr(GOST_F_GOST2001_DO_SIGN, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    s = newsig->s;
    r = newsig->r;
    group = GOST_KEY_get0_group(eckey);
    if ((order = BN_CTX_get(ctx)) == NULL)
        goto err;
    if (EC_GROUP_get_order(group, order, ctx) == 0)
        goto err;
    priv_key = GOST_KEY_get0_private_key(eckey);   
    if ((e = BN_CTX_get(ctx)) == NULL)
        goto err;
    if (BN_mod(e, md, order, ctx) == 0)
        goto err;
    if (BN_is_zero(e))
        BN_one(e);
    if ((k = BN_CTX_get(ctx)) == NULL)
        goto err;
    if ((X = BN_CTX_get(ctx)) == NULL)
        goto err;
    if ((C = EC_POINT_new(group)) == NULL)
        goto err;
    do {
        do {
            if (!BN_rand_range(k, order)) {
                GOSTerr(GOST_F_GOST2001_DO_SIGN,
                        GOST_R_RANDOM_NUMBER_GENERATOR_FAILED);
                goto err;
            }
            /*
             * We do not want timing information to leak the length of k,
             * so we compute G*k using an equivalent scalar of fixed
             * bit-length.
             */
            if (BN_add(k, k, order) == 0)
                goto err;
            if (BN_num_bits(k) <= BN_num_bits(order))
                if (!BN_add(k, k, order))
                    goto err;

            if (EC_POINT_mul(group, C, k, NULL, NULL, ctx) == 0) {
                GOSTerr(GOST_F_GOST2001_DO_SIGN, ERR_R_EC_LIB);
                goto err;
            }
            if (EC_POINT_get_affine_coordinates_GFp(group, C, X, NULL, ctx) == 0) {
                GOSTerr(GOST_F_GOST2001_DO_SIGN, ERR_R_EC_LIB);
                goto err;
            }
            if (BN_nnmod(r, X, order, ctx) == 0)
                goto err;
        } while (BN_is_zero(r));
        /* s =  (r*priv_key+k*e) mod order */
        if (tmp == NULL) {
            if ((tmp = BN_CTX_get(ctx)) == NULL)
                goto err;
        }
        if (BN_mod_mul(tmp, priv_key, r, order, ctx) == 0)
            goto err;
        if (tmp2 == NULL) {
            if ((tmp2 = BN_CTX_get(ctx)) == NULL)
                goto err;
        }
        if (BN_mod_mul(tmp2, k, e, order, ctx) == 0)
            goto err;
        if (BN_mod_add(s, tmp, tmp2, order, ctx) == 0)
            goto err;
    } while (BN_is_zero(s));
    ok = 1;
err:
    EC_POINT_free(C);
    if (ctx != NULL) {
        BN_CTX_end(ctx);
        BN_CTX_free(ctx);
    }
    if (ok == 0) {
        ECDSA_SIG_free(newsig);
        newsig = NULL;
    }
    return newsig;
}

int gost2001_do_verify(BIGNUM *md, ECDSA_SIG *sig, GOST_KEY *ec)
{
    BN_CTX *ctx = BN_CTX_new();
    const EC_GROUP *group = GOST_KEY_get0_group(ec);
    BIGNUM *order;
    BIGNUM *e = NULL, *R = NULL, *v = NULL, *z1 = NULL, *z2 = NULL;
    BIGNUM *X = NULL, *tmp = NULL;
    EC_POINT *C = NULL;
    const EC_POINT *pub_key = NULL;
    int ok = 0;

    if (ctx == NULL)
        goto err;
    BN_CTX_start(ctx);
    if ((order = BN_CTX_get(ctx)) == NULL)
        goto err;
    if ((e = BN_CTX_get(ctx)) == NULL)
        goto err;
    if ((z1 = BN_CTX_get(ctx)) == NULL)
        goto err;
    if ((z2 = BN_CTX_get(ctx)) == NULL)
        goto err;
    if ((tmp = BN_CTX_get(ctx)) == NULL)
        goto err;
    if ((X = BN_CTX_get(ctx)) == NULL)
        goto err;
    if ((R = BN_CTX_get(ctx)) == NULL)
        goto err;
    if ((v = BN_CTX_get(ctx)) == NULL)
        goto err;

    if (EC_GROUP_get_order(group, order, ctx) == 0)
        goto err;
    pub_key = GOST_KEY_get0_public_key(ec);
    if (BN_is_zero(sig->s) || BN_is_zero(sig->r) || (BN_cmp(sig->s, order) >= 1)
        || (BN_cmp(sig->r, order) >= 1)) {
        GOSTerr(GOST_F_GOST2001_DO_VERIFY, GOST_R_SIGNATURE_PARTS_GREATER_THAN_Q);
        goto err;
    }

    if (BN_mod(e, md, order, ctx) == 0)
        goto err;
    if (BN_is_zero(e))
        BN_one(e);
    if ((v = BN_mod_inverse(v, e, order, ctx)) == NULL)
        goto err;
    if (BN_mod_mul(z1, sig->s, v, order, ctx) == 0)
        goto err;
    if (BN_sub(tmp, order, sig->r) == 0)
        goto err;
    if (BN_mod_mul(z2, tmp, v, order, ctx) == 0)
        goto err;
    if ((C = EC_POINT_new(group)) == NULL)
        goto err;
    if (EC_POINT_mul(group, C, z1, pub_key, z2, ctx) == 0) {
        GOSTerr(GOST_F_GOST2001_DO_VERIFY, ERR_R_EC_LIB);
        goto err;
    }
    if (EC_POINT_get_affine_coordinates_GFp(group, C, X, NULL, ctx) == 0) {
        GOSTerr(GOST_F_GOST2001_DO_VERIFY, ERR_R_EC_LIB);
        goto err;
    }
    if (BN_mod(R, X, order, ctx) == 0)
        goto err;
    if (BN_cmp(R, sig->r) != 0) {
        GOSTerr(GOST_F_GOST2001_DO_VERIFY, GOST_R_SIGNATURE_MISMATCH);
    } else {
        ok = 1;
    }
err:
    EC_POINT_free(C);
    if (ctx != NULL) {
        BN_CTX_end(ctx);
        BN_CTX_free(ctx);
    }    
    return ok;
}

/* Implementation of CryptoPro VKO 34.10-2001 algorithm */
int VKO_compute_key(BIGNUM *X, BIGNUM *Y, const GOST_KEY *pkey, GOST_KEY *priv_key,
                    const BIGNUM *ukm)
{
    BIGNUM *p = NULL, *order = NULL;
    const BIGNUM *key = GOST_KEY_get0_private_key(priv_key);
    const EC_GROUP *group = GOST_KEY_get0_group(priv_key);
    const EC_POINT *pub_key = GOST_KEY_get0_public_key(pkey);
    EC_POINT *pnt;
    BN_CTX *ctx = NULL;
    int ok = 0;

    pnt = EC_POINT_new(group);
    if (pnt == NULL)
        goto err;
    ctx = BN_CTX_new();
    if (ctx == NULL)
        goto err;
    BN_CTX_start(ctx);
    if ((p = BN_CTX_get(ctx)) == NULL)
        goto err;
    if ((order = BN_CTX_get(ctx)) == NULL)
        goto err;
    if (EC_GROUP_get_order(group, order, ctx) == 0)
        goto err;
    if (BN_mod_mul(p, key, ukm, order, ctx) == 0)
        goto err;
    if (EC_POINT_mul(group, pnt, NULL, pub_key, p, ctx) == 0)
        goto err;
    if (EC_POINT_get_affine_coordinates_GFp(group, pnt, X, Y, ctx) == 0)
        goto err;
    ok = 1;

err:
    if (ctx != NULL) {
        BN_CTX_end(ctx);
        BN_CTX_free(ctx);
    }
    EC_POINT_free(pnt);
    return ok;
}

int gost2001_keygen(GOST_KEY *ec)
{
    BIGNUM *order = BN_new(), *d = BN_new();
    const EC_GROUP *group = GOST_KEY_get0_group(ec);
    int ret = 0;

    if (order == NULL || d == NULL)
        goto err;
    if (EC_GROUP_get_order(group, order, NULL) == 0)
        goto err;
    do {
        if (BN_rand_range(d, order) == 0) {
            GOSTerr(GOST_F_GOST2001_KEYGEN, GOST_R_RANDOM_NUMBER_GENERATOR_FAILED);
            goto err;
        }
    } while (BN_is_zero(d));

    if (GOST_KEY_set_private_key(ec, d) == 0)
        goto err;
    ret =  gost2001_compute_public(ec);

err:
    BN_free(d);
    BN_free(order);
    return ret;
}
#endif
