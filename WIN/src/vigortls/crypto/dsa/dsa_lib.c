/*
 * Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <openssl/bn.h>
#include <openssl/dsa.h>
#include <openssl/asn1.h>
#ifndef OPENSSL_NO_ENGINE
#include <openssl/engine.h>
#endif
#include <openssl/dh.h>

#include "internal/threads.h"

static const DSA_METHOD *default_DSA_method = NULL;

void DSA_set_default_method(const DSA_METHOD *meth)
{
    default_DSA_method = meth;
}

const DSA_METHOD *DSA_get_default_method(void)
{
    if (!default_DSA_method) {
        default_DSA_method = DSA_OpenSSL();
    }
    return default_DSA_method;
}

DSA *DSA_new(void)
{
    return DSA_new_method(NULL);
}

int DSA_set_method(DSA *dsa, const DSA_METHOD *meth)
{
    /* NB: The caller is specifically setting a method, so it's not up to us
     * to deal with which ENGINE it comes from. */
    const DSA_METHOD *mtmp;
    mtmp = dsa->meth;
    if (mtmp->finish)
        mtmp->finish(dsa);
#ifndef OPENSSL_NO_ENGINE
    if (dsa->engine) {
        ENGINE_finish(dsa->engine);
        dsa->engine = NULL;
    }
#endif
    dsa->meth = meth;
    if (meth->init)
        meth->init(dsa);
    return 1;
}

DSA *DSA_new_method(ENGINE *engine)
{
    DSA *ret;

    ret = malloc(sizeof(DSA));
    if (ret == NULL) {
        DSAerr(DSA_F_DSA_NEW_METHOD, ERR_R_MALLOC_FAILURE);
        return NULL;
    }
    ret->meth = DSA_get_default_method();
#ifndef OPENSSL_NO_ENGINE
    if (engine) {
        if (!ENGINE_init(engine)) {
            DSAerr(DSA_F_DSA_NEW_METHOD, ERR_R_ENGINE_LIB);
            free(ret);
            return NULL;
        }
        ret->engine = engine;
    } else
        ret->engine = ENGINE_get_default_DSA();
    if (ret->engine) {
        ret->meth = ENGINE_get_DSA(ret->engine);
        if (!ret->meth) {
            DSAerr(DSA_F_DSA_NEW_METHOD,
                   ERR_R_ENGINE_LIB);
            ENGINE_finish(ret->engine);
            free(ret);
            return NULL;
        }
    }
#endif

    ret->pad = 0;
    ret->version = 0;
    ret->p = NULL;
    ret->q = NULL;
    ret->g = NULL;

    ret->pub_key = NULL;
    ret->priv_key = NULL;

    ret->kinv = NULL;
    ret->r = NULL;
    ret->method_mont_p = NULL;

    ret->references = 1;

    CRYPTO_new_ex_data(CRYPTO_EX_INDEX_DSA, ret, &ret->ex_data);

    ret->lock = CRYPTO_thread_new();
    if (ret->lock == NULL) {
#ifndef OPENSSL_NO_ENGINE
        if (ret->engine)
            ENGINE_finish(ret->engine);
#endif
        CRYPTO_free_ex_data(CRYPTO_EX_INDEX_DSA, ret, &ret->ex_data);
        free(ret);
        return NULL;
    }

    if ((ret->meth->init != NULL) && !ret->meth->init(ret)) {
        DSA_free(ret);
        ret = NULL;
    }

    return ret;
}

void DSA_free(DSA *r)
{
    int i;

    if (r == NULL)
        return;

    CRYPTO_atomic_add(&r->references, -1, &i, r->lock);
    if (i > 0)
        return;

    if (r->meth->finish)
        r->meth->finish(r);
#ifndef OPENSSL_NO_ENGINE
    if (r->engine)
        ENGINE_finish(r->engine);
#endif

    CRYPTO_free_ex_data(CRYPTO_EX_INDEX_DSA, r, &r->ex_data);

    CRYPTO_thread_cleanup(r->lock);

    BN_clear_free(r->p);
    BN_clear_free(r->q);
    BN_clear_free(r->g);
    BN_clear_free(r->pub_key);
    BN_clear_free(r->priv_key);
    BN_clear_free(r->kinv);
    BN_clear_free(r->r);
    free(r);
}

int DSA_up_ref(DSA *r)
{
    int i;

    if (CRYPTO_atomic_add(&r->references, 1, &i, r->lock) <= 0)
        return 0;

    return ((i > 1) ? 1 : 0);
}

int DSA_size(const DSA *r)
{
    int ret, i;
    ASN1_INTEGER bs;
    uint8_t buf[4]; /* 4 bytes looks really small.
                   However, i2d_ASN1_INTEGER() will not look
                   beyond the first byte, as long as the second
                   parameter is NULL. */

    i = BN_num_bits(r->q);
    bs.length = (i + 7) / 8;
    bs.data = buf;
    bs.type = V_ASN1_INTEGER;
    /* If the top bit is set the asn1 encoding is 1 larger. */
    buf[0] = 0xff;

    i = i2d_ASN1_INTEGER(&bs, NULL);
    i += i; /* r and s */
    ret = ASN1_object_size(1, i, V_ASN1_SEQUENCE);
    return (ret);
}

int DSA_get_ex_new_index(long argl, void *argp, CRYPTO_EX_new *new_func,
                         CRYPTO_EX_dup *dup_func, CRYPTO_EX_free *free_func)
{
    return CRYPTO_get_ex_new_index(CRYPTO_EX_INDEX_DSA, argl, argp,
                                   new_func, dup_func, free_func);
}

int DSA_set_ex_data(DSA *d, int idx, void *arg)
{
    return (CRYPTO_set_ex_data(&d->ex_data, idx, arg));
}

void *DSA_get_ex_data(DSA *d, int idx)
{
    return (CRYPTO_get_ex_data(&d->ex_data, idx));
}

DH *DSA_dup_DH(const DSA *r)
{
    /* DSA has p, q, g, optional pub_key, optional priv_key.
     * DH has p, optional length, g, optional pub_key, optional priv_key,
     * optional q.
     */

    DH *ret = NULL;

    if (r == NULL)
        goto err;
    ret = DH_new();
    if (ret == NULL)
        goto err;
    if (r->p != NULL)
        if ((ret->p = BN_dup(r->p)) == NULL)
            goto err;
    if (r->q != NULL) {
        ret->length = BN_num_bits(r->q);
        if ((ret->q = BN_dup(r->q)) == NULL)
            goto err;
    }
    if (r->g != NULL)
        if ((ret->g = BN_dup(r->g)) == NULL)
            goto err;
    if (r->pub_key != NULL)
        if ((ret->pub_key = BN_dup(r->pub_key)) == NULL)
            goto err;
    if (r->priv_key != NULL)
        if ((ret->priv_key = BN_dup(r->priv_key)) == NULL)
            goto err;

    return ret;

err:
    DH_free(ret);
    return NULL;
}
