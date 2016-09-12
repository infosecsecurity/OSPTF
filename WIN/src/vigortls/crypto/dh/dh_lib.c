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
#include <openssl/dh.h>
#ifndef OPENSSL_NO_ENGINE
#include <openssl/engine.h>
#endif

#include "internal/threads.h"

static const DH_METHOD *default_DH_method = NULL;

void DH_set_default_method(const DH_METHOD *meth)
{
    default_DH_method = meth;
}

const DH_METHOD *DH_get_default_method(void)
{
    if (!default_DH_method) {
        default_DH_method = DH_OpenSSL();
    }
    return default_DH_method;
}

int DH_set_method(DH *dh, const DH_METHOD *meth)
{
    /* NB: The caller is specifically setting a method, so it's not up to us
     * to deal with which ENGINE it comes from. */
    const DH_METHOD *mtmp;
    mtmp = dh->meth;
    if (mtmp->finish)
        mtmp->finish(dh);
#ifndef OPENSSL_NO_ENGINE
    if (dh->engine) {
        ENGINE_finish(dh->engine);
        dh->engine = NULL;
    }
#endif
    dh->meth = meth;
    if (meth->init)
        meth->init(dh);
    return 1;
}

DH *DH_new(void)
{
    return DH_new_method(NULL);
}

DH *DH_new_method(ENGINE *engine)
{
    DH *ret;

    ret = malloc(sizeof(DH));
    if (ret == NULL) {
        DHerr(DH_F_DH_NEW_METHOD, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    ret->meth = DH_get_default_method();
#ifndef OPENSSL_NO_ENGINE
    if (engine) {
        if (!ENGINE_init(engine)) {
            DHerr(DH_F_DH_NEW_METHOD, ERR_R_ENGINE_LIB);
            free(ret);
            return NULL;
        }
        ret->engine = engine;
    } else
        ret->engine = ENGINE_get_default_DH();
    if (ret->engine) {
        ret->meth = ENGINE_get_DH(ret->engine);
        if (!ret->meth) {
            DHerr(DH_F_DH_NEW_METHOD, ERR_R_ENGINE_LIB);
            ENGINE_finish(ret->engine);
            free(ret);
            return NULL;
        }
    }
#endif

    ret->pad = 0;
    ret->version = 0;
    ret->p = NULL;
    ret->g = NULL;
    ret->length = 0;
    ret->pub_key = NULL;
    ret->priv_key = NULL;
    ret->q = NULL;
    ret->j = NULL;
    ret->seed = NULL;
    ret->seedlen = 0;
    ret->counter = NULL;
    ret->method_mont_p = NULL;
    ret->references = 1;

    CRYPTO_new_ex_data(CRYPTO_EX_INDEX_DH, ret, &ret->ex_data);

    ret->lock = CRYPTO_thread_new();
    if (ret->lock == NULL) {
#ifndef OPENSSL_NO_ENGINE
        if (ret->engine)
            ENGINE_finish(ret->engine);
#endif
        CRYPTO_free_ex_data(CRYPTO_EX_INDEX_DH, ret, &ret->ex_data);
        free(ret);
        return NULL;
    }

    if ((ret->meth->init != NULL) && !ret->meth->init(ret)) {
        DH_free(ret);
        ret = NULL;
    }

    return ret;
}

void DH_free(DH *r)
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

    CRYPTO_free_ex_data(CRYPTO_EX_INDEX_DH, r, &r->ex_data);

    CRYPTO_thread_cleanup(r->lock);

    BN_clear_free(r->p);
    BN_clear_free(r->g);
    BN_clear_free(r->q);
    BN_clear_free(r->j);
    free(r->seed);
    BN_clear_free(r->counter);
    BN_clear_free(r->pub_key);
    BN_clear_free(r->priv_key);
    free(r);
}

int DH_up_ref(DH *r)
{
    int i;

    if (CRYPTO_atomic_add(&r->references, 1, &i, r->lock) <= 0)
        return 0;

    return ((i > 1) ? 1 : 0);
}

int DH_get_ex_new_index(long argl, void *argp, CRYPTO_EX_new *new_func,
                        CRYPTO_EX_dup *dup_func, CRYPTO_EX_free *free_func)
{
    return CRYPTO_get_ex_new_index(CRYPTO_EX_INDEX_DH, argl, argp,
                                   new_func, dup_func, free_func);
}

int DH_set_ex_data(DH *d, int idx, void *arg)
{
    return (CRYPTO_set_ex_data(&d->ex_data, idx, arg));
}

void *DH_get_ex_data(DH *d, int idx)
{
    return (CRYPTO_get_ex_data(&d->ex_data, idx));
}

int DH_size(const DH *dh)
{
    return (BN_num_bytes(dh->p));
}

unsigned int DH_num_bits(const DH *dh)
{
    return BN_num_bits(dh->p);
}
