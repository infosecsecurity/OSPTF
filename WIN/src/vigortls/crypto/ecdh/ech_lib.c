/*
 * Copyright 2002-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/* ====================================================================
 * Copyright 2002 Sun Microsystems, Inc. ALL RIGHTS RESERVED.
 * Portions of this software developed by SUN MICROSYSTEMS, INC.,
 * and contributed to the OpenSSL project.
 */

#include "ech_locl.h"
#include <string.h>
#ifndef OPENSSL_NO_ENGINE
#include <openssl/engine.h>
#endif
#include <openssl/err.h>

static const ECDH_METHOD *default_ECDH_method = NULL;

static void *ecdh_data_new(void);
static void *ecdh_data_dup(void *);
static void ecdh_data_free(void *);

void ECDH_set_default_method(const ECDH_METHOD *meth)
{
    default_ECDH_method = meth;
}

const ECDH_METHOD *ECDH_get_default_method(void)
{
    if (!default_ECDH_method) {
        default_ECDH_method = ECDH_OpenSSL();
    }
    return default_ECDH_method;
}

int ECDH_set_method(EC_KEY *eckey, const ECDH_METHOD *meth)
{
    ECDH_DATA *ecdh;

    ecdh = ecdh_check(eckey);

    if (ecdh == NULL)
        return 0;

#ifndef OPENSSL_NO_ENGINE
    if (ecdh->engine) {
        ENGINE_finish(ecdh->engine);
        ecdh->engine = NULL;
    }
#endif
    ecdh->meth = meth;
    return 1;
}

static ECDH_DATA *ECDH_DATA_new_method(ENGINE *engine)
{
    ECDH_DATA *ret;

    ret = malloc(sizeof(ECDH_DATA));
    if (ret == NULL) {
        ECDHerr(ECDH_F_ECDH_DATA_NEW_METHOD, ERR_R_MALLOC_FAILURE);
        return (NULL);
    }

    ret->init = NULL;

    ret->meth = ECDH_get_default_method();
    ret->engine = engine;
#ifndef OPENSSL_NO_ENGINE
    if (!ret->engine)
        ret->engine = ENGINE_get_default_ECDH();
    if (ret->engine) {
        ret->meth = ENGINE_get_ECDH(ret->engine);
        if (!ret->meth) {
            ECDHerr(ECDH_F_ECDH_DATA_NEW_METHOD, ERR_R_ENGINE_LIB);
            ENGINE_finish(ret->engine);
            free(ret);
            return NULL;
        }
    }
#endif

    ret->flags = ret->meth->flags;
    CRYPTO_new_ex_data(CRYPTO_EX_INDEX_ECDH, ret, &ret->ex_data);
    return (ret);
}

static void *ecdh_data_new(void)
{
    return (void *)ECDH_DATA_new_method(NULL);
}

static void *ecdh_data_dup(void *data)
{
    ECDH_DATA *r = (ECDH_DATA *)data;

    /* XXX: dummy operation */
    if (r == NULL)
        return NULL;

    return (void *)ecdh_data_new();
}

void ecdh_data_free(void *data)
{
    ECDH_DATA *r = (ECDH_DATA *)data;

#ifndef OPENSSL_NO_ENGINE
    if (r->engine)
        ENGINE_finish(r->engine);
#endif

    CRYPTO_free_ex_data(CRYPTO_EX_INDEX_ECDH, r, &r->ex_data);

    vigortls_zeroize((void *)r, sizeof(ECDH_DATA));

    free(r);
}

ECDH_DATA *ecdh_check(EC_KEY *key)
{
    ECDH_DATA *ecdh_data;

    void *data = EC_KEY_get_key_method_data(key, ecdh_data_dup,
                                            ecdh_data_free, ecdh_data_free);
    if (data == NULL) {
        ecdh_data = (ECDH_DATA *)ecdh_data_new();
        if (ecdh_data == NULL)
            return NULL;
        data = EC_KEY_insert_key_method_data(key, (void *)ecdh_data,
                                             ecdh_data_dup, ecdh_data_free, ecdh_data_free);
        if (data != NULL) {
            /* Another thread raced us to install the key_method
             * data and won. */
            ecdh_data_free(ecdh_data);
            ecdh_data = (ECDH_DATA *)data;
        }
    } else
        ecdh_data = (ECDH_DATA *)data;

    return ecdh_data;
}

int ECDH_get_ex_new_index(long argl, void *argp, CRYPTO_EX_new *new_func,
                          CRYPTO_EX_dup *dup_func, CRYPTO_EX_free *free_func)
{
    return CRYPTO_get_ex_new_index(CRYPTO_EX_INDEX_ECDH, argl, argp,
                                   new_func, dup_func, free_func);
}

int ECDH_set_ex_data(EC_KEY *d, int idx, void *arg)
{
    ECDH_DATA *ecdh;
    ecdh = ecdh_check(d);
    if (ecdh == NULL)
        return 0;
    return (CRYPTO_set_ex_data(&ecdh->ex_data, idx, arg));
}

void *ECDH_get_ex_data(EC_KEY *d, int idx)
{
    ECDH_DATA *ecdh;
    ecdh = ecdh_check(d);
    if (ecdh == NULL)
        return NULL;
    return (CRYPTO_get_ex_data(&ecdh->ex_data, idx));
}
