/*
 * Copyright 1998-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/* This file contains deprecated functions as wrappers to the new ones */

#include <stdio.h>
#include <openssl/bn.h>
#include <openssl/dh.h>

static void *dummy = &dummy;

#ifndef OPENSSL_NO_DEPRECATED
DH *DH_generate_parameters(int prime_len, int generator,
                           void (*callback)(int, int, void *), void *cb_arg)
{
    BN_GENCB cb;
    DH *ret = NULL;

    if ((ret = DH_new()) == NULL)
        return NULL;

    BN_GENCB_set_old(&cb, callback, cb_arg);

    if (DH_generate_parameters_ex(ret, prime_len, generator, &cb))
        return ret;
    DH_free(ret);
    return NULL;
}
#endif
