/*
 * Copyright 1998-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/* This file contains deprecated function(s) that are now wrappers to the new
 * version(s). */

#include <openssl/opensslconf.h>


#include <stdio.h>
#include <time.h>

#include <openssl/bn.h>
#include <openssl/dsa.h>
#include <openssl/evp.h>
#include <openssl/sha.h>

#ifndef OPENSSL_NO_DEPRECATED
DSA *DSA_generate_parameters(int bits,
                             uint8_t *seed_in, int seed_len,
                             int *counter_ret, unsigned long *h_ret,
                             void (*callback)(int, int, void *),
                             void *cb_arg)
{
    BN_GENCB cb;
    DSA *ret;

    if ((ret = DSA_new()) == NULL)
        return NULL;

    BN_GENCB_set_old(&cb, callback, cb_arg);

    if (DSA_generate_parameters_ex(ret, bits, seed_in, seed_len,
                                   counter_ret, h_ret, &cb))
        return ret;
    DSA_free(ret);
    return NULL;
}
#endif
