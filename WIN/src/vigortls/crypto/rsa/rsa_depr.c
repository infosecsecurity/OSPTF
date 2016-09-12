/*
 * Copyright 1998-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/* NB: This file contains deprecated functions (compatibility wrappers to the
 * "new" versions). */

#include <stdio.h>
#include <time.h>
#include <openssl/bn.h>
#include <openssl/rsa.h>

#ifdef OPENSSL_NO_DEPRECATED

static void *dummy = &dummy;

#else

RSA *RSA_generate_key(int bits, unsigned long e_value,
                      void (*callback)(int, int, void *), void *cb_arg)
{
    BN_GENCB cb;
    int i;
    RSA *rsa = RSA_new();
    BIGNUM *e = BN_new();

    if (!rsa || !e)
        goto err;

    /* The problem is when building with 8, 16, or 32 BN_ULONG,
     * unsigned long can be larger */
    for (i = 0; i < (int)sizeof(unsigned long) * 8; i++) {
        if (e_value & (1UL << i))
            if (BN_set_bit(e, i) == 0)
                goto err;
    }

    BN_GENCB_set_old(&cb, callback, cb_arg);

    if (RSA_generate_key_ex(rsa, bits, e, &cb)) {
        BN_free(e);
        return rsa;
    }
err:
    if (e)
        BN_free(e);
    if (rsa)
        RSA_free(rsa);
    return 0;
}
#endif
