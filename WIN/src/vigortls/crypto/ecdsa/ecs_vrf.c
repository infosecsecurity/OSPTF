/*
 * Copyright 2002-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <string.h>

#include "ecs_locl.h"
#ifndef OPENSSL_NO_ENGINE
#include <openssl/engine.h>
#endif

/* returns
 *      1: correct signature
 *      0: incorrect signature
 *     -1: error
 */
int ECDSA_do_verify(const uint8_t *dgst, int dgst_len,
                    const ECDSA_SIG *sig, EC_KEY *eckey)
{
    ECDSA_DATA *ecdsa = ecdsa_check(eckey);
    if (ecdsa == NULL)
        return 0;
    return ecdsa->meth->ecdsa_do_verify(dgst, dgst_len, sig, eckey);
}

/* returns
 *      1: correct signature
 *      0: incorrect signature
 *     -1: error
 */
int ECDSA_verify(int type, const uint8_t *dgst, int dgst_len,
                 const uint8_t *sigbuf, int sig_len, EC_KEY *eckey)
{
    ECDSA_SIG *s;
    const uint8_t *p = sigbuf;
    uint8_t *der = NULL;
    int derlen = -1;
    int ret = -1;

    s = ECDSA_SIG_new();
    if (s == NULL)
        return (ret);
    if (d2i_ECDSA_SIG(&s, &p, sig_len) == NULL)
        goto err;
    /* Ensure signature uses DER and doesn't have trailing ... */
    derlen = i2d_ECDSA_SIG(s, &der);
    if (derlen != sig_len || memcmp(sigbuf, der, derlen))
        goto err;
    ret = ECDSA_do_verify(dgst, dgst_len, s, eckey);
err:
    if (derlen > 0) {
        vigortls_zeroize(der, derlen);
        free(der);
    }
    ECDSA_SIG_free(s);
    return (ret);
}
