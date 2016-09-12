/*
 * Copyright 2002-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "ecs_locl.h"
#ifndef OPENSSL_NO_ENGINE
#include <openssl/engine.h>
#endif
#include <openssl/rand.h>

ECDSA_SIG *ECDSA_do_sign(const uint8_t *dgst, int dlen, EC_KEY *eckey)
{
    return ECDSA_do_sign_ex(dgst, dlen, NULL, NULL, eckey);
}

ECDSA_SIG *ECDSA_do_sign_ex(const uint8_t *dgst, int dlen,
                            const BIGNUM *kinv, const BIGNUM *rp, EC_KEY *eckey)
{
    ECDSA_DATA *ecdsa = ecdsa_check(eckey);
    if (ecdsa == NULL)
        return NULL;
    return ecdsa->meth->ecdsa_do_sign(dgst, dlen, kinv, rp, eckey);
}

int ECDSA_sign(int type, const uint8_t *dgst, int dlen, uint8_t *sig, unsigned int *siglen, EC_KEY *eckey)
{
    return ECDSA_sign_ex(type, dgst, dlen, sig, siglen, NULL, NULL, eckey);
}

int ECDSA_sign_ex(int type, const uint8_t *dgst, int dlen, uint8_t *sig, unsigned int *siglen, const BIGNUM *kinv, const BIGNUM *r,
                  EC_KEY *eckey)
{
    ECDSA_SIG *s;
    RAND_seed(dgst, dlen);
    s = ECDSA_do_sign_ex(dgst, dlen, kinv, r, eckey);
    if (s == NULL) {
        *siglen = 0;
        return 0;
    }
    *siglen = i2d_ECDSA_SIG(s, &sig);
    ECDSA_SIG_free(s);
    return 1;
}

int ECDSA_sign_setup(EC_KEY *eckey, BN_CTX *ctx_in, BIGNUM **kinvp,
                     BIGNUM **rp)
{
    ECDSA_DATA *ecdsa = ecdsa_check(eckey);
    if (ecdsa == NULL)
        return 0;
    return ecdsa->meth->ecdsa_sign_setup(eckey, ctx_in, kinvp, rp);
}
