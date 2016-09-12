/*
 * Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/dsa.h>
#include <openssl/rand.h>
#include <openssl/bn.h>

DSA_SIG *DSA_do_sign(const uint8_t *dgst, int dlen, DSA *dsa)
{
    return dsa->meth->dsa_do_sign(dgst, dlen, dsa);
}

int DSA_sign_setup(DSA *dsa, BN_CTX *ctx_in, BIGNUM **kinvp, BIGNUM **rp)
{
    return dsa->meth->dsa_sign_setup(dsa, ctx_in, kinvp, rp);
}

DSA_SIG *DSA_SIG_new(void)
{
    DSA_SIG *sig;
    sig = malloc(sizeof(DSA_SIG));
    if (!sig)
        return NULL;
    sig->r = NULL;
    sig->s = NULL;
    return sig;
}

void DSA_SIG_free(DSA_SIG *sig)
{
    if (sig) {
        if (sig->r)
            BN_free(sig->r);
        if (sig->s)
            BN_free(sig->s);
        free(sig);
    }
}
