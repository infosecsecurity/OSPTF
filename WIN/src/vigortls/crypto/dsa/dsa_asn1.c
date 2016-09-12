/*
 * Copyright 2000-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <string.h>

#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <openssl/dsa.h>
#include <openssl/err.h>
#include <openssl/rand.h>

/* Override the default new methods */
static int sig_cb(int operation, ASN1_VALUE **pval, const ASN1_ITEM *it,
                  void *exarg)
{
    if (operation == ASN1_OP_NEW_PRE) {
        DSA_SIG *sig;
        sig = calloc(1, sizeof(DSA_SIG));
        if (sig == NULL) {
            DSAerr(DSA_F_SIG_CB, ERR_R_MALLOC_FAILURE);
            return 0;
        }
        *pval = (ASN1_VALUE *)sig;
        return 2;
    }
    return 1;
}

ASN1_SEQUENCE_cb(DSA_SIG, sig_cb) = {
    ASN1_SIMPLE(DSA_SIG, r, CBIGNUM),
    ASN1_SIMPLE(DSA_SIG, s, CBIGNUM)
} ASN1_SEQUENCE_END_cb(DSA_SIG, DSA_SIG)

DSA_SIG *d2i_DSA_SIG(DSA_SIG **a, const uint8_t **in, long len)
{
    return (DSA_SIG *)ASN1_item_d2i((ASN1_VALUE **)a, in, len,
                                    ASN1_ITEM_rptr(DSA_SIG));
}

int i2d_DSA_SIG(const DSA_SIG *a, uint8_t **out)
{
    return ASN1_item_i2d((ASN1_VALUE *)a, out, ASN1_ITEM_rptr(DSA_SIG));
}

/* Override the default free and new methods */
static int dsa_cb(int operation, ASN1_VALUE **pval, const ASN1_ITEM *it, void *exarg)
{
    if (operation == ASN1_OP_NEW_PRE) {
        *pval = (ASN1_VALUE *)DSA_new();
        if (*pval != NULL)
            return 2;
        return 0;
    } else if (operation == ASN1_OP_FREE_PRE) {
        DSA_free((DSA *)*pval);
        *pval = NULL;
        return 2;
    }
    return 1;
}

ASN1_SEQUENCE_cb(DSAPrivateKey, dsa_cb) = {
    ASN1_SIMPLE(DSA, version, LONG),
    ASN1_SIMPLE(DSA, p, BIGNUM),
    ASN1_SIMPLE(DSA, q, BIGNUM),
    ASN1_SIMPLE(DSA, g, BIGNUM),
    ASN1_SIMPLE(DSA, pub_key, BIGNUM),
    ASN1_SIMPLE(DSA, priv_key, BIGNUM)
} ASN1_SEQUENCE_END_cb(DSA, DSAPrivateKey)

DSA *d2i_DSAPrivateKey(DSA **a, const uint8_t **in, long len)
{
    return (DSA *)ASN1_item_d2i((ASN1_VALUE **)a, in, len, ASN1_ITEM_rptr(DSAPrivateKey));
}

int i2d_DSAPrivateKey(const DSA *a, uint8_t **out)
{
    return ASN1_item_i2d((ASN1_VALUE *)a, out, ASN1_ITEM_rptr(DSAPrivateKey));
}

ASN1_SEQUENCE_cb(DSAparams, dsa_cb) = {
    ASN1_SIMPLE(DSA, p, BIGNUM),
    ASN1_SIMPLE(DSA, q, BIGNUM),
    ASN1_SIMPLE(DSA, g, BIGNUM),
} ASN1_SEQUENCE_END_cb(DSA, DSAparams)

DSA *d2i_DSAparams(DSA **a, const uint8_t **in, long len)
{
    return (DSA *)ASN1_item_d2i((ASN1_VALUE **)a, in, len, ASN1_ITEM_rptr(DSAparams));
}

int i2d_DSAparams(const DSA *a, uint8_t **out)
{
    return ASN1_item_i2d((ASN1_VALUE *)a, out, ASN1_ITEM_rptr(DSAparams));
}

/* DSA public key is a bit trickier... its effectively a CHOICE type
 * decided by a field called write_params which can either write out
 * just the public key as an INTEGER or the parameters and public key
 * in a SEQUENCE
 */

ASN1_SEQUENCE_cb(DSAPublicKey, dsa_cb) = {
    ASN1_SIMPLE(DSA, pub_key, BIGNUM),
    ASN1_SIMPLE(DSA, p, BIGNUM),
    ASN1_SIMPLE(DSA, q, BIGNUM),
    ASN1_SIMPLE(DSA, g, BIGNUM)
} ASN1_SEQUENCE_END_cb(DSA, DSAPublicKey)

DSA *d2i_DSAPublicKey(DSA **a, const uint8_t **in, long len)
{
    return (DSA *)ASN1_item_d2i((ASN1_VALUE **)a, in, len, ASN1_ITEM_rptr(DSAPublicKey));
}

int i2d_DSAPublicKey(const DSA *a, uint8_t **out)
{
    return ASN1_item_i2d((ASN1_VALUE *)a, out, ASN1_ITEM_rptr(DSAPublicKey));
}

DSA *DSAparams_dup(DSA * dsa)
{
    return ASN1_item_dup(ASN1_ITEM_rptr(DSAparams), dsa);
}

int DSA_sign(int type, const uint8_t *dgst, int dlen, uint8_t *sig,
             unsigned int *siglen, DSA *dsa)
{
    DSA_SIG *s;
    RAND_seed(dgst, dlen);
    s = DSA_do_sign(dgst, dlen, dsa);
    if (s == NULL) {
        *siglen = 0;
        return (0);
    }
    *siglen = i2d_DSA_SIG(s, &sig);
    DSA_SIG_free(s);
    return (1);
}

/* data has already been hashed (probably with SHA or SHA-1). */
/* returns
 *      1: correct signature
 *      0: incorrect signature
 *     -1: error
 */
int DSA_verify(int type, const uint8_t *dgst, int dgst_len,
               const uint8_t *sigbuf, int siglen, DSA *dsa)
{
    DSA_SIG *s;
    const uint8_t *p = sigbuf;
    uint8_t *der = NULL;
    int derlen = -1;
    int ret = -1;

    s = DSA_SIG_new();
    if (s == NULL)
        return (ret);
    if (d2i_DSA_SIG(&s, &p, siglen) == NULL)
        goto err;
    /* Ensure signature uses DER and doesn't have trailing ... */
    derlen = i2d_DSA_SIG(s, &der);
    if (derlen != siglen || memcmp(sigbuf, der, derlen))
        goto err;
    ret = DSA_do_verify(dgst, dgst_len, s, dsa);
err:
    if (derlen > 0) {
        vigortls_zeroize(der, derlen);
        free(der);
    }
    DSA_SIG_free(s);
    return (ret);
}
