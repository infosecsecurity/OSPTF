/*
 * Copyright 2000-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/asn1t.h>

ASN1_SEQUENCE(RSA_OAEP_PARAMS) = {
    ASN1_EXP_OPT(RSA_OAEP_PARAMS, hashFunc, X509_ALGOR, 0),
    ASN1_EXP_OPT(RSA_OAEP_PARAMS, maskGenFunc, X509_ALGOR, 1),
    ASN1_EXP_OPT(RSA_OAEP_PARAMS, pSourceFunc, X509_ALGOR, 2),
} ASN1_SEQUENCE_END(RSA_OAEP_PARAMS)

IMPLEMENT_ASN1_FUNCTIONS(RSA_OAEP_PARAMS)

/* Override the default free and new methods */
static int rsa_cb(int operation, ASN1_VALUE **pval, const ASN1_ITEM *it,
                  void *exarg)
{
    if (operation == ASN1_OP_NEW_PRE) {
        *pval = (ASN1_VALUE *)RSA_new();
        if (*pval)
            return 2;
        return 0;
    } else if (operation == ASN1_OP_FREE_PRE) {
        RSA_free((RSA *)*pval);
        *pval = NULL;
        return 2;
    }
    return 1;
}

ASN1_SEQUENCE_cb(RSAPrivateKey, rsa_cb) = {
    ASN1_SIMPLE(RSA, version, LONG),
    ASN1_SIMPLE(RSA, n, BIGNUM),
    ASN1_SIMPLE(RSA, e, BIGNUM),
    ASN1_SIMPLE(RSA, d, BIGNUM),
    ASN1_SIMPLE(RSA, p, BIGNUM),
    ASN1_SIMPLE(RSA, q, BIGNUM),
    ASN1_SIMPLE(RSA, dmp1, BIGNUM),
    ASN1_SIMPLE(RSA, dmq1, BIGNUM),
    ASN1_SIMPLE(RSA, iqmp, BIGNUM)
} ASN1_SEQUENCE_END_cb(RSA, RSAPrivateKey)

ASN1_SEQUENCE_cb(RSAPublicKey, rsa_cb) = {
    ASN1_SIMPLE(RSA, n, BIGNUM),
    ASN1_SIMPLE(RSA, e, BIGNUM),
} ASN1_SEQUENCE_END_cb(RSA, RSAPublicKey)

ASN1_SEQUENCE(RSA_PSS_PARAMS) = {
    ASN1_EXP_OPT(RSA_PSS_PARAMS, hashAlgorithm, X509_ALGOR, 0),
    ASN1_EXP_OPT(RSA_PSS_PARAMS, maskGenAlgorithm, X509_ALGOR, 1),
    ASN1_EXP_OPT(RSA_PSS_PARAMS, saltLength, ASN1_INTEGER, 2),
    ASN1_EXP_OPT(RSA_PSS_PARAMS, trailerField, ASN1_INTEGER, 3)
} ASN1_SEQUENCE_END(RSA_PSS_PARAMS)

RSA_PSS_PARAMS *d2i_RSA_PSS_PARAMS(RSA_PSS_PARAMS **a, const uint8_t **in, long len)
{
    return (RSA_PSS_PARAMS *)ASN1_item_d2i((ASN1_VALUE **)a, in, len, ASN1_ITEM_rptr(RSA_PSS_PARAMS));
}

int i2d_RSA_PSS_PARAMS(RSA_PSS_PARAMS *a, uint8_t **out)
{
    return ASN1_item_i2d((ASN1_VALUE *)a, out, ASN1_ITEM_rptr(RSA_PSS_PARAMS));
}

RSA_PSS_PARAMS *RSA_PSS_PARAMS_new(void)
{
    return (RSA_PSS_PARAMS *)ASN1_item_new(ASN1_ITEM_rptr(RSA_PSS_PARAMS));
}

void RSA_PSS_PARAMS_free(RSA_PSS_PARAMS *a)
{
    ASN1_item_free((ASN1_VALUE *)a, ASN1_ITEM_rptr(RSA_PSS_PARAMS));
}

RSA *d2i_RSAPrivateKey(RSA **a, const uint8_t **in, long len)
{
    return (RSA *)ASN1_item_d2i((ASN1_VALUE **)a, in, len, ASN1_ITEM_rptr(RSAPrivateKey));
}

int i2d_RSAPrivateKey(const RSA *a, uint8_t **out)
{
    return ASN1_item_i2d((ASN1_VALUE *)a, out, ASN1_ITEM_rptr(RSAPrivateKey));
}

RSA *d2i_RSAPublicKey(RSA **a, const uint8_t **in, long len)
{
    return (RSA *)ASN1_item_d2i((ASN1_VALUE **)a, in, len, ASN1_ITEM_rptr(RSAPublicKey));
}

int i2d_RSAPublicKey(const RSA *a, uint8_t **out)
{
    return ASN1_item_i2d((ASN1_VALUE *)a, out, ASN1_ITEM_rptr(RSAPublicKey));
}

RSA *RSAPublicKey_dup(RSA * rsa)
{
    return ASN1_item_dup(ASN1_ITEM_rptr(RSAPublicKey), rsa);
}

RSA *RSAPrivateKey_dup(RSA *rsa)
{
    return ASN1_item_dup(ASN1_ITEM_rptr(RSAPrivateKey), rsa);
}
