/*
 * Copyright 2000-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/x509.h>
#include <openssl/asn1.h>
#include <openssl/asn1t.h>

ASN1_SEQUENCE(X509_ALGOR) = {
    ASN1_SIMPLE(X509_ALGOR, algorithm, ASN1_OBJECT),
    ASN1_OPT(X509_ALGOR, parameter, ASN1_ANY)
} ASN1_SEQUENCE_END(X509_ALGOR)

ASN1_ITEM_TEMPLATE(X509_ALGORS) = ASN1_EX_TEMPLATE_TYPE(ASN1_TFLG_SEQUENCE_OF, 0, algorithms, X509_ALGOR)
ASN1_ITEM_TEMPLATE_END(X509_ALGORS)

X509_ALGOR *d2i_X509_ALGOR(X509_ALGOR **a, const uint8_t **in, long len)
{
    return (X509_ALGOR *)ASN1_item_d2i((ASN1_VALUE **)a, in, len, ASN1_ITEM_rptr(X509_ALGOR));
}

int i2d_X509_ALGOR(X509_ALGOR *a, uint8_t **out)
{
    return ASN1_item_i2d((ASN1_VALUE *)a, out, ASN1_ITEM_rptr(X509_ALGOR));
}

X509_ALGOR *X509_ALGOR_new(void)
{
    return (X509_ALGOR *)ASN1_item_new(ASN1_ITEM_rptr(X509_ALGOR));
}

void X509_ALGOR_free(X509_ALGOR *a)
{
    ASN1_item_free((ASN1_VALUE *)a, ASN1_ITEM_rptr(X509_ALGOR));
}

X509_ALGORS *d2i_X509_ALGORS(X509_ALGORS **a, const uint8_t **in, long len)
{
    return (X509_ALGORS *)ASN1_item_d2i((ASN1_VALUE **)a, in, len, ASN1_ITEM_rptr(X509_ALGORS));
}

int i2d_X509_ALGORS(X509_ALGORS *a, uint8_t **out)
{
    return ASN1_item_i2d((ASN1_VALUE *)a, out, ASN1_ITEM_rptr(X509_ALGORS));
}

X509_ALGOR *X509_ALGOR_dup(X509_ALGOR *x)
{
    return ASN1_item_dup(ASN1_ITEM_rptr(X509_ALGORS), x);
}

int X509_ALGOR_set0(X509_ALGOR * alg, ASN1_OBJECT * aobj, int ptype, void *pval)
{
    if (!alg)
        return 0;
    if (ptype != V_ASN1_UNDEF) {
        if (alg->parameter == NULL)
            alg->parameter = ASN1_TYPE_new();
        if (alg->parameter == NULL)
            return 0;
    }
    if (alg) {
        if (alg->algorithm)
            ASN1_OBJECT_free(alg->algorithm);
        alg->algorithm = aobj;
    }
    if (ptype == 0)
        return 1;
    if (ptype == V_ASN1_UNDEF) {
        if (alg->parameter) {
            ASN1_TYPE_free(alg->parameter);
            alg->parameter = NULL;
        }
    } else
        ASN1_TYPE_set(alg->parameter, ptype, pval);
    return 1;
}

void X509_ALGOR_get0(ASN1_OBJECT **paobj, int *pptype, void **ppval,
                     X509_ALGOR *algor)
{
    if (paobj)
        *paobj = algor->algorithm;
    if (pptype) {
        if (algor->parameter == NULL) {
            *pptype = V_ASN1_UNDEF;
            return;
        } else
            *pptype = algor->parameter->type;
        if (ppval)
            *ppval = algor->parameter->value.ptr;
    }
}

/* Set up an X509_ALGOR DigestAlgorithmIdentifier from an EVP_MD */

void X509_ALGOR_set_md(X509_ALGOR *alg, const EVP_MD *md)
{
    int param_type;

    if (md->flags & EVP_MD_FLAG_DIGALGID_ABSENT)
        param_type = V_ASN1_UNDEF;
    else
        param_type = V_ASN1_NULL;

    X509_ALGOR_set0(alg, OBJ_nid2obj(EVP_MD_type(md)), param_type, NULL);
}

int X509_ALGOR_cmp(const X509_ALGOR *a, const X509_ALGOR *b)
{
    int rv;

    rv = OBJ_cmp(a->algorithm, b->algorithm);
    if (rv)
        return rv;
    if (!a->parameter && !b->parameter)
        return 0;
    return ASN1_TYPE_cmp(a->parameter, b->parameter);
}
