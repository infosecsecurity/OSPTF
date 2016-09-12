/*
 * Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/objects.h>
#include <openssl/asn1t.h>
#include <openssl/x509.h>

#include "x509_lcl.h"

/* X509_ATTRIBUTE: this has the following form:
 *
 * typedef struct x509_attributes_st
 *    {
 *    ASN1_OBJECT *object;
 *    STACK_OF(ASN1_TYPE) *set;
 *    } X509_ATTRIBUTE;
 *
 */

ASN1_SEQUENCE(X509_ATTRIBUTE) = {
    ASN1_SIMPLE(X509_ATTRIBUTE, object, ASN1_OBJECT),
    ASN1_SET_OF(X509_ATTRIBUTE, set, ASN1_ANY)
} ASN1_SEQUENCE_END(X509_ATTRIBUTE)

X509_ATTRIBUTE *d2i_X509_ATTRIBUTE(X509_ATTRIBUTE **a, const uint8_t **in, long len)
{
    return (X509_ATTRIBUTE *)ASN1_item_d2i((ASN1_VALUE **)a, in, len, ASN1_ITEM_rptr(X509_ATTRIBUTE));
}

int i2d_X509_ATTRIBUTE(X509_ATTRIBUTE *a, uint8_t **out)
{
    return ASN1_item_i2d((ASN1_VALUE *)a, out, ASN1_ITEM_rptr(X509_ATTRIBUTE));
}

X509_ATTRIBUTE *X509_ATTRIBUTE_new(void)
{
    return (X509_ATTRIBUTE *)ASN1_item_new(ASN1_ITEM_rptr(X509_ATTRIBUTE));
}

void X509_ATTRIBUTE_free(X509_ATTRIBUTE *a)
{
    ASN1_item_free((ASN1_VALUE *)a, ASN1_ITEM_rptr(X509_ATTRIBUTE));
}

X509_ATTRIBUTE *X509_ATTRIBUTE_dup(X509_ATTRIBUTE *x)
{
    return ASN1_item_dup(ASN1_ITEM_rptr(X509_ATTRIBUTE), x);
}

X509_ATTRIBUTE *X509_ATTRIBUTE_create(int nid, int atrtype, void *value)
{
    X509_ATTRIBUTE *ret = NULL;
    ASN1_TYPE *val = NULL;

    if ((ret = X509_ATTRIBUTE_new()) == NULL)
        return (NULL);
    ret->object = OBJ_nid2obj(nid);
    if ((val = ASN1_TYPE_new()) == NULL)
        goto err;
    if (!sk_ASN1_TYPE_push(ret->set, val))
        goto err;

    ASN1_TYPE_set(val, atrtype, value);
    return (ret);
err:
    X509_ATTRIBUTE_free(ret);
    ASN1_TYPE_free(val);
    return (NULL);
}
