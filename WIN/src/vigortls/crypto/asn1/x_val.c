/*
 * Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <openssl/asn1t.h>
#include <openssl/x509.h>

ASN1_SEQUENCE(X509_VAL) = {
    ASN1_SIMPLE(X509_VAL, notBefore, ASN1_TIME),
    ASN1_SIMPLE(X509_VAL, notAfter, ASN1_TIME)
} ASN1_SEQUENCE_END(X509_VAL)

X509_VAL *d2i_X509_VAL(X509_VAL **a, const uint8_t **in, long len)
{
    return (X509_VAL *)ASN1_item_d2i((ASN1_VALUE **)a, in, len, ASN1_ITEM_rptr(X509_VAL));
}

int i2d_X509_VAL(X509_VAL *a, uint8_t **out)
{
    return ASN1_item_i2d((ASN1_VALUE *)a, out, ASN1_ITEM_rptr(X509_VAL));
}

X509_VAL *X509_VAL_new(void)
{
    return (X509_VAL *)ASN1_item_new(ASN1_ITEM_rptr(X509_VAL));
}

void X509_VAL_free(X509_VAL *a)
{
    ASN1_item_free((ASN1_VALUE *)a, ASN1_ITEM_rptr(X509_VAL));
}
