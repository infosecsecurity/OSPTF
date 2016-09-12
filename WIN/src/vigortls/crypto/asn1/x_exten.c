/*
 * Copyright 2000-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stddef.h>
#include <openssl/x509.h>
#include <openssl/asn1.h>
#include <openssl/asn1t.h>

ASN1_SEQUENCE(X509_EXTENSION) = {
    ASN1_SIMPLE(X509_EXTENSION, object, ASN1_OBJECT),
    ASN1_OPT(X509_EXTENSION, critical, ASN1_BOOLEAN),
    ASN1_SIMPLE(X509_EXTENSION, value, ASN1_OCTET_STRING)
} ASN1_SEQUENCE_END(X509_EXTENSION)

ASN1_ITEM_TEMPLATE(X509_EXTENSIONS) = ASN1_EX_TEMPLATE_TYPE(ASN1_TFLG_SEQUENCE_OF, 0, Extension, X509_EXTENSION)
ASN1_ITEM_TEMPLATE_END(X509_EXTENSIONS)

X509_EXTENSION *d2i_X509_EXTENSION(X509_EXTENSION **a, const uint8_t **in, long len)
{
    return (X509_EXTENSION *)ASN1_item_d2i((ASN1_VALUE **)a, in, len, ASN1_ITEM_rptr(X509_EXTENSION));
}

int i2d_X509_EXTENSION(X509_EXTENSION *a, uint8_t **out)
{
    return ASN1_item_i2d((ASN1_VALUE *)a, out, ASN1_ITEM_rptr(X509_EXTENSION));
}

X509_EXTENSION *X509_EXTENSION_new(void)
{
    return (X509_EXTENSION *)ASN1_item_new(ASN1_ITEM_rptr(X509_EXTENSION));
}

void X509_EXTENSION_free(X509_EXTENSION *a)
{
    ASN1_item_free((ASN1_VALUE *)a, ASN1_ITEM_rptr(X509_EXTENSION));
}

X509_EXTENSIONS *d2i_X509_EXTENSIONS(X509_EXTENSIONS **a, const uint8_t **in, long len)
{
    return (X509_EXTENSIONS *)ASN1_item_d2i((ASN1_VALUE **)a, in, len, ASN1_ITEM_rptr(X509_EXTENSIONS));
}

int i2d_X509_EXTENSIONS(X509_EXTENSIONS *a, uint8_t **out)
{
    return ASN1_item_i2d((ASN1_VALUE *)a, out, ASN1_ITEM_rptr(X509_EXTENSIONS));
}

X509_EXTENSION *X509_EXTENSION_dup(X509_EXTENSION *x)
{
    return ASN1_item_dup(ASN1_ITEM_rptr(X509_EXTENSION), x);
}
