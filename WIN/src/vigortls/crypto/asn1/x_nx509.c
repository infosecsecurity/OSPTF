/*
 * Copyright 2005-2016 The OpenSSL Project Authors. All Rights Reserved.
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

/* Old netscape certificate wrapper format */

ASN1_SEQUENCE(NETSCAPE_X509) = {
    ASN1_SIMPLE(NETSCAPE_X509, header, ASN1_OCTET_STRING),
    ASN1_OPT(NETSCAPE_X509, cert, X509)
} ASN1_SEQUENCE_END(NETSCAPE_X509)

NETSCAPE_X509 *d2i_NETSCAPE_X509(NETSCAPE_X509 **a, const uint8_t **in, long len)
{
    return (NETSCAPE_X509 *)ASN1_item_d2i((ASN1_VALUE **)a, in, len, ASN1_ITEM_rptr(NETSCAPE_X509));
}

int i2d_NETSCAPE_X509(NETSCAPE_X509 *a, uint8_t **out)
{
    return ASN1_item_i2d((ASN1_VALUE *)a, out, ASN1_ITEM_rptr(NETSCAPE_X509));
}

NETSCAPE_X509 *NETSCAPE_X509_new(void)
{
    return (NETSCAPE_X509 *)ASN1_item_new(ASN1_ITEM_rptr(NETSCAPE_X509));
}

void NETSCAPE_X509_free(NETSCAPE_X509 *a)
{
    ASN1_item_free((ASN1_VALUE *)a, ASN1_ITEM_rptr(NETSCAPE_X509));
}
