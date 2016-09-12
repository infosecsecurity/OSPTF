/*
 * Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <openssl/x509.h>
#include <openssl/asn1t.h>

ASN1_SEQUENCE(NETSCAPE_SPKAC) = {
    ASN1_SIMPLE(NETSCAPE_SPKAC, pubkey, X509_PUBKEY),
    ASN1_SIMPLE(NETSCAPE_SPKAC, challenge, ASN1_IA5STRING)
} ASN1_SEQUENCE_END(NETSCAPE_SPKAC)

NETSCAPE_SPKAC *d2i_NETSCAPE_SPKAC(NETSCAPE_SPKAC **a, const uint8_t **in, long len)
{
    return (NETSCAPE_SPKAC *)ASN1_item_d2i((ASN1_VALUE **)a, in, len, ASN1_ITEM_rptr(NETSCAPE_SPKAC));
}

int i2d_NETSCAPE_SPKAC(NETSCAPE_SPKAC *a, uint8_t **out)
{
    return ASN1_item_i2d((ASN1_VALUE *)a, out, ASN1_ITEM_rptr(NETSCAPE_SPKAC));
}

NETSCAPE_SPKAC *NETSCAPE_SPKAC_new(void)
{
    return (NETSCAPE_SPKAC *)ASN1_item_new(ASN1_ITEM_rptr(NETSCAPE_SPKAC));
}

void NETSCAPE_SPKAC_free(NETSCAPE_SPKAC *a)
{
    ASN1_item_free((ASN1_VALUE *)a, ASN1_ITEM_rptr(NETSCAPE_SPKAC));
}

ASN1_SEQUENCE(NETSCAPE_SPKI) = {
    ASN1_SIMPLE(NETSCAPE_SPKI, spkac, NETSCAPE_SPKAC),
    ASN1_SIMPLE(NETSCAPE_SPKI, sig_algor, X509_ALGOR),
    ASN1_SIMPLE(NETSCAPE_SPKI, signature, ASN1_BIT_STRING)
} ASN1_SEQUENCE_END(NETSCAPE_SPKI)

NETSCAPE_SPKI *d2i_NETSCAPE_SPKI(NETSCAPE_SPKI **a, const uint8_t **in, long len)
{
    return (NETSCAPE_SPKI *)ASN1_item_d2i((ASN1_VALUE **)a, in, len, ASN1_ITEM_rptr(NETSCAPE_SPKI));
}

int i2d_NETSCAPE_SPKI(NETSCAPE_SPKI *a, uint8_t **out)
{
    return ASN1_item_i2d((ASN1_VALUE *)a, out, ASN1_ITEM_rptr(NETSCAPE_SPKI));
}

NETSCAPE_SPKI *NETSCAPE_SPKI_new(void)
{
    return (NETSCAPE_SPKI *)ASN1_item_new(ASN1_ITEM_rptr(NETSCAPE_SPKI));
}

void NETSCAPE_SPKI_free(NETSCAPE_SPKI *a)
{
    ASN1_item_free((ASN1_VALUE *)a, ASN1_ITEM_rptr(NETSCAPE_SPKI));
}
