/*
 * Copyright 1999-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/conf.h>
#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <openssl/x509v3.h>

ASN1_SEQUENCE(AUTHORITY_KEYID) = {
    ASN1_IMP_OPT(AUTHORITY_KEYID, keyid, ASN1_OCTET_STRING, 0),
    ASN1_IMP_SEQUENCE_OF_OPT(AUTHORITY_KEYID, issuer, GENERAL_NAME, 1),
    ASN1_IMP_OPT(AUTHORITY_KEYID, serial, ASN1_INTEGER, 2)
} ASN1_SEQUENCE_END(AUTHORITY_KEYID)

AUTHORITY_KEYID *d2i_AUTHORITY_KEYID(AUTHORITY_KEYID **a, const uint8_t **in, long len)
{
    return (AUTHORITY_KEYID *)ASN1_item_d2i((ASN1_VALUE **)a, in, len, ASN1_ITEM_rptr(AUTHORITY_KEYID));
}

int i2d_AUTHORITY_KEYID(AUTHORITY_KEYID *a, uint8_t **out)
{
    return ASN1_item_i2d((ASN1_VALUE *)a, out, ASN1_ITEM_rptr(AUTHORITY_KEYID));
}

AUTHORITY_KEYID *AUTHORITY_KEYID_new(void)
{
    return (AUTHORITY_KEYID *)ASN1_item_new(ASN1_ITEM_rptr(AUTHORITY_KEYID));
}

void AUTHORITY_KEYID_free(AUTHORITY_KEYID *a)
{
    ASN1_item_free((ASN1_VALUE *)a, ASN1_ITEM_rptr(AUTHORITY_KEYID));
}
