/*
 * Copyright 2002-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "ecs_locl.h"
#include <openssl/err.h>
#include <openssl/asn1t.h>

DECLARE_ASN1_FUNCTIONS_const(ECDSA_SIG)
DECLARE_ASN1_ENCODE_FUNCTIONS_const(ECDSA_SIG, ECDSA_SIG)

ASN1_SEQUENCE(ECDSA_SIG) = {
    ASN1_SIMPLE(ECDSA_SIG, r, CBIGNUM),
    ASN1_SIMPLE(ECDSA_SIG, s, CBIGNUM)
} ASN1_SEQUENCE_END(ECDSA_SIG)

ECDSA_SIG *d2i_ECDSA_SIG(ECDSA_SIG **a, const uint8_t **in, long len)
{
    return (ECDSA_SIG *)ASN1_item_d2i((ASN1_VALUE **)a, in, len, ASN1_ITEM_rptr(ECDSA_SIG));
}

int i2d_ECDSA_SIG(const ECDSA_SIG *a, uint8_t **out)
{
    return ASN1_item_i2d((ASN1_VALUE *)a, out, ASN1_ITEM_rptr(ECDSA_SIG));
}

ECDSA_SIG *ECDSA_SIG_new(void)
{
    return (ECDSA_SIG *)ASN1_item_new(ASN1_ITEM_rptr(ECDSA_SIG));
}

void ECDSA_SIG_free(ECDSA_SIG *a)
{
    ASN1_item_free((ASN1_VALUE *)a, ASN1_ITEM_rptr(ECDSA_SIG));
}
