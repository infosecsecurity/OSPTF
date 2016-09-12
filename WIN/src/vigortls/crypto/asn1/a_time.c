/*
 * Copyright 1999-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/* This is an implementation of the ASN1 Time structure which is:
 *    Time ::= CHOICE {
 *      utcTime        UTCTime,
 *      generalTime    GeneralizedTime }
 * written by Steve Henson.
 */

#include <stdio.h>
#include <string.h>
#include <time.h>
#include <win32compat.h>

#include <openssl/asn1t.h>
#include <openssl/buffer.h>
#include <openssl/err.h>
#include <stdcompat.h>

#include "time_support.h"
#include "asn1_locl.h"

IMPLEMENT_ASN1_MSTRING(ASN1_TIME, B_ASN1_TIME)

ASN1_TIME *d2i_ASN1_TIME(ASN1_TIME **a, const uint8_t **in, long len)
{
    return (ASN1_TIME *)ASN1_item_d2i((ASN1_VALUE **)a, in, len, ASN1_ITEM_rptr(ASN1_TIME));
}

int i2d_ASN1_TIME(ASN1_TIME *a, uint8_t **out)
{
    return ASN1_item_i2d((ASN1_VALUE *)a, out, ASN1_ITEM_rptr(ASN1_TIME));
}

ASN1_TIME *ASN1_TIME_new(void)
{
    return (ASN1_TIME *)ASN1_item_new(ASN1_ITEM_rptr(ASN1_TIME));
}

void ASN1_TIME_free(ASN1_TIME *a)
{
    ASN1_item_free((ASN1_VALUE *)a, ASN1_ITEM_rptr(ASN1_TIME));
}
