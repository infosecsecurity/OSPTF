/*
 * Copyright 2007-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <string.h>

#include <openssl/evp.h>

#include "internal/asn1_int.h"

#define HMAC_TEST_PRIVATE_KEY_FORMAT

/* HMAC "ASN1" method. This is just here to indicate the
 * maximum HMAC output length and to free up an HMAC
 * key.
 */

static int hmac_size(const EVP_PKEY *pkey)
{
    return EVP_MAX_MD_SIZE;
}

static void hmac_key_free(EVP_PKEY *pkey)
{
    ASN1_OCTET_STRING *os = (ASN1_OCTET_STRING *)pkey->pkey.ptr;
    if (os) {
        if (os->data)
            vigortls_zeroize(os->data, os->length);
        ASN1_OCTET_STRING_free(os);
    }
}

static int hmac_pkey_ctrl(EVP_PKEY *pkey, int op, long arg1, void *arg2)
{
    switch (op) {
        case ASN1_PKEY_CTRL_DEFAULT_MD_NID:
            *(int *)arg2 = NID_sha256;
            return 1;

        default:
            return -2;
    }
}

#ifdef HMAC_TEST_PRIVATE_KEY_FORMAT
/* A bogus private key format for test purposes. This is simply the
 * HMAC key with "HMAC PRIVATE KEY" in the headers. When enabled the
 * genpkey utility can be used to "generate" HMAC keys.
 */

static int old_hmac_decode(EVP_PKEY *pkey,
                           const uint8_t **pder, int derlen)
{
    ASN1_OCTET_STRING *os;
    os = ASN1_OCTET_STRING_new();
    if (!os || !ASN1_OCTET_STRING_set(os, *pder, derlen))
        return 0;
    EVP_PKEY_assign(pkey, EVP_PKEY_HMAC, os);
    return 1;
}

static int old_hmac_encode(const EVP_PKEY *pkey, uint8_t **pder)
{
    int inc;
    ASN1_OCTET_STRING *os = (ASN1_OCTET_STRING *)pkey->pkey.ptr;
    if (pder) {
        if (!*pder) {
            *pder = malloc(os->length);
            inc = 0;
        } else
            inc = 1;

        memcpy(*pder, os->data, os->length);

        if (inc)
            *pder += os->length;
    }

    return os->length;
}

#endif

const EVP_PKEY_ASN1_METHOD hmac_asn1_meth = {
    .pkey_id = EVP_PKEY_HMAC,
    .pkey_base_id = EVP_PKEY_HMAC,

    .pem_str = (char *)"HMAC",
    .info = (char *)"OpenSSL HMAC method",

    .pkey_size = hmac_size,

    .pkey_free = hmac_key_free,
    .pkey_ctrl = hmac_pkey_ctrl,

#ifdef HMAC_TEST_PRIVATE_KEY_FORMAT
    .old_priv_decode = old_hmac_decode,
    .old_priv_encode = old_hmac_encode
#endif
};
