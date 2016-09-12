/*
 * Copyright 2010-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <openssl/evp.h>
#include <openssl/cmac.h>
#include "internal/asn1_int.h"

/* CMAC "ASN1" method. This is just here to indicate the
 * maximum CMAC output length and to free up a CMAC
 * key.
 */

static int cmac_size(const EVP_PKEY *pkey)
{
    return EVP_MAX_BLOCK_LENGTH;
}

static void cmac_key_free(EVP_PKEY *pkey)
{
    CMAC_CTX *cmctx = (CMAC_CTX *)pkey->pkey.ptr;
    if (cmctx)
        CMAC_CTX_free(cmctx);
}

const EVP_PKEY_ASN1_METHOD cmac_asn1_meth = {
    .pkey_id = EVP_PKEY_CMAC,
    .pkey_base_id = EVP_PKEY_CMAC,

    .pem_str = (char *)"CMAC",
    .info = (char *)"OpenSSL CMAC method",

    .pkey_size = cmac_size,
    .pkey_free = cmac_key_free
};
