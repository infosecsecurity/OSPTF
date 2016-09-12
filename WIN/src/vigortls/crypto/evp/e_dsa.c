/*
 * Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/x509.h>

static EVP_PKEY_METHOD dss_method = {
    DSA_sign,
    DSA_verify,
    { EVP_PKEY_DSA, EVP_PKEY_DSA2, EVP_PKEY_DSA3, NULL },
};
