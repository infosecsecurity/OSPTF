/*
 * Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/x509.h>

int EVP_PKEY_encrypt_old(uint8_t *ek, const uint8_t *key, int key_len,
                         EVP_PKEY *pubk)
{
    int ret = 0;

    if (pubk->type != EVP_PKEY_RSA) {
        EVPerr(EVP_F_EVP_PKEY_ENCRYPT_OLD, EVP_R_PUBLIC_KEY_NOT_RSA);
        goto err;
    }
    ret = RSA_public_encrypt(key_len, key, ek, pubk->pkey.rsa, RSA_PKCS1_PADDING);
err:
    return (ret);
}
