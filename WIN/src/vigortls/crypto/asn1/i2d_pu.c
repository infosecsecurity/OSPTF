/*
 * Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/bn.h>
#ifndef OPENSSL_NO_DSA
#include <openssl/dsa.h>
#endif
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/rsa.h>

int i2d_PublicKey(EVP_PKEY *a, uint8_t **pp)
{
    switch (a->type) {
        case EVP_PKEY_RSA:
            return (i2d_RSAPublicKey(a->pkey.rsa, pp));
#ifndef OPENSSL_NO_DSA
        case EVP_PKEY_DSA:
            return (i2d_DSAPublicKey(a->pkey.dsa, pp));
#endif
        case EVP_PKEY_EC:
            return (i2o_ECPublicKey(a->pkey.ec, pp));
        default:
            ASN1err(ASN1_F_I2D_PUBLICKEY, ASN1_R_UNSUPPORTED_PUBLIC_KEY_TYPE);
            return (-1);
    }
}
