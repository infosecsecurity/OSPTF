/*
 * Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <openssl/asn1.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/buffer.h>
#include <openssl/bio.h>
#include <openssl/rsa.h>
#include <openssl/dh.h>
#ifndef OPENSSL_NO_DSA
#include <openssl/dsa.h>
#endif
#include <openssl/ecdsa.h>
#include <openssl/ecdh.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/pem2.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/conf.h>
#include <openssl/pkcs12.h>
#include <openssl/rand.h>
#include <openssl/dso.h>
#ifndef OPENSSL_NO_ENGINE
#include <openssl/engine.h>
#endif
#include <openssl/ui.h>
#include <openssl/ocsp.h>
#include <openssl/err.h>
#include <openssl/ts.h>
#ifndef OPENSSL_NO_CMS
#include <openssl/cms.h>
#endif
#ifndef OPENSSL_NO_GOST
#include <openssl/gost.h>
#endif

void ERR_load_crypto_strings(void)
{
#ifndef OPENSSL_NO_ERR
    ERR_load_ERR_strings(); /* include error strings for SYSerr */
    ERR_load_BN_strings();
    ERR_load_RSA_strings();
    ERR_load_DH_strings();
    ERR_load_EVP_strings();
    ERR_load_BUF_strings();
    ERR_load_OBJ_strings();
    ERR_load_PEM_strings();
#ifndef OPENSSL_NO_DSA
    ERR_load_DSA_strings();
#endif
    ERR_load_X509_strings();
    ERR_load_ASN1_strings();
    ERR_load_CONF_strings();
    ERR_load_CRYPTO_strings();
    ERR_load_EC_strings();
    ERR_load_ECDSA_strings();
    ERR_load_ECDH_strings();
    /* skip ERR_load_SSL_strings() because it is not in this library */
    ERR_load_BIO_strings();
    ERR_load_PKCS7_strings();
    ERR_load_X509V3_strings();
    ERR_load_PKCS12_strings();
    ERR_load_RAND_strings();
    ERR_load_DSO_strings();
    ERR_load_TS_strings();
#ifndef OPENSSL_NO_ENGINE
    ERR_load_ENGINE_strings();
#endif
    ERR_load_OCSP_strings();
    ERR_load_UI_strings();
#ifndef OPENSSL_NO_CMS
    ERR_load_CMS_strings();
#endif
#ifndef OPENSSL_NO_GOST
    ERR_load_GOST_strings();
#endif
#endif
}
