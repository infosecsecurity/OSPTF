/*
 * Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef HEADER_CRYPTLIB_H
#define HEADER_CRYPTLIB_H

#include <openssl/crypto.h>
#include <openssl/buffer.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/opensslconf.h>

#ifdef __cplusplus
extern "C" {
#endif

#define X509_CERT_AREA OPENSSLDIR
#define X509_CERT_DIR OPENSSLDIR "/certs"
#define X509_CERT_FILE OPENSSLDIR "/cert.pem"
#define X509_PRIVATE_DIR OPENSSLDIR "/private"

#define X509_CERT_DIR_EVP "SSL_CERT_DIR"
#define X509_CERT_FILE_EVP "SSL_CERT_FILE"

/* size of string representations */
#define DECIMAL_SIZE(type) ((sizeof(type) * 8 + 2) / 3 + 1)
#define HEX_SIZE(type) (sizeof(type) * 2)

void OPENSSL_cpuid_setup(void);
extern uint32_t OPENSSL_ia32cap_P[4];

#ifdef __cplusplus
}
#endif

#endif
