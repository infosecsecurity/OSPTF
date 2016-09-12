/*
 * Copyright (c) 2014 Dmitry Eremin-Solenikov <dbaryshkov@gmail.com>
 * Copyright (c) 2005-2006 Cryptocom LTD
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef HEADER_GOST_ASN1_H
#define HEADER_GOST_ASN1_H

#include <openssl/asn1.h>

typedef struct {
	ASN1_OCTET_STRING *encrypted_key;
	ASN1_OCTET_STRING *imit;
} GOST_KEY_INFO;

DECLARE_ASN1_FUNCTIONS(GOST_KEY_INFO)

typedef struct {
	ASN1_OBJECT *cipher;
	X509_PUBKEY *ephem_key;
	ASN1_OCTET_STRING *eph_iv;
} GOST_KEY_AGREEMENT_INFO;

DECLARE_ASN1_FUNCTIONS(GOST_KEY_AGREEMENT_INFO)

typedef struct {
	GOST_KEY_INFO *key_info;
	GOST_KEY_AGREEMENT_INFO *key_agreement_info;
} GOST_KEY_TRANSPORT;

DECLARE_ASN1_FUNCTIONS(GOST_KEY_TRANSPORT)

typedef struct {
	ASN1_OBJECT *key_params;
	ASN1_OBJECT *hash_params;
	ASN1_OBJECT *cipher_params;
} GOST_KEY_PARAMS;

DECLARE_ASN1_FUNCTIONS(GOST_KEY_PARAMS)

#endif
