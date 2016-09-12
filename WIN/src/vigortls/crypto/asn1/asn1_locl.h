/*
 * Copyright 2006-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/* Internal ASN1 structures and functions: not for application use */

/* Method to handle CRL access.
 * In general a CRL could be very large (several Mb) and can consume large
 * amounts of resources if stored in memory by multiple processes.
 * This method allows general CRL operations to be redirected to more
 * efficient callbacks: for example a CRL entry database.
 */

#define X509_CRL_METHOD_DYNAMIC 1

struct x509_crl_method_st {
    int flags;
    int (*crl_init)(X509_CRL *crl);
    int (*crl_free)(X509_CRL *crl);
    int (*crl_lookup)(X509_CRL *crl, X509_REVOKED **ret,
                      ASN1_INTEGER *ser, X509_NAME *issuer);
    int (*crl_verify)(X509_CRL *crl, EVP_PKEY *pk);
};

int asn1_get_choice_selector(ASN1_VALUE **pval, const ASN1_ITEM *it);
int asn1_set_choice_selector(ASN1_VALUE **pval, int value, const ASN1_ITEM *it);

ASN1_VALUE **asn1_get_field_ptr(ASN1_VALUE **pval, const ASN1_TEMPLATE *tt);

const ASN1_TEMPLATE *asn1_do_adb(ASN1_VALUE **pval, const ASN1_TEMPLATE *tt, int nullerr);

int asn1_do_lock(ASN1_VALUE **pval, int op, const ASN1_ITEM *it);

void asn1_enc_init(ASN1_VALUE **pval, const ASN1_ITEM *it);
void asn1_enc_free(ASN1_VALUE **pval, const ASN1_ITEM *it);
int asn1_enc_restore(int *len, uint8_t **out, ASN1_VALUE **pval, const ASN1_ITEM *it);
int asn1_enc_save(ASN1_VALUE **pval, const uint8_t *in, int inlen, const ASN1_ITEM *it);

void asn1_primitive_free(ASN1_VALUE **pval, const ASN1_ITEM *it);
void asn1_template_free(ASN1_VALUE **pval, const ASN1_TEMPLATE *tt);

ASN1_OBJECT *c2i_ASN1_OBJECT(ASN1_OBJECT **a, const uint8_t **pp, long length);
int i2c_ASN1_BIT_STRING(ASN1_BIT_STRING *a, uint8_t **pp);
ASN1_BIT_STRING *c2i_ASN1_BIT_STRING(ASN1_BIT_STRING **a, const uint8_t **pp, long length);
int i2c_ASN1_INTEGER(ASN1_INTEGER *a, uint8_t **pp);
ASN1_INTEGER *c2i_ASN1_INTEGER(ASN1_INTEGER **a, const uint8_t **pp, long length);
