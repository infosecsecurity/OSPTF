/*
 * Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <openssl/asn1t.h>
#include <openssl/x509.h>

/* X509_REQ_INFO is handled in an unusual way to get round
 * invalid encodings. Some broken certificate requests don't
 * encode the attributes field if it is empty. This is in
 * violation of PKCS#10 but we need to tolerate it. We do
 * this by making the attributes field OPTIONAL then using
 * the callback to initialise it to an empty STACK.
 *
 * This means that the field will be correctly encoded unless
 * we NULL out the field.
 *
 * As a result we no longer need the req_kludge field because
 * the information is now contained in the attributes field:
 * 1. If it is NULL then it's the invalid omission.
 * 2. If it is empty it is the correct encoding.
 * 3. If it is not empty then some attributes are present.
 *
 */

static int rinf_cb(int operation, ASN1_VALUE **pval, const ASN1_ITEM *it,
                   void *exarg)
{
    X509_REQ_INFO *rinf = (X509_REQ_INFO *)*pval;

    if (operation == ASN1_OP_NEW_POST) {
        rinf->attributes = sk_X509_ATTRIBUTE_new_null();
        if (!rinf->attributes)
            return 0;
    }
    return 1;
}

ASN1_SEQUENCE_enc(X509_REQ_INFO, enc, rinf_cb) = {
    ASN1_SIMPLE(X509_REQ_INFO, version, ASN1_INTEGER),
    ASN1_SIMPLE(X509_REQ_INFO, subject, X509_NAME),
    ASN1_SIMPLE(X509_REQ_INFO, pubkey, X509_PUBKEY),
    /* This isn't really OPTIONAL but it gets round invalid
     * encodings
     */
    ASN1_IMP_SET_OF_OPT(X509_REQ_INFO, attributes, X509_ATTRIBUTE, 0)
} ASN1_SEQUENCE_END_enc(X509_REQ_INFO, X509_REQ_INFO)

X509_REQ_INFO *d2i_X509_REQ_INFO(X509_REQ_INFO **a, const uint8_t **in, long len)
{
    return (X509_REQ_INFO *)ASN1_item_d2i((ASN1_VALUE **)a, in, len, ASN1_ITEM_rptr(X509_REQ_INFO));
}

int i2d_X509_REQ_INFO(X509_REQ_INFO *a, uint8_t **out)
{
    return ASN1_item_i2d((ASN1_VALUE *)a, out, ASN1_ITEM_rptr(X509_REQ_INFO));
}

X509_REQ_INFO *X509_REQ_INFO_new(void)
{
    return (X509_REQ_INFO *)ASN1_item_new(ASN1_ITEM_rptr(X509_REQ_INFO));
}

void X509_REQ_INFO_free(X509_REQ_INFO *a)
{
    ASN1_item_free((ASN1_VALUE *)a, ASN1_ITEM_rptr(X509_REQ_INFO));
}

ASN1_SEQUENCE_ref(X509_REQ, 0) = {
    ASN1_SIMPLE(X509_REQ, req_info, X509_REQ_INFO),
    ASN1_SIMPLE(X509_REQ, sig_alg, X509_ALGOR),
    ASN1_SIMPLE(X509_REQ, signature, ASN1_BIT_STRING)
} ASN1_SEQUENCE_END_ref(X509_REQ, X509_REQ)

X509_REQ *d2i_X509_REQ(X509_REQ **a, const uint8_t **in, long len)
{
    return (X509_REQ *)ASN1_item_d2i((ASN1_VALUE **)a, in, len, ASN1_ITEM_rptr(X509_REQ));
}

int i2d_X509_REQ(X509_REQ *a, uint8_t **out)
{
    return ASN1_item_i2d((ASN1_VALUE *)a, out, ASN1_ITEM_rptr(X509_REQ));
}

X509_REQ *X509_REQ_new(void)
{
    return (X509_REQ *)ASN1_item_new(ASN1_ITEM_rptr(X509_REQ));
}

void X509_REQ_free(X509_REQ *a)
{
    ASN1_item_free((ASN1_VALUE *)a, ASN1_ITEM_rptr(X509_REQ));
}

X509_REQ *X509_REQ_dup(X509_REQ *x)
{
    return ASN1_item_dup(ASN1_ITEM_rptr(X509_REQ), x);
}
