/*
 * Copyright 2004-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/ts.h>
#include <openssl/err.h>
#include <openssl/asn1t.h>

ASN1_SEQUENCE(TS_MSG_IMPRINT) = {
    ASN1_SIMPLE(TS_MSG_IMPRINT, hash_algo, X509_ALGOR),
    ASN1_SIMPLE(TS_MSG_IMPRINT, hashed_msg, ASN1_OCTET_STRING)
} ASN1_SEQUENCE_END(TS_MSG_IMPRINT)

TS_MSG_IMPRINT *d2i_TS_MSG_IMPRINT(TS_MSG_IMPRINT **a, const uint8_t **in, long len)
{
    return (TS_MSG_IMPRINT *)ASN1_item_d2i((ASN1_VALUE **)a, in, len, ASN1_ITEM_rptr(TS_MSG_IMPRINT));
}

int i2d_TS_MSG_IMPRINT(const TS_MSG_IMPRINT *a, uint8_t **out)
{
    return ASN1_item_i2d((ASN1_VALUE *)a, out, ASN1_ITEM_rptr(TS_MSG_IMPRINT));
}

TS_MSG_IMPRINT *TS_MSG_IMPRINT_new(void)
{
    return (TS_MSG_IMPRINT *)ASN1_item_new(ASN1_ITEM_rptr(TS_MSG_IMPRINT));
}

void TS_MSG_IMPRINT_free(TS_MSG_IMPRINT *a)
{
    ASN1_item_free((ASN1_VALUE *)a, ASN1_ITEM_rptr(TS_MSG_IMPRINT));
}

TS_MSG_IMPRINT *TS_MSG_IMPRINT_dup(TS_MSG_IMPRINT *x)
{
    return ASN1_item_dup(ASN1_ITEM_rptr(TS_MSG_IMPRINT), x);
}
TS_MSG_IMPRINT *d2i_TS_MSG_IMPRINT_bio(BIO *bp, TS_MSG_IMPRINT **a)
{
    return ASN1_d2i_bio_of(TS_MSG_IMPRINT, TS_MSG_IMPRINT_new, d2i_TS_MSG_IMPRINT, bp, a);
}

int i2d_TS_MSG_IMPRINT_bio(BIO *bp, TS_MSG_IMPRINT *a)
{
    return ASN1_i2d_bio_of_const(TS_MSG_IMPRINT, i2d_TS_MSG_IMPRINT, bp, a);
}
TS_MSG_IMPRINT *d2i_TS_MSG_IMPRINT_fp(FILE *fp, TS_MSG_IMPRINT **a)
{
    return ASN1_d2i_fp_of(TS_MSG_IMPRINT, TS_MSG_IMPRINT_new, d2i_TS_MSG_IMPRINT, fp, a);
}

int i2d_TS_MSG_IMPRINT_fp(FILE *fp, TS_MSG_IMPRINT *a)
{
    return ASN1_i2d_fp_of_const(TS_MSG_IMPRINT, i2d_TS_MSG_IMPRINT, fp, a);
}

ASN1_SEQUENCE(TS_REQ) = {
    ASN1_SIMPLE(TS_REQ, version, ASN1_INTEGER),
    ASN1_SIMPLE(TS_REQ, msg_imprint, TS_MSG_IMPRINT),
    ASN1_OPT(TS_REQ, policy_id, ASN1_OBJECT),
    ASN1_OPT(TS_REQ, nonce, ASN1_INTEGER),
    ASN1_OPT(TS_REQ, cert_req, ASN1_FBOOLEAN),
    ASN1_IMP_SEQUENCE_OF_OPT(TS_REQ, extensions, X509_EXTENSION, 0)
} ASN1_SEQUENCE_END(TS_REQ)

TS_REQ *d2i_TS_REQ(TS_REQ **a, const uint8_t **in, long len)
{
    return (TS_REQ *)ASN1_item_d2i((ASN1_VALUE **)a, in, len, ASN1_ITEM_rptr(TS_REQ));
}

int i2d_TS_REQ(const TS_REQ *a, uint8_t **out)
{
    return ASN1_item_i2d((ASN1_VALUE *)a, out, ASN1_ITEM_rptr(TS_REQ));
}

TS_REQ *TS_REQ_new(void)
{
    return (TS_REQ *)ASN1_item_new(ASN1_ITEM_rptr(TS_REQ));
}

void TS_REQ_free(TS_REQ *a)
{
    ASN1_item_free((ASN1_VALUE *)a, ASN1_ITEM_rptr(TS_REQ));
}

TS_REQ *TS_REQ_dup(TS_REQ *x)
{
    return ASN1_item_dup(ASN1_ITEM_rptr(TS_REQ), x);
}
TS_REQ * d2i_TS_REQ_bio(BIO *bp, TS_REQ **a)
{
    return ASN1_d2i_bio_of(TS_REQ, TS_REQ_new, d2i_TS_REQ, bp, a);
}

int i2d_TS_REQ_bio(BIO *bp, TS_REQ *a)
{
    return ASN1_i2d_bio_of_const(TS_REQ, i2d_TS_REQ, bp, a);
}
TS_REQ *d2i_TS_REQ_fp(FILE *fp, TS_REQ **a)
{
    return ASN1_d2i_fp_of(TS_REQ, TS_REQ_new, d2i_TS_REQ, fp, a);
}

int i2d_TS_REQ_fp(FILE *fp, TS_REQ *a)
{
    return ASN1_i2d_fp_of_const(TS_REQ, i2d_TS_REQ, fp, a);
}

ASN1_SEQUENCE(TS_ACCURACY) = {
    ASN1_OPT(TS_ACCURACY, seconds, ASN1_INTEGER),
    ASN1_IMP_OPT(TS_ACCURACY, millis, ASN1_INTEGER, 0),
    ASN1_IMP_OPT(TS_ACCURACY, micros, ASN1_INTEGER, 1)
} ASN1_SEQUENCE_END(TS_ACCURACY)

TS_ACCURACY *d2i_TS_ACCURACY(TS_ACCURACY **a, const uint8_t **in, long len)
{
    return (TS_ACCURACY *)ASN1_item_d2i((ASN1_VALUE **)a, in, len, ASN1_ITEM_rptr(TS_ACCURACY));
}

int i2d_TS_ACCURACY(const TS_ACCURACY *a, uint8_t **out)
{
    return ASN1_item_i2d((ASN1_VALUE *)a, out, ASN1_ITEM_rptr(TS_ACCURACY));
}

TS_ACCURACY *TS_ACCURACY_new(void)
{
    return (TS_ACCURACY *)ASN1_item_new(ASN1_ITEM_rptr(TS_ACCURACY));
}

void TS_ACCURACY_free(TS_ACCURACY *a)
{
    ASN1_item_free((ASN1_VALUE *)a, ASN1_ITEM_rptr(TS_ACCURACY));
}

TS_ACCURACY *TS_ACCURACY_dup(TS_ACCURACY *x)
{
    return ASN1_item_dup(ASN1_ITEM_rptr(TS_ACCURACY), x);
}

ASN1_SEQUENCE(TS_TST_INFO) = {
    ASN1_SIMPLE(TS_TST_INFO, version, ASN1_INTEGER),
    ASN1_SIMPLE(TS_TST_INFO, policy_id, ASN1_OBJECT),
    ASN1_SIMPLE(TS_TST_INFO, msg_imprint, TS_MSG_IMPRINT),
    ASN1_SIMPLE(TS_TST_INFO, serial, ASN1_INTEGER),
    ASN1_SIMPLE(TS_TST_INFO, time, ASN1_GENERALIZEDTIME),
    ASN1_OPT(TS_TST_INFO, accuracy, TS_ACCURACY),
    ASN1_OPT(TS_TST_INFO, ordering, ASN1_FBOOLEAN),
    ASN1_OPT(TS_TST_INFO, nonce, ASN1_INTEGER),
    ASN1_EXP_OPT(TS_TST_INFO, tsa, GENERAL_NAME, 0),
    ASN1_IMP_SEQUENCE_OF_OPT(TS_TST_INFO, extensions, X509_EXTENSION, 1)
} ASN1_SEQUENCE_END(TS_TST_INFO)

TS_TST_INFO *d2i_TS_TST_INFO(TS_TST_INFO **a, const uint8_t **in, long len)
{
    return (TS_TST_INFO *)ASN1_item_d2i((ASN1_VALUE **)a, in, len, ASN1_ITEM_rptr(TS_TST_INFO));
}

int i2d_TS_TST_INFO(const TS_TST_INFO *a, uint8_t **out)
{
    return ASN1_item_i2d((ASN1_VALUE *)a, out, ASN1_ITEM_rptr(TS_TST_INFO));
}

TS_TST_INFO *TS_TST_INFO_new(void)
{
    return (TS_TST_INFO *)ASN1_item_new(ASN1_ITEM_rptr(TS_TST_INFO));
}

void TS_TST_INFO_free(TS_TST_INFO *a)
{
    ASN1_item_free((ASN1_VALUE *)a, ASN1_ITEM_rptr(TS_TST_INFO));
}

TS_TST_INFO *TS_TST_INFO_dup(TS_TST_INFO *x)
{
    return ASN1_item_dup(ASN1_ITEM_rptr(TS_TST_INFO), x);
}
TS_TST_INFO *d2i_TS_TST_INFO_bio(BIO *bp, TS_TST_INFO **a)
{
    return ASN1_d2i_bio_of(TS_TST_INFO, TS_TST_INFO_new, d2i_TS_TST_INFO, bp, a);
}

int i2d_TS_TST_INFO_bio(BIO *bp, TS_TST_INFO *a)
{
    return ASN1_i2d_bio_of_const(TS_TST_INFO, i2d_TS_TST_INFO, bp, a);
}
TS_TST_INFO *d2i_TS_TST_INFO_fp(FILE *fp, TS_TST_INFO **a)
{
    return ASN1_d2i_fp_of(TS_TST_INFO, TS_TST_INFO_new, d2i_TS_TST_INFO, fp, a);
}

int i2d_TS_TST_INFO_fp(FILE *fp, TS_TST_INFO *a)
{
    return ASN1_i2d_fp_of_const(TS_TST_INFO, i2d_TS_TST_INFO, fp, a);
}

ASN1_SEQUENCE(TS_STATUS_INFO) = {
    ASN1_SIMPLE(TS_STATUS_INFO, status, ASN1_INTEGER),
    ASN1_SEQUENCE_OF_OPT(TS_STATUS_INFO, text, ASN1_UTF8STRING),
    ASN1_OPT(TS_STATUS_INFO, failure_info, ASN1_BIT_STRING)
} ASN1_SEQUENCE_END(TS_STATUS_INFO)

TS_STATUS_INFO *d2i_TS_STATUS_INFO(TS_STATUS_INFO **a, const uint8_t **in, long len)
{
    return (TS_STATUS_INFO *)ASN1_item_d2i((ASN1_VALUE **)a, in, len, ASN1_ITEM_rptr(TS_STATUS_INFO));
}

int i2d_TS_STATUS_INFO(const TS_STATUS_INFO *a, uint8_t **out)
{
    return ASN1_item_i2d((ASN1_VALUE *)a, out, ASN1_ITEM_rptr(TS_STATUS_INFO));
}

TS_STATUS_INFO *TS_STATUS_INFO_new(void)
{
    return (TS_STATUS_INFO *)ASN1_item_new(ASN1_ITEM_rptr(TS_STATUS_INFO));
}

void TS_STATUS_INFO_free(TS_STATUS_INFO *a)
{
    ASN1_item_free((ASN1_VALUE *)a, ASN1_ITEM_rptr(TS_STATUS_INFO));
}

TS_STATUS_INFO *TS_STATUS_INFO_dup(TS_STATUS_INFO *x)
{
    return ASN1_item_dup(ASN1_ITEM_rptr(TS_STATUS_INFO), x);
}

static int ts_resp_set_tst_info(TS_RESP *a)
{
    long status;

    status = ASN1_INTEGER_get(a->status_info->status);

    if (a->token) {
        if (status != 0 && status != 1) {
            TSerr(TS_F_TS_RESP_SET_TST_INFO, TS_R_TOKEN_PRESENT);
            return 0;
        }
        if (a->tst_info != NULL)
            TS_TST_INFO_free(a->tst_info);
        a->tst_info = PKCS7_to_TS_TST_INFO(a->token);
        if (!a->tst_info) {
            TSerr(TS_F_TS_RESP_SET_TST_INFO, TS_R_PKCS7_TO_TS_TST_INFO_FAILED);
            return 0;
        }
    } else if (status == 0 || status == 1) {
        TSerr(TS_F_TS_RESP_SET_TST_INFO, TS_R_TOKEN_NOT_PRESENT);
        return 0;
    }

    return 1;
}

static int ts_resp_cb(int op, ASN1_VALUE **pval, const ASN1_ITEM *it,
                      void *exarg)
{
    TS_RESP *ts_resp = (TS_RESP *)*pval;
    if (op == ASN1_OP_NEW_POST) {
        ts_resp->tst_info = NULL;
    } else if (op == ASN1_OP_FREE_POST) {
        if (ts_resp->tst_info != NULL)
            TS_TST_INFO_free(ts_resp->tst_info);
    } else if (op == ASN1_OP_D2I_POST) {
        if (ts_resp_set_tst_info(ts_resp) == 0)
            return 0;
    }
    return 1;
}

ASN1_SEQUENCE_cb(TS_RESP, ts_resp_cb) = {
    ASN1_SIMPLE(TS_RESP, status_info, TS_STATUS_INFO),
    ASN1_OPT(TS_RESP, token, PKCS7),
} ASN1_SEQUENCE_END_cb(TS_RESP, TS_RESP)

TS_RESP *d2i_TS_RESP(TS_RESP **a, const uint8_t **in, long len)
{
    return (TS_RESP *)ASN1_item_d2i((ASN1_VALUE **)a, in, len, ASN1_ITEM_rptr(TS_RESP));
}

int i2d_TS_RESP(const TS_RESP *a, uint8_t **out)
{
    return ASN1_item_i2d((ASN1_VALUE *)a, out, ASN1_ITEM_rptr(TS_RESP));
}

TS_RESP *TS_RESP_new(void)
{
    return (TS_RESP *)ASN1_item_new(ASN1_ITEM_rptr(TS_RESP));
}

void TS_RESP_free(TS_RESP *a)
{
    ASN1_item_free((ASN1_VALUE *)a, ASN1_ITEM_rptr(TS_RESP));
}

TS_RESP *TS_RESP_dup(TS_RESP *x)
{
    return ASN1_item_dup(ASN1_ITEM_rptr(TS_RESP), x);
}
TS_RESP *d2i_TS_RESP_bio(BIO *bp, TS_RESP **a)
{
    return ASN1_d2i_bio_of(TS_RESP, TS_RESP_new, d2i_TS_RESP, bp, a);
}

int i2d_TS_RESP_bio(BIO *bp, TS_RESP *a)
{
    return ASN1_i2d_bio_of_const(TS_RESP, i2d_TS_RESP, bp, a);
}
TS_RESP *d2i_TS_RESP_fp(FILE *fp, TS_RESP **a)
{
    return ASN1_d2i_fp_of(TS_RESP, TS_RESP_new, d2i_TS_RESP, fp, a);
}

int i2d_TS_RESP_fp(FILE *fp, TS_RESP *a)
{
    return ASN1_i2d_fp_of_const(TS_RESP, i2d_TS_RESP, fp, a);
}

ASN1_SEQUENCE(ESS_ISSUER_SERIAL) = {
    ASN1_SEQUENCE_OF(ESS_ISSUER_SERIAL, issuer, GENERAL_NAME),
    ASN1_SIMPLE(ESS_ISSUER_SERIAL, serial, ASN1_INTEGER)
} ASN1_SEQUENCE_END(ESS_ISSUER_SERIAL)

ESS_ISSUER_SERIAL *d2i_ESS_ISSUER_SERIAL(ESS_ISSUER_SERIAL **a, const uint8_t **in, long len)
{
    return (ESS_ISSUER_SERIAL *)ASN1_item_d2i((ASN1_VALUE **)a, in, len, ASN1_ITEM_rptr(ESS_ISSUER_SERIAL));
}

int i2d_ESS_ISSUER_SERIAL(const ESS_ISSUER_SERIAL *a, uint8_t **out)
{
    return ASN1_item_i2d((ASN1_VALUE *)a, out, ASN1_ITEM_rptr(ESS_ISSUER_SERIAL));
}

ESS_ISSUER_SERIAL *ESS_ISSUER_SERIAL_new(void)
{
    return (ESS_ISSUER_SERIAL *)ASN1_item_new(ASN1_ITEM_rptr(ESS_ISSUER_SERIAL));
}

void ESS_ISSUER_SERIAL_free(ESS_ISSUER_SERIAL *a)
{
    ASN1_item_free((ASN1_VALUE *)a, ASN1_ITEM_rptr(ESS_ISSUER_SERIAL));
}

ESS_ISSUER_SERIAL *ESS_ISSUER_SERIAL_dup(ESS_ISSUER_SERIAL *x)
{
    return ASN1_item_dup(ASN1_ITEM_rptr(ESS_ISSUER_SERIAL), x);
}

ASN1_SEQUENCE(ESS_CERT_ID) = {
    ASN1_SIMPLE(ESS_CERT_ID, hash, ASN1_OCTET_STRING),
    ASN1_OPT(ESS_CERT_ID, issuer_serial, ESS_ISSUER_SERIAL)
} ASN1_SEQUENCE_END(ESS_CERT_ID)

ESS_CERT_ID *d2i_ESS_CERT_ID(ESS_CERT_ID **a, const uint8_t **in, long len)
{
    return (ESS_CERT_ID *)ASN1_item_d2i((ASN1_VALUE **)a, in, len, ASN1_ITEM_rptr(ESS_CERT_ID));
}

int i2d_ESS_CERT_ID(const ESS_CERT_ID *a, uint8_t **out)
{
    return ASN1_item_i2d((ASN1_VALUE *)a, out, ASN1_ITEM_rptr(ESS_CERT_ID));
}

ESS_CERT_ID *ESS_CERT_ID_new(void)
{
    return (ESS_CERT_ID *)ASN1_item_new(ASN1_ITEM_rptr(ESS_CERT_ID));
}

void ESS_CERT_ID_free(ESS_CERT_ID *a)
{
    ASN1_item_free((ASN1_VALUE *)a, ASN1_ITEM_rptr(ESS_CERT_ID));
}

ESS_CERT_ID *ESS_CERT_ID_dup(ESS_CERT_ID *x)
{
    return ASN1_item_dup(ASN1_ITEM_rptr(ESS_CERT_ID), x);
}

ASN1_SEQUENCE(ESS_SIGNING_CERT) = {
    ASN1_SEQUENCE_OF(ESS_SIGNING_CERT, cert_ids, ESS_CERT_ID),
    ASN1_SEQUENCE_OF_OPT(ESS_SIGNING_CERT, policy_info, POLICYINFO)
} ASN1_SEQUENCE_END(ESS_SIGNING_CERT)

ESS_SIGNING_CERT *d2i_ESS_SIGNING_CERT(ESS_SIGNING_CERT **a, const uint8_t **in, long len)
{
    return (ESS_SIGNING_CERT *)ASN1_item_d2i((ASN1_VALUE **)a, in, len, ASN1_ITEM_rptr(ESS_SIGNING_CERT));
}

int i2d_ESS_SIGNING_CERT(const ESS_SIGNING_CERT *a, uint8_t **out)
{
    return ASN1_item_i2d((ASN1_VALUE *)a, out, ASN1_ITEM_rptr(ESS_SIGNING_CERT));
}

ESS_SIGNING_CERT *ESS_SIGNING_CERT_new(void)
{
    return (ESS_SIGNING_CERT *)ASN1_item_new(ASN1_ITEM_rptr(ESS_SIGNING_CERT));
}

void ESS_SIGNING_CERT_free(ESS_SIGNING_CERT *a)
{
    ASN1_item_free((ASN1_VALUE *)a, ASN1_ITEM_rptr(ESS_SIGNING_CERT));
}

ESS_SIGNING_CERT *ESS_SIGNING_CERT_dup(ESS_SIGNING_CERT *x)
{
    return ASN1_item_dup(ASN1_ITEM_rptr(ESS_SIGNING_CERT), x);
}

/* Getting encapsulated TS_TST_INFO object from PKCS7. */
TS_TST_INFO *PKCS7_to_TS_TST_INFO(PKCS7 *token)
{
    PKCS7_SIGNED *pkcs7_signed;
    PKCS7 *enveloped;
    ASN1_TYPE *tst_info_wrapper;
    ASN1_OCTET_STRING *tst_info_der;
    const uint8_t *p;

    if (!PKCS7_type_is_signed(token)) {
        TSerr(TS_F_PKCS7_TO_TS_TST_INFO, TS_R_BAD_PKCS7_TYPE);
        return NULL;
    }

    /* Content must be present. */
    if (PKCS7_get_detached(token)) {
        TSerr(TS_F_PKCS7_TO_TS_TST_INFO, TS_R_DETACHED_CONTENT);
        return NULL;
    }

    /* We have a signed data with content. */
    pkcs7_signed = token->d.sign;
    enveloped = pkcs7_signed->contents;
    if (OBJ_obj2nid(enveloped->type) != NID_id_smime_ct_TSTInfo) {
        TSerr(TS_F_PKCS7_TO_TS_TST_INFO, TS_R_BAD_PKCS7_TYPE);
        return NULL;
    }

    /* We have a DER encoded TST_INFO as the signed data. */
    tst_info_wrapper = enveloped->d.other;
    if (tst_info_wrapper->type != V_ASN1_OCTET_STRING) {
        TSerr(TS_F_PKCS7_TO_TS_TST_INFO, TS_R_BAD_TYPE);
        return NULL;
    }

    /* We have the correct ASN1_OCTET_STRING type. */
    tst_info_der = tst_info_wrapper->value.octet_string;
    /* At last, decode the TST_INFO. */
    p = tst_info_der->data;
    return d2i_TS_TST_INFO(NULL, &p, tst_info_der->length);
}
