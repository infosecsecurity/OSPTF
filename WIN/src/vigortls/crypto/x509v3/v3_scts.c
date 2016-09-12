/*
 * Copyright 2014-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <string.h>

#include <openssl/asn1.h>
#include <openssl/x509v3.h>

#include "cryptlib.h"

/* Signature and hash algorithms from RFC 5246 */
#define TLSEXT_hash_sha256     4

#define TLSEXT_signature_rsa   1
#define TLSEXT_signature_ecdsa 3

#define n2s(c, s) \
    ((s = (((unsigned int)(c[0])) << 8) | (((unsigned int)(c[1])))), c += 2)

#if (defined(_WIN32) || defined(_WIN64)) && !defined(__MINGW32__)
#define SCT_TIMESTAMP unsigned __int64
#elif defined(__arch64__)
#define SCT_TIMESTAMP unsigned long
#else
#define SCT_TIMESTAMP unsigned long long
#endif

#define n2l8(c, l)                          \
    (l = ((SCT_TIMESTAMP)(*((c)++))) << 56, \
    l |= ((SCT_TIMESTAMP)(*((c)++))) << 48, \
    l |= ((SCT_TIMESTAMP)(*((c)++))) << 40, \
    l |= ((SCT_TIMESTAMP)(*((c)++))) << 32, \
    l |= ((SCT_TIMESTAMP)(*((c)++))) << 24, \
    l |= ((SCT_TIMESTAMP)(*((c)++))) << 16, \
    l |= ((SCT_TIMESTAMP)(*((c)++))) <<  8, \
    l |= ((SCT_TIMESTAMP)(*((c)++)))      )

typedef struct SCT_st {
    /* The encoded SCT */
    uint8_t *sct;
    uint16_t sctlen;

    /*
     * Components of the SCT.
     * "logid", "ext" and "sig" point to addresses inside "sct".
     */
    uint8_t version;
    uint8_t *logid;
    uint16_t logidlen;
    SCT_TIMESTAMP timestamp;
    uint8_t *ext;
    uint16_t extlen;
    uint8_t hash_alg;
    uint8_t sig_alg;
    uint8_t *sig;
    uint16_t siglen;
} SCT;

DECLARE_STACK_OF(SCT)

static void SCT_LIST_free(STACK_OF(SCT) *a);
static STACK_OF(SCT) *d2i_SCT_LIST(STACK_OF(SCT) **a, const uint8_t **pp,
                                   long length);
static int i2r_SCT_LIST(X509V3_EXT_METHOD *method, STACK_OF(SCT) *sct_list,
                        BIO *out, int indent);

const X509V3_EXT_METHOD v3_ct_scts[] = {
    {
        .ext_nid = NID_ct_precert_scts,
        .ext_free = (X509V3_EXT_FREE)SCT_LIST_free,
        .d2i = (X509V3_EXT_D2I)d2i_SCT_LIST,
        .i2r = (X509V3_EXT_I2R)i2r_SCT_LIST,
    },
    {
        .ext_nid = NID_ct_cert_scts,
        .ext_free = (X509V3_EXT_FREE)SCT_LIST_free,
        .d2i = (X509V3_EXT_D2I)d2i_SCT_LIST,
        .i2r = (X509V3_EXT_I2R)i2r_SCT_LIST,
    },
};

static void tls12_signature_print(BIO *out, const uint8_t hash_alg,
                                  const uint8_t sig_alg)
{
    int nid = NID_undef;
    /* RFC6962 only permits two signature algorithms */
    if (hash_alg == TLSEXT_hash_sha256) {
        if (sig_alg == TLSEXT_signature_rsa)
            nid = NID_sha256WithRSAEncryption;
        else if (sig_alg == TLSEXT_signature_ecdsa)
            nid = NID_ecdsa_with_SHA256;
    }
    if (nid == NID_undef)
        BIO_printf(out, "%02X%02X", hash_alg, sig_alg);
    else
        BIO_printf(out, "%s", OBJ_nid2ln(nid));
}

static void timestamp_print(BIO *out, SCT_TIMESTAMP timestamp)
{
    ASN1_GENERALIZEDTIME *gen;
    char genstr[20];
    gen = ASN1_GENERALIZEDTIME_new();
    ASN1_GENERALIZEDTIME_adj(gen, (time_t)0, timestamp / 86400000,
                             (timestamp % 86400000) / 1000);
    /*
     * Note GeneralizedTime from ASN1_GENERALIZETIME_adj is always 15
     * characters long with a final Z. Update it with fractional seconds.
     */
    snprintf(genstr, sizeof(genstr), "%.14s.%03dZ", ASN1_STRING_data(gen),
                 (unsigned int)(timestamp % 1000));
    ASN1_GENERALIZEDTIME_set_string(gen, genstr);
    ASN1_GENERALIZEDTIME_print(out, gen);
    ASN1_GENERALIZEDTIME_free(gen);
}

static void SCT_free(SCT *sct)
{
    if (sct == NULL)
        return;
    free(sct->sct);
    free(sct);
}

static void SCT_LIST_free(STACK_OF(SCT) *a)
{
    sk_SCT_pop_free(a, SCT_free);
}

static STACK_OF(SCT) *d2i_SCT_LIST(STACK_OF(SCT) **a, const uint8_t **pp,
                                   long length)
{
    ASN1_OCTET_STRING *oct = NULL;
    STACK_OF(SCT) *sk = NULL;
    SCT *sct;
    uint8_t *p, *p2;
    uint16_t listlen, sctlen = 0, fieldlen;
    const uint8_t *q = *pp;

    if (d2i_ASN1_OCTET_STRING(&oct, &q, length) == NULL)
        return NULL;
    if (oct->length < 2)
        goto done;
    p = oct->data;
    n2s(p, listlen);
    if (listlen != oct->length - 2)
        goto done;

    if ((sk = sk_SCT_new_null()) == NULL)
        goto done;

    while (listlen > 0) {
        if (listlen < 2)
            goto err;
        n2s(p, sctlen);
        listlen -= 2;

        if ((sctlen < 1) || (sctlen > listlen))
            goto err;
        listlen -= sctlen;

        sct = malloc(sizeof(SCT));
        if (sct == NULL)
            goto err;
        if (!sk_SCT_push(sk, sct)) {
            free(sct);
            goto err;
        }

        sct->sct = malloc(sctlen);
        if (sct->sct == NULL)
            goto err;
        memcpy(sct->sct, p, sctlen);
        sct->sctlen = sctlen;
        p += sctlen;
        p2 = sct->sct;

        sct->version = *p2++;
        if (sct->version == 0) { /* SCT v1 */
            /*
             * Fixed-length header:
             *		        struct {
             * (1 byte)	      Version sct_version;
             * (32 bytes)	  LogID id;
             * (8 bytes)	  uint64 timestamp;
             * (2 bytes + ?)  CtExtensions extensions;
             */
            if (sctlen < 43)
                goto err;
            sctlen -= 43;

            sct->logid = p2;
            sct->logidlen = 32;
            p2 += 32;

            n2l8(p2, sct->timestamp);

            n2s(p2, fieldlen);
            if (sctlen < fieldlen)
                goto err;
            sct->ext = p2;
            sct->extlen = fieldlen;
            p2 += fieldlen;
            sctlen -= fieldlen;

            /*
             * digitally-signed struct header:
             * (1 byte)       Hash algorithm
             * (1 byte)       Signature algorithm
             * (2 bytes + ?)  Signature
             */
            if (sctlen < 4)
                goto err;
            sctlen -= 4;

            sct->hash_alg = *p2++;
            sct->sig_alg = *p2++;
            n2s(p2, fieldlen);
            if (sctlen != fieldlen)
                goto err;
            sct->sig = p2;
            sct->siglen = fieldlen;
        }
    }

done:
    ASN1_OCTET_STRING_free(oct);
    *pp = q;
    return sk;

err:
    SCT_LIST_free(sk);
    sk = NULL;
    goto done;
}

static int i2r_SCT_LIST(X509V3_EXT_METHOD *method, STACK_OF(SCT) *sct_list,
                        BIO *out, int indent)
{
    SCT *sct;
    int i;

    for (i = 0; i < sk_SCT_num(sct_list);) {
        sct = sk_SCT_value(sct_list, i);

        BIO_printf(out, "%*sSigned Certificate Timestamp:", indent, "");
        BIO_printf(out, "\n%*sVersion   : ", indent + 4, "");

        if (sct->version == 0) { /* SCT v1 */
            BIO_printf(out, "v1(0)");

            BIO_printf(out, "\n%*sLog ID    : ", indent + 4, "");
            BIO_hex_string(out, indent + 16, 16, sct->logid, sct->logidlen);

            BIO_printf(out, "\n%*sTimestamp : ", indent + 4, "");
            timestamp_print(out, sct->timestamp);

            BIO_printf(out, "\n%*sExtensions: ", indent + 4, "");
            if (sct->extlen == 0)
                BIO_printf(out, "none");
            else
                BIO_hex_string(out, indent + 16, 16, sct->ext, sct->extlen);

            BIO_printf(out, "\n%*sSignature : ", indent + 4, "");
            tls12_signature_print(out, sct->hash_alg, sct->sig_alg);
            BIO_printf(out, "\n%*s            ", indent + 4, "");
            BIO_hex_string(out, indent + 16, 16, sct->sig, sct->siglen);
        } else { /* Unknown version */
            BIO_printf(out, "unknown\n%*s", indent + 16, "");
            BIO_hex_string(out, indent + 16, 16, sct->sct, sct->sctlen);
        }

        if (++i < sk_SCT_num(sct_list))
            BIO_printf(out, "\n");
    }

    return 1;
}