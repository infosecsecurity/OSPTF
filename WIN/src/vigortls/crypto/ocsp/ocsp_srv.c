/*
 * Copyright 2001-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <cryptlib.h>
#include <openssl/objects.h>
#include <openssl/rand.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/x509v3.h>
#include <openssl/ocsp.h>

/* Utility functions related to sending OCSP responses and extracting
 * relevant information from the request.
 */

int OCSP_request_onereq_count(OCSP_REQUEST *req)
{
    return sk_OCSP_ONEREQ_num(req->tbsRequest->requestList);
}

OCSP_ONEREQ *OCSP_request_onereq_get0(OCSP_REQUEST *req, int i)
{
    return sk_OCSP_ONEREQ_value(req->tbsRequest->requestList, i);
}

OCSP_CERTID *OCSP_onereq_get0_id(OCSP_ONEREQ *one)
{
    return one->reqCert;
}

int OCSP_id_get0_info(ASN1_OCTET_STRING **piNameHash, ASN1_OBJECT **pmd,
                      ASN1_OCTET_STRING **pikeyHash,
                      ASN1_INTEGER **pserial, OCSP_CERTID *cid)
{
    if (!cid)
        return 0;
    if (pmd)
        *pmd = cid->hashAlgorithm->algorithm;
    if (piNameHash)
        *piNameHash = cid->issuerNameHash;
    if (pikeyHash)
        *pikeyHash = cid->issuerKeyHash;
    if (pserial)
        *pserial = cid->serialNumber;
    return 1;
}

int OCSP_request_is_signed(OCSP_REQUEST *req)
{
    if (req->optionalSignature)
        return 1;
    return 0;
}

/* Create an OCSP response and encode an optional basic response */
OCSP_RESPONSE *OCSP_response_create(int status, OCSP_BASICRESP *bs)
{
    OCSP_RESPONSE *rsp = NULL;

    if (!(rsp = OCSP_RESPONSE_new()))
        goto err;
    if (!(ASN1_ENUMERATED_set(rsp->responseStatus, status)))
        goto err;
    if (!bs)
        return rsp;
    if (!(rsp->responseBytes = OCSP_RESPBYTES_new()))
        goto err;
    rsp->responseBytes->responseType = OBJ_nid2obj(NID_id_pkix_OCSP_basic);
    if (!ASN1_item_pack(bs, ASN1_ITEM_rptr(OCSP_BASICRESP), &rsp->responseBytes->response))
        goto err;
    return rsp;
err:
    if (rsp)
        OCSP_RESPONSE_free(rsp);
    return NULL;
}

OCSP_SINGLERESP *OCSP_basic_add1_status(OCSP_BASICRESP *rsp,
                                        OCSP_CERTID *cid,
                                        int status, int reason,
                                        ASN1_TIME *revtime,
                                        ASN1_TIME *thisupd, ASN1_TIME *nextupd)
{
    OCSP_SINGLERESP *single = NULL;
    OCSP_CERTSTATUS *cs;
    OCSP_REVOKEDINFO *ri;

    if (!rsp->tbsResponseData->responses && !(rsp->tbsResponseData->responses = sk_OCSP_SINGLERESP_new_null()))
        goto err;

    if (!(single = OCSP_SINGLERESP_new()))
        goto err;

    if (!ASN1_TIME_to_generalizedtime(thisupd, &single->thisUpdate))
        goto err;
    if (nextupd && !ASN1_TIME_to_generalizedtime(nextupd, &single->nextUpdate))
        goto err;

    OCSP_CERTID_free(single->certId);

    if (!(single->certId = OCSP_CERTID_dup(cid)))
        goto err;

    cs = single->certStatus;
    switch (cs->type = status) {
        case V_OCSP_CERTSTATUS_REVOKED:
            if (!revtime) {
                OCSPerr(OCSP_F_OCSP_BASIC_ADD1_STATUS, OCSP_R_NO_REVOKED_TIME);
                goto err;
            }
            if (!(cs->value.revoked = ri = OCSP_REVOKEDINFO_new()))
                goto err;
            if (!ASN1_TIME_to_generalizedtime(revtime, &ri->revocationTime))
                goto err;
            if (reason != OCSP_REVOKED_STATUS_NOSTATUS) {
                if (!(ri->revocationReason = ASN1_ENUMERATED_new()))
                    goto err;
                if (!(ASN1_ENUMERATED_set(ri->revocationReason,
                                          reason)))
                    goto err;
            }
            break;

        case V_OCSP_CERTSTATUS_GOOD:
            cs->value.good = ASN1_NULL_new();
            break;

        case V_OCSP_CERTSTATUS_UNKNOWN:
            cs->value.unknown = ASN1_NULL_new();
            break;

        default:
            goto err;
    }
    if (!(sk_OCSP_SINGLERESP_push(rsp->tbsResponseData->responses, single)))
        goto err;
    return single;
err:
    OCSP_SINGLERESP_free(single);
    return NULL;
}

/* Add a certificate to an OCSP request */

int OCSP_basic_add1_cert(OCSP_BASICRESP *resp, X509 *cert)
{
    if (!resp->certs && !(resp->certs = sk_X509_new_null()))
        return 0;

    if (!sk_X509_push(resp->certs, cert))
        return 0;

    X509_up_ref(cert);

    return 1;
}

int OCSP_basic_sign(OCSP_BASICRESP *brsp,
                    X509 *signer, EVP_PKEY *key, const EVP_MD *dgst,
                    STACK_OF(X509) *certs, unsigned long flags)
{
    int i;
    OCSP_RESPID *rid;

    if (!X509_check_private_key(signer, key)) {
        OCSPerr(OCSP_F_OCSP_BASIC_SIGN, OCSP_R_PRIVATE_KEY_DOES_NOT_MATCH_CERTIFICATE);
        goto err;
    }

    if (!(flags & OCSP_NOCERTS)) {
        if (!OCSP_basic_add1_cert(brsp, signer))
            goto err;
        for (i = 0; i < sk_X509_num(certs); i++) {
            X509 *tmpcert = sk_X509_value(certs, i);
            if (!OCSP_basic_add1_cert(brsp, tmpcert))
                goto err;
        }
    }

    rid = brsp->tbsResponseData->responderId;
    if (flags & OCSP_RESPID_KEY) {
        uint8_t md[SHA_DIGEST_LENGTH];
        X509_pubkey_digest(signer, EVP_sha1(), md, NULL);
        if (!(rid->value.byKey = ASN1_OCTET_STRING_new()))
            goto err;
        if (!(ASN1_OCTET_STRING_set(rid->value.byKey, md, SHA_DIGEST_LENGTH)))
            goto err;
        rid->type = V_OCSP_RESPID_KEY;
    } else {
        if (!X509_NAME_set(&rid->value.byName,
                           X509_get_subject_name(signer)))
            goto err;
        rid->type = V_OCSP_RESPID_NAME;
    }

    if (!(flags & OCSP_NOTIME) && !X509_gmtime_adj(brsp->tbsResponseData->producedAt, 0))
        goto err;

    /* Right now, I think that not doing double hashing is the right
       thing.    -- Richard Levitte */

    if (!OCSP_BASICRESP_sign(brsp, key, dgst, 0))
        goto err;

    return 1;
err:
    return 0;
}
