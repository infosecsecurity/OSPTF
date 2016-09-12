/*
 * Copyright 2008-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef HEADER_CMS_H
#define HEADER_CMS_H

#include <openssl/base.h>
#include <openssl/x509.h>

#ifdef OPENSSL_NO_CMS
#error CMS is disabled.
#endif

#ifdef __cplusplus
extern "C" {
#endif

typedef struct CMS_ContentInfo_st CMS_ContentInfo;
typedef struct CMS_SignerInfo_st CMS_SignerInfo;
typedef struct CMS_CertificateChoices CMS_CertificateChoices;
typedef struct CMS_RevocationInfoChoice_st CMS_RevocationInfoChoice;
typedef struct CMS_RecipientInfo_st CMS_RecipientInfo;
typedef struct CMS_ReceiptRequest_st CMS_ReceiptRequest;
typedef struct CMS_Receipt_st CMS_Receipt;
typedef struct CMS_RecipientEncryptedKey_st CMS_RecipientEncryptedKey;
typedef struct CMS_OtherKeyAttribute_st CMS_OtherKeyAttribute;

DECLARE_STACK_OF(CMS_SignerInfo)
DECLARE_STACK_OF(GENERAL_NAMES)
DECLARE_STACK_OF(CMS_RecipientEncryptedKey)
DECLARE_ASN1_FUNCTIONS(CMS_ContentInfo)
DECLARE_ASN1_FUNCTIONS(CMS_ReceiptRequest)
DECLARE_ASN1_PRINT_FUNCTION(CMS_ContentInfo)

#define CMS_SIGNERINFO_ISSUER_SERIAL 0
#define CMS_SIGNERINFO_KEYIDENTIFIER 1

#define CMS_RECIPINFO_NONE -1
#define CMS_RECIPINFO_TRANS 0
#define CMS_RECIPINFO_AGREE 1
#define CMS_RECIPINFO_KEK   2
#define CMS_RECIPINFO_PASS  3
#define CMS_RECIPINFO_OTHER 4

/* S/MIME related flags */

#define CMS_TEXT                    0x1
#define CMS_NOCERTS                 0x2
#define CMS_NO_CONTENT_VERIFY       0x4
#define CMS_NO_ATTR_VERIFY          0x8
#define CMS_NOSIGS                  (CMS_NO_CONTENT_VERIFY | CMS_NO_ATTR_VERIFY)
#define CMS_NOINTERN                0x10
#define CMS_NO_SIGNER_CERT_VERIFY   0x20
#define CMS_NOVERIFY                0x20
#define CMS_DETACHED                0x40
#define CMS_BINARY                  0x80
#define CMS_NOATTR                  0x100
#define CMS_NOSMIMECAP              0x200
#define CMS_NOOLDMIMETYPE           0x400
#define CMS_CRLFEOL                 0x800
#define CMS_STREAM                  0x1000
#define CMS_NOCRL                   0x2000
#define CMS_PARTIAL                 0x4000
#define CMS_REUSE_DIGEST            0x8000
#define CMS_USE_KEYID               0x10000
#define CMS_DEBUG_DECRYPT           0x20000
#define CMS_KEY_PARAM               0x40000

VIGORTLS_EXPORT const ASN1_OBJECT *CMS_get0_type(CMS_ContentInfo *cms);

VIGORTLS_EXPORT BIO *CMS_dataInit(CMS_ContentInfo *cms, BIO *icont);
VIGORTLS_EXPORT int CMS_dataFinal(CMS_ContentInfo *cms, BIO *bio);

VIGORTLS_EXPORT ASN1_OCTET_STRING **CMS_get0_content(CMS_ContentInfo *cms);
VIGORTLS_EXPORT int CMS_is_detached(CMS_ContentInfo *cms);
VIGORTLS_EXPORT int CMS_set_detached(CMS_ContentInfo *cms, int detached);

#ifdef HEADER_PEM_H
DECLARE_PEM_rw_const(CMS, CMS_ContentInfo)
#endif

VIGORTLS_EXPORT int CMS_stream(uint8_t ***boundary, CMS_ContentInfo *cms);
VIGORTLS_EXPORT CMS_ContentInfo *d2i_CMS_bio(BIO *bp, CMS_ContentInfo **cms);
VIGORTLS_EXPORT int i2d_CMS_bio(BIO *bp, CMS_ContentInfo *cms);

VIGORTLS_EXPORT BIO *BIO_new_CMS(BIO *out, CMS_ContentInfo *cms);
VIGORTLS_EXPORT int i2d_CMS_bio_stream(BIO *out, CMS_ContentInfo *cms, BIO *in,
                                       int flags);
VIGORTLS_EXPORT int PEM_write_bio_CMS_stream(BIO *out, CMS_ContentInfo *cms,
                                             BIO *in, int flags);
VIGORTLS_EXPORT CMS_ContentInfo *SMIME_read_CMS(BIO *bio, BIO **bcont);
VIGORTLS_EXPORT int SMIME_write_CMS(BIO *bio, CMS_ContentInfo *cms, BIO *data,
                                    int flags);

VIGORTLS_EXPORT int CMS_final(CMS_ContentInfo *cms, BIO *data, BIO *dcont,
                              unsigned int flags);

VIGORTLS_EXPORT CMS_ContentInfo *CMS_sign(X509 *signcert, EVP_PKEY *pkey,
                                          STACK_OF(X509) *certs, BIO *data,
                                          unsigned int flags);

VIGORTLS_EXPORT CMS_ContentInfo *
CMS_sign_receipt(CMS_SignerInfo *si, X509 *signcert, EVP_PKEY *pkey,
                 STACK_OF(X509) *certs, unsigned int flags);

VIGORTLS_EXPORT int CMS_data(CMS_ContentInfo *cms, BIO *out,
                             unsigned int flags);
VIGORTLS_EXPORT CMS_ContentInfo *CMS_data_create(BIO *in, unsigned int flags);

VIGORTLS_EXPORT int CMS_digest_verify(CMS_ContentInfo *cms, BIO *dcont,
                                      BIO *out, unsigned int flags);
VIGORTLS_EXPORT CMS_ContentInfo *CMS_digest_create(BIO *in, const EVP_MD *md,
                                                   unsigned int flags);

VIGORTLS_EXPORT int CMS_EncryptedData_decrypt(CMS_ContentInfo *cms,
                                              const uint8_t *key, size_t keylen,
                                              BIO *dcont, BIO *out,
                                              unsigned int flags);

VIGORTLS_EXPORT CMS_ContentInfo *
CMS_EncryptedData_encrypt(BIO *in, const EVP_CIPHER *cipher, const uint8_t *key,
                          size_t keylen, unsigned int flags);

VIGORTLS_EXPORT int CMS_EncryptedData_set1_key(CMS_ContentInfo *cms,
                                               const EVP_CIPHER *ciph,
                                               const uint8_t *key,
                                               size_t keylen);

VIGORTLS_EXPORT int CMS_verify(CMS_ContentInfo *cms, STACK_OF(X509) *certs,
                               X509_STORE *store, BIO *dcont, BIO *out,
                               unsigned int flags);

VIGORTLS_EXPORT int CMS_verify_receipt(CMS_ContentInfo *rcms,
                                       CMS_ContentInfo *ocms,
                                       STACK_OF(X509) *certs,
                                       X509_STORE *store, unsigned int flags);

VIGORTLS_EXPORT STACK_OF(X509) *CMS_get0_signers(CMS_ContentInfo *cms);

VIGORTLS_EXPORT CMS_ContentInfo *CMS_encrypt(STACK_OF(X509) *certs, BIO *in,
                                             const EVP_CIPHER *cipher,
                                             unsigned int flags);

VIGORTLS_EXPORT int CMS_decrypt(CMS_ContentInfo *cms, EVP_PKEY *pkey,
                                X509 *cert, BIO *dcont, BIO *out,
                                unsigned int flags);

VIGORTLS_EXPORT int CMS_decrypt_set1_pkey(CMS_ContentInfo *cms, EVP_PKEY *pk,
                                          X509 *cert);
VIGORTLS_EXPORT int CMS_decrypt_set1_key(CMS_ContentInfo *cms, uint8_t *key,
                                         size_t keylen, uint8_t *id,
                                         size_t idlen);
VIGORTLS_EXPORT int CMS_decrypt_set1_password(CMS_ContentInfo *cms,
                                              uint8_t *pass, ssize_t passlen);

VIGORTLS_EXPORT STACK_OF(CMS_RecipientInfo) *
    CMS_get0_RecipientInfos(CMS_ContentInfo *cms);
VIGORTLS_EXPORT int CMS_RecipientInfo_type(CMS_RecipientInfo *ri);
VIGORTLS_EXPORT EVP_PKEY_CTX *
CMS_RecipientInfo_get0_pkey_ctx(CMS_RecipientInfo *ri);
VIGORTLS_EXPORT CMS_ContentInfo *
CMS_EnvelopedData_create(const EVP_CIPHER *cipher);
VIGORTLS_EXPORT CMS_RecipientInfo *
CMS_add1_recipient_cert(CMS_ContentInfo *cms, X509 *recip, unsigned int flags);
VIGORTLS_EXPORT int CMS_RecipientInfo_set0_pkey(CMS_RecipientInfo *ri,
                                                EVP_PKEY *pkey);
VIGORTLS_EXPORT int CMS_RecipientInfo_ktri_cert_cmp(CMS_RecipientInfo *ri,
                                                    X509 *cert);
VIGORTLS_EXPORT int CMS_RecipientInfo_ktri_get0_algs(CMS_RecipientInfo *ri,
                                                     EVP_PKEY **pk,
                                                     X509 **recip,
                                                     X509_ALGOR **palg);
VIGORTLS_EXPORT int
CMS_RecipientInfo_ktri_get0_signer_id(CMS_RecipientInfo *ri,
                                      ASN1_OCTET_STRING **keyid,
                                      X509_NAME **issuer, ASN1_INTEGER **sno);

VIGORTLS_EXPORT CMS_RecipientInfo *
CMS_add0_recipient_key(CMS_ContentInfo *cms, int nid, uint8_t *key,
                       size_t keylen, uint8_t *id, size_t idlen,
                       ASN1_GENERALIZEDTIME *date, ASN1_OBJECT *otherTypeId,
                       ASN1_TYPE *otherType);

VIGORTLS_EXPORT int
CMS_RecipientInfo_kekri_get0_id(CMS_RecipientInfo *ri, X509_ALGOR **palg,
                                ASN1_OCTET_STRING **pid,
                                ASN1_GENERALIZEDTIME **pdate,
                                ASN1_OBJECT **potherid, ASN1_TYPE **pothertype);

VIGORTLS_EXPORT int CMS_RecipientInfo_set0_key(CMS_RecipientInfo *ri,
                                               uint8_t *key, size_t keylen);

VIGORTLS_EXPORT int CMS_RecipientInfo_kekri_id_cmp(CMS_RecipientInfo *ri,
                                                   const uint8_t *id,
                                                   size_t idlen);

VIGORTLS_EXPORT int CMS_RecipientInfo_set0_password(CMS_RecipientInfo *ri,
                                                    uint8_t *pass,
                                                    ssize_t passlen);

VIGORTLS_EXPORT CMS_RecipientInfo *
CMS_add0_recipient_password(CMS_ContentInfo *cms, int iter, int wrap_nid,
                            int pbe_nid, uint8_t *pass, ssize_t passlen,
                            const EVP_CIPHER *kekciph);

VIGORTLS_EXPORT int CMS_RecipientInfo_decrypt(CMS_ContentInfo *cms,
                                              CMS_RecipientInfo *ri);
VIGORTLS_EXPORT int CMS_RecipientInfo_encrypt(CMS_ContentInfo *cms,
                                              CMS_RecipientInfo *ri);

VIGORTLS_EXPORT int CMS_uncompress(CMS_ContentInfo *cms, BIO *dcont, BIO *out,
                                   unsigned int flags);
VIGORTLS_EXPORT CMS_ContentInfo *CMS_compress(BIO *in, int comp_nid,
                                              unsigned int flags);

VIGORTLS_EXPORT int CMS_set1_eContentType(CMS_ContentInfo *cms,
                                          const ASN1_OBJECT *oid);
VIGORTLS_EXPORT const ASN1_OBJECT *CMS_get0_eContentType(CMS_ContentInfo *cms);

VIGORTLS_EXPORT CMS_CertificateChoices *
CMS_add0_CertificateChoices(CMS_ContentInfo *cms);
VIGORTLS_EXPORT int CMS_add0_cert(CMS_ContentInfo *cms, X509 *cert);
VIGORTLS_EXPORT int CMS_add1_cert(CMS_ContentInfo *cms, X509 *cert);
VIGORTLS_EXPORT STACK_OF(X509) *CMS_get1_certs(CMS_ContentInfo *cms);

VIGORTLS_EXPORT CMS_RevocationInfoChoice *
CMS_add0_RevocationInfoChoice(CMS_ContentInfo *cms);
VIGORTLS_EXPORT int CMS_add0_crl(CMS_ContentInfo *cms, X509_CRL *crl);
VIGORTLS_EXPORT int CMS_add1_crl(CMS_ContentInfo *cms, X509_CRL *crl);
VIGORTLS_EXPORT STACK_OF(X509_CRL) *CMS_get1_crls(CMS_ContentInfo *cms);

VIGORTLS_EXPORT int CMS_SignedData_init(CMS_ContentInfo *cms);
VIGORTLS_EXPORT CMS_SignerInfo *CMS_add1_signer(CMS_ContentInfo *cms,
                                                X509 *signer, EVP_PKEY *pk,
                                                const EVP_MD *md,
                                                unsigned int flags);
VIGORTLS_EXPORT EVP_PKEY_CTX *CMS_SignerInfo_get0_pkey_ctx(CMS_SignerInfo *si);
VIGORTLS_EXPORT EVP_MD_CTX *CMS_SignerInfo_get0_md_ctx(CMS_SignerInfo *si);
VIGORTLS_EXPORT STACK_OF(CMS_SignerInfo) *
    CMS_get0_SignerInfos(CMS_ContentInfo *cms);

VIGORTLS_EXPORT void CMS_SignerInfo_set1_signer_cert(CMS_SignerInfo *si,
                                                     X509 *signer);
VIGORTLS_EXPORT int CMS_SignerInfo_get0_signer_id(CMS_SignerInfo *si,
                                                  ASN1_OCTET_STRING **keyid,
                                                  X509_NAME **issuer,
                                                  ASN1_INTEGER **sno);
VIGORTLS_EXPORT int CMS_SignerInfo_cert_cmp(CMS_SignerInfo *si, X509 *cert);
VIGORTLS_EXPORT int CMS_set1_signers_certs(CMS_ContentInfo *cms,
                                           STACK_OF(X509) *certs,
                                           unsigned int flags);
VIGORTLS_EXPORT void CMS_SignerInfo_get0_algs(CMS_SignerInfo *si, EVP_PKEY **pk,
                                              X509 **signer, X509_ALGOR **pdig,
                                              X509_ALGOR **psig);
VIGORTLS_EXPORT ASN1_OCTET_STRING *
CMS_SignerInfo_get0_signature(CMS_SignerInfo *si);
VIGORTLS_EXPORT int CMS_SignerInfo_sign(CMS_SignerInfo *si);
VIGORTLS_EXPORT int CMS_SignerInfo_verify(CMS_SignerInfo *si);
VIGORTLS_EXPORT int CMS_SignerInfo_verify_content(CMS_SignerInfo *si,
                                                  BIO *chain);

VIGORTLS_EXPORT int CMS_add_smimecap(CMS_SignerInfo *si,
                                     STACK_OF(X509_ALGOR) *algs);
VIGORTLS_EXPORT int CMS_add_simple_smimecap(STACK_OF(X509_ALGOR) **algs,
                                            int algnid, int keysize);
VIGORTLS_EXPORT int CMS_add_standard_smimecap(STACK_OF(X509_ALGOR) **smcap);

VIGORTLS_EXPORT int CMS_signed_get_attr_count(const CMS_SignerInfo *si);
VIGORTLS_EXPORT int CMS_signed_get_attr_by_NID(const CMS_SignerInfo *si,
                                               int nid, int lastpos);
VIGORTLS_EXPORT int CMS_signed_get_attr_by_OBJ(const CMS_SignerInfo *si,
                                               ASN1_OBJECT *obj, int lastpos);
VIGORTLS_EXPORT X509_ATTRIBUTE *CMS_signed_get_attr(const CMS_SignerInfo *si,
                                                    int loc);
VIGORTLS_EXPORT X509_ATTRIBUTE *CMS_signed_delete_attr(CMS_SignerInfo *si,
                                                       int loc);
VIGORTLS_EXPORT int CMS_signed_add1_attr(CMS_SignerInfo *si,
                                         X509_ATTRIBUTE *attr);
VIGORTLS_EXPORT int CMS_signed_add1_attr_by_OBJ(CMS_SignerInfo *si,
                                                const ASN1_OBJECT *obj,
                                                int type, const void *bytes,
                                                int len);
VIGORTLS_EXPORT int CMS_signed_add1_attr_by_NID(CMS_SignerInfo *si, int nid,
                                                int type, const void *bytes,
                                                int len);
VIGORTLS_EXPORT int CMS_signed_add1_attr_by_txt(CMS_SignerInfo *si,
                                                const char *attrname, int type,
                                                const void *bytes, int len);
VIGORTLS_EXPORT void *CMS_signed_get0_data_by_OBJ(CMS_SignerInfo *si,
                                                  ASN1_OBJECT *oid, int lastpos,
                                                  int type);

VIGORTLS_EXPORT int CMS_unsigned_get_attr_count(const CMS_SignerInfo *si);
VIGORTLS_EXPORT int CMS_unsigned_get_attr_by_NID(const CMS_SignerInfo *si,
                                                 int nid, int lastpos);
VIGORTLS_EXPORT int CMS_unsigned_get_attr_by_OBJ(const CMS_SignerInfo *si,
                                                 ASN1_OBJECT *obj, int lastpos);
VIGORTLS_EXPORT X509_ATTRIBUTE *CMS_unsigned_get_attr(const CMS_SignerInfo *si,
                                                      int loc);
VIGORTLS_EXPORT X509_ATTRIBUTE *CMS_unsigned_delete_attr(CMS_SignerInfo *si,
                                                         int loc);
VIGORTLS_EXPORT int CMS_unsigned_add1_attr(CMS_SignerInfo *si,
                                           X509_ATTRIBUTE *attr);
VIGORTLS_EXPORT int CMS_unsigned_add1_attr_by_OBJ(CMS_SignerInfo *si,
                                                  const ASN1_OBJECT *obj,
                                                  int type, const void *bytes,
                                                  int len);
VIGORTLS_EXPORT int CMS_unsigned_add1_attr_by_NID(CMS_SignerInfo *si, int nid,
                                                  int type, const void *bytes,
                                                  int len);
VIGORTLS_EXPORT int CMS_unsigned_add1_attr_by_txt(CMS_SignerInfo *si,
                                                  const char *attrname,
                                                  int type, const void *bytes,
                                                  int len);
VIGORTLS_EXPORT void *CMS_unsigned_get0_data_by_OBJ(CMS_SignerInfo *si,
                                                    ASN1_OBJECT *oid,
                                                    int lastpos, int type);

#ifdef HEADER_X509V3_H

VIGORTLS_EXPORT int CMS_get1_ReceiptRequest(CMS_SignerInfo *si,
                                            CMS_ReceiptRequest **prr);
VIGORTLS_EXPORT CMS_ReceiptRequest *
CMS_ReceiptRequest_create0(uint8_t *id, int idlen, int allorfirst,
                           STACK_OF(GENERAL_NAMES) *receiptList,
                           STACK_OF(GENERAL_NAMES) *receiptsTo);
VIGORTLS_EXPORT int CMS_add1_ReceiptRequest(CMS_SignerInfo *si,
                                            CMS_ReceiptRequest *rr);
VIGORTLS_EXPORT void CMS_ReceiptRequest_get0_values(
    CMS_ReceiptRequest *rr, ASN1_STRING **pcid, int *pallorfirst,
    STACK_OF(GENERAL_NAMES) **plist, STACK_OF(GENERAL_NAMES) **prto);

#endif

VIGORTLS_EXPORT int CMS_RecipientInfo_kari_get0_alg(CMS_RecipientInfo *ri,
                                                    X509_ALGOR **palg,
                                                    ASN1_OCTET_STRING **pukm);
VIGORTLS_EXPORT STACK_OF(CMS_RecipientEncryptedKey) *
    CMS_RecipientInfo_kari_get0_reks(CMS_RecipientInfo *ri);

VIGORTLS_EXPORT int CMS_RecipientInfo_kari_get0_orig_id(
    CMS_RecipientInfo *ri, X509_ALGOR **pubalg, ASN1_BIT_STRING **pubkey,
    ASN1_OCTET_STRING **keyid, X509_NAME **issuer, ASN1_INTEGER **sno);

VIGORTLS_EXPORT int CMS_RecipientInfo_kari_orig_id_cmp(CMS_RecipientInfo *ri,
                                                       X509 *cert);

VIGORTLS_EXPORT int CMS_RecipientEncryptedKey_get0_id(
    CMS_RecipientEncryptedKey *rek, ASN1_OCTET_STRING **keyid,
    ASN1_GENERALIZEDTIME **tm, CMS_OtherKeyAttribute **other,
    X509_NAME **issuer, ASN1_INTEGER **sno);
VIGORTLS_EXPORT int
CMS_RecipientEncryptedKey_cert_cmp(CMS_RecipientEncryptedKey *rek, X509 *cert);
VIGORTLS_EXPORT int CMS_RecipientInfo_kari_set0_pkey(CMS_RecipientInfo *ri,
                                                     EVP_PKEY *pk);
VIGORTLS_EXPORT EVP_CIPHER_CTX *
CMS_RecipientInfo_kari_get0_ctx(CMS_RecipientInfo *ri);
VIGORTLS_EXPORT int
CMS_RecipientInfo_kari_decrypt(CMS_ContentInfo *cms, CMS_RecipientInfo *ri,
                               CMS_RecipientEncryptedKey *rek);

VIGORTLS_EXPORT int CMS_SharedInfo_encode(uint8_t **pder, X509_ALGOR *kekalg,
                                          ASN1_OCTET_STRING *ukm, int keylen);

/* BEGIN ERROR CODES */
/*
 * The following lines are auto generated by the script mkerr.pl. Any changes
 * made after this point may be overwritten when the script is next run.
 */
VIGORTLS_EXPORT void ERR_load_CMS_strings(void);

/* Error codes for the CMS functions. */

/* Function codes. */
# define CMS_F_CHECK_CONTENT                              99
# define CMS_F_CMS_ADD0_CERT                              164
# define CMS_F_CMS_ADD0_RECIPIENT_KEY                     100
# define CMS_F_CMS_ADD0_RECIPIENT_PASSWORD                165
# define CMS_F_CMS_ADD1_RECEIPTREQUEST                    158
# define CMS_F_CMS_ADD1_RECIPIENT_CERT                    101
# define CMS_F_CMS_ADD1_SIGNER                            102
# define CMS_F_CMS_ADD1_SIGNINGTIME                       103
# define CMS_F_CMS_COMPRESS                               104
# define CMS_F_CMS_COMPRESSEDDATA_CREATE                  105
# define CMS_F_CMS_COMPRESSEDDATA_INIT_BIO                106
# define CMS_F_CMS_COPY_CONTENT                           107
# define CMS_F_CMS_COPY_MESSAGEDIGEST                     108
# define CMS_F_CMS_DATA                                   109
# define CMS_F_CMS_DATAFINAL                              110
# define CMS_F_CMS_DATAINIT                               111
# define CMS_F_CMS_DECRYPT                                112
# define CMS_F_CMS_DECRYPT_SET1_KEY                       113
# define CMS_F_CMS_DECRYPT_SET1_PASSWORD                  166
# define CMS_F_CMS_DECRYPT_SET1_PKEY                      114
# define CMS_F_CMS_DIGESTALGORITHM_FIND_CTX               115
# define CMS_F_CMS_DIGESTALGORITHM_INIT_BIO               116
# define CMS_F_CMS_DIGESTEDDATA_DO_FINAL                  117
# define CMS_F_CMS_DIGEST_VERIFY                          118
# define CMS_F_CMS_ENCODE_RECEIPT                         161
# define CMS_F_CMS_ENCRYPT                                119
# define CMS_F_CMS_ENCRYPTEDCONTENT_INIT_BIO              120
# define CMS_F_CMS_ENCRYPTEDDATA_DECRYPT                  121
# define CMS_F_CMS_ENCRYPTEDDATA_ENCRYPT                  122
# define CMS_F_CMS_ENCRYPTEDDATA_SET1_KEY                 123
# define CMS_F_CMS_ENVELOPEDDATA_CREATE                   124
# define CMS_F_CMS_ENVELOPEDDATA_INIT_BIO                 125
# define CMS_F_CMS_ENVELOPED_DATA_INIT                    126
# define CMS_F_CMS_ENV_ASN1_CTRL                          171
# define CMS_F_CMS_FINAL                                  127
# define CMS_F_CMS_GET0_CERTIFICATE_CHOICES               128
# define CMS_F_CMS_GET0_CONTENT                           129
# define CMS_F_CMS_GET0_ECONTENT_TYPE                     130
# define CMS_F_CMS_GET0_ENVELOPED                         131
# define CMS_F_CMS_GET0_REVOCATION_CHOICES                132
# define CMS_F_CMS_GET0_SIGNED                            133
# define CMS_F_CMS_MSGSIGDIGEST_ADD1                      162
# define CMS_F_CMS_RECEIPTREQUEST_CREATE0                 159
# define CMS_F_CMS_RECEIPT_VERIFY                         160
# define CMS_F_CMS_RECIPIENTINFO_DECRYPT                  134
# define CMS_F_CMS_RECIPIENTINFO_ENCRYPT                  169
# define CMS_F_CMS_RECIPIENTINFO_KARI_ENCRYPT             178
# define CMS_F_CMS_RECIPIENTINFO_KARI_GET0_ALG            175
# define CMS_F_CMS_RECIPIENTINFO_KARI_GET0_ORIG_ID        173
# define CMS_F_CMS_RECIPIENTINFO_KARI_GET0_REKS           172
# define CMS_F_CMS_RECIPIENTINFO_KARI_ORIG_ID_CMP         174
# define CMS_F_CMS_RECIPIENTINFO_KEKRI_DECRYPT            135
# define CMS_F_CMS_RECIPIENTINFO_KEKRI_ENCRYPT            136
# define CMS_F_CMS_RECIPIENTINFO_KEKRI_GET0_ID            137
# define CMS_F_CMS_RECIPIENTINFO_KEKRI_ID_CMP             138
# define CMS_F_CMS_RECIPIENTINFO_KTRI_CERT_CMP            139
# define CMS_F_CMS_RECIPIENTINFO_KTRI_DECRYPT             140
# define CMS_F_CMS_RECIPIENTINFO_KTRI_ENCRYPT             141
# define CMS_F_CMS_RECIPIENTINFO_KTRI_GET0_ALGS           142
# define CMS_F_CMS_RECIPIENTINFO_KTRI_GET0_SIGNER_ID      143
# define CMS_F_CMS_RECIPIENTINFO_PWRI_CRYPT               167
# define CMS_F_CMS_RECIPIENTINFO_SET0_KEY                 144
# define CMS_F_CMS_RECIPIENTINFO_SET0_PASSWORD            168
# define CMS_F_CMS_RECIPIENTINFO_SET0_PKEY                145
# define CMS_F_CMS_SD_ASN1_CTRL                           170
#define CMS_F_CMS_SET1_IAS                                176
#define CMS_F_CMS_SET1_KEYID                              177
# define CMS_F_CMS_SET1_SIGNERIDENTIFIER                  146
# define CMS_F_CMS_SET_DETACHED                           147
# define CMS_F_CMS_SIGN                                   148
# define CMS_F_CMS_SIGNED_DATA_INIT                       149
# define CMS_F_CMS_SIGNERINFO_CONTENT_SIGN                150
# define CMS_F_CMS_SIGNERINFO_SIGN                        151
# define CMS_F_CMS_SIGNERINFO_VERIFY                      152
# define CMS_F_CMS_SIGNERINFO_VERIFY_CERT                 153
# define CMS_F_CMS_SIGNERINFO_VERIFY_CONTENT              154
# define CMS_F_CMS_SIGN_RECEIPT                           163
# define CMS_F_CMS_STREAM                                 155
# define CMS_F_CMS_UNCOMPRESS                             156
# define CMS_F_CMS_VERIFY                                 157

/* Reason codes. */
# define CMS_R_ADD_SIGNER_ERROR                           99
# define CMS_R_CERTIFICATE_ALREADY_PRESENT                175
# define CMS_R_CERTIFICATE_HAS_NO_KEYID                   160
# define CMS_R_CERTIFICATE_VERIFY_ERROR                   100
# define CMS_R_CIPHER_INITIALISATION_ERROR                101
# define CMS_R_CIPHER_PARAMETER_INITIALISATION_ERROR      102
# define CMS_R_CMS_DATAFINAL_ERROR                        103
# define CMS_R_CMS_LIB                                    104
# define CMS_R_CONTENTIDENTIFIER_MISMATCH                 170
# define CMS_R_CONTENT_NOT_FOUND                          105
# define CMS_R_CONTENT_TYPE_MISMATCH                      171
# define CMS_R_CONTENT_TYPE_NOT_COMPRESSED_DATA           106
# define CMS_R_CONTENT_TYPE_NOT_ENVELOPED_DATA            107
# define CMS_R_CONTENT_TYPE_NOT_SIGNED_DATA               108
# define CMS_R_CONTENT_VERIFY_ERROR                       109
# define CMS_R_CTRL_ERROR                                 110
# define CMS_R_CTRL_FAILURE                               111
# define CMS_R_DECRYPT_ERROR                              112
# define CMS_R_DIGEST_ERROR                               161
# define CMS_R_ERROR_GETTING_PUBLIC_KEY                   113
# define CMS_R_ERROR_READING_MESSAGEDIGEST_ATTRIBUTE      114
# define CMS_R_ERROR_SETTING_KEY                          115
# define CMS_R_ERROR_SETTING_RECIPIENTINFO                116
# define CMS_R_INVALID_ENCRYPTED_KEY_LENGTH               117
# define CMS_R_INVALID_KEY_ENCRYPTION_PARAMETER           176
# define CMS_R_INVALID_KEY_LENGTH                         118
# define CMS_R_MD_BIO_INIT_ERROR                          119
# define CMS_R_MESSAGEDIGEST_ATTRIBUTE_WRONG_LENGTH       120
# define CMS_R_MESSAGEDIGEST_WRONG_LENGTH                 121
# define CMS_R_MSGSIGDIGEST_ERROR                         172
# define CMS_R_MSGSIGDIGEST_VERIFICATION_FAILURE          162
# define CMS_R_MSGSIGDIGEST_WRONG_LENGTH                  163
# define CMS_R_NEED_ONE_SIGNER                            164
# define CMS_R_NOT_A_SIGNED_RECEIPT                       165
# define CMS_R_NOT_ENCRYPTED_DATA                         122
# define CMS_R_NOT_KEK                                    123
# define CMS_R_NOT_KEY_AGREEMENT                          181
# define CMS_R_NOT_KEY_TRANSPORT                          124
# define CMS_R_NOT_PWRI                                   177
# define CMS_R_NOT_SUPPORTED_FOR_THIS_KEY_TYPE            125
# define CMS_R_NO_CIPHER                                  126
# define CMS_R_NO_CONTENT                                 127
# define CMS_R_NO_CONTENT_TYPE                            173
# define CMS_R_NO_DEFAULT_DIGEST                          128
# define CMS_R_NO_DIGEST_SET                              129
# define CMS_R_NO_KEY                                     130
# define CMS_R_NO_KEY_OR_CERT                             174
# define CMS_R_NO_MATCHING_DIGEST                         131
# define CMS_R_NO_MATCHING_RECIPIENT                      132
# define CMS_R_NO_MATCHING_SIGNATURE                      166
# define CMS_R_NO_MSGSIGDIGEST                            167
# define CMS_R_NO_PASSWORD                                178
# define CMS_R_NO_PRIVATE_KEY                             133
# define CMS_R_NO_PUBLIC_KEY                              134
# define CMS_R_NO_RECEIPT_REQUEST                         168
# define CMS_R_NO_SIGNERS                                 135
# define CMS_R_PRIVATE_KEY_DOES_NOT_MATCH_CERTIFICATE     136
# define CMS_R_RECEIPT_DECODE_ERROR                       169
# define CMS_R_RECIPIENT_ERROR                            137
# define CMS_R_SIGNER_CERTIFICATE_NOT_FOUND               138
# define CMS_R_SIGNFINAL_ERROR                            139
# define CMS_R_SMIME_TEXT_ERROR                           140
# define CMS_R_STORE_INIT_ERROR                           141
# define CMS_R_TYPE_NOT_COMPRESSED_DATA                   142
# define CMS_R_TYPE_NOT_DATA                              143
# define CMS_R_TYPE_NOT_DIGESTED_DATA                     144
# define CMS_R_TYPE_NOT_ENCRYPTED_DATA                    145
# define CMS_R_TYPE_NOT_ENVELOPED_DATA                    146
# define CMS_R_UNABLE_TO_FINALIZE_CONTEXT                 147
# define CMS_R_UNKNOWN_CIPHER                             148
# define CMS_R_UNKNOWN_DIGEST_ALGORIHM                    149
# define CMS_R_UNKNOWN_ID                                 150
# define CMS_R_UNSUPPORTED_COMPRESSION_ALGORITHM          151
# define CMS_R_UNSUPPORTED_CONTENT_TYPE                   152
# define CMS_R_UNSUPPORTED_KEK_ALGORITHM                  153
# define CMS_R_UNSUPPORTED_KEY_ENCRYPTION_ALGORITHM       179
# define CMS_R_UNSUPPORTED_RECIPIENT_TYPE                 154
# define CMS_R_UNSUPPORTED_RECPIENTINFO_TYPE              155
# define CMS_R_UNSUPPORTED_TYPE                           156
# define CMS_R_UNWRAP_ERROR                               157
# define CMS_R_UNWRAP_FAILURE                             180
# define CMS_R_VERIFICATION_FAILURE                       158
# define CMS_R_WRAP_ERROR                                 159

#ifdef  __cplusplus
}
#endif
#endif
