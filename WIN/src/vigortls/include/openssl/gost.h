/*
 * Copyright (c) 2014 Dmitry Eremin-Solenikov <dbaryshkov@gmail.com>
 * Copyright (c) 2005-2006 Cryptocom LTD
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef HEADER_GOST_H
#define HEADER_GOST_H

#include <openssl/base.h>

#ifdef OPENSSL_NO_GOST
#error GOST is disabled.
#endif

#include <openssl/asn1t.h>
#include <openssl/ec.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct gost2814789_key_st {
    unsigned int key[8];
    unsigned int k87[256], k65[256], k43[256], k21[256];
    unsigned int count;
    unsigned key_meshing : 1;
} GOST2814789_KEY;

VIGORTLS_EXPORT int Gost2814789_set_sbox(GOST2814789_KEY *key, int nid);
VIGORTLS_EXPORT int Gost2814789_set_key(GOST2814789_KEY *key,
                                        const uint8_t *userKey, const int bits);
VIGORTLS_EXPORT void Gost2814789_ecb_encrypt(const uint8_t *in, uint8_t *out,
                                             GOST2814789_KEY *key,
                                             const int enc);
VIGORTLS_EXPORT void Gost2814789_cfb64_encrypt(const uint8_t *in, uint8_t *out,
                                               size_t length,
                                               GOST2814789_KEY *key,
                                               uint8_t *ivec, int *num,
                                               const int enc);
VIGORTLS_EXPORT void Gost2814789_cnt_encrypt(const uint8_t *in, uint8_t *out,
                                             size_t length,
                                             GOST2814789_KEY *key,
                                             uint8_t *ivec, uint8_t *cnt_buf,
                                             int *num);

typedef struct {
    ASN1_OCTET_STRING *iv;
    ASN1_OBJECT *enc_param_set;
} GOST_CIPHER_PARAMS;

DECLARE_ASN1_FUNCTIONS(GOST_CIPHER_PARAMS)

#define GOST2814789IMIT_LENGTH 4
#define GOST2814789IMIT_CBLOCK 8
#define GOST2814789IMIT_LONG unsigned int

typedef struct GOST2814789IMITstate_st {
    GOST2814789IMIT_LONG Nl, Nh;
    uint8_t data[GOST2814789IMIT_CBLOCK];
    unsigned int num;

    GOST2814789_KEY cipher;
    uint8_t mac[GOST2814789IMIT_CBLOCK];
} GOST2814789IMIT_CTX;

/* Note, also removed second parameter and removed dctx->cipher setting */
VIGORTLS_EXPORT int GOST2814789IMIT_Init(GOST2814789IMIT_CTX *c, int nid);
VIGORTLS_EXPORT int GOST2814789IMIT_Update(GOST2814789IMIT_CTX *c,
                                           const void *data, size_t len);
VIGORTLS_EXPORT int GOST2814789IMIT_Final(uint8_t *md, GOST2814789IMIT_CTX *c);
VIGORTLS_EXPORT void GOST2814789IMIT_Transform(GOST2814789IMIT_CTX *c,
                                               const uint8_t *data);
VIGORTLS_EXPORT uint8_t *GOST2814789IMIT(const uint8_t *d, size_t n,
                                         uint8_t *md, int nid,
                                         const uint8_t *key, const uint8_t *iv);

#define GOSTR341194_LONG unsigned int

#define GOSTR341194_LENGTH 32
#define GOSTR341194_CBLOCK 32
#define GOSTR341194_LBLOCK (GOSTR341194_CBLOCK / 4)

typedef struct GOSTR341194state_st {
    GOSTR341194_LONG Nl, Nh;
    GOSTR341194_LONG data[GOSTR341194_LBLOCK];
    unsigned int num;

    GOST2814789_KEY cipher;
    uint8_t H[GOSTR341194_CBLOCK];
    uint8_t S[GOSTR341194_CBLOCK];
} GOSTR341194_CTX;

/* Note, also removed second parameter and removed dctx->cipher setting */
VIGORTLS_EXPORT int GOSTR341194_Init(GOSTR341194_CTX *c, int nid);
VIGORTLS_EXPORT int GOSTR341194_Update(GOSTR341194_CTX *c, const void *data,
                                       size_t len);
VIGORTLS_EXPORT int GOSTR341194_Final(uint8_t *md, GOSTR341194_CTX *c);
VIGORTLS_EXPORT void GOSTR341194_Transform(GOSTR341194_CTX *c,
                                           const uint8_t *data);
VIGORTLS_EXPORT uint8_t *GOSTR341194(const uint8_t *d, size_t n, uint8_t *md,
                                     int nid);

#undef U64 /* Fix conflict with SHA header */
#if defined(_LP64)
#define STREEBOG_LONG64 unsigned long
#define U64(C) C##UL
#else
#define STREEBOG_LONG64 uint64_t
#define U64(C) C##ULL
#endif

#define STREEBOG_LBLOCK 8
#define STREEBOG_CBLOCK 64
#define STREEBOG256_LENGTH 32
#define STREEBOG512_LENGTH 64

typedef struct STREEBOGstate_st {
    STREEBOG_LONG64 data[STREEBOG_LBLOCK];
    unsigned int num;
    unsigned int md_len;
    STREEBOG_LONG64 h[STREEBOG_LBLOCK];
    STREEBOG_LONG64 N[STREEBOG_LBLOCK];
    STREEBOG_LONG64 Sigma[STREEBOG_LBLOCK];
} STREEBOG_CTX;

VIGORTLS_EXPORT int STREEBOG256_Init(STREEBOG_CTX *c);
VIGORTLS_EXPORT int STREEBOG256_Update(STREEBOG_CTX *c, const void *data,
                                       size_t len);
VIGORTLS_EXPORT int STREEBOG256_Final(uint8_t *md, STREEBOG_CTX *c);
VIGORTLS_EXPORT void STREEBOG256_Transform(STREEBOG_CTX *c,
                                           const uint8_t *data);
VIGORTLS_EXPORT uint8_t *STREEBOG256(const uint8_t *d, size_t n, uint8_t *md);

VIGORTLS_EXPORT int STREEBOG512_Init(STREEBOG_CTX *c);
VIGORTLS_EXPORT int STREEBOG512_Update(STREEBOG_CTX *c, const void *data,
                                       size_t len);
VIGORTLS_EXPORT int STREEBOG512_Final(uint8_t *md, STREEBOG_CTX *c);
VIGORTLS_EXPORT void STREEBOG512_Transform(STREEBOG_CTX *c,
                                           const uint8_t *data);
VIGORTLS_EXPORT uint8_t *STREEBOG512(const uint8_t *d, size_t n, uint8_t *md);

typedef struct gost_key_st GOST_KEY;
VIGORTLS_EXPORT GOST_KEY *GOST_KEY_new(void);
VIGORTLS_EXPORT void GOST_KEY_free(GOST_KEY *r);
VIGORTLS_EXPORT int GOST_KEY_check_key(const GOST_KEY *eckey);
VIGORTLS_EXPORT int
GOST_KEY_set_public_key_affine_coordinates(GOST_KEY *key, BIGNUM *x, BIGNUM *y);
VIGORTLS_EXPORT const EC_GROUP *GOST_KEY_get0_group(const GOST_KEY *key);
VIGORTLS_EXPORT int GOST_KEY_set_group(GOST_KEY *key, const EC_GROUP *group);
VIGORTLS_EXPORT int GOST_KEY_get_digest(const GOST_KEY *key);
VIGORTLS_EXPORT int GOST_KEY_set_digest(GOST_KEY *key, int digest_nid);
VIGORTLS_EXPORT const BIGNUM *GOST_KEY_get0_private_key(const GOST_KEY *key);
VIGORTLS_EXPORT int GOST_KEY_set_private_key(GOST_KEY *key,
                                             const BIGNUM *priv_key);
VIGORTLS_EXPORT const EC_POINT *GOST_KEY_get0_public_key(const GOST_KEY *key);
VIGORTLS_EXPORT int GOST_KEY_set_public_key(GOST_KEY *key,
                                            const EC_POINT *pub_key);
VIGORTLS_EXPORT size_t GOST_KEY_get_size(const GOST_KEY *r);

/* Gost-specific pmeth control-function parameters */
/* For GOST R34.10 parameters */
#define EVP_PKEY_CTRL_GOST_PARAMSET   (EVP_PKEY_ALG_CTRL + 1)
#define EVP_PKEY_CTRL_GOST_SIG_FORMAT (EVP_PKEY_ALG_CTRL + 2)
#define EVP_PKEY_CTRL_GOST_SET_DIGEST (EVP_PKEY_ALG_CTRL + 3)
#define EVP_PKEY_CTRL_GOST_GET_DIGEST (EVP_PKEY_ALG_CTRL + 4)

#define GOST_SIG_FORMAT_SR_BE 0
#define GOST_SIG_FORMAT_RS_LE 1

/* BEGIN ERROR CODES */
/*
 * The following lines are auto generated by the script mkerr.pl. Any changes
 * made after this point may be overwritten when the script is next run.
 */
VIGORTLS_EXPORT void ERR_load_GOST_strings(void);

/* Error codes for the GOST functions. */

/* Function codes. */
# define GOST_F_DECODE_GOST01_ALGOR_PARAMS                104
# define GOST_F_ENCODE_GOST01_ALGOR_PARAMS                105
# define GOST_F_GOST2001_COMPUTE_PUBLIC                   106
# define GOST_F_GOST2001_DO_SIGN                          107
# define GOST_F_GOST2001_DO_VERIFY                        108
# define GOST_F_GOST2001_KEYGEN                           109
# define GOST_F_GOST89_GET_ASN1_PARAMETERS                102
# define GOST_F_GOST89_SET_ASN1_PARAMETERS                103
# define GOST_F_GOST_KEY_CHECK_KEY                        124
# define GOST_F_GOST_KEY_NEW                              125
# define GOST_F_GOST_KEY_SET_PUBLIC_KEY_AFFINE_COORDINATES 126
# define GOST_F_PARAM_COPY_GOST01                         110
# define GOST_F_PARAM_DECODE_GOST01                       111
# define GOST_F_PKEY_GOST01_CTRL                          116
# define GOST_F_PKEY_GOST01_DECRYPT                       112
# define GOST_F_PKEY_GOST01_DERIVE                        113
# define GOST_F_PKEY_GOST01_ENCRYPT                       114
# define GOST_F_PKEY_GOST01_PARAMGEN                      115
# define GOST_F_PKEY_GOST01_SIGN                          123
# define GOST_F_PKEY_GOST_MAC_CTRL                        100
# define GOST_F_PKEY_GOST_MAC_KEYGEN                      101
# define GOST_F_PRIV_DECODE_GOST01                        117
# define GOST_F_PUB_DECODE_GOST01                         118
# define GOST_F_PUB_ENCODE_GOST01                         119
# define GOST_F_PUB_PRINT_GOST01                          120
# define GOST_F_UNPACK_SIGNATURE_CP                       121
# define GOST_F_UNPACK_SIGNATURE_LE                       122

/* Reason codes. */
# define GOST_R_BAD_KEY_PARAMETERS_FORMAT                 104
# define GOST_R_BAD_PKEY_PARAMETERS_FORMAT                105
# define GOST_R_CANNOT_PACK_EPHEMERAL_KEY                 106
# define GOST_R_CTRL_CALL_FAILED                          107
# define GOST_R_ERROR_COMPUTING_SHARED_KEY                108
# define GOST_R_ERROR_PARSING_KEY_TRANSPORT_INFO          109
# define GOST_R_INCOMPATIBLE_ALGORITHMS                   110
# define GOST_R_INCOMPATIBLE_PEER_KEY                     111
# define GOST_R_INVALID_DIGEST_TYPE                       100
# define GOST_R_INVALID_IV_LENGTH                         103
# define GOST_R_INVALID_MAC_KEY_LENGTH                    101
# define GOST_R_KEY_IS_NOT_INITIALIZED                    112
# define GOST_R_KEY_PARAMETERS_MISSING                    113
# define GOST_R_MAC_KEY_NOT_SET                           102
# define GOST_R_NO_PARAMETERS_SET                         115
# define GOST_R_NO_PEER_KEY                               116
# define GOST_R_NO_PRIVATE_PART_OF_NON_EPHEMERAL_KEYPAIR  117
# define GOST_R_PUBLIC_KEY_UNDEFINED                      118
# define GOST_R_RANDOM_GENERATOR_FAILURE                  119
# define GOST_R_RANDOM_NUMBER_GENERATOR_FAILED            120
# define GOST_R_SIGNATURE_MISMATCH                        121
# define GOST_R_SIGNATURE_PARTS_GREATER_THAN_Q            122
# define GOST_R_UKM_NOT_SET                               123

#ifdef  __cplusplus
}
#endif
#endif
