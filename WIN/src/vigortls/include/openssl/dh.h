/*
 * Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef HEADER_DH_H
#define HEADER_DH_H

#include <openssl/base.h>
#include <openssl/bio.h>
#ifndef OPENSSL_NO_DEPRECATED
#include <openssl/bn.h>
#endif

#ifndef OPENSSL_DH_MAX_MODULUS_BITS
#define OPENSSL_DH_MAX_MODULUS_BITS 10000
#endif

#define DH_FLAG_CACHE_MONT_P        0x01
#define DH_FLAG_NO_EXP_CONSTTIME    0x02
#define DH_CHECK_PUBKEY_INVALID     0x04

#ifdef __cplusplus
extern "C" {
#endif

/* Already defined in ossl_typ.h */
/* typedef struct dh_st DH; */
/* typedef struct dh_method DH_METHOD; */

struct dh_method {
    const char *name;
    /* Methods here */
    int (*generate_key)(DH *dh);
    int (*compute_key)(uint8_t *key, const BIGNUM *pub_key, DH *dh);
    int (*bn_mod_exp)(const DH *dh, BIGNUM *r, const BIGNUM *a, const BIGNUM *p,
                      const BIGNUM *m, BN_CTX *ctx,
                      BN_MONT_CTX *m_ctx); /* Can be null */

    int (*init)(DH *dh);
    int (*finish)(DH *dh);
    int flags;
    char *app_data;
    /* If this is non-NULL, it will be used to generate parameters */
    int (*generate_params)(DH *dh, int prime_len, int generator, BN_GENCB *cb);
};

struct dh_st {
    /* This first argument is used to pick up errors when
     * a DH is passed instead of a EVP_PKEY */
    int pad;
    int version;
    BIGNUM *p;
    BIGNUM *g;
    long length;      /* optional */
    BIGNUM *pub_key;  /* g^x */
    BIGNUM *priv_key; /* x */

    int flags;
    BN_MONT_CTX *method_mont_p;
    /* Place holders if we want to do X9.42 DH */
    BIGNUM *q;
    BIGNUM *j;
    uint8_t *seed;
    int seedlen;
    BIGNUM *counter;

    int references;
    CRYPTO_EX_DATA ex_data;
    const DH_METHOD *meth;
    ENGINE *engine;
    CRYPTO_MUTEX *lock;
};

#define DH_GENERATOR_2  2
/* #define DH_GENERATOR_3    3 */
#define DH_GENERATOR_5  5

/* DH_check error codes */
#define DH_CHECK_P_NOT_PRIME            0x01
#define DH_CHECK_P_NOT_SAFE_PRIME       0x02
#define DH_UNABLE_TO_CHECK_GENERATOR    0x04
#define DH_NOT_SUITABLE_GENERATOR       0x08
#define DH_CHECK_Q_NOT_PRIME            0x10
#define DH_CHECK_INVALID_Q_VALUE        0x20
#define DH_CHECK_INVALID_J_VALUE        0x40

/* DH_check_pub_key error codes */
#define DH_CHECK_PUBKEY_TOO_SMALL 0x01
#define DH_CHECK_PUBKEY_TOO_LARGE 0x02

/* primes p where (p-1)/2 is prime too are called "safe"; we define
   this for backward compatibility: */
#define DH_CHECK_P_NOT_STRONG_PRIME DH_CHECK_P_NOT_SAFE_PRIME

#define d2i_DHparams_fp(fp, x)                                              \
    (DH *)ASN1_d2i_fp((char *(*)())DH_new, (char *(*)())d2i_DHparams, (fp), \
                      (uint8_t **)(x))
#define i2d_DHparams_fp(fp, x) ASN1_i2d_fp(i2d_DHparams, (fp), (uint8_t *)(x))
#define d2i_DHparams_bio(bp, x) ASN1_d2i_bio_of(DH, DH_new, d2i_DHparams, bp, x)
#define i2d_DHparams_bio(bp, x) ASN1_i2d_bio_of_const(DH, i2d_DHparams, bp, x)

VIGORTLS_EXPORT DH *DHparams_dup(DH *);

VIGORTLS_EXPORT const DH_METHOD *DH_OpenSSL(void);

VIGORTLS_EXPORT void DH_set_default_method(const DH_METHOD *meth);
VIGORTLS_EXPORT const DH_METHOD *DH_get_default_method(void);
VIGORTLS_EXPORT int DH_set_method(DH *dh, const DH_METHOD *meth);
VIGORTLS_EXPORT DH *DH_new_method(ENGINE *engine);

VIGORTLS_EXPORT DH *DH_new(void);
VIGORTLS_EXPORT void DH_free(DH *dh);
VIGORTLS_EXPORT int DH_up_ref(DH *dh);
VIGORTLS_EXPORT int DH_size(const DH *dh);

/* DH_num_bits returns the minimum number of bits needed to represent the
 * absolute value of the DH group's prime. */
VIGORTLS_EXPORT unsigned int DH_num_bits(const DH *dh);
VIGORTLS_EXPORT int DH_get_ex_new_index(long argl, void *argp,
                                        CRYPTO_EX_new *new_func,
                                        CRYPTO_EX_dup *dup_func,
                                        CRYPTO_EX_free *free_func);
VIGORTLS_EXPORT int DH_set_ex_data(DH *d, int idx, void *arg);
VIGORTLS_EXPORT void *DH_get_ex_data(DH *d, int idx);

/* Deprecated version */
#ifndef OPENSSL_NO_DEPRECATED
VIGORTLS_EXPORT DH *DH_generate_parameters(int prime_len, int generator,
                                           void (*callback)(int, int, void *),
                                           void *cb_arg);
#endif /* !defined(OPENSSL_NO_DEPRECATED) */

/* New version */
VIGORTLS_EXPORT int DH_generate_parameters_ex(DH *dh, int prime_len,
                                              int generator, BN_GENCB *cb);

VIGORTLS_EXPORT int DH_check(const DH *dh, int *codes);
VIGORTLS_EXPORT int DH_check_pub_key(const DH *dh, const BIGNUM *pub_key,
                                     int *codes);
VIGORTLS_EXPORT int DH_generate_key(DH *dh);
VIGORTLS_EXPORT int DH_compute_key(uint8_t *key, const BIGNUM *pub_key, DH *dh);
VIGORTLS_EXPORT int DH_compute_key_padded(uint8_t *key, const BIGNUM *pub_key,
                                          DH *dh);
VIGORTLS_EXPORT DH *d2i_DHparams(DH **a, const uint8_t **pp, long length);
VIGORTLS_EXPORT int i2d_DHparams(const DH *a, uint8_t **pp);
VIGORTLS_EXPORT DH *d2i_DHxparams(DH **a, const uint8_t **pp, long length);
VIGORTLS_EXPORT int i2d_DHxparams(const DH *a, uint8_t **pp);
VIGORTLS_EXPORT int DHparams_print_fp(FILE *fp, const DH *x);
VIGORTLS_EXPORT int DHparams_print(BIO *bp, const DH *x);

/* RFC 5114 parameters */
VIGORTLS_EXPORT DH *DH_get_1024_160(void);
VIGORTLS_EXPORT DH *DH_get_2048_224(void);
VIGORTLS_EXPORT DH *DH_get_2048_256(void);

#ifndef OPENSSL_NO_CMS
/* RFC2631 KDF */
VIGORTLS_EXPORT int DH_KDF_X9_42(uint8_t *out, size_t outlen, const uint8_t *Z,
                                 size_t Zlen, ASN1_OBJECT *key_oid,
                                 const uint8_t *ukm, size_t ukmlen,
                                 const EVP_MD *md);
#endif

#define EVP_PKEY_CTX_set_dh_paramgen_prime_len(ctx, len)      \
    EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_DH, EVP_PKEY_OP_PARAMGEN, \
                      EVP_PKEY_CTRL_DH_PARAMGEN_PRIME_LEN, len, NULL)

#define EVP_PKEY_CTX_set_dh_paramgen_subprime_len(ctx, len)   \
    EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_DH, EVP_PKEY_OP_PARAMGEN, \
                      EVP_PKEY_CTRL_DH_PARAMGEN_SUBPRIME_LEN, len, NULL)

#define EVP_PKEY_CTX_set_dh_paramgen_type(ctx, typ)           \
    EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_DH, EVP_PKEY_OP_PARAMGEN, \
                      EVP_PKEY_CTRL_DH_PARAMGEN_TYPE, typ, NULL)

#define EVP_PKEY_CTX_set_dh_paramgen_generator(ctx, gen)      \
    EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_DH, EVP_PKEY_OP_PARAMGEN, \
                      EVP_PKEY_CTRL_DH_PARAMGEN_GENERATOR, gen, NULL)

#define EVP_PKEY_CTX_set_dh_rfc5114(ctx, gen)                  \
    EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_DHX, EVP_PKEY_OP_PARAMGEN, \
                      EVP_PKEY_CTRL_DH_RFC5114, gen, NULL)

#define EVP_PKEY_CTX_set_dhx_rfc5114(ctx, gen)                 \
    EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_DHX, EVP_PKEY_OP_PARAMGEN, \
                      EVP_PKEY_CTRL_DH_RFC5114, gen, NULL)

#define EVP_PKEY_CTX_set_dh_kdf_type(ctx, kdf)               \
    EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_DHX, EVP_PKEY_OP_DERIVE, \
                      EVP_PKEY_CTRL_DH_KDF_TYPE, kdf, NULL)

#define EVP_PKEY_CTX_get_dh_kdf_type(ctx)                    \
    EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_DHX, EVP_PKEY_OP_DERIVE, \
                      EVP_PKEY_CTRL_DH_KDF_TYPE, -2, NULL)

#define EVP_PKEY_CTX_set0_dh_kdf_oid(ctx, oid)               \
    EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_DHX, EVP_PKEY_OP_DERIVE, \
                      EVP_PKEY_CTRL_DH_KDF_OID, 0, (void *)oid)

#define EVP_PKEY_CTX_get0_dh_kdf_oid(ctx, poid)              \
    EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_DHX, EVP_PKEY_OP_DERIVE, \
                      EVP_PKEY_CTRL_GET_DH_KDF_OID, 0, (void *)poid)

#define EVP_PKEY_CTX_set_dh_kdf_md(ctx, md)                  \
    EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_DHX, EVP_PKEY_OP_DERIVE, \
                      EVP_PKEY_CTRL_DH_KDF_MD, 0, (void *)md)

#define EVP_PKEY_CTX_get_dh_kdf_md(ctx, pmd)                 \
    EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_DHX, EVP_PKEY_OP_DERIVE, \
                      EVP_PKEY_CTRL_GET_DH_KDF_MD, 0, (void *)pmd)

#define EVP_PKEY_CTX_set_dh_kdf_outlen(ctx, len)             \
    EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_DHX, EVP_PKEY_OP_DERIVE, \
                      EVP_PKEY_CTRL_DH_KDF_OUTLEN, len, NULL)

#define EVP_PKEY_CTX_get_dh_kdf_outlen(ctx, plen)            \
    EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_DHX, EVP_PKEY_OP_DERIVE, \
                      EVP_PKEY_CTRL_GET_DH_KDF_OUTLEN, 0, (void *)plen)

#define EVP_PKEY_CTX_set0_dh_kdf_ukm(ctx, p, plen)           \
    EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_DHX, EVP_PKEY_OP_DERIVE, \
                      EVP_PKEY_CTRL_DH_KDF_UKM, plen, (void *)p)

#define EVP_PKEY_CTX_get0_dh_kdf_ukm(ctx, p)                 \
    EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_DHX, EVP_PKEY_OP_DERIVE, \
                      EVP_PKEY_CTRL_GET_DH_KDF_UKM, 0, (void *)p)

#define EVP_PKEY_CTRL_DH_PARAMGEN_PRIME_LEN     (EVP_PKEY_ALG_CTRL + 1)
#define EVP_PKEY_CTRL_DH_PARAMGEN_GENERATOR     (EVP_PKEY_ALG_CTRL + 2)
#define EVP_PKEY_CTRL_DH_RFC5114                (EVP_PKEY_ALG_CTRL + 3)
#define EVP_PKEY_CTRL_DH_PARAMGEN_SUBPRIME_LEN  (EVP_PKEY_ALG_CTRL + 4)
#define EVP_PKEY_CTRL_DH_PARAMGEN_TYPE          (EVP_PKEY_ALG_CTRL + 5)
#define EVP_PKEY_CTRL_DH_KDF_TYPE               (EVP_PKEY_ALG_CTRL + 6)
#define EVP_PKEY_CTRL_DH_KDF_MD	                (EVP_PKEY_ALG_CTRL + 7)
#define EVP_PKEY_CTRL_GET_DH_KDF_MD             (EVP_PKEY_ALG_CTRL + 8)
#define EVP_PKEY_CTRL_DH_KDF_OUTLEN             (EVP_PKEY_ALG_CTRL + 9)
#define EVP_PKEY_CTRL_GET_DH_KDF_OUTLEN         (EVP_PKEY_ALG_CTRL + 10)
#define EVP_PKEY_CTRL_DH_KDF_UKM                (EVP_PKEY_ALG_CTRL + 11)
#define EVP_PKEY_CTRL_GET_DH_KDF_UKM            (EVP_PKEY_ALG_CTRL + 12)
#define EVP_PKEY_CTRL_DH_KDF_OID                (EVP_PKEY_ALG_CTRL + 13)
#define EVP_PKEY_CTRL_GET_DH_KDF_OID            (EVP_PKEY_ALG_CTRL + 14)

/* KDF types */
#define EVP_PKEY_DH_KDF_NONE  1
#define EVP_PKEY_DH_KDF_X9_42 2

/* BEGIN ERROR CODES */
/*
 * The following lines are auto generated by the script mkerr.pl. Any changes
 * made after this point may be overwritten when the script is next run.
 */
VIGORTLS_EXPORT void ERR_load_DH_strings(void);

/* Error codes for the DH functions. */

/* Function codes. */
# define DH_F_COMPUTE_KEY                                 102
# define DH_F_DHPARAMS_PRINT_FP                           101
# define DH_F_DH_BUILTIN_GENPARAMS                        106
# define DH_F_DH_CMS_DECRYPT                              117
# define DH_F_DH_CMS_SET_PEERKEY                          118
# define DH_F_DH_CMS_SET_SHARED_INFO                      119
# define DH_F_DH_COMPUTE_KEY                              114
# define DH_F_DH_GENERATE_KEY                             115
# define DH_F_DH_GENERATE_PARAMETERS_EX                   116
# define DH_F_DH_NEW_METHOD                               105
# define DH_F_DH_PARAM_DECODE                             107
# define DH_F_DH_PRIV_DECODE                              110
# define DH_F_DH_PRIV_ENCODE                              111
# define DH_F_DH_PUB_DECODE                               108
# define DH_F_DH_PUB_ENCODE                               109
# define DH_F_DO_DH_PRINT                                 100
# define DH_F_GENERATE_KEY                                103
# define DH_F_GENERATE_PARAMETERS                         104
# define DH_F_PKEY_DH_DERIVE                              112
# define DH_F_PKEY_DH_KEYGEN                              113

/* Reason codes. */
# define DH_R_BAD_GENERATOR                               101
# define DH_R_BN_DECODE_ERROR                             109
# define DH_R_BN_ERROR                                    106
# define DH_R_DECODE_ERROR                                104
# define DH_R_INVALID_PUBKEY                              102
# define DH_R_KDF_PARAMETER_ERROR                         112
# define DH_R_KEYS_NOT_SET                                108
# define DH_R_KEY_SIZE_TOO_SMALL                          110
# define DH_R_MODULUS_TOO_LARGE                           103
# define DH_R_NO_PARAMETERS_SET                           107
# define DH_R_NO_PRIVATE_VALUE                            100
# define DH_R_PARAMETER_ENCODING_ERROR                    105
# define DH_R_PEER_KEY_ERROR                              113
# define DH_R_SHARED_INFO_ERROR                           114

#ifdef  __cplusplus
}
#endif
#endif
