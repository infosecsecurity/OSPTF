/*
 * Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef HEADER_DSA_H
#define HEADER_DSA_H

#include <openssl/base.h>

#ifdef OPENSSL_NO_DSA
#error DSA is disabled.
#endif

#include <openssl/bio.h>
#include <openssl/crypto.h>

#ifndef OPENSSL_NO_DEPRECATED
#include <openssl/bn.h>
#include <openssl/dh.h>
#endif

#ifndef OPENSSL_DSA_MAX_MODULUS_BITS
#define OPENSSL_DSA_MAX_MODULUS_BITS 10000
#endif

#define DSA_FLAG_CACHE_MONT_P       0x01
#define DSA_FLAG_NO_EXP_CONSTTIME   0x02

#ifdef __cplusplus
extern "C" {
#endif

/* Already defined in ossl_typ.h */
/* typedef struct dsa_st DSA; */
/* typedef struct dsa_method DSA_METHOD; */

typedef struct DSA_SIG_st {
    BIGNUM *r;
    BIGNUM *s;
} DSA_SIG;

struct dsa_method {
    const char *name;
    DSA_SIG *(*dsa_do_sign)(const uint8_t *dgst, int dlen, DSA *dsa);
    int (*dsa_sign_setup)(DSA *dsa, BN_CTX *ctx_in, BIGNUM **kinvp,
                          BIGNUM **rp);
    int (*dsa_do_verify)(const uint8_t *dgst, int dgst_len, DSA_SIG *sig,
                         DSA *dsa);
    int (*dsa_mod_exp)(DSA *dsa, BIGNUM *rr, BIGNUM *a1, BIGNUM *p1, BIGNUM *a2,
                       BIGNUM *p2, BIGNUM *m, BN_CTX *ctx,
                       BN_MONT_CTX *in_mont);
    int (*bn_mod_exp)(DSA *dsa, BIGNUM *r, BIGNUM *a, const BIGNUM *p,
                      const BIGNUM *m, BN_CTX *ctx,
                      BN_MONT_CTX *m_ctx); /* Can be null */
    int (*init)(DSA *dsa);
    int (*finish)(DSA *dsa);
    int flags;
    char *app_data;
    /* If this is non-NULL, it is used to generate DSA parameters */
    int (*dsa_paramgen)(DSA *dsa, int bits, const uint8_t *seed, int seed_len,
                        int *counter_ret, unsigned long *h_ret, BN_GENCB *cb);
    /* If this is non-NULL, it is used to generate DSA keys */
    int (*dsa_keygen)(DSA *dsa);
};

struct dsa_st {
    /* This first variable is used to pick up errors where
     * a DSA is passed instead of of a EVP_PKEY */
    int pad;
    long version;
    int write_params; /* Kept for compatability (unused) */
    BIGNUM *p;
    BIGNUM *q; /* == 20 */
    BIGNUM *g;

    BIGNUM *pub_key;  /* y public key */
    BIGNUM *priv_key; /* x private key */

    BIGNUM *kinv; /* Signing pre-calc */
    BIGNUM *r;    /* Signing pre-calc */

    int flags;
    /* Normally used to cache montgomery values */
    BN_MONT_CTX *method_mont_p;
    int references;
    CRYPTO_EX_DATA ex_data;
    const DSA_METHOD *meth;
    /* functional reference if 'meth' is ENGINE-provided */
    ENGINE *engine;
    CRYPTO_MUTEX *lock;
};

#define d2i_DSAparams_fp(fp, x)                                                \
    (DSA *)ASN1_d2i_fp((char *(*)())DSA_new, (char *(*)())d2i_DSAparams, (fp), \
                       (uint8_t **)(x))
#define i2d_DSAparams_fp(fp, x) ASN1_i2d_fp(i2d_DSAparams, (fp), (uint8_t *)(x))
#define d2i_DSAparams_bio(bp, x) \
    ASN1_d2i_bio_of(DSA, DSA_new, d2i_DSAparams, bp, x)
#define i2d_DSAparams_bio(bp, x) \
    ASN1_i2d_bio_of_const(DSA, i2d_DSAparams, bp, x)

VIGORTLS_EXPORT DSA *DSAparams_dup(DSA *x);
VIGORTLS_EXPORT DSA_SIG *DSA_SIG_new(void);
VIGORTLS_EXPORT void DSA_SIG_free(DSA_SIG *a);
VIGORTLS_EXPORT int i2d_DSA_SIG(const DSA_SIG *a, uint8_t **pp);
VIGORTLS_EXPORT DSA_SIG *d2i_DSA_SIG(DSA_SIG **v, const uint8_t **pp,
                                     long length);

VIGORTLS_EXPORT DSA_SIG *DSA_do_sign(const uint8_t *dgst, int dlen, DSA *dsa);
VIGORTLS_EXPORT int DSA_do_verify(const uint8_t *dgst, int dgst_len,
                                  DSA_SIG *sig, DSA *dsa);

VIGORTLS_EXPORT const DSA_METHOD *DSA_OpenSSL(void);

VIGORTLS_EXPORT void DSA_set_default_method(const DSA_METHOD *);
VIGORTLS_EXPORT const DSA_METHOD *DSA_get_default_method(void);
VIGORTLS_EXPORT int DSA_set_method(DSA *dsa, const DSA_METHOD *);

VIGORTLS_EXPORT DSA *DSA_new(void);
VIGORTLS_EXPORT DSA *DSA_new_method(ENGINE *engine);
VIGORTLS_EXPORT void DSA_free(DSA *r);
/* "up" the DSA object's reference count */
VIGORTLS_EXPORT int DSA_up_ref(DSA *r);
VIGORTLS_EXPORT int DSA_size(const DSA *);
/* next 4 return -1 on error */
VIGORTLS_EXPORT int DSA_sign_setup(DSA *dsa, BN_CTX *ctx_in, BIGNUM **kinvp,
                                   BIGNUM **rp);
VIGORTLS_EXPORT int DSA_sign(int type, const uint8_t *dgst, int dlen,
                             uint8_t *sig, unsigned int *siglen, DSA *dsa);
VIGORTLS_EXPORT int DSA_verify(int type, const uint8_t *dgst, int dgst_len,
                               const uint8_t *sigbuf, int siglen, DSA *dsa);
VIGORTLS_EXPORT int DSA_get_ex_new_index(long argl, void *argp,
                                         CRYPTO_EX_new *new_func,
                                         CRYPTO_EX_dup *dup_func,
                                         CRYPTO_EX_free *free_func);
VIGORTLS_EXPORT int DSA_set_ex_data(DSA *d, int idx, void *arg);
VIGORTLS_EXPORT void *DSA_get_ex_data(DSA *d, int idx);

VIGORTLS_EXPORT DSA *d2i_DSAPublicKey(DSA **a, const uint8_t **pp, long length);
VIGORTLS_EXPORT DSA *d2i_DSAPrivateKey(DSA **a, const uint8_t **pp,
                                       long length);
VIGORTLS_EXPORT DSA *d2i_DSAparams(DSA **a, const uint8_t **pp, long length);

/* Deprecated version */
#ifndef OPENSSL_NO_DEPRECATED
VIGORTLS_EXPORT DSA *DSA_generate_parameters(int bits, uint8_t *seed,
                                             int seed_len, int *counter_ret,
                                             unsigned long *h_ret,
                                             void (*callback)(int, int, void *),
                                             void *cb_arg);
#endif /* !defined(OPENSSL_NO_DEPRECATED) */

/* New version */
VIGORTLS_EXPORT int DSA_generate_parameters_ex(DSA *dsa, int bits,
                                               const uint8_t *seed,
                                               int seed_len, int *counter_ret,
                                               unsigned long *h_ret,
                                               BN_GENCB *cb);

VIGORTLS_EXPORT int DSA_generate_key(DSA *a);
VIGORTLS_EXPORT int i2d_DSAPublicKey(const DSA *a, uint8_t **pp);
VIGORTLS_EXPORT int i2d_DSAPrivateKey(const DSA *a, uint8_t **pp);
VIGORTLS_EXPORT int i2d_DSAparams(const DSA *a, uint8_t **pp);

VIGORTLS_EXPORT int DSAparams_print(BIO *bp, const DSA *x);
VIGORTLS_EXPORT int DSA_print(BIO *bp, const DSA *x, int off);
VIGORTLS_EXPORT int DSAparams_print_fp(FILE *fp, const DSA *x);
VIGORTLS_EXPORT int DSA_print_fp(FILE *bp, const DSA *x, int off);

#define DSS_prime_checks 50
/* Primality test according to FIPS PUB 186[-1], Appendix 2.1:
 * 50 rounds of Rabin-Miller */
#define DSA_is_prime(n, callback, cb_arg) \
    BN_is_prime(n, DSS_prime_checks, callback, NULL, cb_arg)

/* Convert DSA structure (key or just parameters) into DH structure
 * (be careful to avoid small subgroup attacks when using this!) */
VIGORTLS_EXPORT DH *DSA_dup_DH(const DSA *r);

#define EVP_PKEY_CTX_set_dsa_paramgen_bits(ctx, nbits)         \
    EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_DSA, EVP_PKEY_OP_PARAMGEN, \
                      EVP_PKEY_CTRL_DSA_PARAMGEN_BITS, nbits, NULL)

#define EVP_PKEY_CTRL_DSA_PARAMGEN_BITS     (EVP_PKEY_ALG_CTRL + 1)
#define EVP_PKEY_CTRL_DSA_PARAMGEN_Q_BITS   (EVP_PKEY_ALG_CTRL + 2)
#define EVP_PKEY_CTRL_DSA_PARAMGEN_MD       (EVP_PKEY_ALG_CTRL + 3)

/* BEGIN ERROR CODES */
/*
 * The following lines are auto generated by the script mkerr.pl. Any changes
 * made after this point may be overwritten when the script is next run.
 */
VIGORTLS_EXPORT void ERR_load_DSA_strings(void);

/* Error codes for the DSA functions. */

/* Function codes. */
# define DSA_F_D2I_DSA_SIG                                110
# define DSA_F_DO_DSA_PRINT                               104
# define DSA_F_DSAPARAMS_PRINT                            100
# define DSA_F_DSAPARAMS_PRINT_FP                         101
# define DSA_F_DSA_BUILTIN_PARAMGEN2                      126
# define DSA_F_DSA_DO_SIGN                                112
# define DSA_F_DSA_DO_VERIFY                              113
# define DSA_F_DSA_GENERATE_KEY                           124
# define DSA_F_DSA_GENERATE_PARAMETERS_EX                 123
# define DSA_F_DSA_NEW_METHOD                             103
# define DSA_F_DSA_PARAM_DECODE                           119
# define DSA_F_DSA_PRINT_FP                               105
# define DSA_F_DSA_PRIV_DECODE                            115
# define DSA_F_DSA_PRIV_ENCODE                            116
# define DSA_F_DSA_PUB_DECODE                             117
# define DSA_F_DSA_PUB_ENCODE                             118
# define DSA_F_DSA_SIGN                                   106
# define DSA_F_DSA_SIGN_SETUP                             107
# define DSA_F_DSA_SIG_NEW                                109
# define DSA_F_DSA_SIG_PRINT                              125
# define DSA_F_DSA_VERIFY                                 108
# define DSA_F_I2D_DSA_SIG                                111
# define DSA_F_OLD_DSA_PRIV_DECODE                        122
# define DSA_F_PKEY_DSA_CTRL                              120
# define DSA_F_PKEY_DSA_KEYGEN                            121
# define DSA_F_SIG_CB                                     114

/* Reason codes. */
# define DSA_R_BAD_Q_VALUE                                102
# define DSA_R_BN_DECODE_ERROR                            108
# define DSA_R_BN_ERROR                                   109
# define DSA_R_DATA_TOO_LARGE_FOR_KEY_SIZE                100
# define DSA_R_DECODE_ERROR                               104
# define DSA_R_INVALID_DIGEST_TYPE                        106
# define DSA_R_INVALID_PARAMETERS                         112
# define DSA_R_MISSING_PARAMETERS                         101
# define DSA_R_MODULUS_TOO_LARGE                          103
# define DSA_R_NEED_NEW_SETUP_VALUES                      110
# define DSA_R_NO_PARAMETERS_SET                          107
# define DSA_R_PARAMETER_ENCODING_ERROR                   105
# define DSA_R_Q_NOT_PRIME                                113

#ifdef  __cplusplus
}
#endif
#endif
