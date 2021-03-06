/*
 * Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef HEADER_RSA_H
#define HEADER_RSA_H

#include <openssl/base.h>
#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <openssl/crypto.h>
#ifndef OPENSSL_NO_DEPRECATED
#include <openssl/bn.h>
#endif

#include <openssl/threads.h>

#ifdef __cplusplus
extern "C" {
#endif

struct rsa_meth_st {
    const char *name;
    int (*rsa_pub_enc)(int flen, const uint8_t *from, uint8_t *to, RSA *rsa,
                       int padding);
    int (*rsa_pub_dec)(int flen, const uint8_t *from, uint8_t *to, RSA *rsa,
                       int padding);
    int (*rsa_priv_enc)(int flen, const uint8_t *from, uint8_t *to, RSA *rsa,
                        int padding);
    int (*rsa_priv_dec)(int flen, const uint8_t *from, uint8_t *to, RSA *rsa,
                        int padding);
    int (*rsa_mod_exp)(BIGNUM *r0, const BIGNUM *I, RSA *rsa,
                       BN_CTX *ctx); /* Can be null */
    int (*bn_mod_exp)(BIGNUM *r, const BIGNUM *a, const BIGNUM *p,
                      const BIGNUM *m, BN_CTX *ctx,
                      BN_MONT_CTX *m_ctx); /* Can be null */
    int (*init)(RSA *rsa);                 /* called at new */
    int (*finish)(RSA *rsa);               /* called at free */
    int flags;                             /* RSA_METHOD_FLAG_* things */
    char *app_data;                        /* may be needed! */
    /*
     * New sign and verify functions: some libraries don't allow arbitrary data
     * to be signed/verified: this allows them to be used. Note: for this to
     * work the RSA_public_decrypt() and RSA_private_encrypt() should *NOT* be
     * used RSA_sign(), RSA_verify() should be used instead. Note: for backwards
     * compatibility this functionality is only enabled if the RSA_FLAG_SIGN_VER
     * option is set in 'flags'.
     */
    int (*rsa_sign)(int type, const uint8_t *m, unsigned int m_length,
                    uint8_t *sigret, unsigned int *siglen, const RSA *rsa);
    int (*rsa_verify)(int dtype, const uint8_t *m, unsigned int m_length,
                      const uint8_t *sigbuf, unsigned int siglen,
                      const RSA *rsa);
    /*
     * If this callback is NULL, the builtin software RSA key-gen will be used.
     * This is for behavioural compatibility whilst the code gets rewired, but
     * one day it would be nice to assume there are no such things as
     * "builtin software" implementations.
     */
    int (*rsa_keygen)(RSA *rsa, int bits, BIGNUM *e, BN_GENCB *cb);
};

struct rsa_st {
    /* The first parameter is used to pickup errors where
     * this is passed instead of aEVP_PKEY, it is set to 0 */
    int pad;
    long version;
    const RSA_METHOD *meth;
    /* functional reference if 'meth' is ENGINE-provided */
    ENGINE *engine;
    BIGNUM *n;
    BIGNUM *e;
    BIGNUM *d;
    BIGNUM *p;
    BIGNUM *q;
    BIGNUM *dmp1;
    BIGNUM *dmq1;
    BIGNUM *iqmp;
    /* be careful using this if the RSA structure is shared */
    CRYPTO_EX_DATA ex_data;
    int references;
    int flags;

    /* Used to cache montgomery values */
    BN_MONT_CTX *_method_mod_n;
    BN_MONT_CTX *_method_mod_p;
    BN_MONT_CTX *_method_mod_q;

    /* all BIGNUM values are actually in the following data, if it is not
     * NULL */
    BN_BLINDING *blinding;
    BN_BLINDING *mt_blinding;
    CRYPTO_MUTEX *lock;
};

#ifndef OPENSSL_RSA_MAX_MODULUS_BITS
#define OPENSSL_RSA_MAX_MODULUS_BITS 16384
#endif

#ifndef OPENSSL_RSA_SMALL_MODULUS_BITS
#define OPENSSL_RSA_SMALL_MODULUS_BITS 3072
#endif
#ifndef OPENSSL_RSA_MAX_PUBEXP_BITS
#define OPENSSL_RSA_MAX_PUBEXP_BITS 64 /* exponent limit enforced for "large"
                                        * modulus only */
#endif

#define RSA_3 0x3L
#define RSA_F4 0x10001L

#define RSA_METHOD_FLAG_NO_CHECK 0x0001 /* don't check pub/private match */

#define RSA_FLAG_CACHE_PUBLIC   0x0002
#define RSA_FLAG_CACHE_PRIVATE  0x0004
#define RSA_FLAG_BLINDING       0x0008
#define RSA_FLAG_THREAD_SAFE    0x0010
/*
 * This flag means the private key operations will be handled by rsa_mod_exp
 * and that they do not depend on the private key components being present:
 * for example a key stored in external hardware. Without this flag bn_mod_exp
 * gets called when private key components are absent.
 */
#define RSA_FLAG_EXT_PKEY       0x0020

/*
 * This flag in the RSA_METHOD enables the new rsa_sign, rsa_verify functions.
 */
#define RSA_FLAG_SIGN_VER       0x0040

/*
 * new with 0.9.6j and 0.9.7b; the built-in RSA implementation now uses blinding
 * by default (ignoring RSA_FLAG_BLINDING), but other engines might not need it
 */
#define RSA_FLAG_NO_BLINDING    0x0080

/* new with 0.9.8f; the built-in RSA implementation now uses constant time
 * operations by default in private key operations, e.g., constant time modular
 * exponentiation, modular inverse without leaking branches, division without
 * leaking branches. This flag disables these constant time operations and
 * results in faster RSA private key operations.
 */
#define RSA_FLAG_NO_CONSTTIME   0x0100

#define EVP_PKEY_CTX_set_rsa_padding(ctx, pad)                               \
    EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_RSA, -1, EVP_PKEY_CTRL_RSA_PADDING, pad, \
                      NULL)

#define EVP_PKEY_CTX_get_rsa_padding(ctx, ppad)                                \
    EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_RSA, -1, EVP_PKEY_CTRL_GET_RSA_PADDING, 0, \
                      ppad)

#define EVP_PKEY_CTX_set_rsa_pss_saltlen(ctx, len)             \
    EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_RSA,                       \
                      (EVP_PKEY_OP_SIGN | EVP_PKEY_OP_VERIFY), \
                      EVP_PKEY_CTRL_RSA_PSS_SALTLEN, len, NULL)

#define EVP_PKEY_CTX_get_rsa_pss_saltlen(ctx, plen)            \
    EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_RSA,                       \
                      (EVP_PKEY_OP_SIGN | EVP_PKEY_OP_VERIFY), \
                      EVP_PKEY_CTRL_GET_RSA_PSS_SALTLEN, 0, plen)

#define EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, bits)          \
    EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_RSA, EVP_PKEY_OP_KEYGEN, \
                      EVP_PKEY_CTRL_RSA_KEYGEN_BITS, bits, NULL)

#define EVP_PKEY_CTX_set_rsa_keygen_pubexp(ctx, pubexp)      \
    EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_RSA, EVP_PKEY_OP_KEYGEN, \
                      EVP_PKEY_CTRL_RSA_KEYGEN_PUBEXP, 0, pubexp)

#define EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, md)                   \
    EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_RSA, EVP_PKEY_OP_TYPE_SIG | \
                      EVP_PKEY_OP_TYPE_CRYPT,                   \
                      EVP_PKEY_CTRL_RSA_MGF1_MD, 0, (void *)md)
    
#define EVP_PKEY_CTX_set_rsa_oaep_md(ctx, md)                    \
    EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_RSA, EVP_PKEY_OP_TYPE_CRYPT, \
                      EVP_PKEY_CTRL_RSA_OAEP_MD, 0, (void *)md)

#define EVP_PKEY_CTX_get_rsa_mgf1_md(ctx, pmd)                       \
    EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_RSA, EVP_PKEY_OP_TYPE_SIG |      \
                      EVP_PKEY_OP_TYPE_CRYPT,                        \
                      EVP_PKEY_CTRL_GET_RSA_MGF1_MD, 0, (void *)pmd)

#define EVP_PKEY_CTX_get_rsa_oaep_md(ctx, pmd)                       \
    EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_RSA, EVP_PKEY_OP_TYPE_CRYPT,     \
                      EVP_PKEY_CTRL_GET_RSA_OAEP_MD, 0, (void *)pmd)
    
#define EVP_PKEY_CTX_set0_rsa_oaep_label(ctx, l, llen)           \
    EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_RSA, EVP_PKEY_OP_TYPE_CRYPT, \
    EVP_PKEY_CTRL_RSA_OAEP_LABEL, llen, (void *)l)
    
#define EVP_PKEY_CTX_get0_rsa_oaep_label(ctx, l)                      \
    EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_RSA, EVP_PKEY_OP_TYPE_CRYPT,      \
                      EVP_PKEY_CTRL_GET_RSA_OAEP_LABEL, 0, (void *)l)
    
#define EVP_PKEY_CTRL_RSA_PADDING (EVP_PKEY_ALG_CTRL + 1)
#define EVP_PKEY_CTRL_RSA_PSS_SALTLEN (EVP_PKEY_ALG_CTRL + 2)

#define EVP_PKEY_CTRL_RSA_KEYGEN_BITS (EVP_PKEY_ALG_CTRL + 3)
#define EVP_PKEY_CTRL_RSA_KEYGEN_PUBEXP (EVP_PKEY_ALG_CTRL + 4)
#define EVP_PKEY_CTRL_RSA_MGF1_MD (EVP_PKEY_ALG_CTRL + 5)

#define EVP_PKEY_CTRL_GET_RSA_PADDING (EVP_PKEY_ALG_CTRL + 6)
#define EVP_PKEY_CTRL_GET_RSA_PSS_SALTLEN (EVP_PKEY_ALG_CTRL + 7)
#define EVP_PKEY_CTRL_GET_RSA_MGF1_MD (EVP_PKEY_ALG_CTRL + 8)
    
#define EVP_PKEY_CTRL_RSA_OAEP_MD (EVP_PKEY_ALG_CTRL + 9)
#define EVP_PKEY_CTRL_RSA_OAEP_LABEL (EVP_PKEY_ALG_CTRL + 10)
    
#define EVP_PKEY_CTRL_GET_RSA_OAEP_MD (EVP_PKEY_ALG_CTRL + 11)
#define EVP_PKEY_CTRL_GET_RSA_OAEP_LABEL (EVP_PKEY_ALG_CTRL + 12)

#define RSA_PKCS1_PADDING       1
#define RSA_SSLV23_PADDING      2
#define RSA_NO_PADDING          3
#define RSA_PKCS1_OAEP_PADDING  4
#define RSA_X931_PADDING        5
/* EVP_PKEY_ only */
#define RSA_PKCS1_PSS_PADDING   6

#define RSA_PKCS1_PADDING_SIZE  11

#define RSA_set_app_data(s, arg) RSA_set_ex_data(s, 0, arg)
#define RSA_get_app_data(s) RSA_get_ex_data(s, 0)

VIGORTLS_EXPORT RSA *RSA_new(void);
VIGORTLS_EXPORT RSA *RSA_new_method(ENGINE *engine);
VIGORTLS_EXPORT int RSA_size(const RSA *rsa);

/* Deprecated version */
#ifndef OPENSSL_NO_DEPRECATED
VIGORTLS_EXPORT RSA *RSA_generate_key(int bits, unsigned long e,
                                      void (*callback)(int, int, void *),
                                      void *cb_arg);
#endif /* !defined(OPENSSL_NO_DEPRECATED) */

/* New version */
VIGORTLS_EXPORT int RSA_generate_key_ex(RSA *rsa, int bits, BIGNUM *e,
                                        BN_GENCB *cb);

VIGORTLS_EXPORT int RSA_check_key(const RSA *);
/* next 4 return -1 on error */
VIGORTLS_EXPORT int RSA_public_encrypt(int flen, const uint8_t *from,
                                       uint8_t *to, RSA *rsa, int padding);
VIGORTLS_EXPORT int RSA_private_encrypt(int flen, const uint8_t *from,
                                        uint8_t *to, RSA *rsa, int padding);
VIGORTLS_EXPORT int RSA_public_decrypt(int flen, const uint8_t *from,
                                       uint8_t *to, RSA *rsa, int padding);
VIGORTLS_EXPORT int RSA_private_decrypt(int flen, const uint8_t *from,
                                        uint8_t *to, RSA *rsa, int padding);
VIGORTLS_EXPORT void RSA_free(RSA *r);
/* "up" the RSA object's reference count */
VIGORTLS_EXPORT int RSA_up_ref(RSA *r);

VIGORTLS_EXPORT int RSA_flags(const RSA *r);

VIGORTLS_EXPORT void RSA_set_default_method(const RSA_METHOD *meth);
VIGORTLS_EXPORT const RSA_METHOD *RSA_get_default_method(void);
VIGORTLS_EXPORT const RSA_METHOD *RSA_get_method(const RSA *rsa);
VIGORTLS_EXPORT int RSA_set_method(RSA *rsa, const RSA_METHOD *meth);

/* these are the actual SSLeay RSA functions */
VIGORTLS_EXPORT const RSA_METHOD *RSA_PKCS1_SSLeay(void);

VIGORTLS_EXPORT const RSA_METHOD *RSA_null_method(void);

DECLARE_ASN1_ENCODE_FUNCTIONS_const(RSA, RSAPublicKey)
DECLARE_ASN1_ENCODE_FUNCTIONS_const(RSA, RSAPrivateKey)

typedef struct rsa_pss_params_st {
    X509_ALGOR *hashAlgorithm;
    X509_ALGOR *maskGenAlgorithm;
    ASN1_INTEGER *saltLength;
    ASN1_INTEGER *trailerField;
} RSA_PSS_PARAMS;

DECLARE_ASN1_FUNCTIONS(RSA_PSS_PARAMS)
    
typedef struct rsa_oaep_params_st {
    X509_ALGOR *hashFunc;
    X509_ALGOR *maskGenFunc;
    X509_ALGOR *pSourceFunc;
} RSA_OAEP_PARAMS;
    
DECLARE_ASN1_FUNCTIONS(RSA_OAEP_PARAMS)

VIGORTLS_EXPORT int RSA_print_fp(FILE *fp, const RSA *r, int offset);

VIGORTLS_EXPORT int RSA_print(BIO *bp, const RSA *r, int offset);

VIGORTLS_EXPORT int i2d_RSA_NET(const RSA *a, uint8_t **pp,
                                int (*cb)(char *buf, int len,
                                          const char *prompt, int verify),
                                int sgckey);
VIGORTLS_EXPORT RSA *d2i_RSA_NET(RSA **a, const uint8_t **pp, long length,
                                 int (*cb)(char *buf, int len,
                                           const char *prompt, int verify),
                                 int sgckey);

VIGORTLS_EXPORT int i2d_Netscape_RSA(const RSA *a, uint8_t **pp,
                                     int (*cb)(char *buf, int len,
                                               const char *prompt, int verify));
VIGORTLS_EXPORT RSA *
d2i_Netscape_RSA(RSA **a, const uint8_t **pp, long length,
                 int (*cb)(char *buf, int len, const char *prompt, int verify));

/*
 * The following 2 functions sign and verify a X509_SIG ASN1 object
 * inside PKCS#1 padded RSA encryption
 */
VIGORTLS_EXPORT int RSA_sign(int type, const uint8_t *m, unsigned int m_length,
                             uint8_t *sigret, unsigned int *siglen, RSA *rsa);
VIGORTLS_EXPORT int RSA_verify(int type, const uint8_t *m,
                               unsigned int m_length, const uint8_t *sigbuf,
                               unsigned int siglen, RSA *rsa);

/*
 * The following 2 function sign and verify a ASN1_OCTET_STRING
 * object inside PKCS#1 padded RSA encryption
 */
VIGORTLS_EXPORT int RSA_sign_ASN1_OCTET_STRING(int type, const uint8_t *m,
                                               unsigned int m_length,
                                               uint8_t *sigret,
                                               unsigned int *siglen, RSA *rsa);
VIGORTLS_EXPORT int RSA_verify_ASN1_OCTET_STRING(int type, const uint8_t *m,
                                                 unsigned int m_length,
                                                 uint8_t *sigbuf,
                                                 unsigned int siglen, RSA *rsa);

VIGORTLS_EXPORT int RSA_blinding_on(RSA *rsa, BN_CTX *ctx);
VIGORTLS_EXPORT void RSA_blinding_off(RSA *rsa);
VIGORTLS_EXPORT BN_BLINDING *RSA_setup_blinding(RSA *rsa, BN_CTX *ctx);

VIGORTLS_EXPORT int RSA_padding_add_PKCS1_type_1(uint8_t *to, int tlen,
                                                 const uint8_t *f, int fl);
VIGORTLS_EXPORT int RSA_padding_check_PKCS1_type_1(uint8_t *to, int tlen,
                                                   const uint8_t *f, int fl,
                                                   int rsa_len);
VIGORTLS_EXPORT int RSA_padding_add_PKCS1_type_2(uint8_t *to, int tlen,
                                                 const uint8_t *f, int fl);
VIGORTLS_EXPORT int RSA_padding_check_PKCS1_type_2(uint8_t *to, int tlen,
                                                   const uint8_t *f, int fl,
                                                   int rsa_len);
VIGORTLS_EXPORT int PKCS1_MGF1(uint8_t *mask, long len, const uint8_t *seed,
                               long seedlen, const EVP_MD *dgst);
VIGORTLS_EXPORT int RSA_padding_add_PKCS1_OAEP(uint8_t *to, int tlen,
                                               const uint8_t *f, int fl,
                                               const uint8_t *p, int pl);
VIGORTLS_EXPORT int RSA_padding_check_PKCS1_OAEP(uint8_t *to, int tlen,
                                                 const uint8_t *f, int fl,
                                                 int rsa_len, const uint8_t *p,
                                                 int pl);
VIGORTLS_EXPORT int
RSA_padding_add_PKCS1_OAEP_mgf1(uint8_t *to, int tlen, const uint8_t *from,
                                int flen, const uint8_t *param, int plen,
                                const EVP_MD *md, const EVP_MD *mgf1md);
VIGORTLS_EXPORT int RSA_padding_check_PKCS1_OAEP_mgf1(
    uint8_t *to, int tlen, const uint8_t *from, int flen, int num,
    const uint8_t *param, int plen, const EVP_MD *md, const EVP_MD *mgf1md);
VIGORTLS_EXPORT int RSA_padding_add_SSLv23(uint8_t *to, int tlen,
                                           const uint8_t *f, int fl);
VIGORTLS_EXPORT int RSA_padding_check_SSLv23(uint8_t *to, int tlen,
                                             const uint8_t *f, int fl,
                                             int rsa_len);
VIGORTLS_EXPORT int RSA_padding_add_none(uint8_t *to, int tlen,
                                         const uint8_t *f, int fl);
VIGORTLS_EXPORT int RSA_padding_check_none(uint8_t *to, int tlen,
                                           const uint8_t *f, int fl,
                                           int rsa_len);
VIGORTLS_EXPORT int RSA_padding_add_X931(uint8_t *to, int tlen,
                                         const uint8_t *f, int fl);
VIGORTLS_EXPORT int RSA_padding_check_X931(uint8_t *to, int tlen,
                                           const uint8_t *f, int fl,
                                           int rsa_len);
VIGORTLS_EXPORT int RSA_X931_hash_id(int nid);

VIGORTLS_EXPORT int RSA_verify_PKCS1_PSS(RSA *rsa, const uint8_t *mHash,
                                         const EVP_MD *Hash, const uint8_t *EM,
                                         int sLen);
VIGORTLS_EXPORT int RSA_padding_add_PKCS1_PSS(RSA *rsa, uint8_t *EM,
                                              const uint8_t *mHash,
                                              const EVP_MD *Hash, int sLen);

VIGORTLS_EXPORT int RSA_verify_PKCS1_PSS_mgf1(RSA *rsa, const uint8_t *mHash,
                                              const EVP_MD *Hash,
                                              const EVP_MD *mgf1Hash,
                                              const uint8_t *EM, int sLen);

VIGORTLS_EXPORT int RSA_padding_add_PKCS1_PSS_mgf1(RSA *rsa, uint8_t *EM,
                                                   const uint8_t *mHash,
                                                   const EVP_MD *Hash,
                                                   const EVP_MD *mgf1Hash,
                                                   int sLen);

VIGORTLS_EXPORT int RSA_get_ex_new_index(long argl, void *argp,
                                         CRYPTO_EX_new *new_func,
                                         CRYPTO_EX_dup *dup_func,
                                         CRYPTO_EX_free *free_func);
VIGORTLS_EXPORT int RSA_set_ex_data(RSA *r, int idx, void *arg);
VIGORTLS_EXPORT void *RSA_get_ex_data(const RSA *r, int idx);

VIGORTLS_EXPORT RSA *RSAPublicKey_dup(RSA *rsa);
VIGORTLS_EXPORT RSA *RSAPrivateKey_dup(RSA *rsa);

/* Application has decided PRNG is good enough to generate a key: don't
 * check.
 */
#define RSA_FLAG_CHECKED 0x0800

/* BEGIN ERROR CODES */
/*
 * The following lines are auto generated by the script mkerr.pl. Any changes
 * made after this point may be overwritten when the script is next run.
 */
VIGORTLS_EXPORT void ERR_load_RSA_strings(void);

/* Error codes for the RSA functions. */

/* Function codes. */
# define RSA_F_CHECK_PADDING_MD                           140
# define RSA_F_DO_RSA_PRINT                               146
# define RSA_F_INT_RSA_VERIFY                             145
# define RSA_F_MEMORY_LOCK                                100
# define RSA_F_OLD_RSA_PRIV_DECODE                        147
# define RSA_F_PKEY_RSA_CTRL                              143
# define RSA_F_PKEY_RSA_CTRL_STR                          144
# define RSA_F_PKEY_RSA_SIGN                              142
# define RSA_F_PKEY_RSA_VERIFY                            154
# define RSA_F_PKEY_RSA_VERIFYRECOVER                     141
# define RSA_F_RSA_ALGOR_TO_MD                            157
# define RSA_F_RSA_BUILTIN_KEYGEN                         129
# define RSA_F_RSA_CHECK_KEY                              123
# define RSA_F_RSA_CMS_DECRYPT                            158
# define RSA_F_RSA_EAY_PRIVATE_DECRYPT                    101
# define RSA_F_RSA_EAY_PRIVATE_ENCRYPT                    102
# define RSA_F_RSA_EAY_PUBLIC_DECRYPT                     103
# define RSA_F_RSA_EAY_PUBLIC_ENCRYPT                     104
# define RSA_F_RSA_GENERATE_KEY                           105
# define RSA_F_RSA_GENERATE_KEY_EX                        155
# define RSA_F_RSA_ITEM_VERIFY                            156
# define RSA_F_RSA_MEMORY_LOCK                            130
# define RSA_F_RSA_MGF1_TO_MD                             159
# define RSA_F_RSA_NEW_METHOD                             106
# define RSA_F_RSA_NULL                                   124
# define RSA_F_RSA_NULL_MOD_EXP                           131
# define RSA_F_RSA_NULL_PRIVATE_DECRYPT                   132
# define RSA_F_RSA_NULL_PRIVATE_ENCRYPT                   133
# define RSA_F_RSA_NULL_PUBLIC_DECRYPT                    134
# define RSA_F_RSA_NULL_PUBLIC_ENCRYPT                    135
# define RSA_F_RSA_PADDING_ADD_NONE                       107
# define RSA_F_RSA_PADDING_ADD_PKCS1_OAEP                 121
# define RSA_F_RSA_PADDING_ADD_PKCS1_OAEP_MGF1            160
# define RSA_F_RSA_PADDING_ADD_PKCS1_PSS                  125
# define RSA_F_RSA_PADDING_ADD_PKCS1_PSS_MGF1             148
# define RSA_F_RSA_PADDING_ADD_PKCS1_TYPE_1               108
# define RSA_F_RSA_PADDING_ADD_PKCS1_TYPE_2               109
# define RSA_F_RSA_PADDING_ADD_SSLV23                     110
# define RSA_F_RSA_PADDING_ADD_X931                       127
# define RSA_F_RSA_PADDING_CHECK_NONE                     111
# define RSA_F_RSA_PADDING_CHECK_PKCS1_OAEP               122
# define RSA_F_RSA_PADDING_CHECK_PKCS1_OAEP_MGF1          161
# define RSA_F_RSA_PADDING_CHECK_PKCS1_TYPE_1             112
# define RSA_F_RSA_PADDING_CHECK_PKCS1_TYPE_2             113
# define RSA_F_RSA_PADDING_CHECK_SSLV23                   114
# define RSA_F_RSA_PADDING_CHECK_X931                     128
# define RSA_F_RSA_PRINT                                  115
# define RSA_F_RSA_PRINT_FP                               116
# define RSA_F_RSA_PRIVATE_DECRYPT                        150
# define RSA_F_RSA_PRIVATE_ENCRYPT                        151
# define RSA_F_RSA_PRIV_DECODE                            137
# define RSA_F_RSA_PRIV_ENCODE                            138
# define RSA_F_RSA_PSS_TO_CTX                             162
# define RSA_F_RSA_PUBLIC_DECRYPT                         152
# define RSA_F_RSA_PUBLIC_ENCRYPT                         153
# define RSA_F_RSA_PUB_DECODE                             139
# define RSA_F_RSA_SETUP_BLINDING                         136
# define RSA_F_RSA_SIGN                                   117
# define RSA_F_RSA_SIGN_ASN1_OCTET_STRING                 118
# define RSA_F_RSA_VERIFY                                 119
# define RSA_F_RSA_VERIFY_ASN1_OCTET_STRING               120
# define RSA_F_RSA_VERIFY_PKCS1_PSS                       126
# define RSA_F_RSA_VERIFY_PKCS1_PSS_MGF1                  149

/* Reason codes. */
# define RSA_R_ALGORITHM_MISMATCH                         100
# define RSA_R_BAD_E_VALUE                                101
# define RSA_R_BAD_FIXED_HEADER_DECRYPT                   102
# define RSA_R_BAD_PAD_BYTE_COUNT                         103
# define RSA_R_BAD_SIGNATURE                              104
# define RSA_R_BLOCK_TYPE_IS_NOT_01                       106
# define RSA_R_BLOCK_TYPE_IS_NOT_02                       107
# define RSA_R_DATA_GREATER_THAN_MOD_LEN                  108
# define RSA_R_DATA_TOO_LARGE                             109
# define RSA_R_DATA_TOO_LARGE_FOR_KEY_SIZE                110
# define RSA_R_DATA_TOO_LARGE_FOR_MODULUS                 132
# define RSA_R_DATA_TOO_SMALL                             111
# define RSA_R_DATA_TOO_SMALL_FOR_KEY_SIZE                122
# define RSA_R_DIGEST_DOES_NOT_MATCH                      159
# define RSA_R_DIGEST_TOO_BIG_FOR_RSA_KEY                 112
# define RSA_R_DMP1_NOT_CONGRUENT_TO_D                    124
# define RSA_R_DMQ1_NOT_CONGRUENT_TO_D                    125
# define RSA_R_D_E_NOT_CONGRUENT_TO_1                     123
# define RSA_R_FIRST_OCTET_INVALID                        133
# define RSA_R_ILLEGAL_OR_UNSUPPORTED_PADDING_MODE        144
# define RSA_R_INVALID_DIGEST                             160
# define RSA_R_INVALID_DIGEST_LENGTH                      143
# define RSA_R_INVALID_HEADER                             137
# define RSA_R_INVALID_KEYBITS                            145
# define RSA_R_INVALID_LABEL                              161
# define RSA_R_INVALID_MESSAGE_LENGTH                     131
# define RSA_R_INVALID_MGF1_MD                            156
# define RSA_R_INVALID_OAEP_PARAMETERS                    162
# define RSA_R_INVALID_PADDING                            138
# define RSA_R_INVALID_PADDING_MODE                       141
# define RSA_R_INVALID_PSS_PARAMETERS                     149
# define RSA_R_INVALID_PSS_SALTLEN                        146
# define RSA_R_INVALID_SALT_LENGTH                        150
# define RSA_R_INVALID_TRAILER                            139
# define RSA_R_INVALID_X931_DIGEST                        142
# define RSA_R_IQMP_NOT_INVERSE_OF_Q                      126
# define RSA_R_KEY_SIZE_TOO_SMALL                         120
# define RSA_R_LAST_OCTET_INVALID                         134
# define RSA_R_MODULUS_TOO_LARGE                          105
# define RSA_R_NO_PUBLIC_EXPONENT                         140
# define RSA_R_NULL_BEFORE_BLOCK_MISSING                  113
# define RSA_R_N_DOES_NOT_EQUAL_P_Q                       127
# define RSA_R_OAEP_DECODING_ERROR                        121
# define RSA_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE   148
# define RSA_R_PADDING_CHECK_FAILED                       114
# define RSA_R_PKCS_DECODING_ERROR                        159
# define RSA_R_P_NOT_PRIME                                128
# define RSA_R_Q_NOT_PRIME                                129
# define RSA_R_RSA_OPERATIONS_NOT_SUPPORTED               130
# define RSA_R_SLEN_CHECK_FAILED                          136
# define RSA_R_SLEN_RECOVERY_FAILED                       135
# define RSA_R_SSLV3_ROLLBACK_ATTACK                      115
# define RSA_R_THE_ASN1_OBJECT_IDENTIFIER_IS_NOT_KNOWN_FOR_THIS_MD 116
# define RSA_R_UNKNOWN_ALGORITHM_TYPE                     117
# define RSA_R_UNKNOWN_DIGEST                             163
# define RSA_R_UNKNOWN_MASK_DIGEST                        151
# define RSA_R_UNKNOWN_PADDING_TYPE                       118
# define RSA_R_UNKNOWN_PSS_DIGEST                         152
# define RSA_R_UNSUPPORTED_ENCRYPTION_TYPE                164
# define RSA_R_UNSUPPORTED_LABEL_SOURCE                   165
# define RSA_R_UNSUPPORTED_MASK_ALGORITHM                 153
# define RSA_R_UNSUPPORTED_MASK_PARAMETER                 154
# define RSA_R_UNSUPPORTED_SIGNATURE_TYPE                 155
# define RSA_R_VALUE_MISSING                              147
# define RSA_R_WRONG_SIGNATURE_LENGTH                     119

#ifdef  __cplusplus
}
#endif
#endif
