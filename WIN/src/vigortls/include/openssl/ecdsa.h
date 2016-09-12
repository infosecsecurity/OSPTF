/*
 * Copyright 2000-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef HEADER_ECDSA_H
#define HEADER_ECDSA_H

#include <openssl/base.h>
#include <openssl/ec.h>
#ifndef OPENSSL_NO_DEPRECATED
#include <openssl/bn.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

typedef struct ECDSA_SIG_st {
    BIGNUM *r;
    BIGNUM *s;
} ECDSA_SIG;

/** Allocates and initialize a ECDSA_SIG structure
 *  \return pointer to a ECDSA_SIG structure or NULL if an error occurred
 */
VIGORTLS_EXPORT ECDSA_SIG *ECDSA_SIG_new(void);

/** frees a ECDSA_SIG structure
 *  \param  sig  pointer to the ECDSA_SIG structure
 */
VIGORTLS_EXPORT void ECDSA_SIG_free(ECDSA_SIG *sig);

/** DER encode content of ECDSA_SIG object (note: this function modifies *pp
 *  (*pp += length of the DER encoded signature)).
 *  \param  sig  pointer to the ECDSA_SIG object
 *  \param  pp   pointer to a uint8_t pointer for the output or NULL
 *  \return the length of the DER encoded ECDSA_SIG object or 0
 */
VIGORTLS_EXPORT int i2d_ECDSA_SIG(const ECDSA_SIG *sig, uint8_t **pp);

/** Decodes a DER encoded ECDSA signature (note: this function changes *pp
 *  (*pp += len)).
 *  \param  sig  pointer to ECDSA_SIG pointer (may be NULL)
 *  \param  pp   memory buffer with the DER encoded signature
 *  \param  len  length of the buffer
 *  \return pointer to the decoded ECDSA_SIG structure (or NULL)
 */
VIGORTLS_EXPORT ECDSA_SIG *d2i_ECDSA_SIG(ECDSA_SIG **sig, const uint8_t **pp,
                                         long len);

/** Computes the ECDSA signature of the given hash value using
 *  the supplied private key and returns the created signature.
 *  \param  dgst      pointer to the hash value
 *  \param  dgst_len  length of the hash value
 *  \param  eckey     EC_KEY object containing a private EC key
 *  \return pointer to a ECDSA_SIG structure or NULL if an error occurred
 */
VIGORTLS_EXPORT ECDSA_SIG *ECDSA_do_sign(const uint8_t *dgst, int dgst_len,
                                         EC_KEY *eckey);

/** Computes ECDSA signature of a given hash value using the supplied
 *  private key (note: sig must point to ECDSA_size(eckey) bytes of memory).
 *  \param  dgst     pointer to the hash value to sign
 *  \param  dgstlen  length of the hash value
 *  \param  kinv     BIGNUM with a pre-computed inverse k (optional)
 *  \param  rp       BIGNUM with a pre-computed rp value (optioanl),
 *                   see ECDSA_sign_setup
 *  \param  eckey    EC_KEY object containing a private EC key
 *  \return pointer to a ECDSA_SIG structure or NULL if an error occurred
 */
VIGORTLS_EXPORT ECDSA_SIG *ECDSA_do_sign_ex(const uint8_t *dgst, int dgstlen,
                                            const BIGNUM *kinv,
                                            const BIGNUM *rp, EC_KEY *eckey);

/** Verifies that the supplied signature is a valid ECDSA
 *  signature of the supplied hash value using the supplied public key.
 *  \param  dgst      pointer to the hash value
 *  \param  dgst_len  length of the hash value
 *  \param  sig       ECDSA_SIG structure
 *  \param  eckey     EC_KEY object containing a public EC key
 *  \return 1 if the signature is valid, 0 if the signature is invalid
 *          and -1 on error
 */
VIGORTLS_EXPORT int ECDSA_do_verify(const uint8_t *dgst, int dgst_len,
                                    const ECDSA_SIG *sig, EC_KEY *eckey);

VIGORTLS_EXPORT const ECDSA_METHOD *ECDSA_OpenSSL(void);

/** Sets the default ECDSA method
 *  \param  meth  new default ECDSA_METHOD
 */
VIGORTLS_EXPORT void ECDSA_set_default_method(const ECDSA_METHOD *meth);

/** Returns the default ECDSA method
 *  \return pointer to ECDSA_METHOD structure containing the default method
 */
VIGORTLS_EXPORT const ECDSA_METHOD *ECDSA_get_default_method(void);

/** Sets method to be used for the ECDSA operations
 *  \param  eckey  EC_KEY object
 *  \param  meth   new method
 *  \return 1 on success and 0 otherwise
 */
VIGORTLS_EXPORT int ECDSA_set_method(EC_KEY *eckey, const ECDSA_METHOD *meth);

/** Returns the maximum length of the DER encoded signature
 *  \param  eckey  EC_KEY object
 *  \return numbers of bytes required for the DER encoded signature
 */
VIGORTLS_EXPORT int ECDSA_size(const EC_KEY *eckey);

/** Precompute parts of the signing operation
 *  \param  eckey  EC_KEY object containing a private EC key
 *  \param  ctx    BN_CTX object (optional)
 *  \param  kinv   BIGNUM pointer for the inverse of k
 *  \param  rp     BIGNUM pointer for x coordinate of k * generator
 *  \return 1 on success and 0 otherwise
 */
VIGORTLS_EXPORT int ECDSA_sign_setup(EC_KEY *eckey, BN_CTX *ctx, BIGNUM **kinv,
                                     BIGNUM **rp);

/** Computes ECDSA signature of a given hash value using the supplied
 *  private key (note: sig must point to ECDSA_size(eckey) bytes of memory).
 *  \param  type     this parameter is ignored
 *  \param  dgst     pointer to the hash value to sign
 *  \param  dgstlen  length of the hash value
 *  \param  sig      memory for the DER encoded created signature
 *  \param  siglen   pointer to the length of the returned signature
 *  \param  eckey    EC_KEY object containing a private EC key
 *  \return 1 on success and 0 otherwise
 */
VIGORTLS_EXPORT int ECDSA_sign(int type, const uint8_t *dgst, int dgstlen,
                               uint8_t *sig, unsigned int *siglen,
                               EC_KEY *eckey);

/** Computes ECDSA signature of a given hash value using the supplied
 *  private key (note: sig must point to ECDSA_size(eckey) bytes of memory).
 *  \param  type     this parameter is ignored
 *  \param  dgst     pointer to the hash value to sign
 *  \param  dgstlen  length of the hash value
 *  \param  sig      buffer to hold the DER encoded signature
 *  \param  siglen   pointer to the length of the returned signature
 *  \param  kinv     BIGNUM with a pre-computed inverse k (optional)
 *  \param  rp       BIGNUM with a pre-computed rp value (optioanl),
 *                   see ECDSA_sign_setup
 *  \param  eckey    EC_KEY object containing a private EC key
 *  \return 1 on success and 0 otherwise
 */
VIGORTLS_EXPORT int ECDSA_sign_ex(int type, const uint8_t *dgst, int dgstlen,
                                  uint8_t *sig, unsigned int *siglen,
                                  const BIGNUM *kinv, const BIGNUM *rp,
                                  EC_KEY *eckey);

/** Verifies that the given signature is valid ECDSA signature
 *  of the supplied hash value using the specified public key.
 *  \param  type     this parameter is ignored
 *  \param  dgst     pointer to the hash value
 *  \param  dgstlen  length of the hash value
 *  \param  sig      pointer to the DER encoded signature
 *  \param  siglen   length of the DER encoded signature
 *  \param  eckey    EC_KEY object containing a public EC key
 *  \return 1 if the signature is valid, 0 if the signature is invalid
 *          and -1 on error
 */
VIGORTLS_EXPORT int ECDSA_verify(int type, const uint8_t *dgst, int dgstlen,
                                 const uint8_t *sig, int siglen, EC_KEY *eckey);

/* the standard ex_data functions */
VIGORTLS_EXPORT int ECDSA_get_ex_new_index(long argl, void *argp,
                                           CRYPTO_EX_new *new_func,
                                           CRYPTO_EX_dup *dup_func,
                                           CRYPTO_EX_free *free_func);
VIGORTLS_EXPORT int ECDSA_set_ex_data(EC_KEY *d, int idx, void *arg);
VIGORTLS_EXPORT void *ECDSA_get_ex_data(EC_KEY *d, int idx);

/** Allocates and initialize a ECDSA_METHOD structure
 *  \param ecdsa_method pointer to ECDSA_METHOD to copy.  (May be NULL)
 *  \return pointer to a ECDSA_METHOD structure or NULL if an error occurred
 */

VIGORTLS_EXPORT ECDSA_METHOD *
ECDSA_METHOD_new(const ECDSA_METHOD *ecdsa_method);

/** frees a ECDSA_METHOD structure
 *  \param  ecdsa_method  pointer to the ECDSA_METHOD structure
 */
VIGORTLS_EXPORT void ECDSA_METHOD_free(ECDSA_METHOD *ecdsa_method);

/**  Sets application specific data in the ECDSA_METHOD
 *   \param  ecdsa_method pointer to existing ECDSA_METHOD
 *   \param  app application specific data to set
 */

VIGORTLS_EXPORT void ECDSA_METHOD_set_app_data(ECDSA_METHOD *ecdsa_method,
                                               void *app);

/** Returns application specific data from a ECDSA_METHOD structure
 *  \param ecdsa_method pointer to ECDSA_METHOD structure
 *  \return pointer to application specific data.
 */

VIGORTLS_EXPORT void *ECDSA_METHOD_get_app_data(ECDSA_METHOD *ecdsa_method);

/**  Set the ECDSA_do_sign function in the ECDSA_METHOD
 *   \param  ecdsa_method  pointer to existing ECDSA_METHOD
 *   \param  ecdsa_do_sign a funtion of type ECDSA_do_sign
 */

VIGORTLS_EXPORT void ECDSA_METHOD_set_sign(
    ECDSA_METHOD *ecdsa_method,
    ECDSA_SIG *(*ecdsa_do_sign)(const uint8_t *dgst, int dgst_len,
                                const BIGNUM *inv, const BIGNUM *rp,
                                EC_KEY *eckey));

/**  Set the  ECDSA_sign_setup function in the ECDSA_METHOD
 *   \param  ecdsa_method  pointer to existing ECDSA_METHOD
 *   \param  ecdsa_sign_setup a funtion of type ECDSA_sign_setup
 */

VIGORTLS_EXPORT void
ECDSA_METHOD_set_sign_setup(ECDSA_METHOD *ecdsa_method,
                            int (*ecdsa_sign_setup)(EC_KEY *eckey, BN_CTX *ctx,
                                                    BIGNUM **kinv, BIGNUM **r));

/**  Set the ECDSA_do_verify function in the ECDSA_METHOD
 *   \param  ecdsa_method  pointer to existing ECDSA_METHOD
 *   \param  ecdsa_do_verify a funtion of type ECDSA_do_verify
 */

VIGORTLS_EXPORT void ECDSA_METHOD_set_verify(
    ECDSA_METHOD *ecdsa_method,
    int (*ecdsa_do_verify)(const uint8_t *dgst, int dgst_len,
                           const ECDSA_SIG *sig, EC_KEY *eckey));

VIGORTLS_EXPORT void ECDSA_METHOD_set_flags(ECDSA_METHOD *ecdsa_method,
                                            int flags);

/**  Set the flags field in the ECDSA_METHOD
 *   \param  ecdsa_method  pointer to existing ECDSA_METHOD
 *   \param  flags flags value to set
 */

VIGORTLS_EXPORT void ECDSA_METHOD_set_name(ECDSA_METHOD *ecdsa_method,
                                           char *name);

/**  Set the name field in the ECDSA_METHOD
 *   \param  ecdsa_method  pointer to existing ECDSA_METHOD
 *   \param  name name to set
 */

/* BEGIN ERROR CODES */
/*
 * The following lines are auto generated by the script mkerr.pl. Any changes
 * made after this point may be overwritten when the script is next run.
 */
VIGORTLS_EXPORT void ERR_load_ECDSA_strings(void);

/* Error codes for the ECDSA functions. */

/* Function codes. */
# define ECDSA_F_ECDSA_CHECK                              104
# define ECDSA_F_ECDSA_DATA_NEW_METHOD                    100
# define ECDSA_F_ECDSA_DO_SIGN                            101
# define ECDSA_F_ECDSA_DO_VERIFY                          102
# define ECDSA_F_ECDSA_METHOD_NEW                         105
# define ECDSA_F_ECDSA_SIGN_SETUP                         103

/* Reason codes. */
# define ECDSA_R_BAD_SIGNATURE                            100
# define ECDSA_R_DATA_TOO_LARGE_FOR_KEY_SIZE              101
# define ECDSA_R_ERR_EC_LIB                               102
# define ECDSA_R_MISSING_PARAMETERS                       103
# define ECDSA_R_NEED_NEW_SETUP_VALUES                    106
# define ECDSA_R_RANDOM_NUMBER_GENERATION_FAILED          104
# define ECDSA_R_SIGNATURE_MALLOC_FAILED                  105

#ifdef  __cplusplus
}
#endif
#endif
