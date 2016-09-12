/*
 * Generated by util/mkerr.pl DO NOT EDIT
 * Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/err.h>
#include <openssl/bn.h>

/* BEGIN ERROR CODES */
#ifndef OPENSSL_NO_ERR

# define ERR_FUNC(func) ERR_PACK(ERR_LIB_BN, func, 0)
# define ERR_REASON(reason) ERR_PACK(ERR_LIB_BN, 0, reason)

static ERR_STRING_DATA BN_str_functs[] = {
    { ERR_FUNC(BN_F_BNRAND), "BNRAND" },
    { ERR_FUNC(BN_F_BN_BLINDING_CONVERT_EX), "BN_BLINDING_CONVERT_EX" },
    { ERR_FUNC(BN_F_BN_BLINDING_CREATE_PARAM), "BN_BLINDING_CREATE_PARAM" },
    { ERR_FUNC(BN_F_BN_BLINDING_INVERT_EX), "BN_BLINDING_INVERT_EX" },
    { ERR_FUNC(BN_F_BN_BLINDING_NEW), "BN_BLINDING_NEW" },
    { ERR_FUNC(BN_F_BN_BLINDING_UPDATE), "BN_BLINDING_UPDATE" },
    { ERR_FUNC(BN_F_BN_BN2DEC), "BN_BN2DEC" },
    { ERR_FUNC(BN_F_BN_BN2HEX), "BN_BN2HEX" },
    { ERR_FUNC(BN_F_BN_CTX_GET), "BN_CTX_GET" },
    { ERR_FUNC(BN_F_BN_CTX_NEW), "BN_CTX_NEW" },
    { ERR_FUNC(BN_F_BN_CTX_START), "BN_CTX_START" },
    { ERR_FUNC(BN_F_BN_DIV), "BN_DIV" },
    { ERR_FUNC(BN_F_BN_DIV_NO_BRANCH), "BN_DIV_NO_BRANCH" },
    { ERR_FUNC(BN_F_BN_DIV_RECP), "BN_DIV_RECP" },
    { ERR_FUNC(BN_F_BN_EXP), "BN_EXP" },
    { ERR_FUNC(BN_F_BN_EXPAND2), "BN_EXPAND2" },
    { ERR_FUNC(BN_F_BN_EXPAND_INTERNAL), "BN_EXPAND_INTERNAL" },
    { ERR_FUNC(BN_F_BN_GENERATE_PRIME_EX), "BN_GENERATE_PRIME_EX" },
    { ERR_FUNC(BN_F_BN_GF2M_MOD), "BN_GF2M_MOD" },
    { ERR_FUNC(BN_F_BN_GF2M_MOD_EXP), "BN_GF2M_MOD_EXP" },
    { ERR_FUNC(BN_F_BN_GF2M_MOD_MUL), "BN_GF2M_MOD_MUL" },
    { ERR_FUNC(BN_F_BN_GF2M_MOD_SOLVE_QUAD), "BN_GF2M_MOD_SOLVE_QUAD" },
    { ERR_FUNC(BN_F_BN_GF2M_MOD_SOLVE_QUAD_ARR), "BN_GF2M_MOD_SOLVE_QUAD_ARR" },
    { ERR_FUNC(BN_F_BN_GF2M_MOD_SQR), "BN_GF2M_MOD_SQR" },
    { ERR_FUNC(BN_F_BN_GF2M_MOD_SQRT), "BN_GF2M_MOD_SQRT" },
    { ERR_FUNC(BN_F_BN_LSHIFT), "BN_LSHIFT" },
    { ERR_FUNC(BN_F_BN_MOD_EXP2_MONT), "BN_MOD_EXP2_MONT" },
    { ERR_FUNC(BN_F_BN_MOD_EXP_MONT), "BN_MOD_EXP_MONT" },
    { ERR_FUNC(BN_F_BN_MOD_EXP_MONT_CONSTTIME), "BN_MOD_EXP_MONT_CONSTTIME" },
    { ERR_FUNC(BN_F_BN_MOD_EXP_MONT_WORD), "BN_MOD_EXP_MONT_WORD" },
    { ERR_FUNC(BN_F_BN_MOD_EXP_RECP), "BN_MOD_EXP_RECP" },
    { ERR_FUNC(BN_F_BN_MOD_EXP_SIMPLE), "BN_MOD_EXP_SIMPLE" },
    { ERR_FUNC(BN_F_BN_MOD_INVERSE), "BN_MOD_INVERSE" },
    { ERR_FUNC(BN_F_BN_MOD_INVERSE_NO_BRANCH), "BN_MOD_INVERSE_NO_BRANCH" },
    { ERR_FUNC(BN_F_BN_MOD_LSHIFT_QUICK), "BN_MOD_LSHIFT_QUICK" },
    { ERR_FUNC(BN_F_BN_MOD_MUL_RECIPROCAL), "BN_MOD_MUL_RECIPROCAL" },
    { ERR_FUNC(BN_F_BN_MOD_SQRT), "BN_MOD_SQRT" },
    { ERR_FUNC(BN_F_BN_MPI2BN), "BN_MPI2BN" },
    { ERR_FUNC(BN_F_BN_NEW), "BN_NEW" },
    { ERR_FUNC(BN_F_BN_RAND), "BN_RAND" },
    { ERR_FUNC(BN_F_BN_RAND_RANGE), "BN_RAND_RANGE" },
    { ERR_FUNC(BN_F_BN_RSHIFT), "BN_RSHIFT" },
    { ERR_FUNC(BN_F_BN_USUB), "BN_USUB" },
    { 0, NULL }
};

static ERR_STRING_DATA BN_str_reasons[] = {
    { ERR_REASON(BN_R_ARG2_LT_ARG3), "arg2 lt arg3" },
    { ERR_REASON(BN_R_BAD_RECIPROCAL), "bad reciprocal" },
    { ERR_REASON(BN_R_BIGNUM_TOO_LONG), "bignum too long" },
    { ERR_REASON(BN_R_BITS_TOO_SMALL), "bits too small" },
    { ERR_REASON(BN_R_CALLED_WITH_EVEN_MODULUS), "called with even modulus" },
    { ERR_REASON(BN_R_DIV_BY_ZERO), "div by zero" },
    { ERR_REASON(BN_R_ENCODING_ERROR), "encoding error" },
    { ERR_REASON(BN_R_EXPAND_ON_STATIC_BIGNUM_DATA),
     "expand on static bignum data" },
    { ERR_REASON(BN_R_INPUT_NOT_REDUCED), "input not reduced" },
    { ERR_REASON(BN_R_INVALID_LENGTH), "invalid length" },
    { ERR_REASON(BN_R_INVALID_RANGE), "invalid range" },
    { ERR_REASON(BN_R_INVALID_SHIFT), "invalid shift" },
    { ERR_REASON(BN_R_NOT_A_SQUARE), "not a square" },
    { ERR_REASON(BN_R_NOT_INITIALIZED), "not initialized" },
    { ERR_REASON(BN_R_NO_INVERSE), "no inverse" },
    { ERR_REASON(BN_R_NO_SOLUTION), "no solution" },
    { ERR_REASON(BN_R_P_IS_NOT_PRIME), "p is not prime" },
    { ERR_REASON(BN_R_TOO_MANY_ITERATIONS), "too many iterations" },
    { ERR_REASON(BN_R_TOO_MANY_TEMPORARY_VARIABLES),
     "too many temporary variables" },
    { 0, NULL }
};

#endif

void ERR_load_BN_strings(void)
{
#ifndef OPENSSL_NO_ERR
    if (ERR_func_error_string(BN_str_functs[0].error) == NULL) {
        ERR_load_strings(0, BN_str_functs);
        ERR_load_strings(0, BN_str_reasons);
    }
#endif
}
