/*
 * Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */
/* ====================================================================
 * Copyright 2002 Sun Microsystems, Inc. ALL RIGHTS RESERVED.
 *
 * Portions of the attached software ("Contribution") are developed by
 * SUN MICROSYSTEMS, INC., and are contributed to the OpenSSL project.
 *
 * The Contribution is licensed pursuant to the Eric Young open source
 * license provided above.
 *
 * The binary polynomial arithmetic software is originally written by
 * Sheueling Chang Shantz and Douglas Stebila of Sun Microsystems Laboratories.
 *
 */

#ifndef HEADER_BN_H
#define HEADER_BN_H

#include <limits.h>
#include <stdio.h>

#include <openssl/base.h>
#include <openssl/bio.h>
#include <openssl/crypto.h>
#include <openssl/internal.h>

#include <openssl/threads.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * These preprocessor symbols control various aspects of the bignum headers and
 * library code. They're not defined by any "normal" configuration, as they are
 * intended for development and testing purposes. NB: defining all three can be
 * useful for debugging application code as well as openssl itself.
 *
 * BN_DEBUG - turn on various debugging alterations to the bignum code
 * BN_DEBUG_RAND - uses random poisoning of unused words to trip up
 * mismanagement of bignum internals. You must also define BN_DEBUG.
 */
/* #define BN_DEBUG */
/* #define BN_DEBUG_RAND */

#ifndef OPENSSL_SMALL_FOOTPRINT
#define BN_MUL_COMBA
#define BN_SQR_COMBA
#define BN_RECURSION
#endif

/* This next option uses the C libraries (2 word)/(1 word) function.
 * If it is not defined, I use my C version (which is slower).
 * The reason for this flag is that when the particular C compiler
 * library routine is used, and the library is linked with a different
 * compiler, the library is missing.  This mostly happens when the
 * library is built with gcc and then linked using normal cc.  This would
 * be a common occurrence because gcc normally produces code that is
 * 2 times faster than system compilers for the big number stuff.
 * For machines with only one compiler (or shared libraries), this should
 * be on.  Again this in only really a problem on machines
 * using "long long's", are 32bit, and are not using my assembler code. */
/* #define BN_DIV2W */

#define BN_FLG_MALLOCED         0x01
#define BN_FLG_STATIC_DATA      0x02
#define BN_FLG_CONSTTIME        0x04 /* avoid leaking exponent information through timing,
                                      * BN_mod_exp_mont() will call BN_mod_exp_mont_consttime,
                                      * BN_div() will call BN_div_no_branch,
                                      * BN_mod_inverse() will call BN_mod_inverse_no_branch.
                                      */

#ifndef OPENSSL_NO_DEPRECATED
#define BN_FLG_EXP_CONSTTIME BN_FLG_CONSTTIME /* deprecated name for the flag */
#endif

#ifndef OPENSSL_NO_DEPRECATED
#define BN_FLG_FREE 0x8000 /* used for debuging */
#endif
#define BN_set_flags(b, n) ((b)->flags |= (n))
#define BN_get_flags(b, n) ((b)->flags & (n))

/* get a clone of a BIGNUM with changed flags, for *temporary* use only
 * (the two BIGNUMs cannot not be used in parallel!) */
#define BN_with_flags(dest, b, n)                                          \
    ((dest)->d = (b)->d, (dest)->top = (b)->top, (dest)->dmax = (b)->dmax, \
     (dest)->neg = (b)->neg,                                               \
     (dest)->flags =                                                       \
         (((dest)->flags & BN_FLG_MALLOCED) |                              \
          ((b)->flags & ~BN_FLG_MALLOCED) | BN_FLG_STATIC_DATA | (n)))

struct bignum_st {
    BN_ULONG *d; /* Pointer to an array of 'BN_BITS2' bit chunks. */
    int top;     /* Index of last used d +1. */
    /* The next are internal book keeping for bn_expand. */
    int dmax; /* Size of the d array. */
    int neg;  /* one if the number is negative */
    int flags;
};

/* Used for montgomery multiplication */
struct bn_mont_ctx_st {
    int ri;         /* number of bits in R */
    BIGNUM RR;      /* used to convert to montgomery form */
    BIGNUM N;       /* The modulus */
    BIGNUM Ni;      /* R*(1/R mod N) - N*Ni = 1
                    * (Ni is only stored for bignum algorithm) */
    BN_ULONG n0[2]; /* least significant word(s) of Ni;
                      (type changed with 0.9.9, was "BN_ULONG n0;" before) */
    int flags;
};

/* Used for reciprocal division/mod functions
 * It cannot be shared between threads
 */
struct bn_recp_ctx_st {
    BIGNUM N;  /* the divisor */
    BIGNUM Nr; /* the reciprocal */
    int num_bits;
    int shift;
    int flags;
};

/* Used for slow "generation" functions. */
struct bn_gencb_st {
    unsigned int ver; /* To handle binary (in)compatibility */
    void *arg;        /* callback-specific data */
    union {
        /* if(ver==1) - handles old style callbacks */
        void (*cb_1)(int, int, void *);
        /* if(ver==2) - new callback style */
        int (*cb_2)(int, int, BN_GENCB *);
    } cb;
};
/* Wrapper function to make using BN_GENCB easier,  */
int BN_GENCB_call(BN_GENCB *cb, int a, int b);
/* Macro to populate a BN_GENCB structure with an "old"-style callback */
#define BN_GENCB_set_old(gencb, callback, cb_arg) \
    {                                             \
        BN_GENCB *tmp_gencb = (gencb);            \
        tmp_gencb->ver      = 1;                  \
        tmp_gencb->arg      = (cb_arg);           \
        tmp_gencb->cb.cb_1  = (callback);         \
    }
/* Macro to populate a BN_GENCB structure with a "new"-style callback */
#define BN_GENCB_set(gencb, callback, cb_arg) \
    {                                         \
        BN_GENCB *tmp_gencb = (gencb);        \
        tmp_gencb->ver      = 2;              \
        tmp_gencb->arg      = (cb_arg);       \
        tmp_gencb->cb.cb_2  = (callback);     \
    }

#define BN_prime_checks                       \
    0 /* default: select number of iterations \
         based on the size of the number */

/* number of Miller-Rabin iterations for an error rate  of less than 2^-80
 * for random 'b'-bit input, b >= 100 (taken from table 4.4 in the Handbook
 * of Applied Cryptography [Menezes, van Oorschot, Vanstone; CRC Press 1996];
 * original paper: Damgaard, Landrock, Pomerance: Average case error estimates
 * for the strong probable prime test. -- Math. Comp. 61 (1993) 177-194) */
#define BN_prime_checks_for_size(b)                                        \
    ((b) >= 1300 ? 2 : (b) >= 850 ?                                        \
                   3 :                                                     \
                   (b) >= 650 ? 4 : (b) >= 550 ?                           \
                                5 :                                        \
                                (b) >= 450 ? 6 : (b) >= 400 ?              \
                                             7 :                           \
                                             (b) >= 350 ? 8 : (b) >= 300 ? \
                                                          9 :              \
                                                          (b) >= 250 ?     \
                                                          12 :             \
                                                          (b) >= 200 ?     \
                                                          15 :             \
                                                          (b) >= 150 ?     \
                                                          18 :             \
                                                          /* b >= 100 */ 27)

#define BN_num_bytes(a) ((BN_num_bits(a) + 7) / 8)

/* Note that BN_abs_is_word didn't work reliably for w == 0 until 0.9.8 */
#define BN_abs_is_word(a, w)                              \
    ((((a)->top == 1) && ((a)->d[0] == (BN_ULONG)(w))) || \
     (((w) == 0) && ((a)->top == 0)))
#define BN_is_zero(a) ((a)->top == 0)
#define BN_is_one(a) (BN_abs_is_word((a), 1) && !(a)->neg)
#define BN_is_word(a, w) (BN_abs_is_word((a), (w)) && (!(w) || !(a)->neg))
#define BN_is_odd(a) (((a)->top > 0) && ((a)->d[0] & 1))

#define BN_one(a) (BN_set_word((a), 1))
#define BN_zero_ex(a)          \
    do {                       \
        BIGNUM *_tmp_bn = (a); \
        _tmp_bn->top    = 0;   \
        _tmp_bn->neg    = 0;   \
    } while (0)

#ifdef OPENSSL_NO_DEPRECATED
#define BN_zero(a) BN_zero_ex(a)
#else
#define BN_zero(a) (BN_set_word((a), 0))
#endif

VIGORTLS_EXPORT const BIGNUM *BN_value_one(void);
VIGORTLS_EXPORT char *BN_options(void);
VIGORTLS_EXPORT BN_CTX *BN_CTX_new(void);
#ifndef OPENSSL_NO_DEPRECATED
VIGORTLS_EXPORT void BN_CTX_init(BN_CTX *c);
#endif
VIGORTLS_EXPORT void BN_CTX_free(BN_CTX *c);
VIGORTLS_EXPORT void BN_CTX_start(BN_CTX *ctx);
VIGORTLS_EXPORT BIGNUM *BN_CTX_get(BN_CTX *ctx);
VIGORTLS_EXPORT void BN_CTX_end(BN_CTX *ctx);
VIGORTLS_EXPORT int BN_rand(BIGNUM *rnd, int bits, int top, int bottom);
VIGORTLS_EXPORT int BN_pseudo_rand(BIGNUM *rnd, int bits, int top, int bottom);
VIGORTLS_EXPORT int BN_rand_range(BIGNUM *rnd, const BIGNUM *range);
VIGORTLS_EXPORT int BN_pseudo_rand_range(BIGNUM *rnd, const BIGNUM *range);
VIGORTLS_EXPORT int BN_num_bits(const BIGNUM *a);
VIGORTLS_EXPORT int BN_num_bits_word(BN_ULONG);
VIGORTLS_EXPORT BIGNUM *BN_new(void);
VIGORTLS_EXPORT void BN_init(BIGNUM *);
VIGORTLS_EXPORT void BN_clear_free(BIGNUM *a);
VIGORTLS_EXPORT BIGNUM *BN_copy(BIGNUM *a, const BIGNUM *b);
VIGORTLS_EXPORT void BN_swap(BIGNUM *a, BIGNUM *b);
VIGORTLS_EXPORT BIGNUM *BN_bin2bn(const uint8_t *s, int len, BIGNUM *ret);
VIGORTLS_EXPORT int BN_bn2bin(const BIGNUM *a, uint8_t *to);
VIGORTLS_EXPORT BIGNUM *BN_mpi2bn(const uint8_t *s, int len, BIGNUM *ret);
VIGORTLS_EXPORT int BN_bn2mpi(const BIGNUM *a, uint8_t *to);
VIGORTLS_EXPORT int BN_sub(BIGNUM *r, const BIGNUM *a, const BIGNUM *b);
VIGORTLS_EXPORT int BN_usub(BIGNUM *r, const BIGNUM *a, const BIGNUM *b);
VIGORTLS_EXPORT int BN_uadd(BIGNUM *r, const BIGNUM *a, const BIGNUM *b);
VIGORTLS_EXPORT int BN_add(BIGNUM *r, const BIGNUM *a, const BIGNUM *b);
VIGORTLS_EXPORT int BN_mul(BIGNUM *r, const BIGNUM *a, const BIGNUM *b,
                           BN_CTX *ctx);
VIGORTLS_EXPORT int BN_sqr(BIGNUM *r, const BIGNUM *a, BN_CTX *ctx);
/** BN_set_negative sets sign of a BIGNUM
 * \param  b  pointer to the BIGNUM object
 * \param  n  0 if the BIGNUM b should be positive and a value != 0 otherwise
 */
VIGORTLS_EXPORT void BN_set_negative(BIGNUM *b, int n);
/** BN_is_negative returns 1 if the BIGNUM is negative
 * \param  a  pointer to the BIGNUM object
 * \return 1 if a < 0 and 0 otherwise
 */
#define BN_is_negative(a) ((a)->neg != 0)

VIGORTLS_EXPORT int BN_div(BIGNUM *dv, BIGNUM *rem, const BIGNUM *m,
                           const BIGNUM *d, BN_CTX *ctx);
#define BN_mod(rem, m, d, ctx) BN_div(NULL, (rem), (m), (d), (ctx))
VIGORTLS_EXPORT int BN_nnmod(BIGNUM *r, const BIGNUM *m, const BIGNUM *d,
                             BN_CTX *ctx);
VIGORTLS_EXPORT int BN_mod_add(BIGNUM *r, const BIGNUM *a, const BIGNUM *b,
                               const BIGNUM *m, BN_CTX *ctx);
VIGORTLS_EXPORT int BN_mod_add_quick(BIGNUM *r, const BIGNUM *a,
                                     const BIGNUM *b, const BIGNUM *m);
VIGORTLS_EXPORT int BN_mod_sub(BIGNUM *r, const BIGNUM *a, const BIGNUM *b,
                               const BIGNUM *m, BN_CTX *ctx);
VIGORTLS_EXPORT int BN_mod_sub_quick(BIGNUM *r, const BIGNUM *a,
                                     const BIGNUM *b, const BIGNUM *m);
VIGORTLS_EXPORT int BN_mod_mul(BIGNUM *r, const BIGNUM *a, const BIGNUM *b,
                               const BIGNUM *m, BN_CTX *ctx);
VIGORTLS_EXPORT int BN_mod_sqr(BIGNUM *r, const BIGNUM *a, const BIGNUM *m,
                               BN_CTX *ctx);
VIGORTLS_EXPORT int BN_mod_lshift1(BIGNUM *r, const BIGNUM *a, const BIGNUM *m,
                                   BN_CTX *ctx);
VIGORTLS_EXPORT int BN_mod_lshift1_quick(BIGNUM *r, const BIGNUM *a,
                                         const BIGNUM *m);
VIGORTLS_EXPORT int BN_mod_lshift(BIGNUM *r, const BIGNUM *a, int n,
                                  const BIGNUM *m, BN_CTX *ctx);
VIGORTLS_EXPORT int BN_mod_lshift_quick(BIGNUM *r, const BIGNUM *a, int n,
                                        const BIGNUM *m);

VIGORTLS_EXPORT BN_ULONG BN_mod_word(const BIGNUM *a, BN_ULONG w);
VIGORTLS_EXPORT BN_ULONG BN_div_word(BIGNUM *a, BN_ULONG w);
VIGORTLS_EXPORT int BN_mul_word(BIGNUM *a, BN_ULONG w);
VIGORTLS_EXPORT int BN_add_word(BIGNUM *a, BN_ULONG w);
VIGORTLS_EXPORT int BN_sub_word(BIGNUM *a, BN_ULONG w);
VIGORTLS_EXPORT int BN_set_word(BIGNUM *a, BN_ULONG w);
VIGORTLS_EXPORT BN_ULONG BN_get_word(const BIGNUM *a);

VIGORTLS_EXPORT int BN_cmp(const BIGNUM *a, const BIGNUM *b);
VIGORTLS_EXPORT void BN_free(BIGNUM *a);
VIGORTLS_EXPORT int BN_is_bit_set(const BIGNUM *a, int n);
VIGORTLS_EXPORT int BN_lshift(BIGNUM *r, const BIGNUM *a, int n);
VIGORTLS_EXPORT int BN_lshift1(BIGNUM *r, const BIGNUM *a);
VIGORTLS_EXPORT int BN_exp(BIGNUM *r, const BIGNUM *a, const BIGNUM *p,
                           BN_CTX *ctx);

VIGORTLS_EXPORT int BN_mod_exp(BIGNUM *r, const BIGNUM *a, const BIGNUM *p,
                               const BIGNUM *m, BN_CTX *ctx);
VIGORTLS_EXPORT int BN_mod_exp_mont(BIGNUM *r, const BIGNUM *a, const BIGNUM *p,
                                    const BIGNUM *m, BN_CTX *ctx,
                                    BN_MONT_CTX *m_ctx);
VIGORTLS_EXPORT int BN_mod_exp_mont_consttime(BIGNUM *rr, const BIGNUM *a,
                                              const BIGNUM *p, const BIGNUM *m,
                                              BN_CTX *ctx,
                                              BN_MONT_CTX *in_mont);
VIGORTLS_EXPORT int BN_mod_exp_mont_word(BIGNUM *r, BN_ULONG a, const BIGNUM *p,
                                         const BIGNUM *m, BN_CTX *ctx,
                                         BN_MONT_CTX *m_ctx);
VIGORTLS_EXPORT int BN_mod_exp2_mont(BIGNUM *r, const BIGNUM *a1,
                                     const BIGNUM *p1, const BIGNUM *a2,
                                     const BIGNUM *p2, const BIGNUM *m,
                                     BN_CTX *ctx, BN_MONT_CTX *m_ctx);
VIGORTLS_EXPORT int BN_mod_exp_simple(BIGNUM *r, const BIGNUM *a,
                                      const BIGNUM *p, const BIGNUM *m,
                                      BN_CTX *ctx);

VIGORTLS_EXPORT int BN_mask_bits(BIGNUM *a, int n);
VIGORTLS_EXPORT int BN_print_fp(FILE *fp, const BIGNUM *a);
VIGORTLS_EXPORT int BN_print(BIO *fp, const BIGNUM *a);
VIGORTLS_EXPORT int BN_reciprocal(BIGNUM *r, const BIGNUM *m, int len,
                                  BN_CTX *ctx);
VIGORTLS_EXPORT int BN_rshift(BIGNUM *r, const BIGNUM *a, int n);
VIGORTLS_EXPORT int BN_rshift1(BIGNUM *r, const BIGNUM *a);
VIGORTLS_EXPORT void BN_clear(BIGNUM *a);
VIGORTLS_EXPORT BIGNUM *BN_dup(const BIGNUM *a);
VIGORTLS_EXPORT int BN_ucmp(const BIGNUM *a, const BIGNUM *b);
VIGORTLS_EXPORT int BN_set_bit(BIGNUM *a, int n);
VIGORTLS_EXPORT int BN_clear_bit(BIGNUM *a, int n);
VIGORTLS_EXPORT char *BN_bn2hex(const BIGNUM *a);
VIGORTLS_EXPORT char *BN_bn2dec(const BIGNUM *a);
VIGORTLS_EXPORT int BN_hex2bn(BIGNUM **a, const char *str);
VIGORTLS_EXPORT int BN_dec2bn(BIGNUM **a, const char *str);
VIGORTLS_EXPORT int BN_asc2bn(BIGNUM **a, const char *str);
VIGORTLS_EXPORT int BN_gcd(BIGNUM *r, const BIGNUM *a, const BIGNUM *b,
                           BN_CTX *ctx);
VIGORTLS_EXPORT int BN_kronecker(const BIGNUM *a, const BIGNUM *b,
                                 BN_CTX *ctx); /* returns -2 for error */
VIGORTLS_EXPORT BIGNUM *BN_mod_inverse(BIGNUM *ret, const BIGNUM *a,
                                       const BIGNUM *n, BN_CTX *ctx);
VIGORTLS_EXPORT BIGNUM *BN_mod_sqrt(BIGNUM *ret, const BIGNUM *a,
                                    const BIGNUM *n, BN_CTX *ctx);

VIGORTLS_EXPORT void BN_consttime_swap(BN_ULONG swap, BIGNUM *a, BIGNUM *b,
                                       int nwords);

/* Deprecated versions */
#ifndef OPENSSL_NO_DEPRECATED
VIGORTLS_EXPORT BIGNUM *BN_generate_prime(BIGNUM *ret, int bits, int safe,
                                          const BIGNUM *add, const BIGNUM *rem,
                                          void (*callback)(int, int, void *),
                                          void *cb_arg);
VIGORTLS_EXPORT int BN_is_prime(const BIGNUM *p, int nchecks,
                                void (*callback)(int, int, void *), BN_CTX *ctx,
                                void *cb_arg);
VIGORTLS_EXPORT int BN_is_prime_fasttest(const BIGNUM *p, int nchecks,
                                         void (*callback)(int, int, void *),
                                         BN_CTX *ctx, void *cb_arg,
                                         int do_trial_division);
#endif /* !defined(OPENSSL_NO_DEPRECATED) */

/* Newer versions */
VIGORTLS_EXPORT int BN_generate_prime_ex(BIGNUM *ret, int bits, int safe,
                                         const BIGNUM *add, const BIGNUM *rem,
                                         BN_GENCB *cb);
VIGORTLS_EXPORT int BN_is_prime_ex(const BIGNUM *p, int nchecks, BN_CTX *ctx,
                                   BN_GENCB *cb);
VIGORTLS_EXPORT int BN_is_prime_fasttest_ex(const BIGNUM *p, int nchecks,
                                            BN_CTX *ctx, int do_trial_division,
                                            BN_GENCB *cb);

VIGORTLS_EXPORT int BN_X931_generate_Xpq(BIGNUM *Xp, BIGNUM *Xq, int nbits,
                                         BN_CTX *ctx);

VIGORTLS_EXPORT int BN_X931_derive_prime_ex(BIGNUM *p, BIGNUM *p1, BIGNUM *p2,
                                            const BIGNUM *Xp, const BIGNUM *Xp1,
                                            const BIGNUM *Xp2, const BIGNUM *e,
                                            BN_CTX *ctx, BN_GENCB *cb);
VIGORTLS_EXPORT int BN_X931_generate_prime_ex(BIGNUM *p, BIGNUM *p1, BIGNUM *p2,
                                              BIGNUM *Xp1, BIGNUM *Xp2,
                                              const BIGNUM *Xp, const BIGNUM *e,
                                              BN_CTX *ctx, BN_GENCB *cb);

VIGORTLS_EXPORT BN_MONT_CTX *BN_MONT_CTX_new(void);
VIGORTLS_EXPORT void BN_MONT_CTX_init(BN_MONT_CTX *ctx);
VIGORTLS_EXPORT int BN_mod_mul_montgomery(BIGNUM *r, const BIGNUM *a,
                                          const BIGNUM *b, BN_MONT_CTX *mont,
                                          BN_CTX *ctx);
#define BN_to_montgomery(r, a, mont, ctx) \
    BN_mod_mul_montgomery((r), (a), &((mont)->RR), (mont), (ctx))
VIGORTLS_EXPORT int BN_from_montgomery(BIGNUM *r, const BIGNUM *a,
                                       BN_MONT_CTX *mont, BN_CTX *ctx);
VIGORTLS_EXPORT void BN_MONT_CTX_free(BN_MONT_CTX *mont);
VIGORTLS_EXPORT int BN_MONT_CTX_set(BN_MONT_CTX *mont, const BIGNUM *mod,
                                    BN_CTX *ctx);
VIGORTLS_EXPORT BN_MONT_CTX *BN_MONT_CTX_copy(BN_MONT_CTX *to,
                                              BN_MONT_CTX *from);
VIGORTLS_EXPORT BN_MONT_CTX *BN_MONT_CTX_set_locked(BN_MONT_CTX **pmont,
                                                    CRYPTO_MUTEX *lock,
                                                    const BIGNUM *mod,
                                                    BN_CTX *ctx);

/* BN_BLINDING flags */
#define BN_BLINDING_NO_UPDATE   0x00000001
#define BN_BLINDING_NO_RECREATE 0x00000002

VIGORTLS_EXPORT BN_BLINDING *BN_BLINDING_new(const BIGNUM *A, const BIGNUM *Ai,
                                             BIGNUM *mod);
VIGORTLS_EXPORT void BN_BLINDING_free(BN_BLINDING *b);
VIGORTLS_EXPORT int BN_BLINDING_update(BN_BLINDING *b, BN_CTX *ctx);
VIGORTLS_EXPORT int BN_BLINDING_convert(BIGNUM *n, BN_BLINDING *b, BN_CTX *ctx);
VIGORTLS_EXPORT int BN_BLINDING_invert(BIGNUM *n, BN_BLINDING *b, BN_CTX *ctx);
VIGORTLS_EXPORT int BN_BLINDING_convert_ex(BIGNUM *n, BIGNUM *r, BN_BLINDING *b,
                                           BN_CTX *);
VIGORTLS_EXPORT int BN_BLINDING_invert_ex(BIGNUM *n, const BIGNUM *r,
                                          BN_BLINDING *b, BN_CTX *);
VIGORTLS_EXPORT int BN_BLINDING_is_current_thread(BN_BLINDING *b);
VIGORTLS_EXPORT void BN_BLINDING_set_current_thread(BN_BLINDING *b);
VIGORTLS_EXPORT int BN_BLINDING_lock(BN_BLINDING *b);
VIGORTLS_EXPORT int BN_BLINDING_unlock(BN_BLINDING *b);
VIGORTLS_EXPORT unsigned long BN_BLINDING_get_flags(const BN_BLINDING *);
VIGORTLS_EXPORT void BN_BLINDING_set_flags(BN_BLINDING *, unsigned long);
VIGORTLS_EXPORT BN_BLINDING *BN_BLINDING_create_param(
    BN_BLINDING *b, const BIGNUM *e, BIGNUM *m, BN_CTX *ctx,
    int (*bn_mod_exp)(BIGNUM *r, const BIGNUM *a, const BIGNUM *p,
                      const BIGNUM *m, BN_CTX *ctx, BN_MONT_CTX *m_ctx),
    BN_MONT_CTX *m_ctx);

#ifndef OPENSSL_NO_DEPRECATED
VIGORTLS_EXPORT void BN_set_params(int mul, int high, int low, int mont);
VIGORTLS_EXPORT int BN_get_params(int which); /* 0, mul, 1 high, 2 low, 3 mont */
#endif

VIGORTLS_EXPORT void BN_RECP_CTX_init(BN_RECP_CTX *recp);
VIGORTLS_EXPORT BN_RECP_CTX *BN_RECP_CTX_new(void);
VIGORTLS_EXPORT void BN_RECP_CTX_free(BN_RECP_CTX *recp);
VIGORTLS_EXPORT int BN_RECP_CTX_set(BN_RECP_CTX *recp, const BIGNUM *rdiv,
                                    BN_CTX *ctx);
VIGORTLS_EXPORT int BN_mod_mul_reciprocal(BIGNUM *r, const BIGNUM *x,
                                          const BIGNUM *y, BN_RECP_CTX *recp,
                                          BN_CTX *ctx);
VIGORTLS_EXPORT int BN_mod_exp_recp(BIGNUM *r, const BIGNUM *a, const BIGNUM *p,
                                    const BIGNUM *m, BN_CTX *ctx);
VIGORTLS_EXPORT int BN_div_recp(BIGNUM *dv, BIGNUM *rem, const BIGNUM *m,
                                BN_RECP_CTX *recp, BN_CTX *ctx);

#ifndef OPENSSL_NO_EC2M

/* Functions for arithmetic over binary polynomials represented by BIGNUMs.
 *
 * The BIGNUM::neg property of BIGNUMs representing binary polynomials is
 * ignored.
 *
 * Note that input arguments are not const so that their bit arrays can
 * be expanded to the appropriate size if needed.
 */

VIGORTLS_EXPORT int BN_GF2m_add(BIGNUM *r, const BIGNUM *a,
                                const BIGNUM *b); /*r = a + b*/
#define BN_GF2m_sub(r, a, b) BN_GF2m_add(r, a, b)
VIGORTLS_EXPORT int BN_GF2m_mod(BIGNUM *r, const BIGNUM *a,
                                const BIGNUM *p); /*r=a mod p*/
VIGORTLS_EXPORT int BN_GF2m_mod_mul(BIGNUM *r, const BIGNUM *a, const BIGNUM *b,
                                    const BIGNUM *p,
                                    BN_CTX *ctx); /* r = (a * b) mod p */
VIGORTLS_EXPORT int BN_GF2m_mod_sqr(BIGNUM *r, const BIGNUM *a, const BIGNUM *p,
                                    BN_CTX *ctx); /* r = (a * a) mod p */
VIGORTLS_EXPORT int BN_GF2m_mod_inv(BIGNUM *r, const BIGNUM *b, const BIGNUM *p,
                                    BN_CTX *ctx); /* r = (1 / b) mod p */
VIGORTLS_EXPORT int BN_GF2m_mod_div(BIGNUM *r, const BIGNUM *a, const BIGNUM *b,
                                    const BIGNUM *p,
                                    BN_CTX *ctx); /* r = (a / b) mod p */
VIGORTLS_EXPORT int BN_GF2m_mod_exp(BIGNUM *r, const BIGNUM *a, const BIGNUM *b,
                                    const BIGNUM *p,
                                    BN_CTX *ctx); /* r = (a ^ b) mod p */
VIGORTLS_EXPORT int BN_GF2m_mod_sqrt(BIGNUM *r, const BIGNUM *a,
                                     const BIGNUM *p,
                                     BN_CTX *ctx); /* r = sqrt(a) mod p */
VIGORTLS_EXPORT int BN_GF2m_mod_solve_quad(BIGNUM *r, const BIGNUM *a,
                                           const BIGNUM *p,
                                           BN_CTX *ctx); /* r^2 + r = a mod p */
#define BN_GF2m_cmp(a, b) BN_ucmp((a), (b))
/* Some functions allow for representation of the irreducible polynomials
 * as an unsigned int[], say p.  The irreducible f(t) is then of the form:
 *     t^p[0] + t^p[1] + ... + t^p[k]
 * where m = p[0] > p[1] > ... > p[k] = 0.
 */
VIGORTLS_EXPORT int BN_GF2m_mod_arr(BIGNUM *r, const BIGNUM *a, const int p[]);
/* r = a mod p */
VIGORTLS_EXPORT int BN_GF2m_mod_mul_arr(BIGNUM *r, const BIGNUM *a,
                                        const BIGNUM *b, const int p[],
                                        BN_CTX *ctx); /* r = (a * b) mod p */
VIGORTLS_EXPORT int BN_GF2m_mod_sqr_arr(BIGNUM *r, const BIGNUM *a,
                                        const int p[],
                                        BN_CTX *ctx); /* r = (a * a) mod p */
VIGORTLS_EXPORT int BN_GF2m_mod_inv_arr(BIGNUM *r, const BIGNUM *b,
                                        const int p[],
                                        BN_CTX *ctx); /* r = (1 / b) mod p */
VIGORTLS_EXPORT int BN_GF2m_mod_div_arr(BIGNUM *r, const BIGNUM *a,
                                        const BIGNUM *b, const int p[],
                                        BN_CTX *ctx); /* r = (a / b) mod p */
VIGORTLS_EXPORT int BN_GF2m_mod_exp_arr(BIGNUM *r, const BIGNUM *a,
                                        const BIGNUM *b, const int p[],
                                        BN_CTX *ctx); /* r = (a ^ b) mod p */
VIGORTLS_EXPORT int BN_GF2m_mod_sqrt_arr(BIGNUM *r, const BIGNUM *a,
                                         const int p[],
                                         BN_CTX *ctx); /* r = sqrt(a) mod p */
VIGORTLS_EXPORT int
BN_GF2m_mod_solve_quad_arr(BIGNUM *r, const BIGNUM *a, const int p[],
                           BN_CTX *ctx); /* r^2 + r = a mod p */
VIGORTLS_EXPORT int BN_GF2m_poly2arr(const BIGNUM *a, int p[], int max);
VIGORTLS_EXPORT int BN_GF2m_arr2poly(const int p[], BIGNUM *a);

#endif

/* faster mod functions for the 'NIST primes'
 * 0 <= a < p^2 */
VIGORTLS_EXPORT int BN_nist_mod_192(BIGNUM *r, const BIGNUM *a, const BIGNUM *p,
                                    BN_CTX *ctx);
VIGORTLS_EXPORT int BN_nist_mod_224(BIGNUM *r, const BIGNUM *a, const BIGNUM *p,
                                    BN_CTX *ctx);
VIGORTLS_EXPORT int BN_nist_mod_256(BIGNUM *r, const BIGNUM *a, const BIGNUM *p,
                                    BN_CTX *ctx);
VIGORTLS_EXPORT int BN_nist_mod_384(BIGNUM *r, const BIGNUM *a, const BIGNUM *p,
                                    BN_CTX *ctx);
VIGORTLS_EXPORT int BN_nist_mod_521(BIGNUM *r, const BIGNUM *a, const BIGNUM *p,
                                    BN_CTX *ctx);

VIGORTLS_EXPORT const BIGNUM *BN_get0_nist_prime_192(void);
VIGORTLS_EXPORT const BIGNUM *BN_get0_nist_prime_224(void);
VIGORTLS_EXPORT const BIGNUM *BN_get0_nist_prime_256(void);
VIGORTLS_EXPORT const BIGNUM *BN_get0_nist_prime_384(void);
VIGORTLS_EXPORT const BIGNUM *BN_get0_nist_prime_521(void);

/* library internal functions */

#define bn_expand(a, bits)                                   \
    (bits > (INT_MAX - BN_BITS2 + 1) ?                       \
         NULL :                                              \
         (((bits + BN_BITS2 - 1) / BN_BITS2) <= (a)->dmax) ? \
         (a) :                                               \
         bn_expand2((a), (bits + BN_BITS2 - 1) / BN_BITS2))
#define bn_wexpand(a, words) \
    (((words) <= (a)->dmax) ? (a) : bn_expand2((a), (words)))
VIGORTLS_EXPORT BIGNUM *bn_expand2(BIGNUM *a, int words);
#ifndef OPENSSL_NO_DEPRECATED
VIGORTLS_EXPORT BIGNUM *bn_dup_expand(const BIGNUM *a, int words); /* unused */
#endif

/* Bignum consistency macros
 * There is one "API" macro, bn_fix_top(), for stripping leading zeroes from
 * bignum data after direct manipulations on the data. There is also an
 * "internal" macro, bn_check_top(), for verifying that there are no leading
 * zeroes. Unfortunately, some auditing is required due to the fact that
 * bn_fix_top() has become an overabused duct-tape because bignum data is
 * occasionally passed around in an inconsistent state. So the following
 * changes have been made to sort this out;
 * - bn_fix_top()s implementation has been moved to bn_correct_top()
 * - if BN_DEBUG isn't defined, bn_fix_top() maps to bn_correct_top(), and
 *   bn_check_top() is as before.
 * - if BN_DEBUG *is* defined;
 *   - bn_check_top() tries to pollute unused words even if the bignum 'top' is
 *     consistent. (ed: only if BN_DEBUG_RAND is defined)
 *   - bn_fix_top() maps to bn_check_top() rather than "fixing" anything.
 * The idea is to have debug builds flag up inconsistent bignums when they
 * occur. If that occurs in a bn_fix_top(), we examine the code in question; if
 * the use of bn_fix_top() was appropriate (ie. it follows directly after code
 * that manipulates the bignum) it is converted to bn_correct_top(), and if it
 * was not appropriate, we convert it permanently to bn_check_top() and track
 * down the cause of the bug. Eventually, no internal code should be using the
 * bn_fix_top() macro. External applications and libraries should try this with
 * their own code too, both in terms of building against the openssl headers
 * with BN_DEBUG defined *and* linking with a version of OpenSSL built with it
 * defined. This not only improves external code, it provides more test
 * coverage for openssl's own code.
 */

#ifdef BN_DEBUG

/* We only need assert() when debugging */
#include <assert.h>

#ifdef BN_DEBUG_RAND
/* To avoid "make update" cvs wars due to BN_DEBUG, use some tricks */
#ifndef RAND_pseudo_bytes
VIGORTLS_EXPORT int RAND_pseudo_bytes(uint8_t *buf, int num);
#define BN_DEBUG_TRIX
#endif
#define bn_pollute(a)                                                \
    do {                                                             \
        const BIGNUM *_bnum1 = (a);                                  \
        if (_bnum1->top < _bnum1->dmax) {                            \
            uint8_t _tmp_char;                                       \
            /* We cast away const without the compiler knowing, any  \
             * *genuinely* constant variables that aren't mutable    \
             * wouldn't be constructed with top!=dmax. */            \
            BN_ULONG *_not_const;                                    \
            memcpy(&_not_const, &_bnum1->d, sizeof(BN_ULONG *));     \
            RAND_pseudo_bytes(&_tmp_char, 1);                        \
            memset((uint8_t *)(_not_const + _bnum1->top), _tmp_char, \
                   (_bnum1->dmax - _bnum1->top) * sizeof(BN_ULONG)); \
        }                                                            \
    } while (0)
#ifdef BN_DEBUG_TRIX
#undef RAND_pseudo_bytes
#endif
#else
#define bn_pollute(a)
#endif
#define bn_check_top(a)                                                      \
    do {                                                                     \
        const BIGNUM *_bnum2 = (a);                                          \
        if (_bnum2 != NULL) {                                                \
            assert((_bnum2->top == 0) || (_bnum2->d[_bnum2->top - 1] != 0)); \
            bn_pollute(_bnum2);                                              \
        }                                                                    \
    } while (0)

#define bn_fix_top(a) bn_check_top(a)

#define bn_check_size(bn, bits) \
    bn_wcheck_size(bn, ((bits + BN_BITS2 - 1)) / BN_BITS2)
#define bn_wcheck_size(bn, words)                                  \
    do {                                                           \
        const BIGNUM *_bnum2 = (bn);                               \
        assert(words <= (_bnum2)->dmax && words >= (_bnum2)->top); \
    } while (0)

#else /* !BN_DEBUG */

#define bn_pollute(a)
#define bn_check_top(a)
#define bn_fix_top(a) bn_correct_top(a)
#define bn_check_size(bn, bits)
#define bn_wcheck_size(bn, words)

#endif

#define bn_correct_top(a)                                              \
    {                                                                  \
        BN_ULONG *ftl;                                                 \
        int tmp_top = (a)->top;                                        \
        if (tmp_top > 0) {                                             \
            for (ftl = &((a)->d[tmp_top - 1]); tmp_top > 0; tmp_top--) \
                if (*(ftl--))                                          \
                    break;                                             \
            (a)->top = tmp_top;                                        \
        }                                                              \
        bn_pollute(a);                                                 \
    }

VIGORTLS_EXPORT BN_ULONG bn_mul_add_words(BN_ULONG *rp, const BN_ULONG *ap,
                                          int num, BN_ULONG w);
VIGORTLS_EXPORT BN_ULONG bn_mul_words(BN_ULONG *rp, const BN_ULONG *ap, int num,
                                      BN_ULONG w);
VIGORTLS_EXPORT void bn_sqr_words(BN_ULONG *rp, const BN_ULONG *ap, int num);
VIGORTLS_EXPORT BN_ULONG bn_div_words(BN_ULONG h, BN_ULONG l, BN_ULONG d);
VIGORTLS_EXPORT BN_ULONG bn_add_words(BN_ULONG *rp, const BN_ULONG *ap,
                                      const BN_ULONG *bp, int num);
VIGORTLS_EXPORT BN_ULONG bn_sub_words(BN_ULONG *rp, const BN_ULONG *ap,
                                      const BN_ULONG *bp, int num);

/* Primes from RFC 2409 */
VIGORTLS_EXPORT BIGNUM *get_rfc2409_prime_768(BIGNUM *bn);
VIGORTLS_EXPORT BIGNUM *get_rfc2409_prime_1024(BIGNUM *bn);

/* Primes from RFC 3526 */
VIGORTLS_EXPORT BIGNUM *get_rfc3526_prime_1536(BIGNUM *bn);
VIGORTLS_EXPORT BIGNUM *get_rfc3526_prime_2048(BIGNUM *bn);
VIGORTLS_EXPORT BIGNUM *get_rfc3526_prime_3072(BIGNUM *bn);
VIGORTLS_EXPORT BIGNUM *get_rfc3526_prime_4096(BIGNUM *bn);
VIGORTLS_EXPORT BIGNUM *get_rfc3526_prime_6144(BIGNUM *bn);
VIGORTLS_EXPORT BIGNUM *get_rfc3526_prime_8192(BIGNUM *bn);

VIGORTLS_EXPORT int BN_bntest_rand(BIGNUM *rnd, int bits, int top, int bottom);

/* BEGIN ERROR CODES */
/*
 * The following lines are auto generated by the script mkerr.pl. Any changes
 * made after this point may be overwritten when the script is next run.
 */
VIGORTLS_EXPORT void ERR_load_BN_strings(void);

/* Error codes for the BN functions. */

/* Function codes. */
# define BN_F_BNRAND                                      127
# define BN_F_BN_BLINDING_CONVERT_EX                      100
# define BN_F_BN_BLINDING_CREATE_PARAM                    128
# define BN_F_BN_BLINDING_INVERT_EX                       101
# define BN_F_BN_BLINDING_NEW                             102
# define BN_F_BN_BLINDING_UPDATE                          103
# define BN_F_BN_BN2DEC                                   104
# define BN_F_BN_BN2HEX                                   105
# define BN_F_BN_CTX_GET                                  116
# define BN_F_BN_CTX_NEW                                  106
# define BN_F_BN_CTX_START                                129
# define BN_F_BN_DIV                                      107
# define BN_F_BN_DIV_NO_BRANCH                            138
# define BN_F_BN_DIV_RECP                                 130
# define BN_F_BN_EXP                                      123
# define BN_F_BN_EXPAND2                                  108
# define BN_F_BN_EXPAND_INTERNAL                          120
# define BN_F_BN_GENERATE_PRIME_EX                        140
# define BN_F_BN_GF2M_MOD                                 131
# define BN_F_BN_GF2M_MOD_EXP                             132
# define BN_F_BN_GF2M_MOD_MUL                             133
# define BN_F_BN_GF2M_MOD_SOLVE_QUAD                      134
# define BN_F_BN_GF2M_MOD_SOLVE_QUAD_ARR                  135
# define BN_F_BN_GF2M_MOD_SQR                             136
# define BN_F_BN_GF2M_MOD_SQRT                            137
# define BN_F_BN_LSHIFT                                   145
# define BN_F_BN_MOD_EXP2_MONT                            118
# define BN_F_BN_MOD_EXP_MONT                             109
# define BN_F_BN_MOD_EXP_MONT_CONSTTIME                   124
# define BN_F_BN_MOD_EXP_MONT_WORD                        117
# define BN_F_BN_MOD_EXP_RECP                             125
# define BN_F_BN_MOD_EXP_SIMPLE                           126
# define BN_F_BN_MOD_INVERSE                              110
# define BN_F_BN_MOD_INVERSE_NO_BRANCH                    139
# define BN_F_BN_MOD_LSHIFT_QUICK                         119
# define BN_F_BN_MOD_MUL_RECIPROCAL                       111
# define BN_F_BN_MOD_SQRT                                 121
# define BN_F_BN_MPI2BN                                   112
# define BN_F_BN_NEW                                      113
# define BN_F_BN_RAND                                     114
# define BN_F_BN_RAND_RANGE                               122
# define BN_F_BN_RSHIFT                                   146
# define BN_F_BN_USUB                                     115

/* Reason codes. */
# define BN_R_ARG2_LT_ARG3                                100
# define BN_R_BAD_RECIPROCAL                              101
# define BN_R_BIGNUM_TOO_LONG                             114
# define BN_R_BITS_TOO_SMALL                              117
# define BN_R_CALLED_WITH_EVEN_MODULUS                    102
# define BN_R_DIV_BY_ZERO                                 103
# define BN_R_ENCODING_ERROR                              104
# define BN_R_EXPAND_ON_STATIC_BIGNUM_DATA                105
# define BN_R_INPUT_NOT_REDUCED                           110
# define BN_R_INVALID_LENGTH                              106
# define BN_R_INVALID_RANGE                               115
# define BN_R_INVALID_SHIFT                               119
# define BN_R_NOT_A_SQUARE                                111
# define BN_R_NOT_INITIALIZED                             107
# define BN_R_NO_INVERSE                                  108
# define BN_R_NO_SOLUTION                                 116
# define BN_R_P_IS_NOT_PRIME                              112
# define BN_R_TOO_MANY_ITERATIONS                         113
# define BN_R_TOO_MANY_TEMPORARY_VARIABLES                109

#ifdef  __cplusplus
}
#endif
#endif
