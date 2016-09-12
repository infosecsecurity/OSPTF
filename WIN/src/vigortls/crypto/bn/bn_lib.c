/*
 * Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef BN_DEBUG
#undef NDEBUG /* avoid conflicting definitions */
#define NDEBUG
#endif

#include <assert.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>

#include <openssl/err.h>
#include <stdcompat.h>

#include "bn_lcl.h"

const BIGNUM *BN_value_one(void)
{
    static const BN_ULONG data_one = 1L;
    static const BIGNUM const_one = {(BN_ULONG *)&data_one, 1, 1, 0, BN_FLG_STATIC_DATA };

    return (&const_one);
}

int BN_num_bits_word(BN_ULONG l)
{
    static const uint8_t bits[256] = {
        0, 1, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 4, 4, 4, 4,
        5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5,
        6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6,
        6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6,
        7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
        7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
        7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
        7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
        8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8,
        8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8,
        8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8,
        8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8,
        8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8,
        8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8,
        8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8,
        8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8,
    };

#if defined(VIGORTLS_64_BIT)
    if (l & 0xffffffff00000000L) {
        if (l & 0xffff000000000000L) {
            if (l & 0xff00000000000000L) {
                return (bits[(int)(l >> 56)] + 56);
            } else
                return (bits[(int)(l >> 48)] + 48);
        } else {
            if (l & 0x0000ff0000000000L) {
                return (bits[(int)(l >> 40)] + 40);
            } else
                return (bits[(int)(l >> 32)] + 32);
        }
    } else
#endif
    {
        if (l & 0xffff0000L) {
            if (l & 0xff000000L)
                return (bits[(int)(l >> 24L)] + 24);
            else
                return (bits[(int)(l >> 16L)] + 16);
        } else
        {
            if (l & 0xff00L)
                return (bits[(int)(l >> 8)] + 8);
            else
                return (bits[(int)(l)]);
        }
    }
}

int BN_num_bits(const BIGNUM *a)
{
    int i = a->top - 1;
    bn_check_top(a);

    if (BN_is_zero(a))
        return 0;
    return ((i * BN_BITS2) + BN_num_bits_word(a->d[i]));
}

void BN_clear_free(BIGNUM *a)
{
    int i;

    if (a == NULL)
        return;
    bn_check_top(a);
    if (a->d != NULL) {
        vigortls_zeroize(a->d, a->dmax * sizeof(a->d[0]));
        if (!(BN_get_flags(a, BN_FLG_STATIC_DATA)))
            free(a->d);
    }
    i = BN_get_flags(a, BN_FLG_MALLOCED);
    vigortls_zeroize(a, sizeof(BIGNUM));
    if (i)
        free(a);
}

void BN_free(BIGNUM *a)
{
    if (a == NULL)
        return;
    bn_check_top(a);
    if ((a->d != NULL) && !(BN_get_flags(a, BN_FLG_STATIC_DATA)))
        free(a->d);
    if (a->flags & BN_FLG_MALLOCED)
        free(a);
    else {
#ifndef OPENSSL_NO_DEPRECATED
        a->flags |= BN_FLG_FREE;
#endif
        a->d = NULL;
    }
}

void BN_init(BIGNUM *a)
{
    memset(a, 0, sizeof(BIGNUM));
    bn_check_top(a);
}

BIGNUM *BN_new(void)
{
    BIGNUM *ret;

    if ((ret = malloc(sizeof(BIGNUM))) == NULL) {
        BNerr(BN_F_BN_NEW, ERR_R_MALLOC_FAILURE);
        return (NULL);
    }
    ret->flags = BN_FLG_MALLOCED;
    ret->top = 0;
    ret->neg = 0;
    ret->dmax = 0;
    ret->d = NULL;
    bn_check_top(ret);
    return (ret);
}

/* This is used both by bn_expand2() and bn_dup_expand() */
/* The caller MUST check that words > b->dmax before calling this */
static BN_ULONG *bn_expand_internal(const BIGNUM *b, int words)
{
    BN_ULONG *A, *a = NULL;
    const BN_ULONG *B;
    int i;

    bn_check_top(b);

    if (words > (INT_MAX / (4 * BN_BITS2))) {
        BNerr(BN_F_BN_EXPAND_INTERNAL, BN_R_BIGNUM_TOO_LONG);
        return NULL;
    }
    if (BN_get_flags(b, BN_FLG_STATIC_DATA)) {
        BNerr(BN_F_BN_EXPAND_INTERNAL, BN_R_EXPAND_ON_STATIC_BIGNUM_DATA);
        return (NULL);
    }
    a = A = reallocarray(NULL, sizeof(BN_ULONG), words);
    if (A == NULL) {
        BNerr(BN_F_BN_EXPAND_INTERNAL, ERR_R_MALLOC_FAILURE);
        return (NULL);
    }
#if 1
    B = b->d;
    /* Check if the previous number needs to be copied */
    if (B != NULL) {
        for (i = b->top >> 2; i > 0; i--, A += 4, B += 4) {
            /*
             * The fact that the loop is unrolled
             * 4-wise is a tribute to Intel. It's
             * the one that doesn't have enough
             * registers to accomodate more data.
             * I'd unroll it 8-wise otherwise:-)
             *
             *        <appro@fy.chalmers.se>
             */
            BN_ULONG a0, a1, a2, a3;
            a0 = B[0];
            a1 = B[1];
            a2 = B[2];
            a3 = B[3];
            A[0] = a0;
            A[1] = a1;
            A[2] = a2;
            A[3] = a3;
        }
        switch (b->top & 3) {
            case 3:
                A[2] = B[2];
            case 2:
                A[1] = B[1];
            case 1:
                A[0] = B[0];
        }
    }

#else
    memset(A, 0, sizeof(BN_ULONG) * words);
    memcpy(A, b->d, sizeof(b->d[0]) * b->top);
#endif

    return (a);
}

/* This is an internal function that can be used instead of bn_expand2()
 * when there is a need to copy BIGNUMs instead of only expanding the
 * data part, while still expanding them.
 * Especially useful when needing to expand BIGNUMs that are declared
 * 'const' and should therefore not be changed.
 * The reason to use this instead of a BN_dup() followed by a bn_expand2()
 * is memory allocation overhead.  A BN_dup() followed by a bn_expand2()
 * will allocate new memory for the BIGNUM data twice, and free it once,
 * while bn_dup_expand() makes sure allocation is made only once.
 */

#ifndef OPENSSL_NO_DEPRECATED
BIGNUM *bn_dup_expand(const BIGNUM *b, int words)
{
    BIGNUM *r = NULL;

    bn_check_top(b);

    /* This function does not work if
     *      words <= b->dmax && top < words
     * because BN_dup() does not preserve 'dmax'!
     * (But bn_dup_expand() is not used anywhere yet.)
     */

    if (words > b->dmax) {
        BN_ULONG *a = bn_expand_internal(b, words);

        if (a) {
            r = BN_new();
            if (r) {
                r->top = b->top;
                r->dmax = words;
                r->neg = b->neg;
                r->d = a;
            } else {
                /* r == NULL, BN_new failure */
                free(a);
            }
        }
        /* If a == NULL, there was an error in allocation in
           bn_expand_internal(), and NULL should be returned */
    } else {
        r = BN_dup(b);
    }

    bn_check_top(r);
    return r;
}
#endif

/* This is an internal function that should not be used in applications.
 * It ensures that 'b' has enough room for a 'words' word number
 * and initialises any unused part of b->d with leading zeros.
 * It is mostly used by the various BIGNUM routines. If there is an error,
 * NULL is returned. If not, 'b' is returned. */

BIGNUM *bn_expand2(BIGNUM *b, int words)
{
    bn_check_top(b);

    if (words > b->dmax) {
        BN_ULONG *a = bn_expand_internal(b, words);
        if (!a)
            return NULL;
        if (b->d)
            free(b->d);
        b->d = a;
        b->dmax = words;
    }

    bn_check_top(b);
    return b;
}

BIGNUM *BN_dup(const BIGNUM *a)
{
    BIGNUM *t;

    if (a == NULL)
        return NULL;
    bn_check_top(a);

    t = BN_new();
    if (t == NULL)
        return NULL;
    if (!BN_copy(t, a)) {
        BN_free(t);
        return NULL;
    }
    bn_check_top(t);
    return t;
}

BIGNUM *BN_copy(BIGNUM *a, const BIGNUM *b)
{
    int i;
    BN_ULONG *A;
    const BN_ULONG *B;

    bn_check_top(b);

    if (a == b)
        return (a);
    if (bn_wexpand(a, b->top) == NULL)
        return (NULL);

#if 1
    A = a->d;
    B = b->d;
    for (i = b->top >> 2; i > 0; i--, A += 4, B += 4) {
        BN_ULONG a0, a1, a2, a3;
        a0 = B[0];
        a1 = B[1];
        a2 = B[2];
        a3 = B[3];
        A[0] = a0;
        A[1] = a1;
        A[2] = a2;
        A[3] = a3;
    }
    switch (b->top & 3) {
        case 3:
            A[2] = B[2];
        case 2:
            A[1] = B[1];
        case 1:
            A[0] = B[0];
    }
#else
    memcpy(a->d, b->d, sizeof(b->d[0]) * b->top);
#endif

    a->top = b->top;
    a->neg = b->neg;
    bn_check_top(a);
    return (a);
}

void BN_swap(BIGNUM *a, BIGNUM *b)
{
    int flags_old_a, flags_old_b;
    BN_ULONG *tmp_d;
    int tmp_top, tmp_dmax, tmp_neg;

    bn_check_top(a);
    bn_check_top(b);

    flags_old_a = a->flags;
    flags_old_b = b->flags;

    tmp_d = a->d;
    tmp_top = a->top;
    tmp_dmax = a->dmax;
    tmp_neg = a->neg;

    a->d = b->d;
    a->top = b->top;
    a->dmax = b->dmax;
    a->neg = b->neg;

    b->d = tmp_d;
    b->top = tmp_top;
    b->dmax = tmp_dmax;
    b->neg = tmp_neg;

    a->flags = (flags_old_a & BN_FLG_MALLOCED) | (flags_old_b & BN_FLG_STATIC_DATA);
    b->flags = (flags_old_b & BN_FLG_MALLOCED) | (flags_old_a & BN_FLG_STATIC_DATA);
    bn_check_top(a);
    bn_check_top(b);
}

void BN_clear(BIGNUM *a)
{
    if (a == NULL)
        return;
    bn_check_top(a);
    if (a->d != NULL)
        memset(a->d, 0, a->dmax * sizeof(a->d[0]));
    a->top = 0;
    a->neg = 0;
}

BN_ULONG BN_get_word(const BIGNUM *a)
{
    if (a->top > 1)
        return BN_MASK2;
    else if (a->top == 1)
        return a->d[0];
    /* a->top == 0 */
    return 0;
}

int BN_set_word(BIGNUM *a, BN_ULONG w)
{
    bn_check_top(a);
    if (bn_expand(a, (int)sizeof(BN_ULONG) * 8) == NULL)
        return (0);
    a->neg = 0;
    a->d[0] = w;
    a->top = (w ? 1 : 0);
    bn_check_top(a);
    return (1);
}

BIGNUM *BN_bin2bn(const uint8_t *s, int len, BIGNUM *ret)
{
    unsigned int i, m;
    unsigned int n;
    BN_ULONG l;
    BIGNUM *bn = NULL;

    if (ret == NULL)
        ret = bn = BN_new();
    if (ret == NULL)
        return (NULL);
    bn_check_top(ret);
    l = 0;
    n = len;
    if (n == 0) {
        ret->top = 0;
        return (ret);
    }
    i = ((n - 1) / BN_BYTES) + 1;
    m = ((n - 1) % (BN_BYTES));
    if (bn_wexpand(ret, (int)i) == NULL) {
        if (bn)
            BN_free(bn);
        return NULL;
    }
    ret->top = i;
    ret->neg = 0;
    while (n--) {
        l = (l << 8L) | *(s++);
        if (m-- == 0) {
            ret->d[--i] = l;
            l = 0;
            m = BN_BYTES - 1;
        }
    }
    /* need to call this due to clear byte at top if avoiding
     * having the top bit set (-ve number) */
    bn_correct_top(ret);
    return (ret);
}

/* ignore negative */
int BN_bn2bin(const BIGNUM *a, uint8_t *to)
{
    int n, i;
    BN_ULONG l;

    bn_check_top(a);
    n = i = BN_num_bytes(a);
    while (i--) {
        l = a->d[i / BN_BYTES];
        *(to++) = (uint8_t)(l >> (8 * (i % BN_BYTES))) & 0xff;
    }
    return (n);
}

int BN_ucmp(const BIGNUM *a, const BIGNUM *b)
{
    int i;
    BN_ULONG t1, t2, *ap, *bp;

    bn_check_top(a);
    bn_check_top(b);

    i = a->top - b->top;
    if (i != 0)
        return (i);
    ap = a->d;
    bp = b->d;
    for (i = a->top - 1; i >= 0; i--) {
        t1 = ap[i];
        t2 = bp[i];
        if (t1 != t2)
            return ((t1 > t2) ? 1 : -1);
    }
    return (0);
}

int BN_cmp(const BIGNUM *a, const BIGNUM *b)
{
    int i;
    int gt, lt;
    BN_ULONG t1, t2;

    if ((a == NULL) || (b == NULL)) {
        if (a != NULL)
            return (-1);
        else if (b != NULL)
            return (1);
        else
            return (0);
    }

    bn_check_top(a);
    bn_check_top(b);

    if (a->neg != b->neg) {
        if (a->neg)
            return (-1);
        else
            return (1);
    }
    if (a->neg == 0) {
        gt = 1;
        lt = -1;
    } else {
        gt = -1;
        lt = 1;
    }

    if (a->top > b->top)
        return (gt);
    if (a->top < b->top)
        return (lt);
    for (i = a->top - 1; i >= 0; i--) {
        t1 = a->d[i];
        t2 = b->d[i];
        if (t1 > t2)
            return (gt);
        if (t1 < t2)
            return (lt);
    }
    return (0);
}

int BN_set_bit(BIGNUM *a, int n)
{
    int i, j, k;

    if (n < 0)
        return 0;

    i = n / BN_BITS2;
    j = n % BN_BITS2;
    if (a->top <= i) {
        if (bn_wexpand(a, i + 1) == NULL)
            return (0);
        for (k = a->top; k < i + 1; k++)
            a->d[k] = 0;
        a->top = i + 1;
    }

    a->d[i] |= (((BN_ULONG)1) << j);
    bn_check_top(a);
    return (1);
}

int BN_clear_bit(BIGNUM *a, int n)
{
    int i, j;

    bn_check_top(a);
    if (n < 0)
        return 0;

    i = n / BN_BITS2;
    j = n % BN_BITS2;
    if (a->top <= i)
        return (0);

    a->d[i] &= (~(((BN_ULONG)1) << j));
    bn_correct_top(a);
    return (1);
}

int BN_is_bit_set(const BIGNUM *a, int n)
{
    int i, j;

    bn_check_top(a);
    if (n < 0)
        return 0;
    i = n / BN_BITS2;
    j = n % BN_BITS2;
    if (a->top <= i)
        return 0;
    return (int)(((a->d[i]) >> j) & ((BN_ULONG)1));
}

int BN_mask_bits(BIGNUM *a, int n)
{
    int b, w;

    bn_check_top(a);
    if (n < 0)
        return 0;

    w = n / BN_BITS2;
    b = n % BN_BITS2;
    if (w >= a->top)
        return 0;
    if (b == 0)
        a->top = w;
    else {
        a->top = w + 1;
        a->d[w] &= ~(BN_MASK2 << b);
    }
    bn_correct_top(a);
    return (1);
}

void BN_set_negative(BIGNUM *a, int b)
{
    if (b && !BN_is_zero(a))
        a->neg = 1;
    else
        a->neg = 0;
}

int bn_cmp_words(const BN_ULONG *a, const BN_ULONG *b, int n)
{
    int i;
    BN_ULONG aa, bb;

    aa = a[n - 1];
    bb = b[n - 1];
    if (aa != bb)
        return ((aa > bb) ? 1 : -1);
    for (i = n - 2; i >= 0; i--) {
        aa = a[i];
        bb = b[i];
        if (aa != bb)
            return ((aa > bb) ? 1 : -1);
    }
    return (0);
}

/* Here follows a specialised variants of bn_cmp_words().  It has the
   property of performing the operation on arrays of different sizes.
   The sizes of those arrays is expressed through cl, which is the
   common length ( basicall, min(len(a),len(b)) ), and dl, which is the
   delta between the two lengths, calculated as len(a)-len(b).
   All lengths are the number of BN_ULONGs...  */

int bn_cmp_part_words(const BN_ULONG *a, const BN_ULONG *b,
                      int cl, int dl)
{
    int n, i;
    n = cl - 1;

    if (dl < 0) {
        for (i = dl; i < 0; i++) {
            if (b[n - i] != 0)
                return -1; /* a < b */
        }
    }
    if (dl > 0) {
        for (i = dl; i > 0; i--) {
            if (a[n + i] != 0)
                return 1; /* a > b */
        }
    }
    return bn_cmp_words(a, b, cl);
}

/*
 * Constant-time conditional swap of a and b.
 * a and b are swapped if condition is not 0.  The code assumes that at most one bit of condition is set.
 * nwords is the number of words to swap.  The code assumes that at least nwords are allocated in both a and b,
 * and that no more than nwords are used by either a or b.
 * a and b cannot be the same number
 */
void BN_consttime_swap(BN_ULONG condition, BIGNUM *a, BIGNUM *b, int nwords)
{
    BN_ULONG t;
    int i;

    bn_wcheck_size(a, nwords);
    bn_wcheck_size(b, nwords);

    assert(a != b);
    assert((condition & (condition - 1)) == 0);
    assert(sizeof(BN_ULONG) >= sizeof(int));

    condition = ((condition - 1) >> (BN_BITS2 - 1)) - 1;

    t = (a->top ^ b->top) & condition;
    a->top ^= t;
    b->top ^= t;

#define BN_CONSTTIME_SWAP(ind)                   \
    do {                                         \
        t = (a->d[ind] ^ b->d[ind]) & condition; \
        a->d[ind] ^= t;                          \
        b->d[ind] ^= t;                          \
    } while (0)

    switch (nwords) {
        default:
            for (i = 10; i < nwords; i++)
                BN_CONSTTIME_SWAP(i);
        /* Fallthrough */
        case 10:
            BN_CONSTTIME_SWAP(9); /* Fallthrough */
        case 9:
            BN_CONSTTIME_SWAP(8); /* Fallthrough */
        case 8:
            BN_CONSTTIME_SWAP(7); /* Fallthrough */
        case 7:
            BN_CONSTTIME_SWAP(6); /* Fallthrough */
        case 6:
            BN_CONSTTIME_SWAP(5); /* Fallthrough */
        case 5:
            BN_CONSTTIME_SWAP(4); /* Fallthrough */
        case 4:
            BN_CONSTTIME_SWAP(3); /* Fallthrough */
        case 3:
            BN_CONSTTIME_SWAP(2); /* Fallthrough */
        case 2:
            BN_CONSTTIME_SWAP(1); /* Fallthrough */
        case 1:
            BN_CONSTTIME_SWAP(0);
    }
#undef BN_CONSTTIME_SWAP
}
