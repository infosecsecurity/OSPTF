/*
 * Copyright 2014-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef HEADER_CONSTANT_TIME_LOCL_H
#define HEADER_CONSTANT_TIME_LOCL_H

#ifdef __cplusplus
extern "C" {
#endif

/*
 * The boolean methods return a bitmask of all ones (0xff...f) for true
 * and 0 for false. This is useful for choosing a value based on the result
 * of a conditional in constant time. For example,
 *
 * if (a < b) {
 *   c = a;
 * } else {
 *   c = b;
 * }
 *
 * can be written as
 *
 * unsigned int lt = constant_time_lt(a, b);
 * c = constant_time_select(lt, a, b);
 */

/*
 * Returns the given value with the MSB copied to all the other
 * bits. Uses the fact that arithmetic shift shifts-in the sign bit.
 * However, this is not ensured by the C standard so you may need to
 * replace this with something else on odd CPUs.
 */
static inline unsigned int constant_time_msb(unsigned int a);

/*
 * Returns 0xff..f if a < b and 0 otherwise.
 */
static inline unsigned int constant_time_lt(unsigned int a, unsigned int b);
/* Convenience method for getting an 8-bit mask. */
static inline uint8_t constant_time_lt_8(unsigned int a, unsigned int b);

/*
 * Returns 0xff..f if a >= b and 0 otherwise.
 */
static inline unsigned int constant_time_ge(unsigned int a, unsigned int b);
/* Convenience method for getting an 8-bit mask. */
static inline uint8_t constant_time_ge_8(unsigned int a, unsigned int b);

/*
 * Returns 0xff..f if a == 0 and 0 otherwise.
 */
static inline unsigned int constant_time_is_zero(unsigned int a);
/* Convenience method for getting an 8-bit mask. */
static inline uint8_t constant_time_is_zero_8(unsigned int a);

/*
 * Returns 0xff..f if a == b and 0 otherwise.
 */
static inline unsigned int constant_time_eq(unsigned int a, unsigned int b);
/* Convenience method for getting an 8-bit mask. */
static inline uint8_t constant_time_eq_8(unsigned int a, unsigned int b);
/* Signed integers. */
static inline unsigned int constant_time_eq_int(int a, int b);
/* Convenience method for getting an 8-bit mask. */
static inline uint8_t constant_time_eq_int_8(int a, int b);

/*
 * Returns (mask & a) | (~mask & b).
 *
 * When |mask| is all 1s or all 0s (as returned by the methods above),
 * the select methods return either |a| (if |mask| is nonzero) or |b|
 * (if |mask| is zero).
 */
static inline unsigned int constant_time_select(unsigned int mask,
                                                unsigned int a, unsigned int b);
/* Convenience method for uint8_ts. */
static inline uint8_t constant_time_select_8(uint8_t mask,
                                                   uint8_t a, uint8_t b);
/* Convenience method for signed integers. */
static inline int constant_time_select_int(unsigned int mask, int a, int b);

static inline unsigned int constant_time_msb(unsigned int a)
{
    return 0 - (a >> (sizeof(a) * 8 - 1));
}

static inline unsigned int constant_time_lt(unsigned int a, unsigned int b)
{
    return constant_time_msb(a ^ ((a ^ b) | ((a - b) ^ b)));
}

static inline uint8_t constant_time_lt_8(unsigned int a, unsigned int b)
{
    return (uint8_t)(constant_time_lt(a, b));
}

static inline unsigned int constant_time_ge(unsigned int a, unsigned int b)
{
    return ~constant_time_lt(a, b);
}

static inline uint8_t constant_time_ge_8(unsigned int a, unsigned int b)
{
    return (uint8_t)(constant_time_ge(a, b));
}

static inline unsigned int constant_time_is_zero(unsigned int a)
{
    return constant_time_msb(~a & (a - 1));
}

static inline uint8_t constant_time_is_zero_8(unsigned int a)
{
    return (uint8_t)(constant_time_is_zero(a));
}

static inline unsigned int constant_time_eq(unsigned int a, unsigned int b)
{
    return constant_time_is_zero(a ^ b);
}

static inline uint8_t constant_time_eq_8(unsigned int a, unsigned int b)
{
    return (uint8_t)(constant_time_eq(a, b));
}

static inline unsigned int constant_time_eq_int(int a, int b)
{
    return constant_time_eq((unsigned)(a), (unsigned)(b));
}

static inline uint8_t constant_time_eq_int_8(int a, int b)
{
    return constant_time_eq_8((unsigned)(a), (unsigned)(b));
}

static inline unsigned int constant_time_select(unsigned int mask,
                                                unsigned int a, unsigned int b)
{
    return (mask & a) | (~mask & b);
}

static inline uint8_t constant_time_select_8(uint8_t mask,
                                                   uint8_t a, uint8_t b)
{
    return (uint8_t)(constant_time_select(mask, a, b));
}

static inline int constant_time_select_int(unsigned int mask, int a, int b)
{
    return (int)(constant_time_select(mask, (unsigned)(a), (unsigned)(b)));
}

#ifdef __cplusplus
}
#endif

#endif /* HEADER_CONSTANT_TIME_LOCL_H */
