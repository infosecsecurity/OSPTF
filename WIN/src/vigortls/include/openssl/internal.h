/*
 * Copyright (c) 2015, Kurt Cancemi (kurt@x64architecture.com)
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#ifndef VIGORTLS_HEADER_INTERNAL_H
#define VIGORTLS_HEADER_INTERNAL_H

#include <stdint.h>
#if !defined(__STDC_FORMAT_MACROS)
#define __STDC_FORMAT_MACROS
#endif
#include <inttypes.h>

#include <openssl/base.h>

/* BN_ULONG is the native word size when working with big integers. */
#if defined(VIGORTLS_64_BIT)
#define BN_ULONG uint64_t
#define BN_BITS2 64
#elif defined(VIGORTLS_32_BIT)
#define BN_ULONG uint32_t
#define BN_BITS2 32
#else
#error "Must define either VIGORTLS_32_BIT or VIGORTLS_64_BIT"
#endif

#if defined(VIGORTLS_64_BIT)

#if !defined(_MSC_VER)
/* MSVC doesn't support two-word integers on 64-bit. */
#define BN_LLONG __int128_t
#define BN_ULLONG __uint128_t
#endif

#define BN_BITS     128
#define BN_BITS2    64
#define BN_BYTES    8
#define BN_BITS4    32
#define BN_MASK     (0xffffffffffffffffffffffffffffffffLL)
#define BN_MASK2    (0xffffffffffffffffL)
#define BN_MASK2l   (0xffffffffL)
#define BN_MASK2h   (0xffffffff00000000L)
#define BN_MASK2h1  (0xffffffff80000000L)
#define BN_TBIT     (0x8000000000000000L)
#define BN_DEC_CONV (10000000000000000000UL)
#define BN_DEC_FMT1 "%" PRIu64
#define BN_DEC_FMT2 "%019" PRIu64
#define BN_DEC_NUM  19
#define BN_HEX_FMT1 "%" PRIx64

#elif defined(VIGORTLS_32_BIT)

#define BN_LLONG    int64_t
#define BN_ULLONG   uint64_t
#define BN_MASK     (0xffffffffffffffffLL)
#define BN_BITS     64
#define BN_BITS2    32
#define BN_BYTES    4
#define BN_BITS4    16
#define BN_MASK2    (0xffffffffL)
#define BN_MASK2l   (0xffff)
#define BN_MASK2h1  (0xffff8000L)
#define BN_MASK2h   (0xffff0000L)
#define BN_TBIT     (0x80000000L)
#define BN_DEC_CONV (1000000000L)
#define BN_DEC_FMT1 "%" PRIu32
#define BN_DEC_FMT2 "%09" PRIu32
#define BN_DEC_NUM  9
#define BN_HEX_FMT1 "%" PRIx32

#else
#error "Must define either VIGORTLS_32_BIT or VIGORTLS_64_BIT"
#endif

#if !defined(BN_LLONG)

#define LBITS(a) ((a)&BN_MASK2l)
#define HBITS(a) (((a) >> BN_BITS4) & BN_MASK2l)
#define L2HBITS(a) (((a) << BN_BITS4) & BN_MASK2)

#define LLBITS(a) ((a)&BN_MASKl)
#define LHBITS(a) (((a) >> BN_BITS2) & BN_MASKl)
#define LL2HBITS(a) ((BN_ULLONG)((a)&BN_MASKl) << BN_BITS2)

#define mul64(l, h, bl, bh)             \
    {                                   \
        BN_ULONG m, m1, lt, ht;         \
                                        \
        lt = l;                         \
        ht = h;                         \
        m  = (bh) * (lt);               \
        lt = (bl) * (lt);               \
        m1 = (bl) * (ht);               \
        ht = (bh) * (ht);               \
        m  = (m + m1) & BN_MASK2;       \
        if (m < m1)                     \
            ht += L2HBITS((BN_ULONG)1); \
        ht += HBITS(m);                 \
        m1 = L2HBITS(m);                \
        lt = (lt + m1) & BN_MASK2;      \
        if (lt < m1)                    \
            ht++;                       \
        (l) = lt;                       \
        (h) = ht;                       \
    }

#endif /* !defined(BN_LLONG) */

#endif /* VIGORTLS_HEADER_INTERNAL_H */
