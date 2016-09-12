/*
 * Copyright (c) 2016, Kurt Cancemi (kurt@x64architecture.com)
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
/*
 * Copyright 2015-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/opensslconf.h>

#ifndef OPENSSL_NO_POLY1305

#include <stdlib.h>
#include <string.h>

#include <openssl/poly1305.h>

#if !defined(OPENSSL_NO_ASM) &&                           \
    (defined(VIGORTLS_X86) || defined(VIGORTLS_X86_64) || \
     defined(VIGORTLS_ARM))

#define POLY1305_ASM
#endif

/* pick 32-bit unsigned int in little endian order */
static uint32_t U8TOU32(const uint8_t *p)
{
    return (((uint32_t)(p[0] & 0xff)      ) |
            ((uint32_t)(p[1] & 0xff) <<  8) |
            ((uint32_t)(p[2] & 0xff) << 16) |
            ((uint32_t)(p[3] & 0xff) << 24));
}

/*
 * Implementations can be classified by amount of significant bits in
 * words making up the multi-precision value, or in other words radix
 * or base of numerical representation, e.g. base 2^64, base 2^32,
 * base 2^26. Complementary characteristic is how wide is the result of
 * multiplication of pair of digits, e.g. it would take 128 bits to
 * accommodate multiplication result in base 2^64 case. These are used
 * interchangeably. To describe implementation that is. But interface
 * is designed to isolate this so that low-level primitives implemented
 * in assembly can be self-contained/self-coherent.
 */
#ifndef POLY1305_ASM
/*
 * Even though there is __int128 reference implementation targeting
 * 64-bit platforms provided below, it's not obvious that it's optimal
 * choice for every one of them. Depending on instruction set overall
 * amount of instructions can be comparable to one in __int64
 * implementation. Amount of multiplication instructions would be lower,
 * but not necessarily overall. And in out-of-order execution context,
 * it is the latter that can be crucial...
 *
 * On related note. Poly1305 author, D. J. Bernstein, discusses and
 * provides floating-point implementations of the algorithm in question.
 * It made a lot of sense by the time of introduction, because most
 * then-modern processors didn't have pipelined integer multiplier.
 * [Not to mention that some had non-constant timing for integer
 * multiplications.] Floating-point instructions on the other hand could
 * be issued every cycle, which allowed to achieve better performance.
 * Nowadays, with SIMD and/or out-or-order execution, shared or
 * even emulated FPU, it's more complicated, and floating-point
 * implementation is not necessarily optimal choice in every situation,
 * rather contrary...
 *
 *                                              <appro@openssl.org>
 */

/*
 * poly1305_blocks processes a multiple of POLY1305_BLOCK_SIZE blocks
 * of |inp| no longer than |len|. Behaviour for |len| not divisible by
 * block size is unspecified in general case, even though in reference
 * implementation the trailing chunk is simply ignored. Per algorithm
 * specification, every input block, complete or last partial, is to be
 * padded with a bit past most significant byte. The latter kind is then
 * padded with zeros till block size. This last partial block padding
 * is caller(*)'s responsibility, and because of this the last partial
 * block is always processed with separate call with |len| set to
 * POLY1305_BLOCK_SIZE and |padbit| to 0. In all other cases |padbit|
 * should be set to 1 to perform implicit padding with 128th bit.
 * poly1305_blocks does not actually check for this constraint though,
 * it's caller(*)'s resposibility to comply.
 *
 * (*)  In the context "caller" is not application code, but higher
 *      level Poly1305_* from this very module, so that quirks are
 *      handled locally.
 */
static void poly1305_blocks(void *ctx, const uint8_t *inp, size_t len,
                            uint32_t padbit);

/*
 * Type-agnostic "rip-off" from constant_time_locl.h
 */
#define CONSTANT_TIME_CARRY(a, b) \
    ((a ^ ((a ^ b) | ((a - b) ^ b))) >> (sizeof(a) * 8 - 1))

#if (defined(__SIZEOF_INT128__) && __SIZEOF_INT128__ == 16)

typedef unsigned __int128 u128;

typedef struct {
    uint64_t h[3];
    uint64_t r[2];
} poly1305_internal;

/* pick 32-bit uint32_teger in little endian order */
static uint64_t U8TOU64(const uint8_t *p)
{
    return (((uint64_t)(p[0] & 0xff)      ) | ((uint64_t)(p[1] & 0xff) <<  8) |
            ((uint64_t)(p[2] & 0xff) << 16) | ((uint64_t)(p[3] & 0xff) << 24) |
            ((uint64_t)(p[4] & 0xff) << 32) | ((uint64_t)(p[5] & 0xff) << 40) |
            ((uint64_t)(p[6] & 0xff) << 48) | ((uint64_t)(p[7] & 0xff) << 56));
}

/* store a 32-bit uint32_teger in little endian */
static void U64TO8(uint8_t *p, uint64_t v)
{
    p[0] = (uint8_t)((v      ) & 0xff);
    p[1] = (uint8_t)((v >>  8) & 0xff);
    p[2] = (uint8_t)((v >> 16) & 0xff);
    p[3] = (uint8_t)((v >> 24) & 0xff);
    p[4] = (uint8_t)((v >> 32) & 0xff);
    p[5] = (uint8_t)((v >> 40) & 0xff);
    p[6] = (uint8_t)((v >> 48) & 0xff);
    p[7] = (uint8_t)((v >> 56) & 0xff);
}

static void poly1305_init(void *ctx, const uint8_t key[16])
{
    poly1305_internal *st = (poly1305_internal *)ctx;

    /* h = 0 */
    st->h[0] = 0;
    st->h[1] = 0;
    st->h[2] = 0;

    /* r &= 0xffffffc0ffffffc0ffffffc0fffffff */
    st->r[0] = U8TOU64(&key[0]) & 0x0ffffffc0fffffff;
    st->r[1] = U8TOU64(&key[8]) & 0x0ffffffc0ffffffc;
}

static void poly1305_blocks(void *ctx, const uint8_t *inp, size_t len,
                            uint32_t padbit)
{
    poly1305_internal *st = (poly1305_internal *)ctx;
    uint64_t r0, r1;
    uint64_t s1;
    uint64_t h0, h1, h2, c;
    u128 d0, d1;

    r0 = st->r[0];
    r1 = st->r[1];

    s1 = r1 + (r1 >> 2);

    h0 = st->h[0];
    h1 = st->h[1];
    h2 = st->h[2];

    while (len >= POLY1305_BLOCK_SIZE) {
        /* h += m[i] */
        h0 = (uint64_t)(d0 = (u128)h0 + U8TOU64(inp + 0));
        h1 = (uint64_t)(d1 = (u128)h1 + (d0 >> 64) + U8TOU64(inp + 8));
        /*
         * padbit can be zero only when original len was
         * POLY1306_BLOCK_SIZE, but we don't check
         */
        h2 += (uint64_t)(d1 >> 64) + padbit;

        /* h *= r "%" p, where "%" stands for "partial remainder" */
        d0 = ((u128)h0 * r0) + ((u128)h1 * s1);
        d1 = ((u128)h0 * r1) + ((u128)h1 * r0) + (h2 * s1);
        h2 = (h2 * r0);

        /* last reduction step: */
        /* a) h2:h0 = h2<<128 + d1<<64 + d0 */
        h0 = (uint64_t)d0;
        h1 = (uint64_t)(d1 += d0 >> 64);
        h2 += (uint64_t)(d1 >> 64);
        /* b) (h2:h0 += (h2:h0>>130) * 5) %= 2^130 */
        c = (h2 >> 2) + (h2 & ~3UL);
        h2 &= 3;
        h0 += c;
        h1 += (c = CONSTANT_TIME_CARRY(h0, c)); /* doesn't overflow */

        inp += POLY1305_BLOCK_SIZE;
        len -= POLY1305_BLOCK_SIZE;
    }

    st->h[0] = h0;
    st->h[1] = h1;
    st->h[2] = h2;
}

static void poly1305_emit(void *ctx, uint8_t mac[16], const uint32_t nonce[4])
{
    poly1305_internal *st = (poly1305_internal *)ctx;
    uint64_t h0, h1, h2;
    uint64_t g0, g1, g2;
    u128 t;
    uint64_t mask;

    h0 = st->h[0];
    h1 = st->h[1];
    h2 = st->h[2];

    /* compute h + -p */
    g0 = (uint64_t)(t = (u128)h0 + 5);
    g1 = (uint64_t)(t = (u128)h1 + (t >> 64));
    g2 = h2 + (uint64_t)(t >> 64);

    /* if there was carry into 130th bit, h1:h0 = g1:g0 */
    mask = 0 - (g2 >> 2);
    g0 &= mask;
    g1 &= mask;
    mask = ~mask;
    h0 = (h0 & mask) | g0;
    h1 = (h1 & mask) | g1;

    /* mac = (h + nonce) % (2^128) */
    h0 = (uint64_t)(t = (u128)h0 + nonce[0] + ((uint64_t)nonce[1] << 32));
    h1 = (uint64_t)(t = (u128)h1 + nonce[2] + ((uint64_t)nonce[3] << 32) +
                        (t >> 64));

    U64TO8(mac + 0, h0);
    U64TO8(mac + 8, h1);
}

#else

typedef struct {
    uint32_t h[5];
    uint32_t r[4];
} poly1305_internal;

/* store a 32-bit unsigned intger in little endian */
static void U32TO8(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)((v      ) & 0xff);
    p[1] = (uint8_t)((v >>  8) & 0xff);
    p[2] = (uint8_t)((v >> 16) & 0xff);
    p[3] = (uint8_t)((v >> 24) & 0xff);
}

static void poly1305_init(void *ctx, const uint8_t key[16])
{
    poly1305_internal *st = (poly1305_internal *)ctx;

    /* h = 0 */
    st->h[0] = 0;
    st->h[1] = 0;
    st->h[2] = 0;
    st->h[3] = 0;
    st->h[4] = 0;

    /* r &= 0xffffffc0ffffffc0ffffffc0fffffff */
    st->r[0] = U8TOU32(&key[0]) & 0x0fffffff;
    st->r[1] = U8TOU32(&key[4]) & 0x0ffffffc;
    st->r[2] = U8TOU32(&key[8]) & 0x0ffffffc;
    st->r[3] = U8TOU32(&key[12]) & 0x0ffffffc;
}

static void poly1305_blocks(void *ctx, const uint8_t *inp, size_t len,
                            uint32_t padbit)
{
    poly1305_internal *st = (poly1305_internal *)ctx;
    uint32_t r0, r1, r2, r3;
    uint32_t s1, s2, s3;
    uint32_t h0, h1, h2, h3, h4, c;
    uint64_t d0, d1, d2, d3;

    r0 = st->r[0];
    r1 = st->r[1];
    r2 = st->r[2];
    r3 = st->r[3];

    s1 = r1 + (r1 >> 2);
    s2 = r2 + (r2 >> 2);
    s3 = r3 + (r3 >> 2);

    h0 = st->h[0];
    h1 = st->h[1];
    h2 = st->h[2];
    h3 = st->h[3];
    h4 = st->h[4];

    while (len >= POLY1305_BLOCK_SIZE) {
        /* h += m[i] */
        h0 = (uint32_t)(d0 = (uint64_t)h0 + U8TOU32(inp + 0));
        h1 = (uint32_t)(d1 = (uint64_t)h1 + (d0 >> 32) + U8TOU32(inp + 4));
        h2 = (uint32_t)(d2 = (uint64_t)h2 + (d1 >> 32) + U8TOU32(inp + 8));
        h3 = (uint32_t)(d3 = (uint64_t)h3 + (d2 >> 32) + U8TOU32(inp + 12));
        h4 += (uint32_t)(d3 >> 32) + padbit;

        /* h *= r "%" p, where "%" stands for "partial remainder" */
        d0 = ((uint64_t)h0 * r0) + ((uint64_t)h1 * s3) + ((uint64_t)h2 * s2) +
                ((uint64_t)h3 * s1);
        d1 = ((uint64_t)h0 * r1) + ((uint64_t)h1 * r0) + ((uint64_t)h2 * s3) +
                ((uint64_t)h3 * s2) + (h4 * s1);
        d2 = ((uint64_t)h0 * r2) + ((uint64_t)h1 * r1) + ((uint64_t)h2 * r0) +
                ((uint64_t)h3 * s3) + (h4 * s2);
        d3 = ((uint64_t)h0 * r3) + ((uint64_t)h1 * r2) + ((uint64_t)h2 * r1) +
                ((uint64_t)h3 * r0) + (h4 * s3);
        h4 = (h4 * r0);

        /* last reduction step: */
        /* a) h4:h0 = h4<<128 + d3<<96 + d2<<64 + d1<<32 + d0 */
        h0 = (uint32_t)d0;
        h1 = (uint32_t)(d1 += d0 >> 32);
        h2 = (uint32_t)(d2 += d1 >> 32);
        h3 = (uint32_t)(d3 += d2 >> 32);
        h4 += (uint32_t)(d3 >> 32);
        /* b) (h4:h0 += (h4:h0>>130) * 5) %= 2^130 */
        c = (h4 >> 2) + (h4 & ~3U);
        h4 &= 3;
        h0 += c;
        h1 += (c = CONSTANT_TIME_CARRY(h0, c));
        h2 += (c = CONSTANT_TIME_CARRY(h1, c));
        h3 += (c = CONSTANT_TIME_CARRY(h2, c)); /* doesn't overflow */

        inp += POLY1305_BLOCK_SIZE;
        len -= POLY1305_BLOCK_SIZE;
    }

    st->h[0] = h0;
    st->h[1] = h1;
    st->h[2] = h2;
    st->h[3] = h3;
    st->h[4] = h4;
}

static void poly1305_emit(void *ctx, uint8_t mac[16], const uint32_t nonce[4])
{
    poly1305_internal *st = (poly1305_internal *)ctx;
    uint32_t h0, h1, h2, h3, h4;
    uint32_t g0, g1, g2, g3, g4;
    uint64_t t;
    uint32_t mask;

    h0 = st->h[0];
    h1 = st->h[1];
    h2 = st->h[2];
    h3 = st->h[3];
    h4 = st->h[4];

    /* compute h + -p */
    g0 = (uint32_t)(t = (uint64_t)h0 + 5);
    g1 = (uint32_t)(t = (uint64_t)h1 + (t >> 32));
    g2 = (uint32_t)(t = (uint64_t)h2 + (t >> 32));
    g3 = (uint32_t)(t = (uint64_t)h3 + (t >> 32));
    g4 = h4 + (uint32_t)(t >> 32);

    /* if there was carry into 130th bit, h3:h0 = g3:g0 */
    mask = 0 - (g4 >> 2);
    g0 &= mask;
    g1 &= mask;
    g2 &= mask;
    g3 &= mask;
    mask = ~mask;
    h0 = (h0 & mask) | g0;
    h1 = (h1 & mask) | g1;
    h2 = (h2 & mask) | g2;
    h3 = (h3 & mask) | g3;

    /* mac = (h + nonce) % (2^128) */
    h0 = (uint32_t)(t = (uint64_t)h0 + nonce[0]);
    h1 = (uint32_t)(t = (uint64_t)h1 + (t >> 32) + nonce[1]);
    h2 = (uint32_t)(t = (uint64_t)h2 + (t >> 32) + nonce[2]);
    h3 = (uint32_t)(t = (uint64_t)h3 + (t >> 32) + nonce[3]);

    U32TO8(mac + 0, h0);
    U32TO8(mac + 4, h1);
    U32TO8(mac + 8, h2);
    U32TO8(mac + 12, h3);
}
#endif
#else
int poly1305_init(void *ctx, const uint8_t key[16], void *func);
void poly1305_blocks(void *ctx, const uint8_t *inp, size_t len,
                     uint32_t padbit);
void poly1305_emit(void *ctx, uint8_t mac[16], const uint32_t nonce[4]);
#endif

void CRYPTO_poly1305_init(poly1305_state *ctx, const uint8_t key[32])
{
    ctx->nonce[0] = U8TOU32(&key[16]);
    ctx->nonce[1] = U8TOU32(&key[20]);
    ctx->nonce[2] = U8TOU32(&key[24]);
    ctx->nonce[3] = U8TOU32(&key[28]);

#ifndef POLY1305_ASM
    poly1305_init(ctx->opaque, key);
#else
    /*
     * Unlike reference poly1305_init assembly counterpart is expected
     * to return a value: non-zero if it initializes ctx->func, and zero
     * otherwise. Latter is to simplify assembly in cases when there no
     * multiple code paths to switch between.
     */
    if (!poly1305_init(ctx->opaque, key, &ctx->func)) {
        ctx->func.blocks = poly1305_blocks;
        ctx->func.emit = poly1305_emit;
    }
#endif

    ctx->num = 0;
}

#ifdef POLY1305_ASM
/*
 * This "eclipses" poly1305_blocks and poly1305_emit, but it's
 * conscious choice imposed by -Wshadow compiler warnings.
 */
#define poly1305_blocks (*poly1305_blocks_p)
#define poly1305_emit (*poly1305_emit_p)
#endif

void CRYPTO_poly1305_update(poly1305_state *ctx, const uint8_t *inp, size_t len)
{
#ifdef POLY1305_ASM
    /*
     * As documented, poly1305_blocks is never called with input
     * longer than single block and padbit argument set to 0. This
     * property is fluently used in assembly modules to optimize
     * padbit handling on loop boundary.
     */
    poly1305_blocks_f poly1305_blocks_p = ctx->func.blocks;
#endif
    size_t rem, num;

    if ((num = ctx->num)) {
        rem = POLY1305_BLOCK_SIZE - num;
        if (len >= rem) {
            memcpy(ctx->data + num, inp, rem);
            poly1305_blocks(ctx->opaque, ctx->data, POLY1305_BLOCK_SIZE, 1);
            inp += rem;
            len -= rem;
        } else {
            /* Still not enough data to process a block. */
            memcpy(ctx->data + num, inp, len);
            ctx->num = num + len;
            return;
        }
    }

    rem = len % POLY1305_BLOCK_SIZE;
    len -= rem;

    if (len >= POLY1305_BLOCK_SIZE) {
        poly1305_blocks(ctx->opaque, inp, len, 1);
        inp += len;
    }

    if (rem)
        memcpy(ctx->data, inp, rem);

    ctx->num = rem;
}

void CRYPTO_poly1305_finish(poly1305_state *ctx, uint8_t mac[16])
{
#ifdef POLY1305_ASM
    poly1305_blocks_f poly1305_blocks_p = ctx->func.blocks;
    poly1305_emit_f poly1305_emit_p = ctx->func.emit;
#endif
    size_t num;

    if ((num = ctx->num)) {
        ctx->data[num++] = 1; /* pad bit */
        while (num < POLY1305_BLOCK_SIZE)
            ctx->data[num++] = 0;
        poly1305_blocks(ctx->opaque, ctx->data, POLY1305_BLOCK_SIZE, 0);
    }

    poly1305_emit(ctx->opaque, mac, ctx->nonce);

    /* zero out the state */
    memset(ctx, 0, sizeof(*ctx));
}

#endif
