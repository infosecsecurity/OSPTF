/*
 * Copyright 1999-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * This is a generic 32 bit "collector" for message digest algorithms.
 * Whenever needed it collects input character stream into chunks of
 * 32 bit values and invokes a block function that performs actual hash
 * calculations.
 *
 * Porting guide.
 *
 * Obligatory macros:
 *
 * DATA_ORDER_IS_BIG_ENDIAN or DATA_ORDER_IS_LITTLE_ENDIAN
 *    this macro defines byte order of input stream.
 * HASH_CBLOCK
 *    size of a unit chunk HASH_BLOCK operates on.
 * HASH_LONG
 *    has to be at lest 32 bit wide, if it's wider, then
 *    HASH_LONG_LOG2 *has to* be defined along
 * HASH_CTX
 *    context structure that at least contains following
 *    members:
 *        typedef struct {
 *            ...
 *            HASH_LONG    Nl,Nh;
 *            either {
 *            HASH_LONG    data[HASH_LBLOCK];
 *            uint8_t    data[HASH_CBLOCK];
 *            };
 *            unsigned int    num;
 *            ...
 *            } HASH_CTX;
 *    data[] vector is expected to be zeroed upon first call to
 *    HASH_UPDATE.
 * HASH_UPDATE
 *    name of "Update" function, implemented here.
 * HASH_TRANSFORM
 *    name of "Transform" function, implemented here.
 * HASH_FINAL
 *    name of "Final" function, implemented here.
 * HASH_BLOCK_DATA_ORDER
 *    name of "block" function capable of treating *unaligned* input
 *    message in original (data) byte order, implemented externally.
 * HASH_MAKE_STRING
 *    macro convering context variables to an ASCII hash string.
 *
 * MD5 example:
 *
 *    #define DATA_ORDER_IS_LITTLE_ENDIAN
 *
 *    #define HASH_LONG        MD5_LONG
 *    #define HASH_LONG_LOG2        MD5_LONG_LOG2
 *    #define HASH_CTX        MD5_CTX
 *    #define HASH_CBLOCK        MD5_CBLOCK
 *    #define HASH_UPDATE        MD5_Update
 *    #define HASH_TRANSFORM        MD5_Transform
 *    #define HASH_FINAL        MD5_Final
 *    #define HASH_BLOCK_DATA_ORDER    md5_block_data_order
 *
 *                    <appro@fy.chalmers.se>
 */

#include <stdint.h>

#include <openssl/opensslconf.h>

#if !defined(DATA_ORDER_IS_BIG_ENDIAN) && !defined(DATA_ORDER_IS_LITTLE_ENDIAN)
#error "DATA_ORDER must be defined!"
#endif

#ifndef HASH_CBLOCK
#error "HASH_CBLOCK must be defined!"
#endif
#ifndef HASH_LONG
#error "HASH_LONG must be defined!"
#endif
#ifndef HASH_CTX
#error "HASH_CTX must be defined!"
#endif

#ifndef HASH_UPDATE
#error "HASH_UPDATE must be defined!"
#endif
#ifndef HASH_TRANSFORM
#error "HASH_TRANSFORM must be defined!"
#endif
#if !defined(HASH_FINAL) && !defined(HASH_NO_FINAL)
#error "HASH_FINAL or HASH_NO_FINAL must be defined!"
#endif

#ifndef HASH_BLOCK_DATA_ORDER
#error "HASH_BLOCK_DATA_ORDER must be defined!"
#endif

static inline uint32_t ROTATE(uint32_t a, unsigned int n)
{
    return ((a << n) | (a >> (32 - n)));
}

#if defined(DATA_ORDER_IS_BIG_ENDIAN)

#if defined(__GNUC__) && __GNUC__ >= 2 && !defined(OPENSSL_NO_ASM) && !defined(OPENSSL_NO_INLINE_ASM)
#if defined(VIGORTLS_X86) || defined(VIGORTLS_X86_64)
/*
 * This gives ~30-40% performance improvement in SHA-256 compiled
 * with gcc [on P4]. Well, first macro to be frank. We can pull
 * this trick on x86* platforms only, because these CPUs can fetch
 * unaligned data without raising an exception.
 */
#define HOST_c2l(c, l)                        \
({                                            \
    uint32_t r = *((const uint32_t *)(c));    \
    __asm__ ("bswapl %0" : "=r"(r) : "0"(r)); \
    (c) += 4;                                 \
    (l) = r;                                  \
})
#define HOST_l2c(l, c)                        \
({                                            \
    unsigned int r = (l);                     \
    __asm__ ("bswapl %0" : "=r"(r) : "0"(r)); \
    *((uint32_t *)(c)) = r;                   \
    (c) += 4;                                 \
})
#endif
#endif

#ifndef HOST_c2l
#define HOST_c2l(c, l)                       \
        l = (((uint32_t)(*((c)++))) <<  24), \
        l |= (((uint32_t)(*((c)++))) << 16), \
        l |= (((uint32_t)(*((c)++))) << 8 ), \
        l |= (((uint32_t)(*((c)++)))      )
#endif
#ifndef HOST_l2c
#define HOST_l2c(l, c)                            \
       (*((c)++) = (uint8_t)(((l) >> 24) & 0xff), \
        *((c)++) = (uint8_t)(((l) >> 16) & 0xff), \
        *((c)++) = (uint8_t)(((l) >> 8 ) & 0xff), \
        *((c)++) = (uint8_t)(((l)      ) & 0xff), \
        l)
#endif

#elif defined(DATA_ORDER_IS_LITTLE_ENDIAN)

#if defined(VIGORTLS_X86) || defined(VIGORTLS_X86_64)
#define HOST_c2l(c, l) ((l) = *((const uint32_t *)(c)), (c) += 4)
#define HOST_l2c(l, c) (*((uint32_t *)(c)) = (l), (c) += 4)
#endif

#ifndef HOST_c2l
#define HOST_c2l(c, l)                       \
        (l = (((uint32_t)(*((c)++)))      ), \
        l |= (((uint32_t)(*((c)++))) << 8 ), \
        l |= (((uint32_t)(*((c)++))) << 16), \
        l |= (((uint32_t)(*((c)++))) << 24))
#endif
#ifndef HOST_l2c
#define HOST_l2c(l, c)                            \
       (*((c)++) = (uint8_t)(((l)      ) & 0xff), \
        *((c)++) = (uint8_t)(((l) >> 8 ) & 0xff), \
        *((c)++) = (uint8_t)(((l) >> 16) & 0xff), \
        *((c)++) = (uint8_t)(((l) >> 24) & 0xff), \
        l)
#endif

#endif

/*
 * Time for some action:-)
 */

int HASH_UPDATE(HASH_CTX *ctx, const void *data_, size_t len)
{
    const uint8_t *data = data_;
    uint8_t *p;
    HASH_LONG l;
    size_t n;

    if (len == 0)
        return 1;

    l = (ctx->Nl + (((HASH_LONG)len) << 3)) & 0xffffffffUL;
    /* 95-05-24 eay Fixed a bug with the overflow handling, thanks to
     * Wei Dai <weidai@eskimo.com> for pointing it out. */
    if (l < ctx->Nl) /* overflow */
        ctx->Nh++;
    ctx->Nh += (HASH_LONG)(len >> 29); /* might cause compiler warning on 16-bit */
    ctx->Nl = l;

    n = ctx->num;
    if (n != 0) {
        p = (uint8_t *)ctx->data;

        if (len >= HASH_CBLOCK || len + n >= HASH_CBLOCK) {
            memcpy(p + n, data, HASH_CBLOCK - n);
            HASH_BLOCK_DATA_ORDER(ctx, p, 1);
            n = HASH_CBLOCK - n;
            data += n;
            len -= n;
            ctx->num = 0;
            memset(p, 0, HASH_CBLOCK); /* keep it zeroed */
        } else {
            memcpy(p + n, data, len);
            ctx->num += (unsigned int)len;
            return 1;
        }
    }

    n = len / HASH_CBLOCK;
    if (n > 0) {
        HASH_BLOCK_DATA_ORDER(ctx, data, n);
        n *= HASH_CBLOCK;
        data += n;
        len -= n;
    }

    if (len != 0) {
        p = (uint8_t *)ctx->data;
        ctx->num = (unsigned int)len;
        memcpy(p, data, len);
    }
    return 1;
}

void HASH_TRANSFORM(HASH_CTX *ctx, const uint8_t *data)
{
    HASH_BLOCK_DATA_ORDER(ctx, data, 1);
}

#ifndef HASH_NO_FINAL
int HASH_FINAL(uint8_t *md, HASH_CTX *ctx)
{
    uint8_t *p = (uint8_t *)ctx->data;
    size_t n = ctx->num;

    p[n] = 0x80; /* there is always room for one */
    n++;

    if (n > (HASH_CBLOCK - 8)) {
        memset(p + n, 0, HASH_CBLOCK - n);
        n = 0;
        HASH_BLOCK_DATA_ORDER(ctx, p, 1);
    }
    memset(p + n, 0, HASH_CBLOCK - 8 - n);

    p += HASH_CBLOCK - 8;
#if defined(DATA_ORDER_IS_BIG_ENDIAN)
    (void) HOST_l2c(ctx->Nh, p);
    (void) HOST_l2c(ctx->Nl, p);
#elif defined(DATA_ORDER_IS_LITTLE_ENDIAN)
    (void) HOST_l2c(ctx->Nl, p);
    (void) HOST_l2c(ctx->Nh, p);
#endif
    p -= HASH_CBLOCK;
    HASH_BLOCK_DATA_ORDER(ctx, p, 1);
    ctx->num = 0;
    memset(p, 0, HASH_CBLOCK);

#ifndef HASH_MAKE_STRING
#error "HASH_MAKE_STRING must be defined!"
#else
    HASH_MAKE_STRING(ctx, md);
#endif

    return 1;
}
#endif

#ifndef MD32_REG_T
#define MD32_REG_T int
#endif
