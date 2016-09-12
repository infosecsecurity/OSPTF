/*
 * Copyright 2010-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/modes.h>

#if defined(__arch64__)
#define U64(C) C##UL
#else
#define U64(C) C##ULL
#endif

#define STRICT_ALIGNMENT 1
#if defined(VIGORTLS_x86) || defined(VIGORTLS_X86_64)
#undef STRICT_ALIGNMENT
#endif

#if !defined(OPENSSL_NO_ASM)
#if defined(__GNUC__) && __GNUC__ >= 2
#if defined(VIGORTLS_X86_64)
#define BSWAP8(x)                         \
    ({                                    \
        uint64_t ret = (x);               \
        __asm__("bswapq %0" : "+r"(ret)); \
        ret;                              \
    })
#define BSWAP4(x)                         \
    ({                                    \
        uint32_t ret = (x);               \
        __asm__("bswapl %0" : "+r"(ret)); \
        ret;                              \
    })
#elif defined(VIGORTLS_X86)
#define BSWAP8(x)                                             \
    ({                                                        \
        uint32_t lo = (uint64_t)(x) >> 32, hi = (x);          \
        __asm__("bswapl %0; bswapl %1" : "+r"(hi), "+r"(lo)); \
        (uint64_t) hi << 32 | lo;                             \
    })
#define BSWAP4(x)                         \
    ({                                    \
        uint32_t ret = (x);               \
        __asm__("bswapl %0" : "+r"(ret)); \
        ret;                              \
    })
#elif defined(VIGORTLS_AARCH64)
#define BSWAP8(x)                                  \
    ({                                             \
        uint64_t ret;                              \
        __asm__("rev %0,%1" : "=r"(ret) : "r"(x)); \
        ret;                                       \
    })
#define BSWAP4(x)                                    \
    ({                                               \
        uint32_t ret;                                \
        __asm__("rev %w0,%w1" : "=r"(ret) : "r"(x)); \
        ret;                                         \
    })
#elif defined(VIGORTLS_ARM) && !defined(STRICT_ALIGNMENT)
#define BSWAP8(x)                                             \
    ({                                                        \
        uint32_t lo = (uint64_t)(x) >> 32, hi = (x);          \
        __asm__("rev %0,%0; rev %1,%1" : "+r"(hi), "+r"(lo)); \
        (uint64_t) hi << 32 | lo;                             \
    })
#define BSWAP4(x)                                              \
    ({                                                         \
        uint32_t ret;                                          \
        __asm__("rev %0,%1" : "=r"(ret) : "r"((uint32_t)(x))); \
        ret;                                                   \
    })
#endif
#elif defined(_MSC_VER)
#if _MSC_VER >= 1300
#pragma warning(push, 3)
#include <intrin.h>
#pragma warning(pop)
#pragma intrinsic(_byteswap_uint64, _byteswap_ulong)
#define BSWAP8(x) _byteswap_uint64((uint64_t)(x))
#define BSWAP4(x) _byteswap_ulong((uint32_t)(x))
#elif defined(VIGORTLS_X86)
__inline uint32_t _bswap4(uint32_t val)
{
    __asm mov eax, val __asm bswap eax
}
#define BSWAP4(x) _bswap4(x)
#endif
#endif
#endif

#if defined(BSWAP4) && !defined(STRICT_ALIGNMENT)
#define GETU32(p) BSWAP4(*(const uint32_t *)(p))
#define PUTU32(p, v) *(uint32_t *)(p) = BSWAP4(v)
#else
#define GETU32(p)                                                            \
    ((uint32_t)(p)[0] << 24 | (uint32_t)(p)[1] << 16 | (uint32_t)(p)[2] << 8 \
     | (uint32_t)(p)[3])
#define PUTU32(p, v)                                               \
    ((p)[0] = (uint8_t)((v) >> 24), (p)[1] = (uint8_t)((v) >> 16), \
     (p)[2] = (uint8_t)((v) >> 8), (p)[3] = (uint8_t)(v))
#endif

/* GCM definitions */

typedef struct {
    uint64_t hi, lo;
} u128;

struct gcm128_context {
    /* Following 6 names follow names in GCM specification */
    union {
        uint64_t u[2];
        uint32_t d[4];
        uint8_t c[16];
        size_t t[16 / sizeof(size_t)];
    } Yi, EKi, EK0, len, Xi, H;
    /* Relative position of Xi, H and pre-computed Htable is used
     * in some assembler modules, i.e. don't change the order! */
    u128 Htable[16];
    void (*gmult)(uint64_t Xi[2], const u128 Htable[16]);
    void (*ghash)(uint64_t Xi[2], const u128 Htable[16], const uint8_t *inp,
                  size_t len);
    unsigned int mres, ares;
    block128_f block;
    void *key;
};

struct xts128_context {
    void *key1, *key2;
    block128_f block1, block2;
};

struct ccm128_context {
    union {
        uint64_t u[2];
        uint8_t c[16];
    } nonce, cmac;
    uint64_t blocks;
    block128_f block;
    void *key;
};
