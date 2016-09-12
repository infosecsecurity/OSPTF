#ifndef HEADER_WHRLPOOL_H
#define HEADER_WHRLPOOL_H

#include <openssl/base.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define WHIRLPOOL_DIGEST_LENGTH (512 / 8)
#define WHIRLPOOL_BBLOCK 512
#define WHIRLPOOL_COUNTER (256 / 8)

typedef struct {
    union {
        uint8_t c[WHIRLPOOL_DIGEST_LENGTH];
        /* double q is here to ensure 64-bit alignment */
        double q[WHIRLPOOL_DIGEST_LENGTH / sizeof(double)];
    } H;
    uint8_t data[WHIRLPOOL_BBLOCK / 8];
    uint32_t bitoff;
    size_t bitlen[WHIRLPOOL_COUNTER / sizeof(size_t)];
} WHIRLPOOL_CTX;

VIGORTLS_EXPORT int WHIRLPOOL_Init(WHIRLPOOL_CTX *c);
VIGORTLS_EXPORT int WHIRLPOOL_Update(WHIRLPOOL_CTX *c, const void *inp,
                                     size_t bytes);
VIGORTLS_EXPORT void WHIRLPOOL_BitUpdate(WHIRLPOOL_CTX *c, const void *inp,
                                         size_t bits);
VIGORTLS_EXPORT int WHIRLPOOL_Final(uint8_t *md, WHIRLPOOL_CTX *c);
VIGORTLS_EXPORT uint8_t *WHIRLPOOL(const void *inp, size_t bytes, uint8_t *md);

#ifdef __cplusplus
}
#endif

#endif
