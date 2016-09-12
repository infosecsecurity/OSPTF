/*
 * Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef HEADER_NEW_DES_H
#define HEADER_NEW_DES_H

#include <stdint.h>

#include <openssl/base.h>

#ifdef OPENSSL_NO_DES
#error DES is disabled.
#endif

#ifdef __cplusplus
extern "C" {
#endif

typedef uint8_t DES_cblock[8];
typedef /* const */ uint8_t const_DES_cblock[8];
/* With "const", gcc 2.8.1 on Solaris thinks that DES_cblock *
 * and const_DES_cblock * are incompatible pointer types. */

typedef struct DES_ks {
    union {
        DES_cblock cblock;
        /* make sure things are correct size on machines with
         * 8 byte longs */
        uint32_t deslong[2];
    } ks[16];
} DES_key_schedule;

#define DES_KEY_SZ (sizeof(DES_cblock))
#define DES_SCHEDULE_SZ (sizeof(DES_key_schedule))

#define DES_ENCRYPT 1
#define DES_DECRYPT 0

#define DES_CBC_MODE 0
#define DES_PCBC_MODE 1

#define DES_ede2_cbc_encrypt(i, o, l, k1, k2, iv, e) \
    DES_ede3_cbc_encrypt((i), (o), (l), (k1), (k2), (k1), (iv), (e))

VIGORTLS_EXPORT extern int DES_rw_mode; /* defaults to DES_PCBC_MODE */

VIGORTLS_EXPORT const char *DES_options(void);
VIGORTLS_EXPORT void DES_ecb3_encrypt(const_DES_cblock *input,
                                      DES_cblock *output, DES_key_schedule *ks1,
                                      DES_key_schedule *ks2,
                                      DES_key_schedule *ks3, int enc);
VIGORTLS_EXPORT void DES_ncbc_encrypt(const uint8_t *input, uint8_t *output,
                                      long length, DES_key_schedule *schedule,
                                      DES_cblock *ivec, int enc);
VIGORTLS_EXPORT void DES_ecb_encrypt(const_DES_cblock *input,
                                     DES_cblock *output, DES_key_schedule *ks,
                                     int enc);

/* This is the DES encryption function that gets called by just about
 * every other DES routine in the library.  You should not use this
 * function except to implement 'modes' of DES.  I say this because the
 * functions that call this routine do the conversion from 'char *' to
 * long, and this needs to be done to make sure 'non-aligned' memory
 * access do not occur.  The characters are loaded 'little endian'.
 * Data is a pointer to 2 unsigned long's and ks is the
 * DES_key_schedule to use.  enc, is non zero specifies encryption,
 * zero if decryption. */
VIGORTLS_EXPORT void DES_encrypt1(uint32_t *data, DES_key_schedule *ks,
                                  int enc);

/* This functions is the same as DES_encrypt1() except that the DES
 * initial permutation (IP) and final permutation (FP) have been left
 * out.  As for DES_encrypt1(), you should not use this function.
 * It is used by the routines in the library that implement triple DES.
 * IP() DES_encrypt2() DES_encrypt2() DES_encrypt2() FP() is the same
 * as DES_encrypt1() DES_encrypt1() DES_encrypt1() except faster :-). */
VIGORTLS_EXPORT void DES_encrypt2(uint32_t *data, DES_key_schedule *ks,
                                  int enc);

VIGORTLS_EXPORT void DES_encrypt3(uint32_t *data, DES_key_schedule *ks1,
                                  DES_key_schedule *ks2, DES_key_schedule *ks3);
VIGORTLS_EXPORT void DES_decrypt3(uint32_t *data, DES_key_schedule *ks1,
                                  DES_key_schedule *ks2, DES_key_schedule *ks3);
VIGORTLS_EXPORT void DES_ede3_cbc_encrypt(const uint8_t *input, uint8_t *output,
                                          long length, DES_key_schedule *ks1,
                                          DES_key_schedule *ks2,
                                          DES_key_schedule *ks3,
                                          DES_cblock *ivec, int enc);
VIGORTLS_EXPORT void DES_ede3_cfb64_encrypt(const uint8_t *in, uint8_t *out,
                                            long length, DES_key_schedule *ks1,
                                            DES_key_schedule *ks2,
                                            DES_key_schedule *ks3,
                                            DES_cblock *ivec, int *num,
                                            int enc);
VIGORTLS_EXPORT void
DES_ede3_cfb_encrypt(const uint8_t *in, uint8_t *out, int numbits, long length,
                     DES_key_schedule *ks1, DES_key_schedule *ks2,
                     DES_key_schedule *ks3, DES_cblock *ivec, int enc);
VIGORTLS_EXPORT void DES_set_odd_parity(DES_cblock *key);
VIGORTLS_EXPORT int DES_set_key(const_DES_cblock *key,
                                DES_key_schedule *schedule);
VIGORTLS_EXPORT int DES_key_sched(const_DES_cblock *key,
                                  DES_key_schedule *schedule);

#define DES_fixup_key_parity DES_set_odd_parity

#ifdef __cplusplus
}
#endif

#endif
