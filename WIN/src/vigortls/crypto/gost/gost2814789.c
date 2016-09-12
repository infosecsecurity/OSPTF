/*
 * Copyright (c) 2014 Dmitry Eremin-Solenikov <dbaryshkov@gmail.com>
 * Copyright (c) 2005-2006 Cryptocom LTD
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <string.h>

#include <openssl/opensslconf.h>

#ifndef OPENSSL_NO_GOST
#include <openssl/objects.h>
#include <openssl/gost.h>

#include "gost_locl.h"

static inline unsigned int f(const GOST2814789_KEY *c, unsigned int x)
{
    return c->k87[(x >> 24) & 255] | c->k65[(x >> 16) & 255]
           | c->k43[(x >> 8) & 255] | c->k21[(x)&255];
}

void Gost2814789_encrypt(const uint8_t *in, uint8_t *out,
                         const GOST2814789_KEY *key)
{
    unsigned int n1, n2; /* As named in the GOST */
    c2l(in, n1);
    c2l(in, n2);

    /* Instead of swapping halves, swap names each round */
    n2 ^= f(key, n1 + key->key[0]);
    n1 ^= f(key, n2 + key->key[1]);
    n2 ^= f(key, n1 + key->key[2]);
    n1 ^= f(key, n2 + key->key[3]);
    n2 ^= f(key, n1 + key->key[4]);
    n1 ^= f(key, n2 + key->key[5]);
    n2 ^= f(key, n1 + key->key[6]);
    n1 ^= f(key, n2 + key->key[7]);

    n2 ^= f(key, n1 + key->key[0]);
    n1 ^= f(key, n2 + key->key[1]);
    n2 ^= f(key, n1 + key->key[2]);
    n1 ^= f(key, n2 + key->key[3]);
    n2 ^= f(key, n1 + key->key[4]);
    n1 ^= f(key, n2 + key->key[5]);
    n2 ^= f(key, n1 + key->key[6]);
    n1 ^= f(key, n2 + key->key[7]);

    n2 ^= f(key, n1 + key->key[0]);
    n1 ^= f(key, n2 + key->key[1]);
    n2 ^= f(key, n1 + key->key[2]);
    n1 ^= f(key, n2 + key->key[3]);
    n2 ^= f(key, n1 + key->key[4]);
    n1 ^= f(key, n2 + key->key[5]);
    n2 ^= f(key, n1 + key->key[6]);
    n1 ^= f(key, n2 + key->key[7]);

    n2 ^= f(key, n1 + key->key[7]);
    n1 ^= f(key, n2 + key->key[6]);
    n2 ^= f(key, n1 + key->key[5]);
    n1 ^= f(key, n2 + key->key[4]);
    n2 ^= f(key, n1 + key->key[3]);
    n1 ^= f(key, n2 + key->key[2]);
    n2 ^= f(key, n1 + key->key[1]);
    n1 ^= f(key, n2 + key->key[0]);

    l2c(n2, out);
    l2c(n1, out);
}

void Gost2814789_decrypt(const uint8_t *in, uint8_t *out,
                         const GOST2814789_KEY *key)
{
    unsigned int n1, n2; /* As named in the GOST */
    c2l(in, n1);
    c2l(in, n2);

    /* Instead of swapping halves, swap names each round */
    n2 ^= f(key, n1 + key->key[0]);
    n1 ^= f(key, n2 + key->key[1]);
    n2 ^= f(key, n1 + key->key[2]);
    n1 ^= f(key, n2 + key->key[3]);
    n2 ^= f(key, n1 + key->key[4]);
    n1 ^= f(key, n2 + key->key[5]);
    n2 ^= f(key, n1 + key->key[6]);
    n1 ^= f(key, n2 + key->key[7]);

    n2 ^= f(key, n1 + key->key[7]);
    n1 ^= f(key, n2 + key->key[6]);
    n2 ^= f(key, n1 + key->key[5]);
    n1 ^= f(key, n2 + key->key[4]);
    n2 ^= f(key, n1 + key->key[3]);
    n1 ^= f(key, n2 + key->key[2]);
    n2 ^= f(key, n1 + key->key[1]);
    n1 ^= f(key, n2 + key->key[0]);

    n2 ^= f(key, n1 + key->key[7]);
    n1 ^= f(key, n2 + key->key[6]);
    n2 ^= f(key, n1 + key->key[5]);
    n1 ^= f(key, n2 + key->key[4]);
    n2 ^= f(key, n1 + key->key[3]);
    n1 ^= f(key, n2 + key->key[2]);
    n2 ^= f(key, n1 + key->key[1]);
    n1 ^= f(key, n2 + key->key[0]);

    n2 ^= f(key, n1 + key->key[7]);
    n1 ^= f(key, n2 + key->key[6]);
    n2 ^= f(key, n1 + key->key[5]);
    n1 ^= f(key, n2 + key->key[4]);
    n2 ^= f(key, n1 + key->key[3]);
    n1 ^= f(key, n2 + key->key[2]);
    n2 ^= f(key, n1 + key->key[1]);
    n1 ^= f(key, n2 + key->key[0]);

    l2c(n2, out);
    l2c(n1, out);
}

static void Gost2814789_mac(const uint8_t *in, uint8_t *mac,
                            GOST2814789_KEY *key)
{
    unsigned int n1, n2; /* As named in the GOST */
    uint8_t *p;
    int i;

    for (i = 0; i < 8; i++)
        mac[i] ^= in[i];

    p = mac;
    c2l(p, n1);
    c2l(p, n2);

    /* Instead of swapping halves, swap names each round */
    n2 ^= f(key, n1 + key->key[0]);
    n1 ^= f(key, n2 + key->key[1]);
    n2 ^= f(key, n1 + key->key[2]);
    n1 ^= f(key, n2 + key->key[3]);
    n2 ^= f(key, n1 + key->key[4]);
    n1 ^= f(key, n2 + key->key[5]);
    n2 ^= f(key, n1 + key->key[6]);
    n1 ^= f(key, n2 + key->key[7]);

    n2 ^= f(key, n1 + key->key[0]);
    n1 ^= f(key, n2 + key->key[1]);
    n2 ^= f(key, n1 + key->key[2]);
    n1 ^= f(key, n2 + key->key[3]);
    n2 ^= f(key, n1 + key->key[4]);
    n1 ^= f(key, n2 + key->key[5]);
    n2 ^= f(key, n1 + key->key[6]);
    n1 ^= f(key, n2 + key->key[7]);

    p = mac;
    l2c(n1, p);
    l2c(n2, p);
}

void Gost2814789_ecb_encrypt(const uint8_t *in, uint8_t *out,
                             GOST2814789_KEY *key, const int enc)
{
    if (key->key_meshing && key->count == 1024) {
        Gost2814789_cryptopro_key_mesh(key);
        key->count = 0;
    }

    if (enc)
        Gost2814789_encrypt(in, out, key);
    else
        Gost2814789_decrypt(in, out, key);
}

static inline void Gost2814789_encrypt_mesh(uint8_t *iv, GOST2814789_KEY *key)
{
    if (key->key_meshing && key->count == 1024) {
        Gost2814789_cryptopro_key_mesh(key);
        Gost2814789_encrypt(iv, iv, key);
        key->count = 0;
    }
    Gost2814789_encrypt(iv, iv, key);
    key->count += 8;
}

static inline void Gost2814789_mac_mesh(const uint8_t *data,
                                        uint8_t *mac, GOST2814789_KEY *key)
{
    if (key->key_meshing && key->count == 1024) {
        Gost2814789_cryptopro_key_mesh(key);
        key->count = 0;
    }
    Gost2814789_mac(data, mac, key);
    key->count += 8;
}

void Gost2814789_cfb64_encrypt(const uint8_t *in, uint8_t *out,
                               size_t len, GOST2814789_KEY *key,
                               uint8_t *ivec, int *num, const int enc)
{
    unsigned int n;
    size_t l = 0;

    OPENSSL_assert(in && out && key && ivec && num);

    n = *num;

    if (enc) {
#if !defined(OPENSSL_SMALL_FOOTPRINT)
        if (8 % sizeof(size_t) == 0)
            do { /* always true actually */
                while (n && len) {
                    *(out++) = ivec[n] ^= *(in++);
                    --len;
                    n = (n + 1) % 8;
                }
#ifdef __STRICT_ALIGNMENT
                if (((size_t)in | (size_t)out | (size_t)ivec) % sizeof(size_t) != 0)
                    break;
#endif
                while (len >= 8) {
                    Gost2814789_encrypt_mesh(ivec, key);
                    for (; n < 8; n += sizeof(size_t)) {
                        *(size_t *)(out + n) = *(size_t *)(ivec + n)
                            ^= *(size_t *)(in + n);
                    }
                    len -= 8;
                    out += 8;
                    in += 8;
                    n = 0;
                }
                if (len) {
                    Gost2814789_encrypt_mesh(ivec, key);
                    while (len--) {
                        out[n] = ivec[n] ^= in[n];
                        ++n;
                    }
                }
                *num = n;
                return;
            } while (0);
/* the rest would be commonly eliminated by x86* compiler */
#endif
        while (l < len) {
            if (n == 0) {
                Gost2814789_encrypt_mesh(ivec, key);
            }
            out[l] = ivec[n] ^= in[l];
            ++l;
            n = (n + 1) % 8;
        }
        *num = n;
    } else {
#if !defined(OPENSSL_SMALL_FOOTPRINT)
        if (8 % sizeof(size_t) == 0)
            do { /* always true actually */
                while (n && len) {
                    uint8_t c;
                    *(out++) = ivec[n] ^ (c = *(in++));
                    ivec[n] = c;
                    --len;
                    n = (n + 1) % 8;
                }
#ifdef __STRICT_ALIGNMENT
                if (((size_t)in | (size_t)out | (size_t)ivec) % sizeof(size_t) != 0)
                    break;
#endif
                while (len >= 8) {
                    Gost2814789_encrypt_mesh(ivec, key);
                    for (; n < 8; n += sizeof(size_t)) {
                        size_t t = *(size_t *)(in + n);
                        *(size_t *)(out + n) = *(size_t *)(ivec + n) ^ t;
                        *(size_t *)(ivec + n) = t;
                    }
                    len -= 8;
                    out += 8;
                    in += 8;
                    n = 0;
                }
                if (len) {
                    Gost2814789_encrypt_mesh(ivec, key);
                    while (len--) {
                        uint8_t c;
                        out[n] = ivec[n] ^ (c = in[n]);
                        ivec[n] = c;
                        ++n;
                    }
                }
                *num = n;
                return;
            } while (0);
/* the rest would be commonly eliminated by x86* compiler */
#endif
        while (l < len) {
            uint8_t c;
            if (n == 0) {
                Gost2814789_encrypt_mesh(ivec, key);
            }
            out[l] = ivec[n] ^ (c = in[l]);
            ivec[n] = c;
            ++l;
            n = (n + 1) % 8;
        }
        *num = n;
    }
}

static inline void Gost2814789_cnt_next(uint8_t *ivec, uint8_t *out,
                                        GOST2814789_KEY *key)
{
    uint8_t *p = ivec, *p2 = ivec;
    unsigned int val, val2;

    if (key->count == 0)
        Gost2814789_encrypt(ivec, ivec, key);

    if (key->key_meshing && key->count == 1024) {
        Gost2814789_cryptopro_key_mesh(key);
        Gost2814789_encrypt(ivec, ivec, key);
        key->count = 0;
    }

    c2l(p, val);
    val2 = val + 0x01010101;
    l2c(val2, p2);

    c2l(p, val);
    val2 = val + 0x01010104;
    if (val > val2) /* overflow */
        val2++;
    l2c(val2, p2);

    Gost2814789_encrypt(ivec, out, key);
    key->count += 8;
}

void Gost2814789_cnt_encrypt(const uint8_t *in, uint8_t *out,
                             size_t len, GOST2814789_KEY *key, uint8_t *ivec,
                             uint8_t *cnt_buf, int *num)
{
    unsigned int n;
    size_t l = 0;

    OPENSSL_assert(in && out && key && cnt_buf && num);

    n = *num;

#if !defined(OPENSSL_SMALL_FOOTPRINT)
    if (8 % sizeof(size_t) == 0)
        do { /* always true actually */
            while (n && len) {
                *(out++) = *(in++) ^ cnt_buf[n];
                --len;
                n = (n + 1) % 8;
            }

#ifdef __STRICT_ALIGNMENT
            if (((size_t)in | (size_t)out | (size_t)ivec) % sizeof(size_t) != 0)
                break;
#endif
            while (len >= 8) {
                Gost2814789_cnt_next(ivec, cnt_buf, key);
                for (; n < 8; n += sizeof(size_t))
                    *(size_t *)(out + n) = *(size_t *)(in + n)
                                           ^ *(size_t *)(cnt_buf + n);
                len -= 8;
                out += 8;
                in += 8;
                n = 0;
            }
            if (len) {
                Gost2814789_cnt_next(ivec, cnt_buf, key);
                while (len--) {
                    out[n] = in[n] ^ cnt_buf[n];
                    ++n;
                }
            }
            *num = n;
            return;
        } while (0);
/* the rest would be commonly eliminated by x86* compiler */
#endif
    while (l < len) {
        if (n == 0)
            Gost2814789_cnt_next(ivec, cnt_buf, key);
        out[l] = in[l] ^ cnt_buf[n];
        ++l;
        n = (n + 1) % 8;
    }

    *num = n;
}

int GOST2814789IMIT_Init(GOST2814789IMIT_CTX *c, int nid)
{
    c->Nl = c->Nh = c->num = 0;
    memset(c->mac, 0, 8);
    return Gost2814789_set_sbox(&c->cipher, nid);
}

static void GOST2814789IMIT_block_data_order(GOST2814789IMIT_CTX *ctx,
                                             const uint8_t *p, size_t num)
{
    int i;
    for (i = 0; i < num; i++) {
        Gost2814789_mac_mesh(p, ctx->mac, &ctx->cipher);
        p += 8;
    }
}

#define DATA_ORDER_IS_LITTLE_ENDIAN

#define HASH_CBLOCK GOST2814789IMIT_CBLOCK
#define HASH_LONG GOST2814789IMIT_LONG
#define HASH_CTX GOST2814789IMIT_CTX
#define HASH_UPDATE GOST2814789IMIT_Update
#define HASH_TRANSFORM GOST2814789IMIT_Transform
#define HASH_NO_FINAL 1
#define HASH_BLOCK_DATA_ORDER GOST2814789IMIT_block_data_order

#include "md32_common.h"

int GOST2814789IMIT_Final(uint8_t *md, GOST2814789IMIT_CTX *c)
{
    if (c->num) {
        memset(c->data + c->num, 0, 8 - c->num);
        Gost2814789_mac_mesh(c->data, c->mac, &c->cipher);
    }
    if (c->Nl <= 8 * 8 && c->Nl > 0 && c->Nh == 0) {
        memset(c->data, 0, 8);
        Gost2814789_mac_mesh(c->data, c->mac, &c->cipher);
    }
    memcpy(md, c->mac, 4);
    return 1;
}

uint8_t *GOST2814789IMIT(const uint8_t *d, size_t n, uint8_t *md,
                               int nid, const uint8_t *key,
                               const uint8_t *iv)
{
    GOST2814789IMIT_CTX c;
    static uint8_t m[GOST2814789IMIT_LENGTH];

    if (md == NULL)
        md = m;
    GOST2814789IMIT_Init(&c, nid);
    memcpy(c.mac, iv, 8);
    Gost2814789_set_key(&c.cipher, key, 256);
    GOST2814789IMIT_Update(&c, d, n);
    GOST2814789IMIT_Final(md, &c);
    OPENSSL_cleanse(&c, sizeof(c));
    return (md);
}

#endif
