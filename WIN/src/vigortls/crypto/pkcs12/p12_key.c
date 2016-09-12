/*
 * Copyright 1999-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <string.h>

#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/pkcs12.h>

/* PKCS12 compatible key/IV generation */
#ifndef min
#define min(a, b) ((a) < (b) ? (a) : (b))
#endif

int PKCS12_key_gen_asc(const char *pass, int passlen, uint8_t *salt,
                       int saltlen, int id, int iter, int n, uint8_t *out,
                       const EVP_MD *md_type)
{
    int ret;
    uint8_t *unipass;
    int uniplen;

    if (!pass) {
        unipass = NULL;
        uniplen = 0;
    } else if (!OPENSSL_asc2uni(pass, passlen, &unipass, &uniplen)) {
        PKCS12err(PKCS12_F_PKCS12_KEY_GEN_ASC, ERR_R_MALLOC_FAILURE);
        return 0;
    }
    ret = PKCS12_key_gen_uni(unipass, uniplen, salt, saltlen,
                             id, iter, n, out, md_type);
    if (ret <= 0)
        return 0;
    if (unipass) {
        vigortls_zeroize(unipass, uniplen); /* Clear password from memory */
        free(unipass);
    }
    return ret;
}

int PKCS12_key_gen_uni(uint8_t *pass, int passlen, uint8_t *salt,
                       int saltlen, int id, int iter, int n, uint8_t *out,
                       const EVP_MD *md_type)
{
    uint8_t *B, *D, *I, *p, *Ai;
    int Slen, Plen, Ilen, Ijlen;
    int i, j, u, v;
    int ret = 0;
    BIGNUM *Ij, *Bpl1; /* These hold Ij and B + 1 */
    EVP_MD_CTX ctx;

    EVP_MD_CTX_init(&ctx);
    v = EVP_MD_block_size(md_type);
    u = EVP_MD_size(md_type);
    if (u < 0)
        return 0;
    D = malloc(v);
    Ai = malloc(u);
    B = malloc(v + 1);
    Slen = v * ((saltlen + v - 1) / v);
    if (passlen)
        Plen = v * ((passlen + v - 1) / v);
    else
        Plen = 0;
    Ilen = Slen + Plen;
    I = malloc(Ilen);
    Ij = BN_new();
    Bpl1 = BN_new();
    if (!D || !Ai || !B || !I || !Ij || !Bpl1)
        goto err;
    for (i = 0; i < v; i++)
        D[i] = id;
    p = I;
    for (i = 0; i < Slen; i++)
        *p++ = salt[i % saltlen];
    for (i = 0; i < Plen; i++)
        *p++ = pass[i % passlen];
    for (;;) {
        if (!EVP_DigestInit_ex(&ctx, md_type, NULL)
            || !EVP_DigestUpdate(&ctx, D, v)
            || !EVP_DigestUpdate(&ctx, I, Ilen)
            || !EVP_DigestFinal_ex(&ctx, Ai, NULL))
            goto err;
        for (j = 1; j < iter; j++) {
            if (!EVP_DigestInit_ex(&ctx, md_type, NULL)
                || !EVP_DigestUpdate(&ctx, Ai, u)
                || !EVP_DigestFinal_ex(&ctx, Ai, NULL))
                goto err;
        }
        memcpy(out, Ai, min(n, u));
        if (u >= n) {
            ret = 1;
            goto end;
        }
        n -= u;
        out += u;
        for (j = 0; j < v; j++)
            B[j] = Ai[j % u];
        /* Work out B + 1 first then can use B as tmp space */
        if (!BN_bin2bn(B, v, Bpl1))
            goto err;
        if (!BN_add_word(Bpl1, 1))
            goto err;
        for (j = 0; j < Ilen; j += v) {
            if (!BN_bin2bn(I + j, v, Ij))
                goto err;
            if (!BN_add(Ij, Ij, Bpl1))
                goto err;
            if (!BN_bn2bin(Ij, B))
                goto err;
            Ijlen = BN_num_bytes(Ij);
            /* If more than 2^(v*8) - 1 cut off MSB */
            if (Ijlen > v) {
                if (!BN_bn2bin(Ij, B))
                    goto err;
                memcpy(I + j, B + 1, v);
#ifndef PKCS12_BROKEN_KEYGEN
                /* If less than v bytes pad with zeroes */
            } else if (Ijlen < v) {
                memset(I + j, 0, v - Ijlen);
                if (!BN_bn2bin(Ij, I + j + v - Ijlen))
                    goto err;
#endif
            } else if (!BN_bn2bin(Ij, I + j))
                goto err;
        }
    }

err:
    PKCS12err(PKCS12_F_PKCS12_KEY_GEN_UNI, ERR_R_MALLOC_FAILURE);

end:
    free(Ai);
    free(B);
    free(D);
    free(I);
    BN_free(Ij);
    BN_free(Bpl1);
    EVP_MD_CTX_cleanup(&ctx);
    return ret;
}
