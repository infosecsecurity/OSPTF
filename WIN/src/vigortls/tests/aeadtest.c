/*
 * Copyright 2011-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <openssl/evp.h>

/* This program tests an AEAD against a series of test vectors from a file. The
 * test vector file consists of key-value lines where the key and value are
 * separated by a colon and optional whitespace. The keys are listed in
 * |NAMES|, below. The values are hex-encoded data.
 *
 * After a number of key-value lines, a blank line or EOF indicates the end of
 * the test case.
 *
 * For example, here's a valid test case:
 *
 *   KEY: 5a19f3173586b4c42f8412f4d5a786531b3231753e9e00998aec12fda8df10e4
 *   NONCE: 978105dfce667bf4
 *   IN: 6a4583908d
 *   AD: b654574932
 *   CT: 5294265a60
 *   TAG: 1d45758621762e061368e68868e2f929
 */

#define BUF_MAX 1024

/* These are the different types of line that are found in the input file. */
enum {
    KEY = 0, /* hex encoded key. */
    NONCE,   /* hex encoded nonce. */
    IN,      /* hex encoded plaintext. */
    AD,      /* hex encoded additional data. */
    CT,      /* hex encoded ciphertext (not including the authenticator,
              * which is next. */
    TAG,     /* hex encoded authenticator. */
    NUM_TYPES,
};

static const char NAMES[6][NUM_TYPES] = {
    "KEY",
    "NONCE",
    "IN",
    "AD",
    "CT",
    "TAG",
};

static uint8_t hex_digit(char h)
{
    if (h >= '0' && h <= '9')
        return h - '0';
    else if (h >= 'a' && h <= 'f')
        return h - 'a' + 10;
    else if (h >= 'A' && h <= 'F')
        return h - 'A' + 10;
    else
        return 16;
}

static int run_test_case(const EVP_AEAD *aead,
                         uint8_t bufs[NUM_TYPES][BUF_MAX],
                         const unsigned int lengths[NUM_TYPES],
                         unsigned int line_no)
{
    EVP_AEAD_CTX ctx;
    uint8_t out[BUF_MAX + EVP_AEAD_MAX_TAG_LENGTH], out2[BUF_MAX];
    size_t out_len, out_len2;

    if (!EVP_AEAD_CTX_init(&ctx, aead, bufs[KEY], lengths[KEY],
                           lengths[TAG], NULL)) {
        fprintf(stderr, "Failed to init AEAD on line %u\n", line_no);
        return 0;
    }

    if (!EVP_AEAD_CTX_seal(&ctx, out, &out_len, sizeof(out), bufs[NONCE],
                           lengths[NONCE], bufs[IN], lengths[IN], bufs[AD], lengths[AD])) {
        fprintf(stderr, "Failed to run AEAD on line %u\n", line_no);
        return 0;
    }

    if (out_len != lengths[CT] + lengths[TAG]) {
        fprintf(stderr, "Bad output length on line %u: %zu vs %u\n",
                line_no, out_len, (unsigned)(lengths[CT] + lengths[TAG]));
        return 0;
    }

    if (memcmp(out, bufs[CT], lengths[CT]) != 0) {
        fprintf(stderr, "Bad output on line %u\n", line_no);
        return 0;
    }

    if (memcmp(out + lengths[CT], bufs[TAG], lengths[TAG]) != 0) {
        fprintf(stderr, "Bad tag on line %u\n", line_no);
        return 0;
    }

    if (!EVP_AEAD_CTX_open(&ctx, out2, &out_len2, lengths[IN], bufs[NONCE],
                           lengths[NONCE], out, out_len, bufs[AD], lengths[AD])) {
        fprintf(stderr, "Failed to decrypt on line %u\n", line_no);
        return 0;
    }

    if (out_len2 != lengths[IN]) {
        fprintf(stderr, "Bad decrypt on line %u: %zu\n",
                line_no, out_len2);
        return 0;
    }

    out[0] ^= 0x80;
    if (EVP_AEAD_CTX_open(&ctx, out2, &out_len2, lengths[IN], bufs[NONCE],
                          lengths[NONCE], out, out_len, bufs[AD], lengths[AD])) {
        fprintf(stderr, "Decrypted bad data on line %u\n", line_no);
        return 0;
    }

    EVP_AEAD_CTX_cleanup(&ctx);
    return 1;
}

int main(int argc, char **argv)
{
    FILE *fp;
    const EVP_AEAD *aead = NULL;
    unsigned int line_no = 0, num_tests = 0, j;

    uint8_t bufs[NUM_TYPES][BUF_MAX];
    unsigned int lengths[NUM_TYPES];

    if (argc != 3) {
        fprintf(stderr, "%s <aead> <test file.txt>\n", argv[0]);
        return 1;
    }

    if (strcmp(argv[1], "chacha20-poly1305") == 0) {
#if !defined(OPENSSL_NO_CHACHA) && !defined(OPENSSL_NO_POLY1305)
        aead = EVP_aead_chacha20_poly1305();
#else
        fprintf(stderr, "No chacha20-poly1305 support. Skipping test.\n");
        return 0;
#endif
    } else if (strcmp(argv[1], "chacha20-poly1305-old") == 0) {
#if !defined(OPENSSL_NO_CHACHA) && !defined(OPENSSL_NO_POLY1305)
        aead = EVP_aead_chacha20_poly1305_old();
#else
        fprintf(stderr, "No chacha20-poly1305 support. Skipping test.\n");
        return 0;
#endif
    } else if (strcmp(argv[1], "aes-128-gcm") == 0) {
        aead = EVP_aead_aes_128_gcm();
    } else if (strcmp(argv[1], "aes-256-gcm") == 0) {
        aead = EVP_aead_aes_256_gcm();
    } else {
        fprintf(stderr, "Unknown AEAD: %s\n", argv[1]);
        return 2;
    }

    fp = fopen(argv[2], "r");
    if (fp == NULL) {
        perror("failed to open input");
        return 1;
    }

    for (j = 0; j < NUM_TYPES; j++)
        lengths[j] = 0;

    for (;;) {
        char line[4096];
        unsigned int i, type_len = 0;

        uint8_t *buf = NULL;
        unsigned int *buf_len = NULL;

        if (!fgets(line, sizeof(line), fp))
            break;

        line_no++;
        if (line[0] == '#')
            continue;

        if (line[0] == '\n' || line[0] == 0) {
            /* Run a test, if possible. */
            char any_values_set = 0;
            for (j = 0; j < NUM_TYPES; j++) {
                if (lengths[j] != 0) {
                    any_values_set = 1;
                    break;
                }
            }

            if (!any_values_set)
                continue;

            if (!run_test_case(aead, bufs, lengths, line_no))
                return 4;

            for (j = 0; j < NUM_TYPES; j++)
                lengths[j] = 0;

            num_tests++;
            continue;
        }

        /* Each line looks like:
         *   TYPE: 0123abc
         * Where "TYPE" is the type of the data on the line,
         * e.g. "KEY". */
        for (i = 0; line[i] != 0 && line[i] != '\n'; i++) {
            if (line[i] == ':') {
                type_len = i;
                break;
            }
        }
        i++;

        if (type_len == 0) {
            fprintf(stderr, "Parse error on line %u\n",
                    line_no);
            return 3;
        }

        /* After the colon, there's optional whitespace. */
        for (; line[i] != 0 && line[i] != '\n'; i++) {
            if (line[i] != ' ' && line[i] != '\t')
                break;
        }

        line[type_len] = 0;
        for (j = 0; j < NUM_TYPES; j++) {
            if (strcmp(line, NAMES[j]) != 0)
                continue;
            if (lengths[j] != 0) {
                fprintf(stderr, "Duplicate value on line %u\n",
                        line_no);
                return 3;
            }
            buf = bufs[j];
            buf_len = &lengths[j];
        }

        if (buf == NULL) {
            fprintf(stderr, "Unknown line type on line %u\n",
                    line_no);
            return 3;
        }

        j = 0;
        for (; line[i] != 0 && line[i] != '\n'; i++) {
            uint8_t v, v2;
            v = hex_digit(line[i++]);
            if (line[i] == 0 || line[i] == '\n') {
                fprintf(stderr, "Odd-length hex data"
                                " on line %u\n",
                        line_no);
                return 3;
            }
            v2 = hex_digit(line[i]);
            if (v > 15 || v2 > 15) {
                fprintf(stderr, "Invalid hex char"
                                " on line %u\n",
                        line_no);
                return 3;
            }
            v <<= 4;
            v |= v2;

            if (j == BUF_MAX) {
                fprintf(stderr, "Too much hex data"
                                " on line %u (max is"
                                " %u bytes)\n",
                        line_no, (unsigned)BUF_MAX);
                return 3;
            }
            buf[j++] = v;
            *buf_len = *buf_len + 1;
        }
    }

    printf("Completed %u test cases\n", num_tests);
    printf("\x1b[32mPASS\x1b[0m\n");
    fclose(fp);

    return 0;
}
