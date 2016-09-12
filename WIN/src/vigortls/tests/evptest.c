/*
 * Copyright 2001-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <string.h>

#include <openssl/opensslconf.h>
#include <openssl/evp.h>
#ifndef OPENSSL_NO_ENGINE
#include <openssl/engine.h>
#endif
#include <openssl/err.h>
#include <openssl/conf.h>

static void hexdump(FILE *f, const char *title, const uint8_t *s, int l)
{
    int n = 0;

    fprintf(f, "%s", title);
    for (; n < l; ++n) {
        if ((n % 16) == 0)
            fprintf(f, "\n%04x", n);
        fprintf(f, " %02x", s[n]);
    }
    fprintf(f, "\n");
}

static int convert(uint8_t *s)
{
    uint8_t *d;

    for (d = s; *s; s += 2, ++d) {
        unsigned int n;

        if (!s[1]) {
            fprintf(stderr, "Odd number of hex digits!");
            exit(4);
        }
        if (!(sscanf((char *)s, "%2x", &n))) {
            fprintf(stderr, "sscanf failed!");
            exit(4);
        }
        *d = (uint8_t)n;
    }
    return s - d;
}

static char *sstrsep(char **string, const char *delim)
{
    char isdelim[256];
    char *token = *string;

    if (**string == 0)
        return NULL;

    memset(isdelim, 0, 256);
    isdelim[0] = 1;

    while (*delim) {
        isdelim[(uint8_t)(*delim)] = 1;
        delim++;
    }

    while (!isdelim[(uint8_t)(**string)]) {
        (*string)++;
    }

    if (**string) {
        **string = 0;
        (*string)++;
    }

    return token;
}

static uint8_t *ustrsep(char **p, const char *sep)
{
    return (uint8_t *)sstrsep(p, sep);
}

static int test1_exit(int ec)
{
    exit(ec);
    return (0); /* To keep some compilers quiet */
}

static void test1(const EVP_CIPHER *c, const uint8_t *key, int kn,
                  const uint8_t *iv, int in,
                  const uint8_t *plaintext, int pn,
                  const uint8_t *ciphertext, int cn,
                  const uint8_t *aad, int an,
                  const uint8_t *tag, int tn,
                  int encdec)
{
    EVP_CIPHER_CTX ctx;
    uint8_t out[4096];
    int outl, outl2, mode;

    printf("Testing cipher %s%s\n", EVP_CIPHER_name(c),
           (encdec == 1 ? "(encrypt)" : (encdec == 0 ? "(decrypt)" : "(encrypt/decrypt)")));
    hexdump(stdout, "Key", key, kn);
    if (in)
        hexdump(stdout, "IV", iv, in);
    hexdump(stdout, "Plaintext", plaintext, pn);
    hexdump(stdout, "Ciphertext", ciphertext, cn);

    if (an)
        hexdump(stdout, "AAD", aad, an);
    if (tn)
        hexdump(stdout, "Tag", tag, tn);
    mode = EVP_CIPHER_mode(c);

    if (kn != EVP_CIPHER_key_length(c)) {
        fprintf(stderr, "Key length doesn't match, got %d expected %lu\n", kn,
                (unsigned long)EVP_CIPHER_key_length(c));
        test1_exit(5);
    }
    EVP_CIPHER_CTX_init(&ctx);
    EVP_CIPHER_CTX_set_flags(&ctx, EVP_CIPHER_CTX_FLAG_WRAP_ALLOW);
    if (encdec != 0) {
        if (mode == EVP_CIPH_GCM_MODE) {
            if (!EVP_EncryptInit_ex(&ctx, c, NULL, NULL, NULL)) {
                fprintf(stderr, "EncryptInit failed\n");
                ERR_print_errors_fp(stderr);
                test1_exit(10);
            }
            if (!EVP_CIPHER_CTX_ctrl(&ctx, EVP_CTRL_GCM_SET_IVLEN, in, NULL)) {
                fprintf(stderr, "IV length set failed\n");
                ERR_print_errors_fp(stderr);
                test1_exit(11);
            }
            if (!EVP_EncryptInit_ex(&ctx, NULL, NULL, key, iv)) {
                fprintf(stderr, "Key/IV set failed\n");
                ERR_print_errors_fp(stderr);
                test1_exit(12);
            }
            if (an && !EVP_EncryptUpdate(&ctx, NULL, &outl, aad, an)) {
                fprintf(stderr, "AAD set failed\n");
                ERR_print_errors_fp(stderr);
                test1_exit(13);
            }
        } else if (mode == EVP_CIPH_CCM_MODE) {
            if (!EVP_EncryptInit_ex(&ctx, c, NULL, NULL, NULL)) {
                fprintf(stderr, "EncryptInit failed\n");
                ERR_print_errors_fp(stderr);
                test1_exit(10);
            }
            if (!EVP_CIPHER_CTX_ctrl(&ctx, EVP_CTRL_CCM_SET_IVLEN, in, NULL)) {
                fprintf(stderr, "IV length set failed\n");
                ERR_print_errors_fp(stderr);
                test1_exit(11);
            }
            if (!EVP_CIPHER_CTX_ctrl(&ctx, EVP_CTRL_CCM_SET_TAG, tn, NULL)) {
                fprintf(stderr, "Tag length set failed\n");
                ERR_print_errors_fp(stderr);
                test1_exit(11);
            }
            if (!EVP_EncryptInit_ex(&ctx, NULL, NULL, key, iv)) {
                fprintf(stderr, "Key/IV set failed\n");
                ERR_print_errors_fp(stderr);
                test1_exit(12);
            }
            if (!EVP_EncryptUpdate(&ctx, NULL, &outl, NULL, pn)) {
                fprintf(stderr, "Plaintext length set failed\n");
                ERR_print_errors_fp(stderr);
                test1_exit(12);
            }
            if (an && !EVP_EncryptUpdate(&ctx, NULL, &outl, aad, an)) {
                fprintf(stderr, "AAD set failed\n");
                ERR_print_errors_fp(stderr);
                test1_exit(13);
            }
        } else if (mode == EVP_CIPH_WRAP_MODE) {
            if (!EVP_EncryptInit_ex(&ctx, c, NULL, key, in ? iv : NULL)) {
                fprintf(stderr, "EncryptInit failed\n");
                ERR_print_errors_fp(stderr);
                test1_exit(10);
            }
        } else if (!EVP_EncryptInit_ex(&ctx, c, NULL, key, iv)) {
            fprintf(stderr, "EncryptInit failed\n");
            ERR_print_errors_fp(stderr);
            test1_exit(10);
        }
        EVP_CIPHER_CTX_set_padding(&ctx, 0);

        if (!EVP_EncryptUpdate(&ctx, out, &outl, plaintext, pn)) {
            fprintf(stderr, "Encrypt failed\n");
            ERR_print_errors_fp(stderr);
            test1_exit(6);
        }
        if (!EVP_EncryptFinal_ex(&ctx, out + outl, &outl2)) {
            fprintf(stderr, "EncryptFinal failed\n");
            ERR_print_errors_fp(stderr);
            test1_exit(7);
        }

        if (outl + outl2 != cn) {
            fprintf(stderr, "Ciphertext length mismatch got %d expected %d\n",
                    outl + outl2, cn);
            test1_exit(8);
        }

        if (memcmp(out, ciphertext, cn)) {
            fprintf(stderr, "Ciphertext mismatch\n");
            hexdump(stderr, "Got", out, cn);
            hexdump(stderr, "Expected", ciphertext, cn);
            test1_exit(9);
        }

        if (mode == EVP_CIPH_GCM_MODE || mode == EVP_CIPH_CCM_MODE) {
            uint8_t rtag[16];
            /*
             * Note: EVP_CTRL_CCM_GET_TAG has same value as
             * EVP_CTRL_GCM_GET_TAG
             */
            if (!EVP_CIPHER_CTX_ctrl(&ctx, EVP_CTRL_GCM_GET_TAG, tn, rtag)) {
                fprintf(stderr, "Get tag failed\n");
                ERR_print_errors_fp(stderr);
                test1_exit(14);
            }
            if (memcmp(rtag, tag, tn)) {
                fprintf(stderr, "Tag mismatch\n");
                hexdump(stderr, "Got", rtag, tn);
                hexdump(stderr, "Expected", tag, tn);
                test1_exit(9);
            }
        }
    }

    if (encdec <= 0) {
        if (mode == EVP_CIPH_GCM_MODE) {
            if (!EVP_DecryptInit_ex(&ctx, c, NULL, NULL, NULL)) {
                fprintf(stderr, "EncryptInit failed\n");
                ERR_print_errors_fp(stderr);
                test1_exit(10);
            }
            if (!EVP_CIPHER_CTX_ctrl(&ctx, EVP_CTRL_GCM_SET_IVLEN, in, NULL)) {
                fprintf(stderr, "IV length set failed\n");
                ERR_print_errors_fp(stderr);
                test1_exit(11);
            }
            if (!EVP_DecryptInit_ex(&ctx, NULL, NULL, key, iv)) {
                fprintf(stderr, "Key/IV set failed\n");
                ERR_print_errors_fp(stderr);
                test1_exit(12);
            }
            if (!EVP_CIPHER_CTX_ctrl(&ctx, EVP_CTRL_GCM_SET_TAG, tn, (void *)tag)) {
                fprintf(stderr, "Set tag failed\n");
                ERR_print_errors_fp(stderr);
                test1_exit(14);
            }
            if (an && !EVP_DecryptUpdate(&ctx, NULL, &outl, aad, an)) {
                fprintf(stderr, "AAD set failed\n");
                ERR_print_errors_fp(stderr);
                test1_exit(13);
            }
        } else if (mode == EVP_CIPH_CCM_MODE) {
            if (!EVP_DecryptInit_ex(&ctx, c, NULL, NULL, NULL)) {
                fprintf(stderr, "DecryptInit failed\n");
                ERR_print_errors_fp(stderr);
                test1_exit(10);
            }
            if (!EVP_CIPHER_CTX_ctrl(&ctx, EVP_CTRL_CCM_SET_IVLEN, in, NULL)) {
                fprintf(stderr, "IV length set failed\n");
                ERR_print_errors_fp(stderr);
                test1_exit(11);
            }
            if (!EVP_CIPHER_CTX_ctrl(&ctx, EVP_CTRL_CCM_SET_TAG, tn, (void *)tag)) {
                fprintf(stderr, "Tag length set failed\n");
                ERR_print_errors_fp(stderr);
                test1_exit(11);
            }
            if (!EVP_DecryptInit_ex(&ctx, NULL, NULL, key, iv)) {
                fprintf(stderr, "Key/Nonce set failed\n");
                ERR_print_errors_fp(stderr);
                test1_exit(12);
            }
            if (!EVP_DecryptUpdate(&ctx, NULL, &outl, NULL, pn)) {
                fprintf(stderr, "Plaintext length set failed\n");
                ERR_print_errors_fp(stderr);
                test1_exit(12);
            }
            if (an && !EVP_EncryptUpdate(&ctx, NULL, &outl, aad, an)) {
                fprintf(stderr, "AAD set failed\n");
                ERR_print_errors_fp(stderr);
                test1_exit(13);
            }
        } else if (mode == EVP_CIPH_WRAP_MODE) {
            if (!EVP_DecryptInit_ex(&ctx, c, NULL, key, in ? iv : NULL)) {
                fprintf(stderr, "EncryptInit failed\n");
                ERR_print_errors_fp(stderr);
                test1_exit(10);
            }
        } else if (!EVP_DecryptInit_ex(&ctx, c, NULL, key, iv)) {
            fprintf(stderr, "DecryptInit failed\n");
            ERR_print_errors_fp(stderr);
            test1_exit(11);
        }
        EVP_CIPHER_CTX_set_padding(&ctx, 0);

        if (!EVP_DecryptUpdate(&ctx, out, &outl, ciphertext, cn)) {
            fprintf(stderr, "Decrypt failed\n");
            ERR_print_errors_fp(stderr);
            test1_exit(6);
        }
        if (mode != EVP_CIPH_CCM_MODE && !EVP_DecryptFinal_ex(&ctx, out + outl, &outl2)) {
            fprintf(stderr, "DecryptFinal failed\n");
            ERR_print_errors_fp(stderr);
            test1_exit(7);
        }

        if (outl + outl2 != pn) {
            fprintf(stderr, "Plaintext length mismatch got %d expected %d\n",
                    outl + outl2, pn);
            test1_exit(8);
        }

        if (memcmp(out, plaintext, pn)) {
            fprintf(stderr, "Plaintext mismatch\n");
            hexdump(stderr, "Got", out, pn);
            hexdump(stderr, "Expected", plaintext, pn);
            test1_exit(9);
        }
    }

    EVP_CIPHER_CTX_cleanup(&ctx);

    printf("\n");
}

static int test_cipher(const char *cipher, const uint8_t *key, int kn,
                       const uint8_t *iv, int in,
                       const uint8_t *plaintext, int pn,
                       const uint8_t *ciphertext, int cn,
                       const uint8_t *aad, int an,
                       const uint8_t *tag,int tn,
                       int encdec)
{
    const EVP_CIPHER *c;

    c = EVP_get_cipherbyname(cipher);
    if (!c)
        return 0;

    test1(c, key, kn, iv, in, plaintext, pn, ciphertext, cn, aad, an, tag, tn, encdec);

    return 1;
}

static int test_digest(const char *digest,
                       const uint8_t *plaintext, int pn,
                       const uint8_t *ciphertext, unsigned int cn)
{
    const EVP_MD *d;
    EVP_MD_CTX ctx;
    uint8_t md[EVP_MAX_MD_SIZE];
    unsigned int mdn;

    d = EVP_get_digestbyname(digest);
    if (!d)
        return 0;

    printf("Testing digest %s\n", EVP_MD_name(d));
    hexdump(stdout, "Plaintext", plaintext, pn);
    hexdump(stdout, "Digest", ciphertext, cn);

    EVP_MD_CTX_init(&ctx);
    if (!EVP_DigestInit_ex(&ctx, d, NULL)) {
        fprintf(stderr, "DigestInit failed\n");
        ERR_print_errors_fp(stderr);
        exit(100);
    }
    if (!EVP_DigestUpdate(&ctx, plaintext, pn)) {
        fprintf(stderr, "DigestUpdate failed\n");
        ERR_print_errors_fp(stderr);
        exit(101);
    }
    if (!EVP_DigestFinal_ex(&ctx, md, &mdn)) {
        fprintf(stderr, "DigestFinal failed\n");
        ERR_print_errors_fp(stderr);
        exit(101);
    }
    EVP_MD_CTX_cleanup(&ctx);

    if (mdn != cn) {
        fprintf(stderr, "Digest length mismatch, got %d expected %d\n", mdn, cn);
        exit(102);
    }

    if (memcmp(md, ciphertext, cn)) {
        fprintf(stderr, "Digest mismatch\n");
        hexdump(stderr, "Got", md, cn);
        hexdump(stderr, "Expected", ciphertext, cn);
        exit(103);
    }

    printf("\n");

    EVP_MD_CTX_cleanup(&ctx);

    return 1;
}

int main(int argc, char **argv)
{
    const char *testfile = "data/evptests.txt";
    FILE *fp;

    if (argc > 1)
        testfile = argv[1];

    fp = fopen(testfile, "r");
    if (!fp) {
        perror(testfile);
        exit(2);
    }

    ERR_load_crypto_strings();
    /* Load up the software EVP_CIPHER and EVP_MD definitions */
    OpenSSL_add_all_ciphers();
    OpenSSL_add_all_digests();
#ifndef OPENSSL_NO_ENGINE
    /* Load all compiled-in ENGINEs */
    ENGINE_load_builtin_engines();
#endif
#ifndef OPENSSL_NO_ENGINE
    /* Register all available ENGINE implementations of ciphers and digests.
     * This could perhaps be changed to "ENGINE_register_all_complete()"? */
    ENGINE_register_all_ciphers();
    ENGINE_register_all_digests();
/* If we add command-line options, this statement should be switchable.
     * It'll prevent ENGINEs being ENGINE_init()ialised for cipher/digest use if
     * they weren't already initialised. */
/* ENGINE_set_cipher_flags(ENGINE_CIPHER_FLAG_NOINIT); */
#endif

    for (;;) {
        char line[4096];
        char *p;
        char *cipher;
        uint8_t *iv, *key, *plaintext, *ciphertext;
        uint8_t *aad, *tag;
        int encdec;
        int kn, in, pn, cn;
        int an = 0;
        int tn = 0;

        if (!fgets((char *)line, sizeof line, fp))
            break;
        if (line[0] == '#' || line[0] == '\n')
            continue;
        p = line;
        cipher = sstrsep(&p, ":");
        key = ustrsep(&p, ":");
        iv = ustrsep(&p, ":");
        plaintext = ustrsep(&p, ":");
        ciphertext = ustrsep(&p, ":");
        if (p[-1] == '\n') {
            encdec = -1;
            p[-1] = '\0';
            tag = aad = NULL;
            an = tn = 0;
        } else {
            aad = ustrsep(&p, ":");
            tag = ustrsep(&p, ":");
            if (tag == NULL) {
                p = (char *)aad;
                tag = aad = NULL;
                an = tn = 0;
            }
            if (p[-1] == '\n') {
                encdec = -1;
                p[-1] = '\0';
            } else
                encdec = atoi(sstrsep(&p, "\n"));
        }

        kn = convert(key);
        in = convert(iv);
        pn = convert(plaintext);
        cn = convert(ciphertext);

        if (aad) {
            an = convert(aad);
            tn = convert(tag);
        }

        if (!test_cipher(cipher, key, kn, iv, in, plaintext, pn, ciphertext, cn, aad, an, tag, tn, encdec)
            && !test_digest(cipher, plaintext, pn, ciphertext, cn)) {
#ifdef OPENSSL_NO_DES
            if (strstr(cipher, "DES") == cipher) {
                fprintf(stdout, "Cipher disabled, skipping %s\n", cipher);
                continue;
            }
#endif
#ifdef OPENSSL_NO_GOST
        if (strstr(cipher, "md_gost") == cipher ||
            strstr(cipher, "streebog") == cipher) {
            fprintf(stdout, "Cipher disabled, skipping %s\n", cipher);
            continue;
        }
#endif
            fprintf(stderr, "Can't find %s\n", cipher);
            exit(3);
        }
    }
    fclose(fp);

#ifndef OPENSSL_NO_ENGINE
    ENGINE_cleanup();
#endif
    EVP_cleanup();
    CRYPTO_cleanup_all_ex_data();
    ERR_remove_thread_state(NULL);
    ERR_free_strings();

    return 0;
}
