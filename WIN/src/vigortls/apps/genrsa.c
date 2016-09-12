/*
 * Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/opensslconf.h>
/* Until the key-gen callbacks are modified to use newer prototypes, we allow
 * deprecated functions for openssl-internal code */
#ifdef OPENSSL_NO_DEPRECATED
#undef OPENSSL_NO_DEPRECATED
#endif

#include <stdio.h>
#include <string.h>

#include <sys/stat.h>
#include <sys/types.h>

#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>

#include "apps.h"

#define DEFBITS 2048

static int genrsa_cb(int p, int n, BN_GENCB *cb);

int genrsa_main(int argc, char **argv)
{
    BN_GENCB cb;
#ifndef OPENSSL_NO_ENGINE
    ENGINE *e = NULL;
#endif
    int ret = 1;
    int i, num = DEFBITS;
    long l;
    const EVP_CIPHER *enc = NULL;
    unsigned long f4 = RSA_F4;
    char *outfile = NULL;
    char *passargout = NULL, *passout = NULL;
#ifndef OPENSSL_NO_ENGINE
    char *engine = NULL;
#endif
    BIO *out = NULL;
    BIGNUM *bn = BN_new();
    RSA *rsa = NULL;

    if (!bn)
        goto err;

    BN_GENCB_set(&cb, genrsa_cb, bio_err);

    if (bio_err == NULL)
        if ((bio_err = BIO_new(BIO_s_file())) != NULL)
            BIO_set_fp(bio_err, stderr, BIO_NOCLOSE | BIO_FP_TEXT);

    if (!load_config(bio_err, NULL))
        goto err;
    if ((out = BIO_new(BIO_s_file())) == NULL) {
        BIO_printf(bio_err, "unable to create BIO for output\n");
        goto err;
    }

    argv++;
    argc--;
    for (;;) {
        if (argc <= 0)
            break;
        if (strcmp(*argv, "-out") == 0) {
            if (--argc < 1)
                goto bad;
            outfile = *(++argv);
        } else if (strcmp(*argv, "-3") == 0)
            f4 = 3;
        else if (strcmp(*argv, "-F4") == 0 || strcmp(*argv, "-f4") == 0)
            f4 = RSA_F4;
#ifndef OPENSSL_NO_ENGINE
        else if (strcmp(*argv, "-engine") == 0) {
            if (--argc < 1)
                goto bad;
            engine = *(++argv);
        }
#endif
#ifndef OPENSSL_NO_DES
        else if (strcmp(*argv, "-des") == 0)
            enc = EVP_des_cbc();
        else if (strcmp(*argv, "-des3") == 0)
            enc = EVP_des_ede3_cbc();
#endif
#ifndef OPENSSL_NO_IDEA
        else if (strcmp(*argv, "-idea") == 0)
            enc = EVP_idea_cbc();
#endif
        else if (strcmp(*argv, "-aes128") == 0)
            enc = EVP_aes_128_cbc();
        else if (strcmp(*argv, "-aes192") == 0)
            enc = EVP_aes_192_cbc();
        else if (strcmp(*argv, "-aes256") == 0)
            enc = EVP_aes_256_cbc();
        else if (strcmp(*argv, "-camellia128") == 0)
            enc = EVP_camellia_128_cbc();
        else if (strcmp(*argv, "-camellia192") == 0)
            enc = EVP_camellia_192_cbc();
        else if (strcmp(*argv, "-camellia256") == 0)
            enc = EVP_camellia_256_cbc();
        else if (strcmp(*argv, "-passout") == 0) {
            if (--argc < 1)
                goto bad;
            passargout = *(++argv);
        } else
            break;
        argv++;
        argc--;
    }
    if ((argc >= 1) && ((sscanf(*argv, "%d", &num) == 0) || (num < 0))) {
    bad:
        BIO_printf(bio_err, "usage: genrsa [args] [numbits]\n");
        BIO_printf(bio_err, " -des            encrypt the generated key with "
                            "DES in cbc mode\n");
        BIO_printf(bio_err, " -des3           encrypt the generated key with "
                            "DES in ede cbc mode (168 bit key)\n");
#ifndef OPENSSL_NO_IDEA
        BIO_printf(bio_err, " -idea           encrypt the generated key with "
                            "IDEA in cbc mode\n");
#endif
        BIO_printf(bio_err, " -aes128, -aes192, -aes256\n");
        BIO_printf(bio_err, "                 encrypt PEM output with cbc aes\n");
        BIO_printf(bio_err, " -camellia128, -camellia192, -camellia256\n");
        BIO_printf(bio_err, "                 encrypt PEM output with cbc camellia\n");
        BIO_printf(bio_err, " -out file       output the key to 'file\n");
        BIO_printf(bio_err, " -passout arg    output file pass phrase source\n");
        BIO_printf(bio_err, " -f4             use F4 (0x10001) for the E value\n");
        BIO_printf(bio_err, " -3              use 3 for the E value\n");
#ifndef OPENSSL_NO_ENGINE
        BIO_printf(bio_err, " -engine e       use engine e, possibly a hardware device.\n");
#endif
        goto err;
    }

    if (!app_passwd(bio_err, NULL, passargout, NULL, &passout)) {
        BIO_printf(bio_err, "Error getting password\n");
        goto err;
    }

#ifndef OPENSSL_NO_ENGINE
    e = setup_engine(bio_err, engine, 0);
#endif

    if (outfile == NULL)
        BIO_set_fp(out, stdout, BIO_NOCLOSE);
    else {
        if (BIO_write_filename(out, outfile) <= 0) {
            perror(outfile);
            goto err;
        }
    }

    BIO_printf(bio_err, "Generating RSA private key, %d bit long modulus\n",
               num);
#ifdef OPENSSL_NO_ENGINE
    rsa = RSA_new();
#else
    rsa = RSA_new_method(e);
#endif
    if (!rsa)
        goto err;

    if (!BN_set_word(bn, f4) || !RSA_generate_key_ex(rsa, num, bn, &cb))
        goto err;

    /* We need to do the following for when the base number size is <
     * long, esp windows 3.1 :-(. */
    l = 0L;
    for (i = 0; i < rsa->e->top; i++) {
#ifndef _LP64
        l <<= BN_BITS4;
        l <<= BN_BITS4;
#endif
        l += rsa->e->d[i];
    }
    BIO_printf(bio_err, "e is %ld (0x%lX)\n", l, l);
    {
        PW_CB_DATA cb_data;
        cb_data.password = passout;
        cb_data.prompt_info = outfile;
        if (!PEM_write_bio_RSAPrivateKey(out, rsa, enc, NULL, 0,
                                         (pem_password_cb *)password_callback,
                                         &cb_data))
            goto err;
    }

    ret = 0;
err:
    if (bn)
        BN_free(bn);
    if (rsa)
        RSA_free(rsa);
    if (out)
        BIO_free_all(out);
    if (passout)
        free(passout);
    if (ret != 0)
        ERR_print_errors(bio_err);
    return (ret);
}

static int genrsa_cb(int p, int n, BN_GENCB *cb)
{
    char c = '*';

    if (p == 0)
        c = '.';
    if (p == 1)
        c = '+';
    if (p == 2)
        c = '*';
    if (p == 3)
        c = '\n';
    BIO_write(cb->arg, &c, 1);
    (void)BIO_flush(cb->arg);

    return 1;
}
