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

#include "apps.h"
#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/dh.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>

#define DEFBITS 2048

static int dh_cb(int p, int n, BN_GENCB *cb);

int gendh_main(int argc, char **argv)
{
    BN_GENCB cb;
    DH *dh = NULL;
    int ret = 1, num = DEFBITS;
    int g = 2;
    char *outfile = NULL;
#ifndef OPENSSL_NO_ENGINE
    char *engine = NULL;
#endif
    BIO *out = NULL;

    BN_GENCB_set(&cb, dh_cb, bio_err);
    if (bio_err == NULL)
        if ((bio_err = BIO_new(BIO_s_file())) != NULL)
            BIO_set_fp(bio_err, stderr, BIO_NOCLOSE | BIO_FP_TEXT);

    if (!load_config(bio_err, NULL))
        goto end;

    argv++;
    argc--;
    for (;;) {
        if (argc <= 0)
            break;
        if (strcmp(*argv, "-out") == 0) {
            if (--argc < 1)
                goto bad;
            outfile = *(++argv);
        } else if (strcmp(*argv, "-2") == 0)
            g = 2;
        /*    else if (strcmp(*argv,"-3") == 0)
            g=3; */
        else if (strcmp(*argv, "-5") == 0)
            g = 5;
#ifndef OPENSSL_NO_ENGINE
        else if (strcmp(*argv, "-engine") == 0) {
            if (--argc < 1)
                goto bad;
            engine = *(++argv);
        }
#endif
        else
            break;
        argv++;
        argc--;
    }
    if ((argc >= 1) && ((sscanf(*argv, "%d", &num) == 0) || (num < 0))) {
    bad:
        BIO_printf(bio_err, "usage: gendh [args] [numbits]\n");
        BIO_printf(bio_err, " -out file - output the key to 'file\n");
        BIO_printf(bio_err, " -2        - use 2 as the generator value\n");
        /*    BIO_printf(bio_err," -3        - use 3 as the generator value\n");
         */
        BIO_printf(bio_err, " -5        - use 5 as the generator value\n");
#ifndef OPENSSL_NO_ENGINE
        BIO_printf(bio_err, " -engine e - use engine e, possibly a hardware device.\n");
#endif
        goto end;
    }

#ifndef OPENSSL_NO_ENGINE
    setup_engine(bio_err, engine, 0);
#endif

    out = BIO_new(BIO_s_file());
    if (out == NULL) {
        ERR_print_errors(bio_err);
        goto end;
    }

    if (outfile == NULL) {
        BIO_set_fp(out, stdout, BIO_NOCLOSE);
    } else {
        if (BIO_write_filename(out, outfile) <= 0) {
            perror(outfile);
            goto end;
        }
    }

    BIO_printf(
        bio_err,
        "Generating DH parameters, %d bit long safe prime, generator %d\n", num,
        g);
    BIO_printf(bio_err, "This is going to take a long time\n");

    if (((dh = DH_new()) == NULL) ||
        !DH_generate_parameters_ex(dh, num, g, &cb))
        goto end;

    if (!PEM_write_bio_DHparams(out, dh))
        goto end;
    ret = 0;
end:
    if (ret != 0)
        ERR_print_errors(bio_err);
    if (out != NULL)
        BIO_free_all(out);
    if (dh != NULL)
        DH_free(dh);
    return (ret);
}

static int dh_cb(int p, int n, BN_GENCB *cb)
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
