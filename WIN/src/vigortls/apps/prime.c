/*
 * Copyright 2004-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <limits.h>
#include <string.h>

#include <openssl/bn.h>
#include <stdcompat.h>

#include "apps.h"

int prime_main(int argc, char **argv)
{
    int hex = 0;
    int checks = 20;
    int generate = 0;
    int bits = 0;
    int safe = 0;
    const char *stnerr = NULL;
    BIGNUM *bn = NULL;
    BIO *bio_out;

    if (bio_err == NULL)
        if ((bio_err = BIO_new(BIO_s_file())) != NULL)
            BIO_set_fp(bio_err, stderr, BIO_NOCLOSE | BIO_FP_TEXT);

    --argc;
    ++argv;
    while (argc >= 1 && **argv == '-') {
        if (!strcmp(*argv, "-hex"))
            hex = 1;
        else if (!strcmp(*argv, "-generate"))
            generate = 1;
        else if (!strcmp(*argv, "-bits")) {
            if (--argc < 1)
                goto bad;
            else
                bits = strtonum(*(++argv), 0, INT_MAX, &stnerr);
            if (stnerr)
                goto bad;
        } else if (!strcmp(*argv, "-safe"))
            safe = 1;
        else if (!strcmp(*argv, "-checks")) {
            if (--argc < 1)
                goto bad;
            else
                checks = strtonum(*(++argv), 0, INT_MAX, &stnerr);
            if (stnerr)
                goto bad;
        } else {
            BIO_printf(bio_err, "Unknown option '%s'\n", *argv);
            goto bad;
        }
        --argc;
        ++argv;
    }

    if (argv[0] == NULL && !generate) {
        BIO_printf(bio_err, "No prime specified\n");
        goto bad;
    }

    if ((bio_out = BIO_new(BIO_s_file())) != NULL) {
        BIO_set_fp(bio_out, stdout, BIO_NOCLOSE);
    }

    if (generate) {
        char *s;

        if (!bits) {
            BIO_printf(bio_err, "Specify the number of bits.\n");
            return 1;
        }
        bn = BN_new();
        BN_generate_prime_ex(bn, bits, safe, NULL, NULL, NULL);
        s = hex ? BN_bn2hex(bn) : BN_bn2dec(bn);
        BIO_printf(bio_out, "%s\n", s);
        free(s);
    } else {
        if (hex) {
            if (!BN_hex2bn(&bn, argv[0])) {
                BIO_printf(bio_err, "BN_hex2bn() failed\n");
                goto bad;
            }
        } else {
            if (!BN_dec2bn(&bn, argv[0])) {
                BIO_printf(bio_err, "BN_dec2bn() failed\n");
                goto bad;
            }
        }

        BN_print(bio_out, bn);
        BIO_printf(bio_out, " is %sprime\n",
                   BN_is_prime_ex(bn, checks, NULL, NULL) ? "" : "not ");
    }

    BIO_free_all(bio_out);

    return 0;

bad:
    BN_free(bn);
    if (stnerr)
        BIO_printf(bio_err, "invalid argument %s, errmsg=%s\n", *argv, stnerr);
    else {
        BIO_printf(bio_err, "options are\n");
        BIO_printf(bio_err, "%-14s hex\n", "-hex");
        BIO_printf(bio_err, "%-14s number of checks\n", "-checks <n>");
    }
    return 1;
}
