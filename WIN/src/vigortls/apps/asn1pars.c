/*
 * Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <stdcompat.h>

#include "apps.h"

static int do_generate(BIO *bio, char *genstr, char *genconf, BUF_MEM *buf);

int asn1parse_main(int argc, char **argv)
{
    int i, badops = 0, offset = 0, ret = 1, j;
    const char *stnerr = NULL;
    unsigned int length = 0;
    long num, tmplen;
    BIO *in = NULL, *out = NULL, *b64 = NULL, *derout = NULL;
    int informat, indent = 0, noout = 0, dump = 0;
    char *infile = NULL, *str = NULL, *prog, *oidfile = NULL, *derfile = NULL;
    char *genstr = NULL, *genconf = NULL;
    uint8_t *tmpbuf;
    const uint8_t *ctmpbuf;
    BUF_MEM *buf = NULL;
    STACK_OF(OPENSSL_STRING) *osk = NULL;
    ASN1_TYPE *at = NULL;

    informat = FORMAT_PEM;

    if (bio_err == NULL)
        if ((bio_err = BIO_new(BIO_s_file())) != NULL)
            BIO_set_fp(bio_err, stderr, BIO_NOCLOSE | BIO_FP_TEXT);

    if (!load_config(bio_err, NULL))
        goto end;

    prog = argv[0];
    argc--;
    argv++;
    if ((osk = sk_OPENSSL_STRING_new_null()) == NULL) {
        BIO_printf(bio_err, "Memory allocation failure\n");
        goto end;
    }
    while (argc >= 1) {
        if (strcmp(*argv, "-inform") == 0) {
            if (--argc < 1)
                goto bad;
            informat = str2fmt(*(++argv));
        } else if (strcmp(*argv, "-in") == 0) {
            if (--argc < 1)
                goto bad;
            infile = *(++argv);
        } else if (strcmp(*argv, "-out") == 0) {
            if (--argc < 1)
                goto bad;
            derfile = *(++argv);
        } else if (strcmp(*argv, "-i") == 0)
            indent = 1;
        else if (strcmp(*argv, "-noout") == 0)
            noout = 1;
        else if (strcmp(*argv, "-oid") == 0) {
            if (--argc < 1)
                goto bad;
            oidfile = *(++argv);
        } else if (strcmp(*argv, "-offset") == 0) {
            if (--argc < 1)
                goto bad;
            offset = strtonum(*(++argv), 0, INT_MAX, &stnerr);
            if (stnerr)
                goto bad;
        } else if (strcmp(*argv, "-length") == 0) {
            if (--argc < 1)
                goto bad;
            length = strtonum(*(++argv), 1, UINT_MAX, &stnerr);
            if (stnerr)
                goto bad;
        } else if (strcmp(*argv, "-dump") == 0)
            dump = -1;
        else if (strcmp(*argv, "-dlimit") == 0) {
            if (--argc < 1)
                goto bad;
            dump = strtonum(*(++argv), 1, INT_MAX, &stnerr);
            if (stnerr)
                goto bad;
        } else if (strcmp(*argv, "-strparse") == 0) {
            if (--argc < 1)
                goto bad;
            sk_OPENSSL_STRING_push(osk, *(++argv));
        } else if (strcmp(*argv, "-genstr") == 0) {
            if (--argc < 1)
                goto bad;
            genstr = *(++argv);
        } else if (strcmp(*argv, "-genconf") == 0) {
            if (--argc < 1)
                goto bad;
            genconf = *(++argv);
        } else {
            BIO_printf(bio_err, "unknown option %s\n", *argv);
            badops = 1;
            break;
        }
        argc--;
        argv++;
    }

    if (badops) {
    bad:
        BIO_printf(bio_err, "%s [options] <infile\n", prog);
        BIO_printf(bio_err, "where options are\n");
        BIO_printf(bio_err, " -inform arg   input format - one of DER PEM\n");
        BIO_printf(bio_err, " -in arg       input file\n");
        BIO_printf(bio_err, " -out arg      output file (output format is always DER\n");
        BIO_printf(bio_err, " -noout arg    don't produce any output\n");
        BIO_printf(bio_err, " -offset arg   offset into file\n");
        BIO_printf(bio_err, " -length arg   length of section in file\n");
        BIO_printf(bio_err, " -i            indent entries\n");
        BIO_printf(bio_err, " -dump         dump unknown data in hex form\n");
        BIO_printf(bio_err, " -dlimit arg   dump the first arg bytes of "
                            "unknown data in hex form\n");
        BIO_printf(bio_err, " -oid file     file of extra oid definitions\n");
        BIO_printf(bio_err, " -strparse offset\n");
        BIO_printf(bio_err, "               a series of these can be used to "
                            "'dig' into multiple\n");
        BIO_printf(bio_err, "               ASN1 blob wrappings\n");
        BIO_printf(bio_err, " -genstr str   string to generate ASN1 structure from\n");
        BIO_printf(bio_err, " -genconf file file to generate ASN1 structure from\n");
        goto end;
    }

    in = BIO_new(BIO_s_file());
    out = BIO_new(BIO_s_file());
    if ((in == NULL) || (out == NULL)) {
        ERR_print_errors(bio_err);
        goto end;
    }
    BIO_set_fp(out, stdout, BIO_NOCLOSE | BIO_FP_TEXT);

    if (oidfile != NULL) {
        if (BIO_read_filename(in, oidfile) <= 0) {
            BIO_printf(bio_err, "problems opening %s\n", oidfile);
            ERR_print_errors(bio_err);
            goto end;
        }
        OBJ_create_objects(in);
    }

    if (infile == NULL)
        BIO_set_fp(in, stdin, BIO_NOCLOSE);
    else {
        if (BIO_read_filename(in, infile) <= 0) {
            perror(infile);
            goto end;
        }
    }

    if (derfile) {
        if (!(derout = BIO_new_file(derfile, "wb"))) {
            BIO_printf(bio_err, "problems opening %s\n", derfile);
            ERR_print_errors(bio_err);
            goto end;
        }
    }

    if ((buf = BUF_MEM_new()) == NULL)
        goto end;
    if (!BUF_MEM_grow(buf, BUFSIZ * 8))
        goto end; /* Pre-allocate :-) */

    if (genstr || genconf) {
        num = do_generate(bio_err, genstr, genconf, buf);
        if (num < 0) {
            ERR_print_errors(bio_err);
            goto end;
        }
    } else {
        if (informat == FORMAT_PEM) {
            BIO *tmp;

            if ((b64 = BIO_new(BIO_f_base64())) == NULL)
                goto end;
            BIO_push(b64, in);
            tmp = in;
            in = b64;
            b64 = tmp;
        }

        num = 0;
        for (;;) {
            if (!BUF_MEM_grow(buf, (int)num + BUFSIZ))
                goto end;
            i = BIO_read(in, &(buf->data[num]), BUFSIZ);
            if (i <= 0)
                break;
            num += i;
        }
    }
    str = buf->data;

    /* If any structs to parse go through in sequence */

    if (sk_OPENSSL_STRING_num(osk)) {
        tmpbuf = (uint8_t *)str;
        tmplen = num;
        for (i = 0; i < sk_OPENSSL_STRING_num(osk); i++) {
            ASN1_TYPE *atmp;
            int typ;
            j = strtonum(sk_OPENSSL_STRING_value(osk, i), 1, INT_MAX, &stnerr);
            if (stnerr) {
                BIO_printf(bio_err, "'%s' is an invalid number, errmsg=%s\n",
                           sk_OPENSSL_STRING_value(osk, i), stnerr);
                continue;
            }
            tmpbuf += j;
            tmplen -= j;
            atmp = at;
            ctmpbuf = tmpbuf;
            at = d2i_ASN1_TYPE(NULL, &ctmpbuf, tmplen);
            ASN1_TYPE_free(atmp);
            if (!at) {
                BIO_printf(bio_err, "Error parsing structure\n");
                ERR_print_errors(bio_err);
                goto end;
            }
            typ = ASN1_TYPE_get(at);
            if ((typ == V_ASN1_OBJECT) || (typ == V_ASN1_BOOLEAN) ||
                (typ == V_ASN1_NULL))
            {
                BIO_printf(bio_err, "Can't parse %s type\n", ASN1_tag2str(typ));
                ERR_print_errors(bio_err);
                goto end;
            }
            /* hmm... this is a little evil but it works */
            tmpbuf = at->value.asn1_string->data;
            tmplen = at->value.asn1_string->length;
        }
        str = (char *)tmpbuf;
        num = tmplen;
    }

    if (offset >= num) {
        BIO_printf(bio_err, "Error: offset too large\n");
        goto end;
    }

    num -= offset;

    if ((length == 0) || ((long)length > num))
        length = (unsigned int)num;
    if (derout) {
        if (BIO_write(derout, str + offset, length) != (int)length) {
            BIO_printf(bio_err, "Error writing output\n");
            ERR_print_errors(bio_err);
            goto end;
        }
    }
    if (!noout &&
        !ASN1_parse_dump(out, (uint8_t *)&(str[offset]), length, indent,
                         dump)) {
        ERR_print_errors(bio_err);
        goto end;
    }
    ret = 0;
end:
    BIO_free(derout);
    if (in != NULL)
        BIO_free(in);
    if (out != NULL)
        BIO_free_all(out);
    if (b64 != NULL)
        BIO_free(b64);
    if (ret != 0)
        ERR_print_errors(bio_err);
    if (buf != NULL)
        BUF_MEM_free(buf);
    if (at != NULL)
        ASN1_TYPE_free(at);
    if (osk != NULL)
        sk_OPENSSL_STRING_free(osk);
    OBJ_cleanup();
    return (ret);
}

static int do_generate(BIO *bio, char *genstr, char *genconf, BUF_MEM *buf)
{
    CONF *cnf = NULL;
    int len;
    long errline;
    uint8_t *p;
    ASN1_TYPE *atyp = NULL;

    if (genconf) {
        cnf = NCONF_new(NULL);
        if (!NCONF_load(cnf, genconf, &errline))
            goto conferr;
        if (!genstr)
            genstr = NCONF_get_string(cnf, "default", "asn1");
        if (!genstr) {
            BIO_printf(bio, "Can't find 'asn1' in '%s'\n", genconf);
            goto err;
        }
    }

    atyp = ASN1_generate_nconf(genstr, cnf);
    NCONF_free(cnf);
    cnf = NULL;

    if (!atyp)
        return -1;

    len = i2d_ASN1_TYPE(atyp, NULL);

    if (len <= 0)
        goto err;

    if (!BUF_MEM_grow(buf, len))
        goto err;

    p = (uint8_t *)buf->data;

    i2d_ASN1_TYPE(atyp, &p);

    ASN1_TYPE_free(atyp);
    return len;

conferr:

    if (errline > 0)
        BIO_printf(bio, "Error on line %ld of config file '%s'\n", errline,
                   genconf);
    else
        BIO_printf(bio, "Error loading config file '%s'\n", genconf);

err:
    NCONF_free(cnf);
    ASN1_TYPE_free(atyp);

    return -1;
}
