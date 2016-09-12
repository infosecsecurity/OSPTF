/*
 * Copyright (c) 2014 - 2015, Kurt Cancemi (kurt@x64architecture.com)
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
/*
 * Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <sys/stat.h>
#include <sys/times.h>
#include <sys/types.h>

#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>

#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/pkcs12.h>
#include <openssl/safestack.h>
#include <openssl/ui.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <stdcompat.h>
#include <win32compat.h>

#ifndef OPENSSL_NO_ENGINE
#include <openssl/engine.h>
#endif

#include <openssl/rsa.h>

#include "apps.h"

typedef struct {
    const char *name;
    unsigned long flag;
    unsigned long mask;
} NAME_EX_TBL;

static UI_METHOD *ui_method = NULL;

static int set_table_opts(unsigned long *flags, const char *arg,
                          const NAME_EX_TBL *in_tbl);
static int set_multi_opts(unsigned long *flags, const char *arg,
                          const NAME_EX_TBL *in_tbl);

#if !defined(OPENSSL_NO_RC4) && !defined(OPENSSL_NO_RSA)
/* Looks like this stuff is worth moving into separate function */
static EVP_PKEY *load_netscape_key(BIO *err, BIO *key, const char *file,
                                   const char *key_descrip, int format);
#endif

int str2fmt(char *s)
{
    if (s == NULL)
        return FORMAT_UNDEF;
    if ((*s == 'D') || (*s == 'd'))
        return (FORMAT_ASN1);
    else if ((*s == 'T') || (*s == 't'))
        return (FORMAT_TEXT);
    else if ((*s == 'N') || (*s == 'n'))
        return (FORMAT_NETSCAPE);
    else if ((*s == 'S') || (*s == 's'))
        return (FORMAT_SMIME);
    else if ((*s == 'M') || (*s == 'm'))
        return (FORMAT_MSBLOB);
    else if ((*s == '1') || (strcmp(s, "PKCS12") == 0) ||
             (strcmp(s, "pkcs12") == 0) || (strcmp(s, "P12") == 0) ||
             (strcmp(s, "p12") == 0))
        return (FORMAT_PKCS12);
    else if ((*s == 'E') || (*s == 'e'))
        return (FORMAT_ENGINE);
    else if ((*s == 'H') || (*s == 'h'))
        return FORMAT_HTTP;
    else if ((*s == 'P') || (*s == 'p')) {
        if (s[1] == 'V' || s[1] == 'v')
            return FORMAT_PVK;
        else
            return (FORMAT_PEM);
    } else
        return (FORMAT_UNDEF);
}

void program_name(char *in, char *out, int size)
{
    char *p;

    p = strrchr(in, '/');
    if (p != NULL)
        p++;
    else
        p = in;
    strlcpy(out, p, size);
}

int chopup_args(ARGS *arg, char *buf, int *argc, char **argv[])
{
    int num, i;
    char *p;

    *argc = 0;
    *argv = NULL;

    i = 0;
    if (arg->count == 0) {
        arg->count = 20;
        arg->data = reallocarray(NULL, arg->count, sizeof(char *));
        if (arg->data == NULL)
            return 0;
    }
    for (i = 0; i < arg->count; i++)
        arg->data[i] = NULL;

    num = 0;
    p = buf;
    for (;;) {
        /* first scan over white space */
        if (!*p)
            break;
        while (*p && ((*p == ' ') || (*p == '\t') || (*p == '\n')))
            p++;

        if (!*p)
            break;

        /* The start of something good :-) */
        if (num >= arg->count) {
            char **tmp_p;
            int tlen = arg->count + 20;
            tmp_p = reallocarray(arg->data, tlen, sizeof(char *));
            if (tmp_p == NULL)
                return 0;
            arg->data = tmp_p;
            arg->count = tlen;
            /* initialize newly allocated data */
            for (i = num; i < arg->count; i++)
                arg->data[i] = NULL;
        }
        arg->data[num++] = p;

        /* now look for the end of this */
        if ((*p == '\'') || (*p == '\"')) { /* scan for closing quote */
            i = *(p++);
            arg->data[num - 1]++; /* jump over quote */
            while (*p && (*p != i))
                p++;
            *p = '\0';
        } else {
            while (*p && ((*p != ' ') && (*p != '\t') && (*p != '\n')))
                p++;

            if (*p == '\0')
                p--;
            else
                *p = '\0';
        }
        p++;
    }
    *argc = num;
    *argv = arg->data;
    return (1);
}

int dump_cert_text(BIO *out, X509 *x)
{
    char *p;

    p = X509_NAME_oneline(X509_get_subject_name(x), NULL, 0);
    BIO_puts(out, "subject=");
    BIO_puts(out, p);
    free(p);

    p = X509_NAME_oneline(X509_get_issuer_name(x), NULL, 0);
    BIO_puts(out, "\nissuer=");
    BIO_puts(out, p);
    BIO_puts(out, "\n");
    free(p);

    return 0;
}

static int ui_open(UI *ui)
{
    return UI_method_get_opener(UI_OpenSSL())(ui);
}
static int ui_read(UI *ui, UI_STRING *uis)
{
    if (UI_get_input_flags(uis) & UI_INPUT_FLAG_DEFAULT_PWD &&
        UI_get0_user_data(ui)) {

        switch (UI_get_string_type(uis)) {
            case UIT_PROMPT:
            case UIT_VERIFY: {
                const char *password =
                    ((PW_CB_DATA *)UI_get0_user_data(ui))->password;
                if (password && password[0] != '\0') {
                    UI_set_result(ui, uis, password);
                    return 1;
                }
            }
            default:
                break;
        }
    }
    return UI_method_get_reader(UI_OpenSSL())(ui, uis);
}
static int ui_write(UI *ui, UI_STRING *uis)
{
    if (UI_get_input_flags(uis) & UI_INPUT_FLAG_DEFAULT_PWD &&
        UI_get0_user_data(ui)) {

        switch (UI_get_string_type(uis)) {
            case UIT_PROMPT:
            case UIT_VERIFY: {
                const char *password =
                    ((PW_CB_DATA *)UI_get0_user_data(ui))->password;
                if (password && password[0] != '\0')
                    return 1;
            }
            default:
                break;
        }
    }
    return UI_method_get_writer(UI_OpenSSL())(ui, uis);
}
static int ui_close(UI *ui)
{
    return UI_method_get_closer(UI_OpenSSL())(ui);
}
int setup_ui_method(void)
{
    ui_method = UI_create_method("OpenSSL application user interface");
    UI_method_set_opener(ui_method, ui_open);
    UI_method_set_reader(ui_method, ui_read);
    UI_method_set_writer(ui_method, ui_write);
    UI_method_set_closer(ui_method, ui_close);
    return 0;
}
void destroy_ui_method(void)
{
    if (ui_method) {
        UI_destroy_method(ui_method);
        ui_method = NULL;
    }
}
int password_callback(char *buf, int bufsiz, int verify, PW_CB_DATA *cb_tmp)
{
    UI *ui = NULL;
    int res = 0;
    const char *prompt_info = NULL;
    const char *password = NULL;
    PW_CB_DATA *cb_data = (PW_CB_DATA *)cb_tmp;

    if (cb_data) {
        if (cb_data->password)
            password = cb_data->password;
        if (cb_data->prompt_info)
            prompt_info = cb_data->prompt_info;
    }

    if (password) {
        res = strlen(password);
        if (res > bufsiz)
            res = bufsiz;
        memcpy(buf, password, res);
        return res;
    }

    ui = UI_new_method(ui_method);
    if (ui) {
        int ok = 0;
        char *buff = NULL;
        int ui_flags = 0;
        char *prompt;

        prompt = UI_construct_prompt(ui, "pass phrase", prompt_info);
        if (prompt == NULL) {
            BIO_printf(bio_err, "Out of memory\n");
            UI_free(ui);
            return 0;
        }

        ui_flags |= UI_INPUT_FLAG_DEFAULT_PWD;
        UI_ctrl(ui, UI_CTRL_PRINT_ERRORS, 1, 0, 0);

        if (ok >= 0)
            ok = UI_add_input_string(ui, prompt, ui_flags, buf, PW_MIN_LENGTH,
                                     bufsiz - 1);
        if (ok >= 0 && verify) {
            buff = malloc(bufsiz);
            if (buff == NULL) {
                BIO_printf(bio_err, "Out of memory\n");
                UI_free(ui);
                free(prompt);
                return 0;
            }
            ok = UI_add_verify_string(ui, prompt, ui_flags, buff, PW_MIN_LENGTH,
                                      bufsiz - 1, buf);
        }
        if (ok >= 0)
            do {
                ok = UI_process(ui);
            } while (ok < 0 && UI_ctrl(ui, UI_CTRL_IS_REDOABLE, 0, 0, 0));

        if (buff) {
            vigortls_zeroize(buff, (unsigned int)bufsiz);
            free(buff);
        }

        if (ok >= 0)
            res = strlen(buf);
        if (ok == -1) {
            BIO_printf(bio_err, "User interface error\n");
            ERR_print_errors(bio_err);
            vigortls_zeroize(buf, (unsigned int)bufsiz);
            res = 0;
        }
        if (ok == -2) {
            BIO_printf(bio_err, "aborted!\n");
            vigortls_zeroize(buf, (unsigned int)bufsiz);
            res = 0;
        }
        UI_free(ui);
        free(prompt);
    }
    return res;
}

static char *app_get_pass(BIO *err, char *arg, int keepbio);

int app_passwd(BIO *err, char *arg1, char *arg2, char **pass1, char **pass2)
{
    int same;
    if (!arg2 || !arg1 || strcmp(arg1, arg2))
        same = 0;
    else
        same = 1;
    if (arg1) {
        *pass1 = app_get_pass(err, arg1, same);
        if (!*pass1)
            return 0;
    } else if (pass1)
        *pass1 = NULL;
    if (arg2) {
        *pass2 = app_get_pass(err, arg2, same ? 2 : 0);
        if (!*pass2)
            return 0;
    } else if (pass2)
        *pass2 = NULL;
    return 1;
}

static char *app_get_pass(BIO *err, char *arg, int keepbio)
{
    char *tmp, tpass[APP_PASS_LEN];
    static BIO *pwdbio = NULL;
    int i;
    const char *stnerr = NULL;
    if (!strncmp(arg, "pass:", 5))
        return strdup(arg + 5);
    if (!strncmp(arg, "env:", 4)) {
        tmp = getenv(arg + 4);
        if (!tmp) {
            BIO_printf(err, "Can't read environment variable %s\n", arg + 4);
            return NULL;
        }
        return strdup(tmp);
    }
    if (!keepbio || !pwdbio) {
        if (!strncmp(arg, "file:", 5)) {
            pwdbio = BIO_new_file(arg + 5, "r");
            if (!pwdbio) {
                BIO_printf(err, "Can't open file %s\n", arg + 5);
                return NULL;
            }
        } else if (!strncmp(arg, "fd:", 3)) {
            BIO *btmp;
            i = strtonum(arg + 3, 1, INT_MAX, &stnerr);
            if (stnerr) {
                BIO_printf(err, "Invalid file descriptor: arg=%s, errmsg=%s\n",
                           arg, stnerr);
                return NULL;
            }
            pwdbio = BIO_new_fd(i, BIO_NOCLOSE);
            if (!pwdbio) {
                BIO_printf(err, "Can't access file descriptor %s\n", arg + 3);
                return NULL;
            }
            /* Can't do BIO_gets on an fd BIO so add a buffering BIO */
            btmp = BIO_new(BIO_f_buffer());
            pwdbio = BIO_push(btmp, pwdbio);
        } else if (!strcmp(arg, "stdin")) {
            pwdbio = BIO_new_fp(stdin, BIO_NOCLOSE);
            if (!pwdbio) {
                BIO_printf(err, "Can't open BIO for stdin\n");
                return NULL;
            }
        } else {
            BIO_printf(err, "Invalid password argument \"%s\"\n", arg);
            return NULL;
        }
    }
    i = BIO_gets(pwdbio, tpass, APP_PASS_LEN);
    if (keepbio != 1) {
        BIO_free_all(pwdbio);
        pwdbio = NULL;
    }
    if (i <= 0) {
        BIO_printf(err, "Error reading password from BIO\n");
        return NULL;
    }
    tmp = strchr(tpass, '\n');
    if (tmp)
        *tmp = 0;
    return strdup(tpass);
}

int add_oid_section(BIO *err, CONF *conf)
{
    char *p;
    STACK_OF(CONF_VALUE) *sktmp;
    CONF_VALUE *cnf;
    int i;
    if (!(p = NCONF_get_string(conf, NULL, "oid_section"))) {
        ERR_clear_error();
        return 1;
    }
    if (!(sktmp = NCONF_get_section(conf, p))) {
        BIO_printf(err, "problem loading oid section %s\n", p);
        return 0;
    }
    for (i = 0; i < sk_CONF_VALUE_num(sktmp); i++) {
        cnf = sk_CONF_VALUE_value(sktmp, i);
        if (OBJ_create(cnf->value, cnf->name, cnf->name) == NID_undef) {
            BIO_printf(err, "problem creating object %s=%s\n", cnf->name,
                       cnf->value);
            return 0;
        }
    }
    return 1;
}

static int load_pkcs12(BIO *err, BIO *in, const char *desc,
                       pem_password_cb *pem_cb, void *cb_data, EVP_PKEY **pkey,
                       X509 **cert, STACK_OF(X509) **ca)
{
    const char *pass;
    char tpass[PEM_BUFSIZE];
    int len, ret = 0;
    PKCS12 *p12;
    p12 = d2i_PKCS12_bio(in, NULL);
    if (p12 == NULL) {
        BIO_printf(err, "Error loading PKCS12 file for %s\n", desc);
        goto die;
    }
    /* See if an empty password will do */
    if (PKCS12_verify_mac(p12, "", 0) || PKCS12_verify_mac(p12, NULL, 0))
        pass = "";
    else {
        if (!pem_cb)
            pem_cb = (pem_password_cb *)password_callback;
        len = pem_cb(tpass, PEM_BUFSIZE, 0, cb_data);
        if (len < 0) {
            BIO_printf(err, "Passphrase callback error for %s\n", desc);
            goto die;
        }
        if (len < PEM_BUFSIZE)
            tpass[len] = 0;
        if (!PKCS12_verify_mac(p12, tpass, len)) {
            BIO_printf(
                err,
                "Mac verify error (wrong password?) in PKCS12 file for %s\n",
                desc);
            goto die;
        }
        pass = tpass;
    }
    ret = PKCS12_parse(p12, pass, pkey, cert, ca);
die:
    if (p12)
        PKCS12_free(p12);
    return ret;
}

int load_cert_crl_http(const char *url, BIO *err, X509 **pcert, X509_CRL **pcrl)
{
    char *host = NULL, *port = NULL, *path = NULL;
    BIO *bio = NULL;
    OCSP_REQ_CTX *rctx = NULL;
    int use_ssl, rv = 0;
    if (!OCSP_parse_url(url, &host, &port, &path, &use_ssl))
        goto err;
    if (use_ssl) {
        if (err)
            BIO_puts(err, "https not supported\n");
        goto err;
    }
    bio = BIO_new_connect(host);
    if (!bio || !BIO_set_conn_port(bio, port))
        goto err;
    rctx = OCSP_REQ_CTX_new(bio, 1024);
    if (rctx == NULL)
        goto err;
    if (!OCSP_REQ_CTX_http(rctx, "GET", path))
        goto err;
    if (!OCSP_REQ_CTX_add1_header(rctx, "Host", host))
        goto err;
    if (pcert) {
        do {
            rv = X509_http_nbio(rctx, pcert);
        } while (rv == -1);
    }
    else {
        do {
            rv = X509_CRL_http_nbio(rctx, pcrl);
        } while (rv == -1);
    }

err:
    free(host);
    free(path);
    free(port);
    BIO_free_all(bio);
    OCSP_REQ_CTX_free(rctx);
    if (rv != 1) {
        if (bio && err)
            BIO_printf(bio_err, "Error loading %s from %s\n",
                       pcert ? "certificate" : "CRL", url);
        ERR_print_errors(bio_err);
    }
    return rv;
}

X509 *load_cert(BIO *err, const char *file, int format, const char *pass,
                ENGINE *e, const char *cert_descrip)
{
    X509 *x = NULL;
    BIO *cert;
    
    if (format == FORMAT_HTTP) {
        load_cert_crl_http(file, err, &x, NULL);
        return x;
    }

    if ((cert = BIO_new(BIO_s_file())) == NULL) {
        ERR_print_errors(err);
        goto end;
    }

    if (file == NULL) {
        setvbuf(stdin, NULL, _IONBF, 0);
        BIO_set_fp(cert, stdin, BIO_NOCLOSE);
    } else {
        if (BIO_read_filename(cert, file) <= 0) {
            BIO_printf(err, "Error opening %s %s\n", cert_descrip, file);
            ERR_print_errors(err);
            goto end;
        }
    }

    if (format == FORMAT_ASN1)
        x = d2i_X509_bio(cert, NULL);
    else if (format == FORMAT_NETSCAPE) {
        NETSCAPE_X509 *nx;
        nx = ASN1_item_d2i_bio(ASN1_ITEM_rptr(NETSCAPE_X509), cert, NULL);
        if (nx == NULL)
            goto end;

        if ((strncmp(NETSCAPE_CERT_HDR, (char *)nx->header->data,
                     nx->header->length) != 0)) {
            NETSCAPE_X509_free(nx);
            BIO_printf(err, "Error reading header on certificate\n");
            goto end;
        }
        x = nx->cert;
        nx->cert = NULL;
        NETSCAPE_X509_free(nx);
    } else if (format == FORMAT_PEM)
        x = PEM_read_bio_X509_AUX(cert, NULL,
                                  (pem_password_cb *)password_callback, NULL);
    else if (format == FORMAT_PKCS12) {
        if (!load_pkcs12(err, cert, cert_descrip, NULL, NULL, NULL, &x, NULL))
            goto end;
    } else {
        BIO_printf(err, "bad input format specified for %s\n", cert_descrip);
        goto end;
    }
end:
    if (x == NULL) {
        BIO_printf(err, "unable to load certificate\n");
        ERR_print_errors(err);
    }
    if (cert != NULL)
        BIO_free(cert);
    return (x);
}

X509_CRL *load_crl(const char *infile, int format)
{
    X509_CRL *x = NULL;
    BIO *in = NULL;

    if (format == FORMAT_HTTP) {
        load_cert_crl_http(infile, bio_err, NULL, &x);
        return x;
    }

    in = BIO_new(BIO_s_file());
    if (in == NULL) {
        ERR_print_errors(bio_err);
        goto end;
    }

    if (infile == NULL)
        BIO_set_fp(in, stdin, BIO_NOCLOSE);
    else {
        if (BIO_read_filename(in, infile) <= 0) {
            perror(infile);
            goto end;
        }
    }
    if (format == FORMAT_ASN1)
        x = d2i_X509_CRL_bio(in, NULL);
    else if (format == FORMAT_PEM)
        x = PEM_read_bio_X509_CRL(in, NULL, NULL, NULL);
    else {
        BIO_printf(bio_err, "bad input format specified for input crl\n");
        goto end;
    }
    if (x == NULL) {
        BIO_printf(bio_err, "unable to load CRL\n");
        ERR_print_errors(bio_err);
        goto end;
    }

end:
    BIO_free(in);
    return x;
}

/* Get first http URL from a DIST_POINT structure */

static const char *get_dp_url(DIST_POINT *dp)
{
    GENERAL_NAMES *gens;
    GENERAL_NAME *gen;
    int i, gtype;
    ASN1_STRING *uri;
    if (!dp->distpoint || dp->distpoint->type != 0)
        return NULL;
    gens = dp->distpoint->name.fullname;
    for (i = 0; i < sk_GENERAL_NAME_num(gens); i++) {
        gen = sk_GENERAL_NAME_value(gens, i);
        uri = GENERAL_NAME_get0_value(gen, &gtype);
        if (gtype == GEN_URI && ASN1_STRING_length(uri) > 6) {
            char *uptr = (char *)ASN1_STRING_data(uri);
            if (strncmp(uptr, "http://", 7) == 0)
                return uptr;
        }
    }
    return NULL;
}

/* Look through a CRLDP structure and attempt to find an http URL to downloads
 * a CRL from.
 */

static X509_CRL *load_crl_crldp(STACK_OF(DIST_POINT) *crldp)
{
    int i;
    const char *urlptr = NULL;
    for (i = 0; i < sk_DIST_POINT_num(crldp); i++) {
        DIST_POINT *dp = sk_DIST_POINT_value(crldp, i);
        urlptr = get_dp_url(dp);
        if (urlptr)
            return load_crl(urlptr, FORMAT_HTTP);
    }
    return NULL;
}

/* Example of downloading CRLs from CRLDP: not usable for real world
 * as it always downloads, doesn't support non-blocking I/O and doesn't
 * cache anything.
 */

static STACK_OF(X509_CRL) *crls_http_cb(X509_STORE_CTX *ctx, X509_NAME *nm)
{
    X509 *x;
    STACK_OF(X509_CRL) *crls = NULL;
    X509_CRL *crl;
    STACK_OF(DIST_POINT) *crldp;
    x = X509_STORE_CTX_get_current_cert(ctx);
    crldp = X509_get_ext_d2i(x, NID_crl_distribution_points, NULL, NULL);
    crl = load_crl_crldp(crldp);
    sk_DIST_POINT_pop_free(crldp, DIST_POINT_free);
    if (!crl)
        return NULL;
    crls = sk_X509_CRL_new_null();
    sk_X509_CRL_push(crls, crl);
    /* Try to download delta CRL */
    crldp = X509_get_ext_d2i(x, NID_freshest_crl, NULL, NULL);
    crl = load_crl_crldp(crldp);
    sk_DIST_POINT_pop_free(crldp, DIST_POINT_free);
    if (crl)
        sk_X509_CRL_push(crls, crl);
    return crls;
}

void store_setup_crl_download(X509_STORE *st)
{
    X509_STORE_set_lookup_crls_cb(st, crls_http_cb);
}

EVP_PKEY *load_key(BIO *err, const char *file, int format, int maybe_stdin,
                   const char *pass, ENGINE *e, const char *key_descrip)
{
    BIO *key = NULL;
    EVP_PKEY *pkey = NULL;
    PW_CB_DATA cb_data;

    cb_data.password = pass;
    cb_data.prompt_info = file;

    if (file == NULL && (!maybe_stdin || format == FORMAT_ENGINE)) {
        BIO_printf(err, "no keyfile specified\n");
        goto end;
    }
#ifndef OPENSSL_NO_ENGINE
    if (format == FORMAT_ENGINE) {
        if (!e)
            BIO_printf(err, "no engine specified\n");
        else {
            pkey = ENGINE_load_private_key(e, file, ui_method, &cb_data);
            if (!pkey) {
                BIO_printf(err, "cannot load %s from engine\n", key_descrip);
                ERR_print_errors(err);
            }
        }
        goto end;
    }
#endif
    key = BIO_new(BIO_s_file());
    if (key == NULL) {
        ERR_print_errors(err);
        goto end;
    }
    if (file == NULL && maybe_stdin) {
        setvbuf(stdin, NULL, _IONBF, 0);
        BIO_set_fp(key, stdin, BIO_NOCLOSE);
    } else if (BIO_read_filename(key, file) <= 0) {
        BIO_printf(err, "Error opening %s %s\n", key_descrip, file);
        ERR_print_errors(err);
        goto end;
    }
    if (format == FORMAT_ASN1)
        pkey = d2i_PrivateKey_bio(key, NULL);
    else if (format == FORMAT_PEM)
        pkey = PEM_read_bio_PrivateKey(
            key, NULL, (pem_password_cb *)password_callback, &cb_data);
#if !defined(OPENSSL_NO_RC4) && !defined(OPENSSL_NO_RSA)
    else if (format == FORMAT_NETSCAPE || format == FORMAT_IISSGC)
        pkey = load_netscape_key(err, key, file, key_descrip, format);
#endif
    else if (format == FORMAT_PKCS12) {
        if (!load_pkcs12(err, key, key_descrip,
                         (pem_password_cb *)password_callback, &cb_data, &pkey,
                         NULL, NULL))
            goto end;
    }
#if !defined(OPENSSL_NO_RSA) && !defined(OPENSSL_NO_DSA) && \
    !defined(OPENSSL_NO_RC4)
    else if (format == FORMAT_MSBLOB)
        pkey = b2i_PrivateKey_bio(key);
    else if (format == FORMAT_PVK)
        pkey = b2i_PVK_bio(key, (pem_password_cb *)password_callback, &cb_data);
#endif
    else {
        BIO_printf(err, "bad input format specified for key file\n");
        goto end;
    }
end:
    if (key != NULL)
        BIO_free(key);
    if (pkey == NULL) {
        BIO_printf(err, "unable to load %s\n", key_descrip);
        ERR_print_errors(err);
    }
    return (pkey);
}

EVP_PKEY *load_pubkey(BIO *err, const char *file, int format, int maybe_stdin,
                      const char *pass, ENGINE *e, const char *key_descrip)
{
    BIO *key = NULL;
    EVP_PKEY *pkey = NULL;
    PW_CB_DATA cb_data;

    cb_data.password = pass;
    cb_data.prompt_info = file;

    if (file == NULL && (!maybe_stdin || format == FORMAT_ENGINE)) {
        BIO_printf(err, "no keyfile specified\n");
        goto end;
    }
#ifndef OPENSSL_NO_ENGINE
    if (format == FORMAT_ENGINE) {
        if (!e)
            BIO_printf(bio_err, "no engine specified\n");
        else
            pkey = ENGINE_load_public_key(e, file, ui_method, &cb_data);
        goto end;
    }
#endif
    key = BIO_new(BIO_s_file());
    if (key == NULL) {
        ERR_print_errors(err);
        goto end;
    }
    if (file == NULL && maybe_stdin) {
        setvbuf(stdin, NULL, _IONBF, 0);
        BIO_set_fp(key, stdin, BIO_NOCLOSE);
    } else if (BIO_read_filename(key, file) <= 0) {
        BIO_printf(err, "Error opening %s %s\n", key_descrip, file);
        ERR_print_errors(err);
        goto end;
    }
    if (format == FORMAT_ASN1)
        pkey = d2i_PUBKEY_bio(key, NULL);
    else if (format == FORMAT_ASN1RSA) {
        RSA *rsa;
        rsa = d2i_RSAPublicKey_bio(key, NULL);
        if (rsa) {
            pkey = EVP_PKEY_new();
            if (pkey)
                EVP_PKEY_set1_RSA(pkey, rsa);
            RSA_free(rsa);
        } else
            pkey = NULL;
    } else if (format == FORMAT_PEMRSA) {
        RSA *rsa;
        rsa = PEM_read_bio_RSAPublicKey(
            key, NULL, (pem_password_cb *)password_callback, &cb_data);
        if (rsa) {
            pkey = EVP_PKEY_new();
            if (pkey)
                EVP_PKEY_set1_RSA(pkey, rsa);
            RSA_free(rsa);
        } else
            pkey = NULL;
    } else if (format == FORMAT_PEM) {
        pkey = PEM_read_bio_PUBKEY(
            key, NULL, (pem_password_cb *)password_callback, &cb_data);
    }
#if !defined(OPENSSL_NO_RC4) && !defined(OPENSSL_NO_RSA)
    else if (format == FORMAT_NETSCAPE || format == FORMAT_IISSGC)
        pkey = load_netscape_key(err, key, file, key_descrip, format);
#endif
#if !defined(OPENSSL_NO_RSA) && !defined(OPENSSL_NO_DSA)
    else if (format == FORMAT_MSBLOB)
        pkey = b2i_PublicKey_bio(key);
#endif
    else {
        BIO_printf(err, "bad input format specified for key file\n");
        goto end;
    }
end:
    if (key != NULL)
        BIO_free(key);
    if (pkey == NULL)
        BIO_printf(err, "unable to load %s\n", key_descrip);
    return (pkey);
}

#if !defined(OPENSSL_NO_RC4) && !defined(OPENSSL_NO_RSA)
static EVP_PKEY *load_netscape_key(BIO *err, BIO *key, const char *file,
                                   const char *key_descrip, int format)
{
    EVP_PKEY *pkey;
    BUF_MEM *buf;
    RSA *rsa;
    const uint8_t *p;
    int size, i;

    buf = BUF_MEM_new();
    pkey = EVP_PKEY_new();
    size = 0;
    if (buf == NULL || pkey == NULL)
        goto error;
    for (;;) {
        if (!BUF_MEM_grow_clean(buf, size + 1024 * 10))
            goto error;
        i = BIO_read(key, &(buf->data[size]), 1024 * 10);
        size += i;
        if (i == 0)
            break;
        if (i < 0) {
            BIO_printf(err, "Error reading %s %s", key_descrip, file);
            goto error;
        }
    }
    p = (uint8_t *)buf->data;
    rsa = d2i_RSA_NET(NULL, &p, (long)size, NULL,
                      (format == FORMAT_IISSGC ? 1 : 0));
    if (rsa == NULL)
        goto error;
    BUF_MEM_free(buf);
    EVP_PKEY_set1_RSA(pkey, rsa);
    return pkey;
error:
    BUF_MEM_free(buf);
    EVP_PKEY_free(pkey);
    return NULL;
}
#endif /* ndef OPENSSL_NO_RC4 */

static int load_certs_crls(BIO *err, const char *file, int format,
                           const char *pass, ENGINE *e, const char *desc,
                           STACK_OF(X509) **pcerts,
                           STACK_OF(X509_CRL) **pcrls)
{
    int i;
    BIO *bio;
    STACK_OF(X509_INFO) *xis = NULL;
    X509_INFO *xi;
    PW_CB_DATA cb_data;
    int rv = 0;

    cb_data.password = pass;
    cb_data.prompt_info = file;

    if (format != FORMAT_PEM) {
        BIO_printf(err, "bad input format specified for %s\n", desc);
        return 0;
    }

    if (file == NULL)
        bio = BIO_new_fp(stdin, BIO_NOCLOSE);
    else
        bio = BIO_new_file(file, "r");

    if (bio == NULL) {
        BIO_printf(err, "Error opening %s %s\n", desc, file ? file : "stdin");
        ERR_print_errors(err);
        return 0;
    }

    xis = PEM_X509_INFO_read_bio(
        bio, NULL, (pem_password_cb *)password_callback, &cb_data);

    BIO_free(bio);

    if (pcerts) {
        *pcerts = sk_X509_new_null();
        if (!*pcerts)
            goto end;
    }

    if (pcrls) {
        *pcrls = sk_X509_CRL_new_null();
        if (!*pcrls)
            goto end;
    }

    for (i = 0; i < sk_X509_INFO_num(xis); i++) {
        xi = sk_X509_INFO_value(xis, i);
        if (xi->x509 && pcerts) {
            if (!sk_X509_push(*pcerts, xi->x509))
                goto end;
            xi->x509 = NULL;
        }
        if (xi->crl && pcrls) {
            if (!sk_X509_CRL_push(*pcrls, xi->crl))
                goto end;
            xi->crl = NULL;
        }
    }

    if (pcerts && sk_X509_num(*pcerts) > 0)
        rv = 1;

    if (pcrls && sk_X509_CRL_num(*pcrls) > 0)
        rv = 1;

end:

    if (xis)
        sk_X509_INFO_pop_free(xis, X509_INFO_free);

    if (rv == 0) {
        if (pcerts) {
            sk_X509_pop_free(*pcerts, X509_free);
            *pcerts = NULL;
        }
        if (pcrls) {
            sk_X509_CRL_pop_free(*pcrls, X509_CRL_free);
            *pcrls = NULL;
        }
        BIO_printf(err, "unable to load %s\n",
                   pcerts ? "certificates" : "CRLs");
        ERR_print_errors(err);
    }
    return rv;
}

STACK_OF(X509) *load_certs(BIO *err, const char *file, int format,
                            const char *pass, ENGINE *e, const char *desc)
{
    STACK_OF(X509) *certs;
    if (!load_certs_crls(err, file, format, pass, e, desc, &certs, NULL))
        return NULL;
    return certs;
}

STACK_OF(X509_CRL) *load_crls(BIO *err, const char *file, int format,
                               const char *pass, ENGINE *e, const char *desc)
{
    STACK_OF(X509_CRL) *crls;
    if (!load_certs_crls(err, file, format, pass, e, desc, NULL, &crls))
        return NULL;
    return crls;
}

#define X509V3_EXT_UNKNOWN_MASK (0xfL << 16)
/* Return error for unknown extensions */
#define X509V3_EXT_DEFAULT 0
/* Print error for unknown extensions */
#define X509V3_EXT_ERROR_UNKNOWN (1L << 16)
/* ASN1 parse unknown extensions */
#define X509V3_EXT_PARSE_UNKNOWN (2L << 16)
/* BIO_dump unknown extensions */
#define X509V3_EXT_DUMP_UNKNOWN (3L << 16)

#define X509_FLAG_CA                                                   \
    (X509_FLAG_NO_ISSUER | X509_FLAG_NO_PUBKEY | X509_FLAG_NO_HEADER | \
     X509_FLAG_NO_VERSION)

int set_cert_ex(unsigned long *flags, const char *arg)
{
    static const NAME_EX_TBL cert_tbl[] = {
        { "compatible", X509_FLAG_COMPAT, 0xffffffffl },
        { "ca_default", X509_FLAG_CA, 0xffffffffl },
        { "no_header", X509_FLAG_NO_HEADER, 0 },
        { "no_version", X509_FLAG_NO_VERSION, 0 },
        { "no_serial", X509_FLAG_NO_SERIAL, 0 },
        { "no_signame", X509_FLAG_NO_SIGNAME, 0 },
        { "no_validity", X509_FLAG_NO_VALIDITY, 0 },
        { "no_subject", X509_FLAG_NO_SUBJECT, 0 },
        { "no_issuer", X509_FLAG_NO_ISSUER, 0 },
        { "no_pubkey", X509_FLAG_NO_PUBKEY, 0 },
        { "no_extensions", X509_FLAG_NO_EXTENSIONS, 0 },
        { "no_sigdump", X509_FLAG_NO_SIGDUMP, 0 },
        { "no_aux", X509_FLAG_NO_AUX, 0 },
        { "no_attributes", X509_FLAG_NO_ATTRIBUTES, 0 },
        { "ext_default", X509V3_EXT_DEFAULT, X509V3_EXT_UNKNOWN_MASK },
        { "ext_error", X509V3_EXT_ERROR_UNKNOWN, X509V3_EXT_UNKNOWN_MASK },
        { "ext_parse", X509V3_EXT_PARSE_UNKNOWN, X509V3_EXT_UNKNOWN_MASK },
        { "ext_dump", X509V3_EXT_DUMP_UNKNOWN, X509V3_EXT_UNKNOWN_MASK },
        { NULL, 0, 0 }
    };
    return set_multi_opts(flags, arg, cert_tbl);
}

int set_name_ex(unsigned long *flags, const char *arg)
{
    static const NAME_EX_TBL ex_tbl[] = {
        { "esc_2253", ASN1_STRFLGS_ESC_2253, 0 },
        { "esc_ctrl", ASN1_STRFLGS_ESC_CTRL, 0 },
        { "esc_msb", ASN1_STRFLGS_ESC_MSB, 0 },
        { "use_quote", ASN1_STRFLGS_ESC_QUOTE, 0 },
        { "utf8", ASN1_STRFLGS_UTF8_CONVERT, 0 },
        { "ignore_type", ASN1_STRFLGS_IGNORE_TYPE, 0 },
        { "show_type", ASN1_STRFLGS_SHOW_TYPE, 0 },
        { "dump_all", ASN1_STRFLGS_DUMP_ALL, 0 },
        { "dump_nostr", ASN1_STRFLGS_DUMP_UNKNOWN, 0 },
        { "dump_der", ASN1_STRFLGS_DUMP_DER, 0 },
        { "compat", XN_FLAG_COMPAT, 0xffffffffL },
        { "sep_comma_plus", XN_FLAG_SEP_COMMA_PLUS, XN_FLAG_SEP_MASK },
        { "sep_comma_plus_space", XN_FLAG_SEP_CPLUS_SPC, XN_FLAG_SEP_MASK },
        { "sep_semi_plus_space", XN_FLAG_SEP_SPLUS_SPC, XN_FLAG_SEP_MASK },
        { "sep_multiline", XN_FLAG_SEP_MULTILINE, XN_FLAG_SEP_MASK },
        { "dn_rev", XN_FLAG_DN_REV, 0 },
        { "nofname", XN_FLAG_FN_NONE, XN_FLAG_FN_MASK },
        { "sname", XN_FLAG_FN_SN, XN_FLAG_FN_MASK },
        { "lname", XN_FLAG_FN_LN, XN_FLAG_FN_MASK },
        { "align", XN_FLAG_FN_ALIGN, 0 },
        { "oid", XN_FLAG_FN_OID, XN_FLAG_FN_MASK },
        { "space_eq", XN_FLAG_SPC_EQ, 0 },
        { "dump_unknown", XN_FLAG_DUMP_UNKNOWN_FIELDS, 0 },
        { "RFC2253", XN_FLAG_RFC2253, 0xffffffffL },
        { "oneline", XN_FLAG_ONELINE, 0xffffffffL },
        { "multiline", XN_FLAG_MULTILINE, 0xffffffffL },
        { "ca_default", XN_FLAG_MULTILINE, 0xffffffffL },
        { NULL, 0, 0 }
    };
    if (set_multi_opts(flags, arg, ex_tbl) == 0)
        return 0;
    if ((*flags & XN_FLAG_SEP_MASK) == 0)
        *flags |= XN_FLAG_SEP_CPLUS_SPC;
    return 1;
}

int set_ext_copy(int *copy_type, const char *arg)
{
    if (!strcasecmp(arg, "none"))
        *copy_type = EXT_COPY_NONE;
    else if (!strcasecmp(arg, "copy"))
        *copy_type = EXT_COPY_ADD;
    else if (!strcasecmp(arg, "copyall"))
        *copy_type = EXT_COPY_ALL;
    else
        return 0;
    return 1;
}

int copy_extensions(X509 *x, X509_REQ *req, int copy_type)
{
    STACK_OF(X509_EXTENSION) *exts = NULL;
    X509_EXTENSION *ext, *tmpext;
    ASN1_OBJECT *obj;
    int i, idx, ret = 0;
    if (!x || !req || (copy_type == EXT_COPY_NONE))
        return 1;
    exts = X509_REQ_get_extensions(req);

    for (i = 0; i < sk_X509_EXTENSION_num(exts); i++) {
        ext = sk_X509_EXTENSION_value(exts, i);
        obj = X509_EXTENSION_get_object(ext);
        idx = X509_get_ext_by_OBJ(x, obj, -1);
        /* Does extension exist? */
        if (idx != -1) {
            /* If normal copy don't override existing extension */
            if (copy_type == EXT_COPY_ADD)
                continue;
            /* Delete all extensions of same type */
            do {
                tmpext = X509_get_ext(x, idx);
                X509_delete_ext(x, idx);
                X509_EXTENSION_free(tmpext);
                idx = X509_get_ext_by_OBJ(x, obj, -1);
            } while (idx != -1);
        }
        if (!X509_add_ext(x, ext, -1))
            goto end;
    }

    ret = 1;

end:

    sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free);

    return ret;
}

static int set_multi_opts(unsigned long *flags, const char *arg,
                          const NAME_EX_TBL *in_tbl)
{
    STACK_OF(CONF_VALUE) *vals;
    CONF_VALUE *val;
    int i, ret = 1;
    if (!arg)
        return 0;
    vals = X509V3_parse_list(arg);
    for (i = 0; i < sk_CONF_VALUE_num(vals); i++) {
        val = sk_CONF_VALUE_value(vals, i);
        if (!set_table_opts(flags, val->name, in_tbl))
            ret = 0;
    }
    sk_CONF_VALUE_pop_free(vals, X509V3_conf_free);
    return ret;
}

static int set_table_opts(unsigned long *flags, const char *arg,
                          const NAME_EX_TBL *in_tbl)
{
    char c;
    const NAME_EX_TBL *ptbl;
    c = arg[0];

    if (c == '-') {
        c = 0;
        arg++;
    } else if (c == '+') {
        c = 1;
        arg++;
    } else
        c = 1;

    for (ptbl = in_tbl; ptbl->name; ptbl++) {
        if (!strcasecmp(arg, ptbl->name)) {
            *flags &= ~ptbl->mask;
            if (c)
                *flags |= ptbl->flag;
            else
                *flags &= ~ptbl->flag;
            return 1;
        }
    }
    return 0;
}

void print_name(BIO *out, const char *title, X509_NAME *nm,
                unsigned long lflags)
{
    char *buf;
    char mline = 0;
    int indent = 0;

    if (title)
        BIO_puts(out, title);
    if ((lflags & XN_FLAG_SEP_MASK) == XN_FLAG_SEP_MULTILINE) {
        mline = 1;
        indent = 4;
    }
    if (lflags == XN_FLAG_COMPAT) {
        buf = X509_NAME_oneline(nm, 0, 0);
        BIO_puts(out, buf);
        BIO_puts(out, "\n");
        free(buf);
    } else {
        if (mline)
            BIO_puts(out, "\n");
        X509_NAME_print_ex(out, nm, indent, lflags);
        BIO_puts(out, "\n");
    }
}

X509_STORE *setup_verify(BIO *bp, char *CAfile, char *CApath)
{
    X509_STORE *store;
    X509_LOOKUP *lookup;
    if (!(store = X509_STORE_new()))
        goto end;
    lookup = X509_STORE_add_lookup(store, X509_LOOKUP_file());
    if (lookup == NULL)
        goto end;
    if (CAfile) {
        if (!X509_LOOKUP_load_file(lookup, CAfile, X509_FILETYPE_PEM)) {
            BIO_printf(bp, "Error loading file %s\n", CAfile);
            goto end;
        }
    } else
        X509_LOOKUP_load_file(lookup, NULL, X509_FILETYPE_DEFAULT);

    lookup = X509_STORE_add_lookup(store, X509_LOOKUP_hash_dir());
    if (lookup == NULL)
        goto end;
    if (CApath) {
        if (!X509_LOOKUP_add_dir(lookup, CApath, X509_FILETYPE_PEM)) {
            BIO_printf(bp, "Error loading directory %s\n", CApath);
            goto end;
        }
    } else
        X509_LOOKUP_add_dir(lookup, NULL, X509_FILETYPE_DEFAULT);

    ERR_clear_error();
    return store;
end:
    X509_STORE_free(store);
    return NULL;
}

#ifndef OPENSSL_NO_ENGINE
ENGINE *setup_engine(BIO *err, const char *engine, int debug)
{
    ENGINE *e = NULL;

    if (engine) {
        if (strcmp(engine, "auto") == 0) {
            BIO_printf(err, "enabling auto ENGINE support\n");
            ENGINE_register_all_complete();
            return NULL;
        }
        if ((e = ENGINE_by_id(engine)) == NULL) {
            BIO_printf(err, "invalid engine \"%s\"\n", engine);
            ERR_print_errors(err);
            return NULL;
        }
        if (debug) {
            ENGINE_ctrl(e, ENGINE_CTRL_SET_LOGSTREAM, 0, err, 0);
        }
        ENGINE_ctrl_cmd(e, "SET_USER_INTERFACE", 0, ui_method, 0, 1);
        if (!ENGINE_set_default(e, ENGINE_METHOD_ALL)) {
            BIO_printf(err, "can't use that engine\n");
            ERR_print_errors(err);
            ENGINE_free(e);
            return NULL;
        }

        BIO_printf(err, "engine \"%s\" set.\n", ENGINE_get_id(e));

        /* Free our "structural" reference. */
        ENGINE_free(e);
    }
    return e;
}
#endif

int load_config(BIO *err, CONF *cnf)
{
    static int load_config_called = 0;
    if (load_config_called)
        return 1;
    load_config_called = 1;
    if (!cnf)
        cnf = config;
    if (!cnf)
        return 1;

    OPENSSL_load_builtin_modules();

    if (CONF_modules_load(cnf, NULL, 0) <= 0) {
        BIO_printf(err, "Error configuring OpenSSL\n");
        ERR_print_errors(err);
        return 0;
    }
    return 1;
}

char *make_config_name(void)
{
    const char *t = X509_get_default_cert_area();
    char *p;

    if (asprintf(&p, "%s/openssl.cnf", t) == -1)
        return NULL;

    return p;
}

static unsigned long index_serial_hash(const OPENSSL_CSTRING *a)
{
    const char *n;

    n = a[DB_serial];
    do {
        n++;
    } while (*n == '0');

    return (lh_strhash(n));
}

static int index_serial_cmp(const OPENSSL_CSTRING *a, const OPENSSL_CSTRING *b)
{
    const char *aa, *bb;

    for (aa = a[DB_serial]; *aa == '0'; aa++)
        ;
    for (bb = b[DB_serial]; *bb == '0'; bb++)
        ;
    return (strcmp(aa, bb));
}

static int index_name_qual(char **a)
{
    return (a[0][0] == 'V');
}

static unsigned long index_name_hash(const OPENSSL_CSTRING *a)
{
    return (lh_strhash(a[DB_name]));
}

int index_name_cmp(const OPENSSL_CSTRING *a, const OPENSSL_CSTRING *b)
{
    return (strcmp(a[DB_name], b[DB_name]));
}

static IMPLEMENT_LHASH_HASH_FN(index_serial, OPENSSL_CSTRING) static IMPLEMENT_LHASH_COMP_FN(
    index_serial,
    OPENSSL_CSTRING) static IMPLEMENT_LHASH_HASH_FN(index_name,
                                                    OPENSSL_CSTRING) static IMPLEMENT_LHASH_COMP_FN(index_name,
                                                                                                    OPENSSL_CSTRING)

#undef BSIZE
#define BSIZE 256

    BIGNUM *load_serial(char *serialfile, int create, ASN1_INTEGER **retai)
{
    BIO *in = NULL;
    BIGNUM *ret = NULL;
    char buf[1024];
    ASN1_INTEGER *ai = NULL;

    ai = ASN1_INTEGER_new();
    if (ai == NULL)
        goto err;

    if ((in = BIO_new(BIO_s_file())) == NULL) {
        ERR_print_errors(bio_err);
        goto err;
    }

    if (BIO_read_filename(in, serialfile) <= 0) {
        if (!create) {
            perror(serialfile);
            goto err;
        } else {
            ret = BN_new();
            if (ret == NULL || !rand_serial(ret, ai))
                BIO_printf(bio_err, "Out of memory\n");
        }
    } else {
        if (!a2i_ASN1_INTEGER(in, ai, buf, 1024)) {
            BIO_printf(bio_err, "unable to load number from %s\n", serialfile);
            goto err;
        }
        ret = ASN1_INTEGER_to_BN(ai, NULL);
        if (ret == NULL) {
            BIO_printf(bio_err, "error converting number from bin to BIGNUM\n");
            goto err;
        }
    }

    if (ret && retai) {
        *retai = ai;
        ai = NULL;
    }
err:
    if (in != NULL)
        BIO_free(in);
    if (ai != NULL)
        ASN1_INTEGER_free(ai);
    return (ret);
}

int save_serial(char *serialfile, char *suffix, BIGNUM *serial,
                ASN1_INTEGER **retai)
{
    char buf[1][BSIZE];
    BIO *out = NULL;
    int ret = 0;
    ASN1_INTEGER *ai = NULL;
    int j;

    if (suffix == NULL)
        j = strlen(serialfile);
    else
        j = strlen(serialfile) + strlen(suffix) + 1;
    if (j >= BSIZE) {
        BIO_printf(bio_err, "file name too long\n");
        goto err;
    }

    if (suffix == NULL)
        strlcpy(buf[0], serialfile, BSIZE);
    else
        j = snprintf(buf[0], sizeof buf[0], "%s.%s", serialfile, suffix);

    out = BIO_new(BIO_s_file());
    if (out == NULL) {
        ERR_print_errors(bio_err);
        goto err;
    }
    if (BIO_write_filename(out, buf[0]) <= 0) {
        perror(serialfile);
        goto err;
    }

    if ((ai = BN_to_ASN1_INTEGER(serial, NULL)) == NULL) {
        BIO_printf(bio_err, "error converting serial to ASN.1 format\n");
        goto err;
    }
    i2a_ASN1_INTEGER(out, ai);
    BIO_puts(out, "\n");
    ret = 1;
    if (retai) {
        *retai = ai;
        ai = NULL;
    }
err:
    if (out != NULL)
        BIO_free_all(out);
    if (ai != NULL)
        ASN1_INTEGER_free(ai);
    return (ret);
}

int rotate_serial(char *serialfile, char *new_suffix, char *old_suffix)
{
    char buf[5][BSIZE];
    int i, j;

    i = strlen(serialfile) + strlen(old_suffix);
    j = strlen(serialfile) + strlen(new_suffix);
    if (i > j)
        j = i;
    if (j + 1 >= BSIZE) {
        BIO_printf(bio_err, "file name too long\n");
        goto err;
    }

    j = snprintf(buf[0], sizeof buf[0], "%s.%s", serialfile, new_suffix);
    j = snprintf(buf[1], sizeof buf[1], "%s.%s", serialfile, old_suffix);

    if (rename(serialfile, buf[1]) < 0 && errno != ENOENT && errno != ENOTDIR) {

        BIO_printf(bio_err, "unable to rename %s to %s\n", serialfile, buf[1]);
        perror("reason");
        goto err;
    }
    if (rename(buf[0], serialfile) < 0) {
        BIO_printf(bio_err, "unable to rename %s to %s\n", buf[0], serialfile);
        perror("reason");
        if (rename(buf[1], serialfile) < 0) {
            BIO_printf(bio_err, "unable to rename %s to %s\n", buf[1], serialfile);
            perror("reason");
        }
        goto err;
    }
    return 1;
err:
    return 0;
}

int rand_serial(BIGNUM *b, ASN1_INTEGER *ai)
{
    BIGNUM *btmp;
    int ret = 0;
    if (b)
        btmp = b;
    else
        btmp = BN_new();

    if (!btmp)
        return 0;

    if (!BN_pseudo_rand(btmp, SERIAL_RAND_BITS, 0, 0))
        goto error;
    if (ai && !BN_to_ASN1_INTEGER(btmp, ai))
        goto error;

    ret = 1;

error:

    if (!b)
        BN_free(btmp);

    return ret;
}

CA_DB *load_index(char *dbfile, DB_ATTR *db_attr)
{
    CA_DB *retdb = NULL;
    TXT_DB *tmpdb = NULL;
    BIO *in = BIO_new(BIO_s_file());
    CONF *dbattr_conf = NULL;
    char buf[1][BSIZE];
    long errorline = -1;

    if (in == NULL) {
        ERR_print_errors(bio_err);
        goto err;
    }
    if (BIO_read_filename(in, dbfile) <= 0) {
        perror(dbfile);
        BIO_printf(bio_err, "unable to open '%s'\n", dbfile);
        goto err;
    }
    if ((tmpdb = TXT_DB_read(in, DB_NUMBER)) == NULL)
        goto err;

    snprintf(buf[0], sizeof buf[0], "%s.attr", dbfile);
    dbattr_conf = NCONF_new(NULL);
    if (NCONF_load(dbattr_conf, buf[0], &errorline) <= 0) {
        if (errorline > 0) {
            BIO_printf(bio_err, "error on line %ld of db attribute file '%s'\n",
                       errorline, buf[0]);
            goto err;
        } else {
            NCONF_free(dbattr_conf);
            dbattr_conf = NULL;
        }
    }

    if ((retdb = malloc(sizeof(CA_DB))) == NULL) {
        fprintf(stderr, "Out of memory\n");
        goto err;
    }

    retdb->db = tmpdb;
    tmpdb = NULL;
    if (db_attr)
        retdb->attributes = *db_attr;
    else {
        retdb->attributes.unique_subject = 1;
    }

    if (dbattr_conf) {
        char *p = NCONF_get_string(dbattr_conf, NULL, "unique_subject");
        if (p)
            retdb->attributes.unique_subject = parse_yesno(p, 1);
    }

err:
    if (dbattr_conf)
        NCONF_free(dbattr_conf);
    if (tmpdb)
        TXT_DB_free(tmpdb);
    if (in)
        BIO_free_all(in);
    return retdb;
}

int index_index(CA_DB *db)
{
    if (!TXT_DB_create_index(db->db, DB_serial, NULL,
                             LHASH_HASH_FN(index_serial),
                             LHASH_COMP_FN(index_serial))) {

        BIO_printf(bio_err,
                   "error creating serial number index:(%ld,%ld,%ld)\n",
                   db->db->error, db->db->arg1, db->db->arg2);
        return 0;
    }

    if (db->attributes.unique_subject &&
        !TXT_DB_create_index(db->db, DB_name, index_name_qual,
                             LHASH_HASH_FN(index_name),
                             LHASH_COMP_FN(index_name))) {

        BIO_printf(bio_err, "error creating name index:(%ld,%ld,%ld)\n",
                   db->db->error, db->db->arg1, db->db->arg2);
        return 0;
    }
    return 1;
}

int save_index(const char *dbfile, const char *suffix, CA_DB *db)
{
    char buf[3][BSIZE];
    BIO *out = BIO_new(BIO_s_file());
    int j;

    if (out == NULL) {
        ERR_print_errors(bio_err);
        goto err;
    }

    j = strlen(dbfile) + strlen(suffix);
    if (j + 6 >= BSIZE) {
        BIO_printf(bio_err, "file name too long\n");
        goto err;
    }

    j = snprintf(buf[2], sizeof buf[2], "%s.attr", dbfile);
    j = snprintf(buf[1], sizeof buf[1], "%s.attr.%s", dbfile, suffix);
    j = snprintf(buf[0], sizeof buf[0], "%s.%s", dbfile, suffix);

    if (BIO_write_filename(out, buf[0]) <= 0) {
        perror(dbfile);
        BIO_printf(bio_err, "unable to open '%s'\n", dbfile);
        goto err;
    }
    j = TXT_DB_write(out, db->db);
    if (j <= 0)
        goto err;

    BIO_free(out);

    out = BIO_new(BIO_s_file());
    if (BIO_write_filename(out, buf[1]) <= 0) {
        perror(buf[2]);
        BIO_printf(bio_err, "unable to open '%s'\n", buf[2]);
        goto err;
    }
    BIO_printf(out, "unique_subject = %s\n",
               db->attributes.unique_subject ? "yes" : "no");
    BIO_free(out);

    return 1;
err:
    return 0;
}

int rotate_index(const char *dbfile, const char *new_suffix,
                 const char *old_suffix)
{
    char buf[5][BSIZE];
    int i, j;

    i = strlen(dbfile) + strlen(old_suffix);
    j = strlen(dbfile) + strlen(new_suffix);
    if (i > j)
        j = i;
    if (j + 6 >= BSIZE) {
        BIO_printf(bio_err, "file name too long\n");
        goto err;
    }

    j = snprintf(buf[4], sizeof buf[4], "%s.attr", dbfile);
    j = snprintf(buf[2], sizeof buf[2], "%s.attr.%s", dbfile, new_suffix);
    j = snprintf(buf[0], sizeof buf[0], "%s.%s", dbfile, new_suffix);
    j = snprintf(buf[1], sizeof buf[1], "%s.%s", dbfile, old_suffix);
    j = snprintf(buf[3], sizeof buf[3], "%s.attr.%s", dbfile, old_suffix);
    if (rename(dbfile, buf[1]) < 0 && errno != ENOENT && errno != ENOTDIR) {

        BIO_printf(bio_err, "unable to rename %s to %s\n", dbfile, buf[1]);
        perror("reason");
        goto err;
    }
    if (rename(buf[0], dbfile) < 0) {
        BIO_printf(bio_err, "unable to rename %s to %s\n", buf[0], dbfile);
        perror("reason");
        if (rename(buf[1], dbfile) < 0) {
            BIO_printf(bio_err, "unable to rename %s to %s\n", buf[1], dbfile);
            perror("reason");
        }
        goto err;
    }
    if (rename(buf[4], buf[3]) < 0 && errno != ENOENT && errno != ENOTDIR) {
        BIO_printf(bio_err, "unable to rename %s to %s\n", buf[4], buf[3]);
        perror("reason");
        if (rename(dbfile, buf[0]) < 0) {
            BIO_printf(bio_err, "unable to rename %s to %s\n", dbfile, buf[0]);
            perror("reason");
        }
        if (rename(buf[1], dbfile) < 0) {
            BIO_printf(bio_err, "unable to rename %s to %s\n", buf[1], dbfile);
            perror("reason");
        }
        goto err;
    }
    if (rename(buf[2], buf[4]) < 0) {
        BIO_printf(bio_err, "unable to rename %s to %s\n", buf[2], buf[4]);
        perror("reason");
        if (rename(buf[3], buf[4]) < 0) {
            BIO_printf(bio_err, "unable to rename %s to %s\n", buf[3], buf[4]);
            perror("reason");
        }
        if (rename(dbfile, buf[0]) < 0) {
            BIO_printf(bio_err, "unable to rename %s to %s\n", dbfile, buf[0]);
            perror("reason");
        }
        if (rename(buf[1], dbfile) < 0) {
            BIO_printf(bio_err, "unable to rename %s to %s\n", buf[1], dbfile);
            perror("reason");
        }
        goto err;
    }
    return 1;
err:
    return 0;
}

void free_index(CA_DB *db)
{
    if (db) {
        if (db->db)
            TXT_DB_free(db->db);
        free(db);
    }
}

int parse_yesno(const char *str, int def)
{
    int ret = def;
    if (str) {
        switch (*str) {
            case 'f': /* false */
            case 'F': /* FALSE */
            case 'n': /* no */
            case 'N': /* NO */
            case '0': /* 0 */
                ret = 0;
                break;
            case 't': /* true */
            case 'T': /* TRUE */
            case 'y': /* yes */
            case 'Y': /* YES */
            case '1': /* 1 */
                ret = 1;
                break;
            default:
                ret = def;
                break;
        }
    }
    return ret;
}

/*
 * subject is expected to be in the format /type0=value0/type1=value1/type2=...
 * where characters may be escaped by \
 */
X509_NAME *parse_name(char *subject, long chtype, int multirdn)
{
    size_t buflen = strlen(subject) + 1; /* to copy the types and values into.
                                            due to escaping, the copy can only
                                            become shorter */
    char *buf = malloc(buflen);
    size_t max_ne = buflen / 2 + 1; /* maximum number of name elements */
    char **ne_types = reallocarray(NULL, max_ne, sizeof(char *));
    char **ne_values = reallocarray(NULL, max_ne, sizeof(char *));
    int *mval = reallocarray(NULL, max_ne, sizeof(int));

    char *sp = subject, *bp = buf;
    int i, ne_num = 0;

    X509_NAME *n = NULL;
    int nid;

    if (!buf || !ne_types || !ne_values || !mval) {
        BIO_printf(bio_err, "malloc error\n");
        goto error;
    }

    if (*subject != '/') {
        BIO_printf(bio_err, "Subject does not start with '/'.\n");
        goto error;
    }
    sp++; /* skip leading / */

    /* no multivalued RDN by default */
    mval[ne_num] = 0;

    do {
        /* collect type */
        ne_types[ne_num] = bp;
        do {
            if (*sp == '\\') { /* is there anything to escape in the type...? */
                if (*++sp)
                    *bp++ = *sp++;
                else {
                    BIO_printf(bio_err, "escape character at end of string\n");
                    goto error;
                }
            } else if (*sp == '=') {
                sp++;
                *bp++ = '\0';
                break;
            } else
                *bp++ = *sp++;
        } while (*sp);
        if (!*sp) {
            BIO_printf(bio_err, "end of string encountered while processing "
                                "type of subject name element #%d\n",
                       ne_num);
            goto error;
        }
        ne_values[ne_num] = bp;
        do {
            if (*sp == '\\') {
                if (*++sp)
                    *bp++ = *sp++;
                else {
                    BIO_printf(bio_err, "escape character at end of string\n");
                    goto error;
                }
            } else if (*sp == '/') {
                sp++;
                /* no multivalued RDN by default */
                mval[ne_num + 1] = 0;
                break;
            } else if (*sp == '+' && multirdn) {
                /* a not escaped + signals a multivalued RDN */
                sp++;
                mval[ne_num + 1] = -1;
                break;
            } else
                *bp++ = *sp++;
        } while (*sp);
        *bp++ = '\0';
        ne_num++;
    } while (*sp);

    if (!(n = X509_NAME_new()))
        goto error;

    for (i = 0; i < ne_num; i++) {
        if ((nid = OBJ_txt2nid(ne_types[i])) == NID_undef) {
            BIO_printf(bio_err,
                       "Subject Attribute %s has no known NID, skipped\n",
                       ne_types[i]);
            continue;
        }

        if (!*ne_values[i]) {
            BIO_printf(bio_err,
                       "No value provided for Subject Attribute %s, skipped\n",
                       ne_types[i]);
            continue;
        }

        if (!X509_NAME_add_entry_by_NID(n, nid, chtype, (uint8_t *)ne_values[i],
                                        -1, -1, mval[i]))
            goto error;
    }

    free(ne_values);
    free(ne_types);
    free(buf);
    free(mval);
    return n;

error:
    X509_NAME_free(n);
    if (ne_values)
        free(ne_values);
    if (ne_types)
        free(ne_types);
    if (mval)
        free(mval);
    if (buf)
        free(buf);
    return NULL;
}

int args_verify(char ***pargs, int *pargc, int *badarg, BIO *err,
                X509_VERIFY_PARAM **pm)
{
    ASN1_OBJECT *otmp = NULL;
    unsigned long flags = 0;
    int i;
    const char *stnerr = NULL;
    int purpose = 0, depth = -1;
    char **oldargs = *pargs;
    char *arg = **pargs, *argn = (*pargs)[1];
    time_t at_time = 0;
    const char *hostname = NULL;
    const char *email = NULL;
    char *ipasc = NULL;
    if (!strcmp(arg, "-policy")) {
        if (!argn)
            *badarg = 1;
        else {
            otmp = OBJ_txt2obj(argn, 0);
            if (!otmp) {
                BIO_printf(err, "Invalid Policy \"%s\"\n", argn);
                *badarg = 1;
            }
        }
        (*pargs)++;
    } else if (strcmp(arg, "-purpose") == 0) {
        X509_PURPOSE *xptmp;
        if (!argn)
            *badarg = 1;
        else {
            i = X509_PURPOSE_get_by_sname(argn);
            if (i < 0) {
                BIO_printf(err, "unrecognized purpose\n");
                *badarg = 1;
            } else {
                xptmp = X509_PURPOSE_get0(i);
                purpose = X509_PURPOSE_get_id(xptmp);
            }
        }
        (*pargs)++;
    } else if (strcmp(arg, "-verify_depth") == 0) {
        if (!argn)
            *badarg = 1;
        else {
            depth = strtonum(argn, 1, INT_MAX, &stnerr);
            if (stnerr) {
                BIO_printf(err, "invalid depth: depth=%s, errmsg=%s\n", argn,
                           stnerr);
                *badarg = 1;
            }
        }
        (*pargs)++;
    } else if (strcmp(arg, "-attime") == 0) {
        if (!argn)
            *badarg = 1;
        else {
            long timestamp;
            /* interpret the -attime argument as seconds since
             * Epoch */
            if (sscanf(argn, "%li", &timestamp) != 1) {
                BIO_printf(bio_err, "Error parsing timestamp %s\n", argn);
                *badarg = 1;
            }
            /* on some platforms time_t may be a float */
            at_time = (time_t)timestamp;
        }
        (*pargs)++;
    } else if (strcmp(arg, "-verify_hostname") == 0) {
        if (!argn)
            *badarg = 1;
        hostname = argn;
        (*pargs)++;
    } else if (strcmp(arg, "-verify_email") == 0) {
        if (!argn)
            *badarg = 1;
        email = argn;
        (*pargs)++;
    } else if (strcmp(arg, "-verify_ip") == 0) {
        if (!argn)
            *badarg = 1;
        ipasc = argn;
        (*pargs)++;
    } else if (!strcmp(arg, "-ignore_critical"))
        flags |= X509_V_FLAG_IGNORE_CRITICAL;
    else if (!strcmp(arg, "-issuer_checks"))
        flags |= X509_V_FLAG_CB_ISSUER_CHECK;
    else if (!strcmp(arg, "-crl_check"))
        flags |= X509_V_FLAG_CRL_CHECK;
    else if (!strcmp(arg, "-crl_check_all"))
        flags |= X509_V_FLAG_CRL_CHECK | X509_V_FLAG_CRL_CHECK_ALL;
    else if (!strcmp(arg, "-policy_check"))
        flags |= X509_V_FLAG_POLICY_CHECK;
    else if (!strcmp(arg, "-explicit_policy"))
        flags |= X509_V_FLAG_EXPLICIT_POLICY;
    else if (!strcmp(arg, "-inhibit_any"))
        flags |= X509_V_FLAG_INHIBIT_ANY;
    else if (!strcmp(arg, "-inhibit_map"))
        flags |= X509_V_FLAG_INHIBIT_MAP;
    else if (!strcmp(arg, "-x509_strict"))
        flags |= X509_V_FLAG_X509_STRICT;
    else if (!strcmp(arg, "-extended_crl"))
        flags |= X509_V_FLAG_EXTENDED_CRL_SUPPORT;
    else if (!strcmp(arg, "-use_deltas"))
        flags |= X509_V_FLAG_USE_DELTAS;
    else if (!strcmp(arg, "-policy_print"))
        flags |= X509_V_FLAG_NOTIFY_POLICY;
    else if (!strcmp(arg, "-check_ss_sig"))
        flags |= X509_V_FLAG_CHECK_SS_SIGNATURE;
    else if (!strcmp(arg, "-trusted_first"))
        flags |= X509_V_FLAG_TRUSTED_FIRST;
    else if (!strcmp(arg, "-suiteB_128_only"))
        flags |= X509_V_FLAG_SUITEB_128_LOS_ONLY;
    else if (!strcmp(arg, "-suiteB_128"))
        flags |= X509_V_FLAG_SUITEB_128_LOS;
    else if (!strcmp(arg, "-suiteB_192"))
        flags |= X509_V_FLAG_SUITEB_192_LOS;
    else if (!strcmp(arg, "-partial_chain"))
        flags |= X509_V_FLAG_PARTIAL_CHAIN;
    else if (!strcmp(arg, "-no_alt_chains"))
        flags |= X509_V_FLAG_NO_ALT_CHAINS;
    else
        return 0;

    if (*badarg) {
        if (*pm)
            X509_VERIFY_PARAM_free(*pm);
        *pm = NULL;
        goto end;
    }

    if (!*pm && !(*pm = X509_VERIFY_PARAM_new())) {
        *badarg = 1;
        goto end;
    }

    if (otmp)
        X509_VERIFY_PARAM_add0_policy(*pm, otmp);
    if (flags)
        X509_VERIFY_PARAM_set_flags(*pm, flags);

    if (purpose)
        X509_VERIFY_PARAM_set_purpose(*pm, purpose);

    if (depth >= 0)
        X509_VERIFY_PARAM_set_depth(*pm, depth);

    if (at_time)
        X509_VERIFY_PARAM_set_time(*pm, at_time);
    
    if (hostname && !X509_VERIFY_PARAM_set1_host(*pm, hostname, 0))
        *badarg = 1;

    if (email && !X509_VERIFY_PARAM_set1_email(*pm, email, 0))
        *badarg = 1;

    if (ipasc && !X509_VERIFY_PARAM_set1_ip_asc(*pm, ipasc))
        *badarg = 1;

end:
    (*pargs)++;

    if (pargc)
        *pargc -= *pargs - oldargs;

    return 1;
}

/* Read whole contents of a BIO into an allocated memory buffer and
 * return it.
 */

int bio_to_mem(uint8_t **out, int maxlen, BIO *in)
{
    BIO *mem;
    int len, ret;
    uint8_t tbuf[1024];
    mem = BIO_new(BIO_s_mem());
    if (!mem)
        return -1;
    for (;;) {
        if ((maxlen != -1) && maxlen < 1024)
            len = maxlen;
        else
            len = 1024;
        len = BIO_read(in, tbuf, len);
        if (len < 0) {
            BIO_free(mem);
            return -1;
        }
        if (len == 0)
            break;
        if (BIO_write(mem, tbuf, len) != len) {
            BIO_free(mem);
            return -1;
        }
        maxlen -= len;

        if (maxlen == 0)
            break;
    }
    ret = BIO_get_mem_data(mem, (char **)out);
    BIO_set_flags(mem, BIO_FLAGS_MEM_RDONLY);
    BIO_free(mem);
    return ret;
}

int pkey_ctrl_string(EVP_PKEY_CTX *ctx, const char *value)
{
    int rv;
    char *stmp, *vtmp = NULL;
    stmp = strdup(value);
    if (!stmp)
        return -1;
    vtmp = strchr(stmp, ':');
    if (vtmp) {
        *vtmp = 0;
        vtmp++;
    }
    rv = EVP_PKEY_CTX_ctrl_str(ctx, stmp, vtmp);
    free(stmp);
    return rv;
}

static void nodes_print(BIO *out, const char *name,
                        STACK_OF(X509_POLICY_NODE) *nodes)
{
    X509_POLICY_NODE *node;
    int i;
    BIO_printf(out, "%s Policies:", name);
    if (nodes) {
        BIO_puts(out, "\n");
        for (i = 0; i < sk_X509_POLICY_NODE_num(nodes); i++) {
            node = sk_X509_POLICY_NODE_value(nodes, i);
            X509_POLICY_NODE_print(out, node, 2);
        }
    } else
        BIO_puts(out, " <empty>\n");
}

void policies_print(BIO *out, X509_STORE_CTX *ctx)
{
    X509_POLICY_TREE *tree;
    int explicit_policy;
    int free_out = 0;
    if (out == NULL) {
        out = BIO_new_fp(stderr, BIO_NOCLOSE);
        free_out = 1;
    }
    tree = X509_STORE_CTX_get0_policy_tree(ctx);
    explicit_policy = X509_STORE_CTX_get_explicit_policy(ctx);

    BIO_printf(out, "Require explicit Policy: %s\n",
               explicit_policy ? "True" : "False");

    nodes_print(out, "Authority", X509_policy_tree_get0_policies(tree));
    nodes_print(out, "User", X509_policy_tree_get0_user_policies(tree));
    if (free_out)
        BIO_free(out);
}

/* next_protos_parse parses a comma separated list of strings into a string
 * in a format suitable for passing to SSL_CTX_set_next_protos_advertised.
 *   outlen: (output) set to the length of the resulting buffer on success.
 *   err: (maybe NULL) on failure, an error message line is written to this BIO.
 *   in: a NUL terminated string like "abc,def,ghi"
 *
 *   returns: a malloced buffer or NULL on failure.
 */
uint8_t *next_protos_parse(unsigned short *outlen, const char *in)
{
    size_t len;
    uint8_t *out;
    size_t i, start = 0;

    len = strlen(in);
    if (len >= 65535)
        return NULL;

    out = malloc(strlen(in) + 1);
    if (!out)
        return NULL;

    for (i = 0; i <= len; ++i) {
        if (i == len || in[i] == ',') {
            if (i - start > 255) {
                free(out);
                return NULL;
            }
            out[start] = i - start;
            start = i + 1;
        } else
            out[i + 1] = in[i];
    }

    *outlen = len + 1;
    return out;
}

void print_cert_checks(BIO *bio, X509 *x, const char *checkhost,
                       const char *checkemail, const char *checkip)
{
    if (x == NULL)
        return;

    if (checkhost) {
        BIO_printf(bio, "Hostname %s does%s match certificate\n", checkhost,
                   X509_check_host(x, checkhost, 0, 0, NULL) == 1
                   ? "" : " NOT");
    }

    if (checkemail) {
        BIO_printf(bio, "Email %s does%s match certificate\n", checkemail,
                   X509_check_email(x, checkemail, 0, 0) ? "" : " NOT");
    }

    if (checkip) {
        BIO_printf(bio, "IP %s does%s match certificate\n", checkip,
                   X509_check_ip_asc(x, checkip, 0) ? "" : " NOT");
    }
}

int app_isdir(const char *name)
{
    struct stat st;

    if (stat(name, &st) == 0)
        return S_ISDIR(st.st_mode);
    else
        return -1;
}

#define OPT_WIDTH 5

void options_usage(struct OPTION *opts)
{
    const char *p, *q;
    char optstr[36];
    int i;

    for (i = 0; opts[i].name != NULL; i++) {
        if (opts[i].desc == NULL)
            continue;

        snprintf(optstr, sizeof optstr, "-%s %s", opts[i].name,
                 (opts[i].argname != NULL) ? opts[i].argname : "");
        fprintf(stderr, " %-*s", OPT_WIDTH, optstr);
        if (strlen(optstr) > OPT_WIDTH)
            fprintf(stderr, "\n %-*s", OPT_WIDTH, "");

        p = opts[i].desc;
        for (;;) {
            q = strchr(p, '\n');
            if (q == NULL)
                break;
            fprintf(stderr, " %.*s", (int)(q - p), p);
            fprintf(stderr, "\n %-*s", OPT_WIDTH, "");
            p = q + 1;
        }
        fprintf(stderr, " %s\n", p);
    }
}

int options_parse(int argc, char **argv, struct OPTION *opts, char **unnamed)
{
    struct OPTION *opt;
    char *arg, *p;
    int i, j;

    for (i = 1; i < argc; i++) {
        p = arg = argv[i];

        /* Handle arguments without a leading dash */
        if (*p++ != '-') {
            if (unnamed == NULL)
                goto unknown;
            *unnamed = arg;
            continue;
        }

        for (j = 0; opts[j].name != NULL; j++) {
            opt = &opts[j];
            if (strcmp(p, opt->name) != 0)
                continue;

            switch (opt->type) {
                case OPTION_FLAG:
                    *opt->opt.flag = 1;
                    break;

                case OPTION_FUNC:
                    if (opt->func(opt, NULL) != 0)
                        return (1);
                    break;

                default: /* invalid type */
                    fprintf(stderr, "option %s - unknown type %i\n", opt->name,
                            opt->type);
                    return (1);
            }

            break;
        }

        if (opts[j].name == NULL)
            goto unknown;
    }

    return (0);

unknown:
    fprintf(stderr, "unknown option '%s'\n", arg);
    return (1);
}
