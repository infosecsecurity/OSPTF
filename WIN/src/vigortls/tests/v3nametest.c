/*
 * Copyright (c) 2016, Kurt Cancemi (kurt@x64architecture.com)
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
 * Copyright 2012-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdcompat.h>
#include <string.h>
#include <strings.h>

#include <openssl/x509.h>
#include <openssl/x509v3.h>

#define NELEMS(x) sizeof(x) / sizeof(x[0])

static const char *names[] = {
    "a", "b", ".", "*", "@",
    ".a", "a.", ".b", "b.", ".*", "*.", "*@", "@*", "a@", "@a", "b@", "..",
    "-example.com", "example-.com",
    "@@", "**", "*.com", "*com", "*.*.com", "*com", "com*", "*example.com",
    "*@example.com", "test@*.example.com", "example.com", "www.example.com",
    "test.www.example.com", "*.example.com", "*.www.example.com",
    "test.*.example.com", "www.*.com",
    ".www.example.com", "*www.example.com",
    "example.com", "www.example.com", "test.www.example.com",
    "*.example.com", "*.www.example.com", "test.*.example.com", "www.*.com",
    "example.net", "xn--rger-koa.example.com",
    "*.xn--rger-koa.example.com", "www.xn--rger-koa.example.com",
    "*.good--example.com", "www.good--example.com",
    "*.xn--bar.com", "xn--foo.xn--bar.com",
    "a.example.com", "b.example.com",
    "postmaster@example.com", "Postmaster@example.com",
    "postmaster@EXAMPLE.COM",
};

static const char *exceptions[] = {
    "set CN: host: [*.example.com] matches [a.example.com]",
    "set CN: host: [*.example.com] matches [b.example.com]",
    "set CN: host: [*.example.com] matches [www.example.com]",
    "set CN: host: [*.example.com] matches [xn--rger-koa.example.com]",
    "set CN: host: [*.www.example.com] matches [test.www.example.com]",
    "set CN: host: [*.www.example.com] matches [.www.example.com]",
    "set CN: host: [*www.example.com] matches [www.example.com]",
    "set CN: host: [test.www.example.com] matches [.www.example.com]",
    "set CN: host: [*.xn--rger-koa.example.com] matches [www.xn--rger-koa.example.com]",
    "set CN: host: [*.xn--bar.com] matches [xn--foo.xn--bar.com]",
    "set CN: host: [*.good--example.com] matches [www.good--example.com]",
    "set CN: host-no-wildcards: [*.www.example.com] matches [.www.example.com]",
    "set CN: host-no-wildcards: [test.www.example.com] matches [.www.example.com]",
    "set emailAddress: email: [postmaster@example.com] does not match "
    "[Postmaster@example.com]",
    "set emailAddress: email: [postmaster@EXAMPLE.COM] does not match "
    "[Postmaster@example.com]",
    "set emailAddress: email: [Postmaster@example.com] does not match "
    "[postmaster@example.com]",
    "set emailAddress: email: [Postmaster@example.com] does not match "
    "[postmaster@EXAMPLE.COM]",
    "set dnsName: host: [*.example.com] matches [www.example.com]",
    "set dnsName: host: [*.example.com] matches [a.example.com]",
    "set dnsName: host: [*.example.com] matches [b.example.com]",
    "set dnsName: host: [*.example.com] matches [xn--rger-koa.example.com]",
    "set dnsName: host: [*.www.example.com] matches [test.www.example.com]",
    "set dnsName: host-no-wildcards: [*.www.example.com] matches [.www.example.com]",
    "set dnsName: host-no-wildcards: [test.www.example.com] matches [.www.example.com]",
    "set dnsName: host: [*.www.example.com] matches [.www.example.com]",
    "set dnsName: host: [*www.example.com] matches [www.example.com]",
    "set dnsName: host: [test.www.example.com] matches [.www.example.com]",
    "set dnsName: host: [*.xn--rger-koa.example.com] matches [www.xn--rger-koa.example.com]",
    "set dnsName: host: [*.xn--bar.com] matches [xn--foo.xn--bar.com]",
    "set dnsName: host: [*.good--example.com] matches [www.good--example.com]",
    "set rfc822Name: email: [postmaster@example.com] does not match "
    "[Postmaster@example.com]",
    "set rfc822Name: email: [Postmaster@example.com] does not match "
    "[postmaster@example.com]",
    "set rfc822Name: email: [Postmaster@example.com] does not match "
    "[postmaster@EXAMPLE.COM]",
    "set rfc822Name: email: [postmaster@EXAMPLE.COM] does not match "
    "[Postmaster@example.com]",
};

static int set_commonname(X509 *crt, int *nids, const char *cnames[], int numelems, int unused)
{
    int i, ret = 0;
    X509_NAME *n;

    n = X509_NAME_new();
    if (n == NULL)
        goto out;

    for (i = 0; i < numelems; i++) {
        int nid = nids[i];
        const char *name = cnames[i];
        if (nid == 0)
            break;
        if (!X509_NAME_add_entry_by_NID(n, nid, MBSTRING_ASC,
                                        (uint8_t *)name, -1, -1, 1))
            goto out;
    }
    if (!X509_set_subject_name(crt, n))
        goto out;
    ret = 1;
out:
    X509_NAME_free(n);
    return ret;
}

static int set_altname(X509 *crt, int *types, const char *anames[], int numelems, int unused)
{
    int i, ret = 0;
    GENERAL_NAME *gen = NULL;
    GENERAL_NAMES *gens = NULL;
    ASN1_IA5STRING *ia5 = NULL;

    gens = sk_GENERAL_NAME_new_null();
    if (gens == NULL)
        goto out;

    for (i = 0; i < numelems; i++) {
        int type = types[i];
        const char *name = anames[i];
        if (type == 0)
            break;

        gen = GENERAL_NAME_new();
        if (gen == NULL)
            goto out;
        ia5 = ASN1_IA5STRING_new();
        if (ia5 == NULL)
            goto out;
        if (!ASN1_STRING_set(ia5, name, -1))
            goto out;
        switch (type) {
            case GEN_EMAIL:
            case GEN_DNS:
                GENERAL_NAME_set0_value(gen, type, ia5);
                ia5 = NULL;
                break;
            default:
                abort();
        }
        sk_GENERAL_NAME_push(gens, gen);
        gen = NULL;
    }
    if (!X509_add1_ext_i2d(crt, NID_subject_alt_name, gens, 0, 0))
        goto out;
    ret = 1;
out:
    ASN1_IA5STRING_free(ia5);
    GENERAL_NAME_free(gen);
    GENERAL_NAMES_free(gens);
    return ret;
}

static int set_cn1(X509 *crt, const char *name)
{
    int nids[] = { NID_commonName };
    const char *cnames[] = { name };
    return set_commonname(crt, nids, cnames, NELEMS(nids), 0);
}

static int set_cn_and_email(X509 *crt, const char *name)
{
    int nids[] = { NID_commonName, NID_pkcs9_emailAddress };
    const char *cnames[] = { name, "dummy@example.com" };
    return set_commonname(crt, nids, cnames, NELEMS(nids), 0);
}

static int set_cn2(X509 *crt, const char *name)
{
    int nids[] = { NID_commonName, NID_commonName };
    const char *cnames[] = { "dummy value", name };
    return set_commonname(crt, nids, cnames, NELEMS(nids), 0);
}

static int set_cn3(X509 *crt, const char *name)
{
    int nids[] = { NID_commonName, NID_commonName };
    const char *cnames[] = { name, "dummy value" };
    return set_commonname(crt, nids, cnames, NELEMS(nids), 0);
}

static int set_email1(X509 *crt, const char *name)
{
    int nids[] = { NID_pkcs9_emailAddress };
    const char *cnames[] = { name };
    return set_commonname(crt, nids, cnames, NELEMS(nids), 0);
}

static int set_email2(X509 *crt, const char *name)
{
    int nids[] = { NID_pkcs9_emailAddress, NID_pkcs9_emailAddress };
    const char *cnames[] = { "dummy@example.com", name };
    return set_commonname(crt, nids, cnames, NELEMS(nids), 0);
}

static int set_email3(X509 *crt, const char *name)
{
    int nids[] = { NID_pkcs9_emailAddress, NID_pkcs9_emailAddress };
    const char *cnames[] = { name, "dummy@example.com" };
    return set_commonname(crt, nids, cnames, NELEMS(nids), 0);
}

static int set_email_and_cn(X509 *crt, const char *name)
{
    int nids[] = { NID_pkcs9_emailAddress, NID_commonName };
    const char *cnames[] = { name, "www.example.org" };
    return set_commonname(crt, nids, cnames, NELEMS(nids), 0);
}

static int set_altname_dns(X509 *crt, const char *name)
{
    int types[] = { GEN_DNS };
    const char *anames[] = { name };
    return set_altname(crt, types, anames, NELEMS(types), 0);
}

static int set_altname_email(X509 *crt, const char *name)
{
    int types[] = { GEN_EMAIL };
    const char *anames[] = { name };

    return set_altname(crt, types, anames, NELEMS(types), 0);
}

struct set_name_fn {
    int (*fn)(X509 *, const char *);
    const char *name;
    int host;
    int email;
};

static const struct set_name_fn name_fns[] = {
    { set_cn1, "set CN", 1, 0 },
    { set_cn2, "set CN", 1, 0 },
    { set_cn3, "set CN", 1, 0 },
    { set_cn_and_email, "set CN", 1, 0 },
    { set_email1, "set emailAddress", 0, 1 },
    { set_email2, "set emailAddress", 0, 1 },
    { set_email3, "set emailAddress", 0, 1 },
    { set_email_and_cn, "set emailAddress", 0, 1 },
    { set_altname_dns, "set dnsName", 1, 0 },
    { set_altname_email, "set rfc822Name", 0, 1 },
};

static X509 *make_cert()
{
    X509 *ret = NULL;
    X509 *crt = NULL;
    X509_NAME *issuer = NULL;

    crt = X509_new();
    if (crt == NULL)
        goto out;
    if (!X509_set_version(crt, 3))
        goto out;
    ret = crt;
    crt = NULL;
out:
    X509_NAME_free(issuer);
    return ret;
}

static int errors = 0;

static void check_message(const struct set_name_fn *fn, const char *op,
                          const char *nameincert, int match, const char *name)
{
    char *msg;
    int i, ret;

    if (match < 0)
        return;

    ret = asprintf(&msg, "%s: %s: [%s] %s [%s]", fn->name, op, nameincert,
              match ? "matches" : "does not match", name);
    if (ret == -1) {
        puts("malloc failure\n");
        abort();
    }

    for (i = 0; i < NELEMS(exceptions); i++) {
        if (strcmp(msg, exceptions[i]) == 0)
            return;
    }
    puts(msg);
    ++errors;
}

static void run_cert(X509 *crt, const char *nameincert,
                     const struct set_name_fn *fn)
{
    int i;

    for (i = 0; i < NELEMS(names); i++) {
        const char *const *pname = &names[i];
        int samename = strcasecmp(nameincert, *pname) == 0;
        size_t namelen = strlen(*pname);
        char *name = malloc(namelen);
        if (name == NULL) {
            fprintf(stderr, "malloc failure");
            ++errors;
        }
        int match, ret;
        memcpy(name, *pname, namelen);

        ret = X509_check_host(crt, name, namelen, 0, NULL);
        match = -1;
        if (ret < 0) {
            fprintf(stderr, "internal error in X509_check_host");
            ++errors;
        } else if (fn->host) {
            if (ret == 1 && !samename)
                match = 1;
            if (ret == 0 && samename)
                match = 0;
        } else if (ret == 1)
            match = 1;
        check_message(fn, "host", nameincert, match, *pname);

        ret = X509_check_host(crt, name, namelen, X509_CHECK_FLAG_NO_WILDCARDS,
                              NULL);
        match = -1;
        if (ret < 0) {
            fprintf(stderr, "internal error in X509_check_host");
            ++errors;
        } else if (fn->host) {
            if (ret == 1 && !samename)
                match = 1;
            if (ret == 0 && samename)
                match = 0;
        } else if (ret == 1)
            match = 1;
        check_message(fn, "host-no-wildcards", nameincert, match, *pname);

        ret = X509_check_email(crt, name, namelen, 0);
        match = -1;
        if (fn->email) {
            if (ret && !samename)
                match = 1;
            if (!ret && samename && strchr(nameincert, '@') != NULL)
                match = 0;
        } else if (ret)
            match = 1;
        check_message(fn, "email", nameincert, match, *pname);
        free(name);
    }
}

int main(void)
{
    int i, j;
    const struct set_name_fn *pfn = name_fns;
    for (i = 0; i < NELEMS(name_fns); i++) {
        const char *const *pname = &names[i];
        for (j = 0; j < NELEMS(names); j++) {
            X509 *crt = make_cert();
            if (crt == NULL) {
                fprintf(stderr, "make_cert failed\n");
                return 1;
            }
            if (!pfn->fn(crt, *pname)) {
                fprintf(stderr, "X509 name setting failed\n");
                return 1;
            }
            run_cert(crt, *pname, pfn);
            X509_free(crt);
        }
    }
    return errors > 0 ? 1 : 0;
}
