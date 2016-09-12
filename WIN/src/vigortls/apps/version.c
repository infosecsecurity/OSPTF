/*
 * Copyright (c) 2014 - 2016, Kurt Cancemi (kurt@x64architecture.com)
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>

#include <openssl/rc4.h>
#ifndef OPENSSL_NO_DES
#include <openssl/des.h>
#endif
#ifndef OPENSSL_NO_IDEA
#include <openssl/idea.h>
#endif
#ifndef OPENSSL_NO_BF
#include <openssl/blowfish.h>
#endif

#include "apps.h"
#include "buildinf.h"

static struct {
    int cflags;
    int date;
    int options;
    int platform;
    int version;
} version_opts;

static int version_print_all_opts(struct OPTION *opt, char *arg)
{
    version_opts.cflags = 1;
    version_opts.date = 1;
    version_opts.options = 1;
    version_opts.platform = 1;
    version_opts.version = 1;

    return (0);
}

static struct OPTION version_options[] = {
    {
        .name = "a",
        .desc = "Print all the information (equivalent to setting all the "
                "other flags)",
        .type = OPTION_FUNC,
        .func = version_print_all_opts,
    },
    {
        .name = "b",
        .desc = "Print the date the current version of VigorTLS was built",
        .type = OPTION_FLAG,
        .opt.flag = &version_opts.date,
    },
    {
        .name = "f",
        .desc = "Print the compilation flags",
        .type = OPTION_FLAG,
        .opt.flag = &version_opts.cflags,
    },
    {
        .name = "o",
        .desc = "Print the cipher options",
        .type = OPTION_FLAG,
        .opt.flag = &version_opts.options,
    },
    {
        .name = "p",
        .desc = "Print the Platform",
        .type = OPTION_FLAG,
        .opt.flag = &version_opts.platform,
    },
    {
        .name = "v",
        .desc = "Print the current VigorTLS version",
        .type = OPTION_FLAG,
        .opt.flag = &version_opts.version,
    },
};

static void version_usage(void)
{
    fprintf(stderr, "usage: version [-abfopv]\n");
    options_usage(version_options);
}

int version_main(int argc, char **argv)
{
    memset(&version_opts, 0, sizeof(version_opts));

    if (options_parse(argc, argv, version_options, NULL) != 0) {
        version_usage();
        return (1);
    }

    if (argc == 1)
        version_opts.version = 1;

    if (version_opts.version)
        printf("%s\n", OPENSSL_VERSION_TEXT);
    if (version_opts.date)
        printf("Built on: %s at %s\n", BUILDDATE, BUILDTIME);
    if (version_opts.platform)
        printf("Platform: %s\n", PLATFORM);
    if (version_opts.options) {
        printf("Options:  ");
        printf("%s ", BN_options());
        printf("%s ", RC4_options());
#ifndef OPENSSL_NO_DES
        printf("%s ", DES_options());
#endif
#ifndef OPENSSL_NO_IDEA
        printf("%s ", idea_options());
#endif
#ifndef OPENSSL_NO_BF
        printf("%s ", BF_options());
#endif
        printf("\n");
    }
    if (version_opts.cflags)
        printf("Compiler: %s\n", CFLAGS);

    return (0);
}
