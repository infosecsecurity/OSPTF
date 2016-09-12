/*
 * Copyright 2012-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <strings.h>

#include <openssl/conf.h>
#include <openssl/objects.h>
#include <openssl/dh.h>

#include "ssl_locl.h"

/*
 * Structure holding name tables. This is used for pemitted elements in
 * lists such as TLSv1 and single command line switches such as no_tls1
 */

typedef struct {
    const char *name;
    int namelen;
    unsigned int name_flags;
    unsigned long option_value;
} ssl_flag_tbl;

/* Sense of name is inverted e.g. "TLSv1" will clear SSL_OP_NO_TLSv1 */
#define SSL_TFLAG_INV 0x1
/* Flags refers to cert_flags not options */
#define SSL_TFLAG_CERT 0x2
/* Option can only be used for clients */
#define SSL_TFLAG_CLIENT SSL_CONF_FLAG_CLIENT
/* Option can only be used for servers */
#define SSL_TFLAG_SERVER SSL_CONF_FLAG_SERVER
#define SSL_TFLAG_BOTH (SSL_TFLAG_CLIENT | SSL_TFLAG_SERVER)

#define SSL_FLAG_TBL(str, flag)                           \
    {                                                     \
        str, (int)(sizeof(str) - 1), SSL_TFLAG_BOTH, flag \
    }
#define SSL_FLAG_TBL_SRV(str, flag)                         \
    {                                                       \
        str, (int)(sizeof(str) - 1), SSL_TFLAG_SERVER, flag \
    }
#define SSL_FLAG_TBL_CLI(str, flag)                         \
    {                                                       \
        str, (int)(sizeof(str) - 1), SSL_TFLAG_CLIENT, flag \
    }
#define SSL_FLAG_TBL_INV(str, flag)                                       \
    {                                                                     \
        str, (int)(sizeof(str) - 1), SSL_TFLAG_INV | SSL_TFLAG_BOTH, flag \
    }
#define SSL_FLAG_TBL_SRV_INV(str, flag)                                     \
    {                                                                       \
        str, (int)(sizeof(str) - 1), SSL_TFLAG_INV | SSL_TFLAG_SERVER, flag \
    }
#define SSL_FLAG_TBL_CERT(str, flag)                                       \
    {                                                                      \
        str, (int)(sizeof(str) - 1), SSL_TFLAG_CERT | SSL_TFLAG_BOTH, flag \
    }

/* Opaque structure containing SSL configuration context.
 */

struct ssl_conf_ctx_st {
    /* Various flags indicating (among other things) which options we
     * will recognise.
     */
    unsigned int flags;
    /* Prefix and length of commands */
    char *prefix;
    size_t prefixlen;
    /* SSL_CTX or SSL structure to perform operations on */
    SSL_CTX *ctx;
    SSL *ssl;
    /* Pointer to SSL or SSL_CTX options field or NULL if none */
    unsigned long *poptions;
    /* Pointer to SSL or SSL_CTX cert_flags or NULL if none */
    unsigned int *pcert_flags;
    /* Current flag table being worked on */
    const ssl_flag_tbl *tbl;
    /* Size of table */
    size_t ntbl;
};

static int ssl_match_option(SSL_CONF_CTX *cctx, const ssl_flag_tbl *tbl,
                            const char *name, int namelen, int onoff)
{
    /* If name not relevant for context skip */
    if (!(cctx->flags & tbl->name_flags & SSL_TFLAG_BOTH))
        return 0;
    if (namelen == -1) {
        if (strcmp(tbl->name, name) != 0)
            return 0;
    } else if (tbl->namelen != namelen || strncasecmp(tbl->name, name, namelen))
        return 0;
    if (cctx->poptions != NULL) {
        if (tbl->name_flags & SSL_TFLAG_INV)
            onoff ^= 1;
        if (tbl->name_flags & SSL_TFLAG_CERT) {
            if (onoff)
                *cctx->pcert_flags |= tbl->option_value;
            else
                *cctx->pcert_flags &= ~tbl->option_value;
        } else {
            if (onoff)
                *cctx->poptions |= tbl->option_value;
            else
                *cctx->poptions &= ~tbl->option_value;
        }
    }
    return 1;
}

static int ssl_set_option_list(const char *elem, int len, void *usr)
{
    SSL_CONF_CTX *cctx = usr;
    size_t i;
    const ssl_flag_tbl *tbl;
    int onoff = 1;
    /*
     * len == -1 indicates not being called in list context, just for
     * single command line switches, so don't allow +, -.
     */
    if (elem == NULL)
        return 0;
    if (len != -1) {
        if (*elem == '+') {
            elem++;
            len--;
            onoff = 1;
        } else if (*elem == '-') {
            elem++;
            len--;
            onoff = 0;
        }
    }
    for (i = 0, tbl = cctx->tbl; i < cctx->ntbl; i++, tbl++) {
        if (ssl_match_option(cctx, tbl, elem, len, onoff))
            return 1;
    }
    return 0;
}

/* Single command line switches with no argument e.g. -no_ssl3 */
static int ctrl_str_option(SSL_CONF_CTX *cctx, const char *cmd)
{
    static const ssl_flag_tbl ssl_option_single[] = {
        SSL_FLAG_TBL("no_ssl2", SSL_OP_NO_SSLv2),
        SSL_FLAG_TBL("no_ssl3", SSL_OP_NO_SSLv3),
        SSL_FLAG_TBL("no_tls1", SSL_OP_NO_TLSv1),
        SSL_FLAG_TBL("no_tls1_1", SSL_OP_NO_TLSv1_1),
        SSL_FLAG_TBL("no_tls1_2", SSL_OP_NO_TLSv1_2),
        SSL_FLAG_TBL("bugs", SSL_OP_ALL),
        SSL_FLAG_TBL("no_comp", SSL_OP_NO_COMPRESSION),
        SSL_FLAG_TBL_SRV("ecdh_single", SSL_OP_SINGLE_ECDH_USE),
        SSL_FLAG_TBL("no_ticket", SSL_OP_NO_TICKET),
        SSL_FLAG_TBL_SRV("serverpref", SSL_OP_CIPHER_SERVER_PREFERENCE),
        SSL_FLAG_TBL("legacy_renegotiation",
                     SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION),
        SSL_FLAG_TBL_SRV("legacy_server_connect", SSL_OP_LEGACY_SERVER_CONNECT),
        SSL_FLAG_TBL_SRV("no_resumption_on_reneg",
                         SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION),
        SSL_FLAG_TBL_SRV_INV("no_legacy_server_connect",
                             SSL_OP_LEGACY_SERVER_CONNECT),
        SSL_FLAG_TBL_CERT("strict", SSL_CERT_FLAG_TLS_STRICT),
    };
    cctx->tbl = ssl_option_single;
    cctx->ntbl = sizeof(ssl_option_single) / sizeof(ssl_flag_tbl);
    return ssl_set_option_list(cmd, -1, cctx);
}

/* Set supported signature algorithms */
static int cmd_SignatureAlgorithms(SSL_CONF_CTX *cctx, const char *value)
{
    int rv;
    if (cctx->ssl != NULL)
        rv = SSL_set1_sigalgs_list(cctx->ssl, value);
    /* NB: ctx == NULL performs syntax checking only */
    else
        rv = SSL_CTX_set1_sigalgs_list(cctx->ctx, value);
    return rv > 0;
}
/* Set supported client signature algorithms */
static int cmd_ClientSignatureAlgorithms(SSL_CONF_CTX *cctx, const char *value)
{
    int rv;
    if (cctx->ssl != NULL)
        rv = SSL_set1_client_sigalgs_list(cctx->ssl, value);
    /* NB: ctx == NULL performs syntax checking only */
    else
        rv = SSL_CTX_set1_client_sigalgs_list(cctx->ctx, value);
    return rv > 0;
}

static int cmd_Curves(SSL_CONF_CTX *cctx, const char *value)
{
    int rv;
    if (cctx->ssl != NULL)
        rv = SSL_set1_curves_list(cctx->ssl, value);
    /* NB: ctx == NULL performs syntax checking only */
    else
        rv = SSL_CTX_set1_curves_list(cctx->ctx, value);
    return rv > 0;
}

/* ECDH temporary parameters */
static int cmd_ECDHParameters(SSL_CONF_CTX *cctx, const char *value)
{
    int onoff = -1, rv = 1;
    if (!(cctx->flags & SSL_CONF_FLAG_SERVER))
        return -2;
    if (cctx->flags & SSL_CONF_FLAG_FILE) {
        if (*value == '+') {
            onoff = 1;
            value++;
        }
        if (*value == '-') {
            onoff = 0;
            value++;
        }
        if (strcasecmp(value, "automatic") == 0) {
            if (onoff == -1)
                onoff = 1;
        } else if (onoff != -1)
            return 0;
    } else if (cctx->flags & SSL_CONF_FLAG_CMDLINE) {
        if (!strcmp(value, "auto"))
            onoff = 1;
    }

    if (onoff != -1) {
        if (cctx->ctx != NULL)
            rv = SSL_CTX_set_ecdh_auto(cctx->ctx, onoff);
        else if (cctx->ssl != NULL)
            rv = SSL_set_ecdh_auto(cctx->ssl, onoff);
    } else {
        EC_KEY *ecdh;
        int nid;
        nid = EC_curve_nist2nid(value);
        if (nid == NID_undef)
            nid = OBJ_sn2nid(value);
        if (nid == 0)
            return 0;
        ecdh = EC_KEY_new_by_curve_name(nid);
        if (ecdh == NULL)
            return 0;
        if (cctx->ctx != NULL)
            rv = SSL_CTX_set_tmp_ecdh(cctx->ctx, ecdh);
        else if (cctx->ssl != NULL)
            rv = SSL_set_tmp_ecdh(cctx->ssl, ecdh);
        EC_KEY_free(ecdh);
    }

    return rv > 0;
}

static int cmd_CipherString(SSL_CONF_CTX *cctx, const char *value)
{
    int rv = 1;
    if (cctx->ctx != NULL)
        rv = SSL_CTX_set_cipher_list(cctx->ctx, value);
    if (cctx->ssl != NULL)
        rv = SSL_set_cipher_list(cctx->ssl, value);
    return rv > 0;
}

static int cmd_Protocol(SSL_CONF_CTX *cctx, const char *value)
{
    static const ssl_flag_tbl ssl_protocol_list[] = {
        SSL_FLAG_TBL_INV("ALL", SSL_OP_NO_SSL_MASK),
        SSL_FLAG_TBL_INV("SSLv2", SSL_OP_NO_SSLv2),
        SSL_FLAG_TBL_INV("SSLv3", SSL_OP_NO_SSLv3),
        SSL_FLAG_TBL_INV("TLSv1", SSL_OP_NO_TLSv1),
        SSL_FLAG_TBL_INV("TLSv1.1", SSL_OP_NO_TLSv1_1),
        SSL_FLAG_TBL_INV("TLSv1.2", SSL_OP_NO_TLSv1_2)
    };
    if (!(cctx->flags & SSL_CONF_FLAG_FILE))
        return -2;
    cctx->tbl = ssl_protocol_list;
    cctx->ntbl = sizeof(ssl_protocol_list) / sizeof(ssl_flag_tbl);
    return CONF_parse_list(value, ',', 1, ssl_set_option_list, cctx);
}

static int cmd_Options(SSL_CONF_CTX *cctx, const char *value)
{
    static const ssl_flag_tbl ssl_option_list[] = {
        SSL_FLAG_TBL_INV("SessionTicket", SSL_OP_NO_TICKET),
        SSL_FLAG_TBL_INV("EmptyFragments", SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS),
        SSL_FLAG_TBL("Bugs", SSL_OP_ALL),
        SSL_FLAG_TBL_INV("Compression", SSL_OP_NO_COMPRESSION),
        SSL_FLAG_TBL_SRV("ServerPreference", SSL_OP_CIPHER_SERVER_PREFERENCE),
        SSL_FLAG_TBL_SRV("NoResumptionOnRenegotiation",
                         SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION),
        SSL_FLAG_TBL_SRV("DHSingle", SSL_OP_SINGLE_DH_USE),
        SSL_FLAG_TBL_SRV("ECDHSingle", SSL_OP_SINGLE_ECDH_USE),
        SSL_FLAG_TBL("UnsafeLegacyRenegotiation",
                     SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION),
    };
    if (!(cctx->flags & SSL_CONF_FLAG_FILE))
        return -2;
    if (value == NULL)
        return -3;
    cctx->tbl = ssl_option_list;
    cctx->ntbl = sizeof(ssl_option_list) / sizeof(ssl_flag_tbl);
    return CONF_parse_list(value, ',', 1, ssl_set_option_list, cctx);
}

static int cmd_Certificate(SSL_CONF_CTX *cctx, const char *value)
{
    int rv = 1;
    if (!(cctx->flags & SSL_CONF_FLAG_CERTIFICATE))
        return -2;
    if (cctx->ctx)
        rv = SSL_CTX_use_certificate_chain_file(cctx->ctx, value);
    if (cctx->ssl)
        rv = SSL_use_certificate_file(cctx->ssl, value, SSL_FILETYPE_PEM);
    return rv > 0;
}

static int cmd_PrivateKey(SSL_CONF_CTX *cctx, const char *value)
{
    int rv = 1;
    if (!(cctx->flags & SSL_CONF_FLAG_CERTIFICATE))
        return -2;
    if (cctx->ctx)
        rv = SSL_CTX_use_PrivateKey_file(cctx->ctx, value, SSL_FILETYPE_PEM);
    if (cctx->ssl)
        rv = SSL_use_PrivateKey_file(cctx->ssl, value, SSL_FILETYPE_PEM);
    return rv > 0;
}

static int cmd_ServerInfoFile(SSL_CONF_CTX *cctx, const char *value)
{
    int rv = 1;
    if (!(cctx->flags & SSL_CONF_FLAG_CERTIFICATE))
        return -2;
    if (!(cctx->flags & SSL_CONF_FLAG_SERVER))
        return -2;
    if (cctx->ctx)
        rv = SSL_CTX_use_serverinfo_file(cctx->ctx, value);
    return rv > 0;
}

static int cmd_DHParameters(SSL_CONF_CTX *cctx, const char *value)
{
    int rv = 0;
    DH *dh = NULL;
    BIO *in = NULL;

    if (!(cctx->flags & SSL_CONF_FLAG_CERTIFICATE))
        return -2;
    if (cctx->ctx || cctx->ssl) {
        BIO *in;
        in = BIO_new(BIO_s_file_internal());
        if (in == NULL)
            goto end;
        if (BIO_read_filename(in, value) <= 0)
            goto end;
        dh = PEM_read_bio_DHparams(in, NULL, NULL, NULL);
        if (dh == NULL)
            goto end;
    } else
        return 1;
    if (cctx->ctx != NULL)
        rv = SSL_CTX_set_tmp_dh(cctx->ctx, dh);
    if (cctx->ssl != NULL)
        rv = SSL_set_tmp_dh(cctx->ssl, dh);
end:
    DH_free(dh);
    BIO_free(in);
    return rv > 0;
}

typedef struct {
    int (*cmd)(SSL_CONF_CTX *cctx, const char *value);
    const char *str_file;
    const char *str_cmdline;
    unsigned int value_type;
} ssl_conf_cmd_tbl;

/* Table of supported parameters */
#define SSL_CONF_CMD(name, cmdopt, type) \
    { cmd_##name, #name, cmdopt, type }

#define SSL_CONF_CMD_STRING(name, cmdopt) \
    SSL_CONF_CMD(name, cmdopt, SSL_CONF_TYPE_STRING)

static const ssl_conf_cmd_tbl ssl_conf_cmds[] = {
    SSL_CONF_CMD_STRING(SignatureAlgorithms, "sigalgs"),
    SSL_CONF_CMD_STRING(ClientSignatureAlgorithms, "client_sigalgs"),
    SSL_CONF_CMD_STRING(Curves, "curves"),
    SSL_CONF_CMD_STRING(ECDHParameters, "named_curve"),
    SSL_CONF_CMD_STRING(CipherString, "cipher"),
    SSL_CONF_CMD_STRING(Protocol, NULL),
    SSL_CONF_CMD_STRING(Options, NULL),
    SSL_CONF_CMD(Certificate, "cert", SSL_CONF_TYPE_FILE),
    SSL_CONF_CMD(PrivateKey, "key", SSL_CONF_TYPE_FILE),
    SSL_CONF_CMD(ServerInfoFile, NULL, SSL_CONF_TYPE_FILE),
    SSL_CONF_CMD(DHParameters, "dhparam", SSL_CONF_TYPE_FILE),
};

static int ssl_conf_cmd_skip_prefix(SSL_CONF_CTX *cctx, const char **pcmd)
{
    if (pcmd == NULL || *pcmd == NULL)
        return 0;
    /* If a prefix is set, check and skip */
    if (cctx->prefix) {
        if (strlen(*pcmd) <= cctx->prefixlen)
            return 0;
        if (cctx->flags & SSL_CONF_FLAG_CMDLINE &&
            strncmp(*pcmd, cctx->prefix, cctx->prefixlen) != 0)
            return 0;
        if (cctx->flags & SSL_CONF_FLAG_FILE &&
            strncasecmp(*pcmd, cctx->prefix, cctx->prefixlen) != 0)
            return 0;
        *pcmd += cctx->prefixlen;
    } else if (cctx->flags & SSL_CONF_FLAG_CMDLINE) {
        if (**pcmd != '-' || !(*pcmd)[1])
            return 0;
        *pcmd += 1;
    }
    return 1;
}

static const ssl_conf_cmd_tbl *ssl_conf_cmd_lookup(SSL_CONF_CTX *cctx, const char *cmd)
{
    const ssl_conf_cmd_tbl *t;
    size_t i;

    if (cmd == NULL)
        return NULL;

    /* Look for matching parameter name in table */
    for (i = 0, t = ssl_conf_cmds;
         i < sizeof(ssl_conf_cmds) / sizeof(ssl_conf_cmd_tbl); i++, t++)
    {
        if (cctx->flags & SSL_CONF_FLAG_CMDLINE) {
            if (t->str_cmdline && strcmp(t->str_cmdline, cmd) == 0)
                return t;
        }
        if (cctx->flags & SSL_CONF_FLAG_FILE) {
            if (t->str_file && !strcasecmp(t->str_file, cmd))
                return t;
        }
    }
    return NULL;
}

int SSL_CONF_cmd(SSL_CONF_CTX *cctx, const char *cmd, const char *value)
{
    const ssl_conf_cmd_tbl *runcmd;
    if (cmd == NULL) {
        SSLerr(SSL_F_SSL_CONF_CMD, SSL_R_INVALID_NULL_CMD_NAME);
        return 0;
    }

    if (!ssl_conf_cmd_skip_prefix(cctx, &cmd))
        return -2;

    runcmd = ssl_conf_cmd_lookup(cctx, cmd);

    if (runcmd) {
        int rv;
        if (value == NULL)
            return -3;
        rv = runcmd->cmd(cctx, value);
        if (rv > 0)
            return 2;
        if (rv == -2)
            return -2;
        if (cctx->flags & SSL_CONF_FLAG_SHOW_ERRORS) {
            SSLerr(SSL_F_SSL_CONF_CMD, SSL_R_BAD_VALUE);
            ERR_add_error_data(4, "cmd=", cmd, ", value=", value);
        }
        return 0;
    }

    if (cctx->flags & SSL_CONF_FLAG_CMDLINE) {
        if (ctrl_str_option(cctx, cmd))
            return 1;
    }

    if (cctx->flags & SSL_CONF_FLAG_SHOW_ERRORS) {
        SSLerr(SSL_F_SSL_CONF_CMD, SSL_R_UNKNOWN_CMD_NAME);
        ERR_add_error_data(2, "cmd=", cmd);
    }

    return -2;
}

int SSL_CONF_cmd_argv(SSL_CONF_CTX *cctx, int *pargc, char ***pargv)
{
    int rv;
    const char *arg = NULL, *argn;
    if (pargc && *pargc == 0)
        return 0;
    if (!pargc || *pargc > 0)
        arg = **pargv;
    if (arg == NULL)
        return 0;
    if (!pargc || *pargc > 1)
        argn = (*pargv)[1];
    else
        argn = NULL;
    cctx->flags &= ~SSL_CONF_FLAG_FILE;
    cctx->flags |= SSL_CONF_FLAG_CMDLINE;
    rv = SSL_CONF_cmd(cctx, arg, argn);
    if (rv > 0) {
        /* Success: update pargc, pargv */
        (*pargv) += rv;
        if (pargc != NULL)
            (*pargc) -= rv;
        return rv;
    }
    /* Unknown switch: indicate no arguments processed */
    if (rv == -2)
        return 0;
    /* Some error occurred processing command, return fatal error */
    if (rv == 0)
        return -1;
    return rv;
}

int SSL_CONF_cmd_value_type(SSL_CONF_CTX *cctx, const char *cmd)
{
    if (ssl_conf_cmd_skip_prefix(cctx, &cmd)) {
        const ssl_conf_cmd_tbl *runcmd;
        runcmd = ssl_conf_cmd_lookup(cctx, cmd);
        if (runcmd != NULL)
            return runcmd->value_type;
    }
    return SSL_CONF_TYPE_UNKNOWN;
}

SSL_CONF_CTX *SSL_CONF_CTX_new(void)
{
    SSL_CONF_CTX *ret;
    ret = calloc(1, sizeof(SSL_CONF_CTX));
    return ret;
}

int SSL_CONF_CTX_finish(SSL_CONF_CTX *cctx)
{
    return 1;
}

void SSL_CONF_CTX_free(SSL_CONF_CTX *cctx)
{
    if (cctx == NULL)
        return;

    free(cctx->prefix);
    free(cctx);
}

unsigned int SSL_CONF_CTX_set_flags(SSL_CONF_CTX *cctx, unsigned int flags)
{
    cctx->flags |= flags;
    return cctx->flags;
}

unsigned int SSL_CONF_CTX_clear_flags(SSL_CONF_CTX *cctx, unsigned int flags)
{
    cctx->flags &= ~flags;
    return cctx->flags;
}

int SSL_CONF_CTX_set1_prefix(SSL_CONF_CTX *cctx, const char *pre)
{
    char *tmp = NULL;
    if (pre != NULL) {
        tmp = strdup(pre);
        if (tmp == NULL)
            return 0;
    }
    free(cctx->prefix);
    cctx->prefix = tmp;
    if (tmp != NULL)
        cctx->prefixlen = strlen(tmp);
    else
        cctx->prefixlen = 0;
    return 1;
}

void SSL_CONF_CTX_set_ssl(SSL_CONF_CTX *cctx, SSL *ssl)
{
    cctx->ssl = ssl;
    cctx->ctx = NULL;
    if (ssl != NULL) {
        cctx->poptions = &ssl->options;
        cctx->pcert_flags = &ssl->cert->cert_flags;
    } else {
        cctx->poptions = NULL;
        cctx->pcert_flags = NULL;
    }
}

void SSL_CONF_CTX_set_ssl_ctx(SSL_CONF_CTX *cctx, SSL_CTX *ctx)
{
    cctx->ctx = ctx;
    cctx->ssl = NULL;
    if (ctx != NULL) {
        cctx->poptions = &ctx->options;
        cctx->pcert_flags = &ctx->cert->cert_flags;
    } else {
        cctx->poptions = NULL;
        cctx->pcert_flags = NULL;
    }
}
