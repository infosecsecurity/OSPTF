/*
 * Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <assert.h>
#include <ctype.h>
#include <limits.h>
#include <netdb.h>
#include <openssl/opensslconf.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "apps.h"
#include "s_apps.h"
#include "timeouts.h"
#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/ocsp.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <stdcompat.h>

/*#define SSL_HOST_NAME    "www.netscape.com" */
/*#define SSL_HOST_NAME    "193.118.187.102" */
#define SSL_HOST_NAME "localhost"

/*#define TEST_CERT "client.pem" */ /* no default cert. */

#undef BUFSIZZ
#define BUFSIZZ 1024 * 8

extern int verify_depth;
extern int verify_error;
extern int verify_return_error;
extern int verify_quiet;

static int c_nbio = 0;
static int c_Pause = 0;
static int c_debug = 0;
static int c_tlsextdebug = 0;
static int c_status_req = 0;
static int c_msg = 0;
static int c_showcerts = 0;

static char *keymatexportlabel = NULL;
static int keymatexportlen = 20;

static void sc_usage(void);
static void print_stuff(BIO *berr, SSL *con, int full);
static int ocsp_resp_cb(SSL *s, void *arg);
static BIO *bio_c_out = NULL;
static BIO *bio_c_msg = NULL;
static int c_quiet = 0;
static int c_ign_eof = 0;
static int c_brief = 0;

static void sc_usage(void)
{
    BIO_printf(bio_err, "usage: s_client args\n");
    BIO_printf(bio_err, "\n");
    BIO_printf(bio_err, " -host host     - use -connect instead\n");
    BIO_printf(bio_err, " -port port     - use -connect instead\n");
    BIO_printf(bio_err, " -connect host:port - who to connect to (default is %s:%s)\n", SSL_HOST_NAME, PORT_STR);
    BIO_printf(bio_err, " -verify_hostname host - check peer certificate matches \"host\"\n");
    BIO_printf(bio_err, " -verify_email email - check peer certificate matches \"email\"\n");
    BIO_printf(bio_err, " -verify_ip ipaddr - check peer certificate matches \"ipaddr\"\n");

    BIO_printf(bio_err, " -verify arg   - turn on peer certificate verification\n");
    BIO_printf(bio_err, " -verify_return_error - return verification errors\n");
    BIO_printf(bio_err, " -cert arg     - certificate file to use, PEM format assumed\n");
    BIO_printf(bio_err, " -certform arg - certificate format (PEM or DER) PEM default\n");
    BIO_printf(bio_err, " -key arg      - Private key file to use, in cert file if\n");
    BIO_printf(bio_err, "                 not specified but cert file is.\n");
    BIO_printf(bio_err, " -keyform arg  - key format (PEM or DER) PEM default\n");
    BIO_printf(bio_err, " -pass arg     - private key file pass phrase source\n");
    BIO_printf(bio_err, " -CApath arg   - PEM format directory of CA's\n");
    BIO_printf(bio_err, " -CAfile arg   - PEM format file of CA's\n");
    BIO_printf(bio_err, " -no_alt_chains - only ever use the first certificate chain found\n");
    BIO_printf(bio_err, " -reconnect    - Drop and re-make the connection with the same Session-ID\n");
    BIO_printf(bio_err, " -pause        - sleep(1) after each read(2) and write(2) system call\n");
    BIO_printf(bio_err, " -prexit       - print session information even on connection failure\n");
    BIO_printf(bio_err, " -showcerts    - show all certificates in the chain\n");
    BIO_printf(bio_err, " -debug        - extra output\n");
    BIO_printf(bio_err, " -msg          - Show protocol messages\n");
    BIO_printf(bio_err, " -nbio_test    - more ssl protocol testing\n");
    BIO_printf(bio_err, " -state        - print the 'ssl' states\n");
    BIO_printf(bio_err, " -nbio         - Run with non-blocking IO\n");
    BIO_printf(bio_err, " -crlf         - convert LF from terminal into CRLF\n");
    BIO_printf(bio_err, " -quiet        - no s_client output\n");
    BIO_printf(bio_err, " -ign_eof      - ignore input eof (default when -quiet)\n");
    BIO_printf(bio_err, " -no_ign_eof   - don't ignore input eof\n");
    BIO_printf(bio_err, " -tls1_2       - just use TLSv1.2\n");
    BIO_printf(bio_err, " -tls1_1       - just use TLSv1.1\n");
    BIO_printf(bio_err, " -tls1         - just use TLSv1\n");
    BIO_printf(bio_err, " -dtls1        - just use DTLSv1\n");
    BIO_printf(bio_err, " -fallback_scsv - send TLS_FALLBACK_SCSV\n");
    BIO_printf(bio_err, " -mtu          - set the link layer MTU\n");
    BIO_printf(bio_err, " -no_tls1_2/-no_tls1_1/-no_tls1/-no_ssl3 - turn off that protocol\n");
    BIO_printf(bio_err, " -bugs         - Switch on all SSL implementation bug workarounds\n");
    BIO_printf(bio_err, " -cipher       - preferred cipher to use, use the 'openssl ciphers'\n");
    BIO_printf(bio_err, "                 command to see what is available\n");
    BIO_printf(bio_err, " -starttls prot - use the STARTTLS command before starting TLS\n");
    BIO_printf(bio_err, "                 for those protocols that support it, where\n");
    BIO_printf(bio_err, "                 'prot' defines which one to assume.  Currently,\n");
    BIO_printf(bio_err, "                 only \"smtp\", \"pop3\", \"imap\", \"ftp\" and \"xmpp\"\n");
    BIO_printf(bio_err, "                 are supported.\n");
#ifndef OPENSSL_NO_ENGINE
    BIO_printf(bio_err, " -engine id    - Initialize and use the specified engine\n");
#endif
    BIO_printf(bio_err, " -sess_out arg - file to write SSL session to\n");
    BIO_printf(bio_err, " -sess_in arg  - file to read SSL session from\n");
    BIO_printf(bio_err, " -servername host  - Set TLS extension servername in ClientHello\n");
    BIO_printf(bio_err, " -tlsextdebug      - hex dump of all TLS extensions received\n");
    BIO_printf(bio_err, " -status           - request certificate status from server\n");
    BIO_printf(bio_err, " -no_ticket        - disable use of RFC4507bis session tickets\n");
    BIO_printf(bio_err, " -nextprotoneg arg - enable NPN extension, considering named protocols supported (comma-separated list)\n");
    BIO_printf(bio_err, " -alpn arg - enable ALPN extension, considering named protocols supported (comma-separated list)\n");
    BIO_printf(bio_err, " -serverinfo types - send empty ClientHello extensions (comma-separated numbers)\n");
    BIO_printf(bio_err, " -curves arg       - Elliptic curves to advertise (colon-separated list)\n");
    BIO_printf(bio_err, " -sigalgs arg      - Signature algorithms to support (colon-separated list)\n");
    BIO_printf(bio_err, " -client_sigalgs arg - Signature algorithms to support for client\n");
    BIO_printf(bio_err, "                       certificate authentication (colon-separated list)\n");
    BIO_printf(bio_err, " -legacy_renegotiation - enable use of legacy renegotiation (dangerous)\n");
#ifndef OPENSSL_NO_SRTP
    BIO_printf(bio_err, " -use_srtp profiles - Offer SRTP key management with a colon-separated profile list\n");
#endif
    BIO_printf(bio_err, " -keymatexport label   - Export keying material using label\n");
    BIO_printf(bio_err, " -keymatexportlen len  - Export len bytes of keying "
                        "material (default 20)\n");
}

/* This is a context that we pass to callbacks */
typedef struct tlsextctx_st {
    BIO *biodebug;
    int ack;
} tlsextctx;

static int ssl_servername_cb(SSL *s, int *ad, void *arg)
{
    tlsextctx *p = (tlsextctx *)arg;
    const char *hn = SSL_get_servername(s, TLSEXT_NAMETYPE_host_name);
    if (SSL_get_servername_type(s) != -1)
        p->ack = !SSL_session_reused(s) && hn != NULL;
    else
        BIO_printf(bio_err, "Can't use SSL_get_servername\n");

    return SSL_TLSEXT_ERR_OK;
}

#ifndef OPENSSL_NO_SRTP
char *srtp_profiles = NULL;
#endif

/* This the context that we pass to next_proto_cb */
typedef struct tlsextnextprotoctx_st {
    uint8_t *data;
    unsigned short len;
    int status;
} tlsextnextprotoctx;

static tlsextnextprotoctx next_proto;

static int next_proto_cb(SSL *s, uint8_t **out, unsigned char *outlen,
                         const unsigned char *in, unsigned int inlen, void *arg)
{
    tlsextnextprotoctx *ctx = arg;

    if (!c_quiet) {
        /* We can assume that |in| is syntactically valid. */
        unsigned i;
        BIO_printf(bio_c_out, "Protocols advertised by server: ");
        for (i = 0; i < inlen;) {
            if (i)
                BIO_write(bio_c_out, ", ", 2);
            BIO_write(bio_c_out, &in[i + 1], in[i]);
            i += in[i] + 1;
        }
        BIO_write(bio_c_out, "\n", 1);
    }

    ctx->status =
        SSL_select_next_proto(out, outlen, in, inlen, ctx->data, ctx->len);
    return SSL_TLSEXT_ERR_OK;
}

static int serverinfo_cli_parse_cb(SSL *s, unsigned int ext_type,
                                   const uint8_t *in, size_t inlen,
                                   int *al, void *arg)
{
    char pem_name[100];
    uint8_t ext_buf[4 + 65536];

    /* Reconstruct the type/len fields prior to extension data */
    ext_buf[0] = ext_type >> 8;
    ext_buf[1] = ext_type & 0xFF;
    ext_buf[2] = inlen >> 8;
    ext_buf[3] = inlen & 0xFF;
    memcpy(ext_buf + 4, in, inlen);

    snprintf(pem_name, sizeof(pem_name), "SERVERINFO FOR EXTENSION %d",
             ext_type);
    PEM_write_bio(bio_c_out, pem_name, "", ext_buf, 4 + inlen);
    return 1;
}

enum {
    PROTO_OFF = 0,
    PROTO_SMTP,
    PROTO_POP3,
    PROTO_IMAP,
    PROTO_FTP,
    PROTO_XMPP
};

int s_client_main(int, char **);

int s_client_main(int argc, char **argv)
{
    int build_chain = 0;
    SSL *con = NULL;
    int s, k, state = 0, af = AF_UNSPEC;
    char *cbuf = NULL, *sbuf = NULL, *mbuf = NULL;
    int cbuf_len, cbuf_off;
    int sbuf_len, sbuf_off;
    char *port = PORT_STR;
    int full_log = 1;
    char *host = SSL_HOST_NAME;
    char *cert_file = NULL, *key_file = NULL, *chain_file = NULL;
    int cert_format = FORMAT_PEM, key_format = FORMAT_PEM;
    char *passarg = NULL, *pass = NULL;
    X509 *cert = NULL;
    EVP_PKEY *key = NULL;
    STACK_OF(X509) *chain = NULL;
    char *CApath = NULL, *CAfile = NULL;
    char *chCApath = NULL, *chCAfile = NULL;
    char *vfyCApath = NULL, *vfyCAfile = NULL;
    int reconnect = 0, badop = 0, verify = SSL_VERIFY_NONE;
    int crlf = 0;
    int write_tty, read_tty, write_ssl, read_ssl, tty_on, ssl_pending;
    SSL_CTX *ctx = NULL;
    int ret = 1, in_init = 1, i;
    int starttls_proto = PROTO_OFF;
    int prexit = 0;
    X509_VERIFY_PARAM *vpm = NULL;
    int badarg = 0;
    const SSL_METHOD *meth = NULL;
    int socket_type = SOCK_STREAM;
    BIO *sbio;
    int mbuf_len = 0;
    struct timeval timeout;
    const char *stnerr = NULL;
#ifndef OPENSSL_NO_ENGINE
    char *engine_id = NULL;
    char *ssl_client_engine_id = NULL;
    ENGINE *ssl_client_engine = NULL;
#endif
    ENGINE *e = NULL;
    char *servername = NULL;
    tlsextctx tlsextcbp = { NULL, 0 };
    const char *next_proto_neg_in = NULL;
    const char *alpn_in = NULL;
#define MAX_SI_TYPES 100
    uint16_t serverinfo_types[MAX_SI_TYPES];
    int serverinfo_types_count = 0;
    char *sess_in = NULL;
    char *sess_out = NULL;
    struct sockaddr peer;
    int peerlen = sizeof(peer);
    int fallback_scsv = 0;
    int enable_timeouts = 0;
    long socket_mtu = 0;
    SSL_EXCERT *exc = NULL;
    
    SSL_CONF_CTX *cctx = NULL;
    STACK_OF(OPENSSL_STRING) *ssl_args = NULL;
    
    char *crl_file = NULL;
    int crl_format = FORMAT_PEM;
    int crl_download = 0;
    STACK_OF(X509_CRL) *crls = NULL;

    meth = SSLv23_client_method();

    c_Pause = 0;
    c_quiet = 0;
    c_ign_eof = 0;
    c_debug = 0;
    c_msg = 0;
    c_showcerts = 0;

    if (bio_err == NULL)
        bio_err = BIO_new_fp(stderr, BIO_NOCLOSE);

    if (!load_config(bio_err, NULL))
        goto end;
    
    cctx = SSL_CONF_CTX_new();
    if (cctx == NULL)
        goto end;
    SSL_CONF_CTX_set_flags(cctx, SSL_CONF_FLAG_CLIENT);
    SSL_CONF_CTX_set_flags(cctx, SSL_CONF_FLAG_CMDLINE);

    if (((cbuf = malloc(BUFSIZZ)) == NULL) ||
        ((sbuf = malloc(BUFSIZZ)) == NULL) ||
        ((mbuf = malloc(BUFSIZZ)) == NULL)) {
        BIO_printf(bio_err, "out of memory\n");
        goto end;
    }

    verify_depth = 0;
    verify_error = X509_V_OK;
    c_nbio = 0;

    argc--;
    argv++;
    while (argc >= 1) {
        if (strcmp(*argv, "-host") == 0) {
            if (--argc < 1)
                goto bad;
            host = *(++argv);
        } else if (strcmp(*argv, "-port") == 0) {
            if (--argc < 1)
                goto bad;
            port = *(++argv);
            if (port == 0)
                goto bad;
        } else if (strcmp(*argv, "-connect") == 0) {
            if (--argc < 1)
                goto bad;
            if (!extract_host_port(*(++argv), &host, NULL, &port))
                goto bad;
        } else if (strcmp(*argv, "-verify") == 0) {
            verify = SSL_VERIFY_PEER;
            if (--argc < 1)
                goto bad;
            verify_depth = strtonum(*(++argv), 0, INT_MAX, &stnerr);
            if (stnerr)
                goto bad;
            if (!c_quiet)
                BIO_printf(bio_err, "verify depth is %d\n", verify_depth);
        } else if (strcmp(*argv, "-cert") == 0) {
            if (--argc < 1)
                goto bad;
            cert_file = *(++argv);
        } else if (strcmp(*argv, "-CRL") == 0) {
            if (--argc < 1)
                goto bad;
            crl_file = *(++argv);
        } else if (strcmp(*argv,"-crl_download") == 0) {
            crl_download = 1;
        } else if (strcmp(*argv, "-sess_out") == 0) {
            if (--argc < 1)
                goto bad;
            sess_out = *(++argv);
        } else if (strcmp(*argv, "-sess_in") == 0) {
            if (--argc < 1)
                goto bad;
            sess_in = *(++argv);
        } else if (strcmp(*argv, "-certform") == 0) {
            if (--argc < 1)
                goto bad;
            cert_format = str2fmt(*(++argv));
        } else if (strcmp(*argv, "-CRLform") == 0) {
            if (--argc < 1)
                goto bad;
            crl_format = str2fmt(*(++argv));
        } else if (args_verify(&argv, &argc, &badarg, bio_err, &vpm)) {
            if (badarg)
                goto bad;
            continue;
        } else if (strcmp(*argv, "-verify_return_error") == 0)
            verify_return_error = 1;
        else if (strcmp(*argv, "-verify_quiet") == 0)
            verify_quiet = 1;
        else if (strcmp(*argv, "-brief") == 0) {
            c_brief = 1;
            verify_quiet = 1;
            c_quiet = 1;
        }
        else if (args_excert(&argv, &argc, &badarg, bio_err, &exc)) {
            if (badarg)
                goto bad;
            continue;
        } else if (args_ssl(&argv, &argc, cctx, &badarg, bio_err, &ssl_args)) {
            if (badarg)
                goto bad;
            continue;
        } else if (strcmp(*argv, "-prexit") == 0)
            prexit = 1;
        else if (strcmp(*argv, "-crlf") == 0)
            crlf = 1;
        else if (strcmp(*argv, "-quiet") == 0) {
            c_quiet = 1;
            c_ign_eof = 1;
        } else if (strcmp(*argv, "-ign_eof") == 0)
            c_ign_eof = 1;
        else if (strcmp(*argv, "-no_ign_eof") == 0)
            c_ign_eof = 0;
        else if (strcmp(*argv, "-pause") == 0)
            c_Pause = 1;
        else if (strcmp(*argv, "-debug") == 0)
            c_debug = 1;
        else if (strcmp(*argv, "-tlsextdebug") == 0)
            c_tlsextdebug = 1;
        else if (strcmp(*argv, "-status") == 0)
            c_status_req = 1;
        else if (strcmp(*argv, "-msg") == 0)
            c_msg = 1;
        else if (strcmp(*argv, "-msgfile") == 0) {
            if (--argc < 1)
                goto bad;
            bio_c_msg = BIO_new_file(*(++argv), "w");
        }
#ifndef OPENSSL_NO_SSL_TRACE
        else if (strcmp(*argv, "-trace") == 0)
            c_msg = 2;
#endif
        else if (strcmp(*argv, "-showcerts") == 0)
            c_showcerts = 1;
        else if (strcmp(*argv, "-state") == 0)
            state = 1;
        else if (strcmp(*argv, "-tls1_2") == 0)
            meth = TLSv1_2_client_method();
        else if (strcmp(*argv, "-tls1_1") == 0)
            meth = TLSv1_1_client_method();
        else if (strcmp(*argv, "-tls1") == 0)
            meth = TLSv1_client_method();
#ifndef OPENSSL_NO_DTLS1
        else if (strcmp(*argv, "-dtls") == 0) {
            meth = DTLS_client_method();
            socket_type = SOCK_DGRAM;
        } else if (strcmp(*argv, "-dtls1") == 0) {
            meth = DTLSv1_client_method();
            socket_type = SOCK_DGRAM;
        } else if (strcmp(*argv, "-dtls1_2") == 0) {
            meth = DTLSv1_2_client_method();
            socket_type = SOCK_DGRAM;
        } else if (strcmp(*argv, "-fallback_scsv") == 0) {
            fallback_scsv = 1;
        } else if (strcmp(*argv, "-timeout") == 0)
            enable_timeouts = 1;
        else if (strcmp(*argv, "-mtu") == 0) {
            if (--argc < 1)
                goto bad;
            socket_mtu = strtonum(*(++argv), 0, LONG_MAX, &stnerr);
            if (stnerr)
                goto bad;
        }
#endif
        else if (strcmp(*argv, "-keyform") == 0) {
            if (--argc < 1)
                goto bad;
            key_format = str2fmt(*(++argv));
        } else if (strcmp(*argv, "-pass") == 0) {
            if (--argc < 1)
                goto bad;
            passarg = *(++argv);
        } else if (strcmp(*argv, "-cert_chain") == 0) {
            if (--argc < 1)
                goto bad;
            chain_file = *(++argv);
        } else if (strcmp(*argv, "-key") == 0) {
            if (--argc < 1)
                goto bad;
            key_file = *(++argv);
        } else if (strcmp(*argv, "-reconnect") == 0) {
            reconnect = 5;
        } else if (strcmp(*argv, "-CApath") == 0) {
            if (--argc < 1)
                goto bad;
            CApath = *(++argv);
        } else if (strcmp(*argv, "-chainCApath") == 0) {
            if (--argc < 1)
                goto bad;
            chCApath = *(++argv);
        } else if (strcmp(*argv, "-verifyCApath") == 0) {
            if (--argc < 1)
                goto bad;
            vfyCApath = *(++argv);
        } else if (strcmp(*argv, "-build_chain") == 0) {
            build_chain = 1;
        } else if (strcmp(*argv, "-CAfile") == 0) {
            if (--argc < 1)
                goto bad;
            CAfile = *(++argv);
        } else if (strcmp(*argv, "-chainCAfile") == 0) {
            if (--argc < 1)
                goto bad;
            chCAfile = *(++argv);
        } else if (strcmp(*argv, "-verifyCAfile") == 0) {
            if (--argc < 1)
                goto bad;
            vfyCAfile = *(++argv);
        } else if (strcmp(*argv, "-nextprotoneg") == 0) {
            if (--argc < 1)
                goto bad;
            next_proto_neg_in = *(++argv);
        } else if (strcmp(*argv, "-alpn") == 0) {
            if (--argc < 1)
                goto bad;
            alpn_in = *(++argv);
        } else if (strcmp(*argv, "-serverinfo") == 0) {
            char *c;
            int start = 0;
            int len;

            if (--argc < 1)
                goto bad;
            c = *(++argv);
            serverinfo_types_count = 0;
            len = strlen(c);
            for (i = 0; i <= len; ++i) {
                if (i == len || c[i] == ',') {
                    serverinfo_types[serverinfo_types_count] =
                        strtonum(c + start, 0, 65535, &stnerr);
                    if (stnerr)
                        goto bad;
                    serverinfo_types_count++;
                    start = i + 1;
                }
                if (serverinfo_types_count == MAX_SI_TYPES)
                    break;
            }
        } else if (strcmp(*argv, "-nbio") == 0) {
            c_nbio = 1;
        } else if (strcmp(*argv, "-starttls") == 0) {
            if (--argc < 1)
                goto bad;
            ++argv;
            if (strcmp(*argv, "smtp") == 0)
                starttls_proto = PROTO_SMTP;
            else if (strcmp(*argv, "pop3") == 0)
                starttls_proto = PROTO_POP3;
            else if (strcmp(*argv, "imap") == 0)
                starttls_proto = PROTO_IMAP;
            else if (strcmp(*argv, "ftp") == 0)
                starttls_proto = PROTO_FTP;
            else if (strcmp(*argv, "xmpp") == 0)
                starttls_proto = PROTO_XMPP;
            else
                goto bad;
        }
#ifndef OPENSSL_NO_ENGINE
        else if (strcmp(*argv, "-engine") == 0) {
            if (--argc < 1)
                goto bad;
            engine_id = *(++argv);
        } else if (strcmp(*argv, "-ssl_client_engine") == 0) {
            if (--argc < 1)
                goto bad;
            ssl_client_engine_id = *(++argv);
        }
#endif
        else if (strcmp(*argv, "-4") == 0) {
            af = AF_INET;
        } else if (strcmp(*argv, "-6") == 0) {
            af = AF_INET6;
        } else if (strcmp(*argv, "-servername") == 0) {
            if (--argc < 1)
                goto bad;
            servername = *(++argv);
            /* meth=TLSv1_client_method(); */
        }
#ifndef OPENSSL_NO_SRTP
        else if (strcmp(*argv, "-use_srtp") == 0) {
            if (--argc < 1)
                goto bad;
            srtp_profiles = *(++argv);
        }
#endif
        else if (strcmp(*argv, "-keymatexport") == 0) {
            if (--argc < 1)
                goto bad;
            keymatexportlabel = *(++argv);
        } else if (strcmp(*argv, "-keymatexportlen") == 0) {
            if (--argc < 1)
                goto bad;
            keymatexportlen = strtonum(*(++argv), 1, INT_MAX, &stnerr);
            if (stnerr)
                goto bad;
        } else {
            BIO_printf(bio_err, "unknown option %s\n", *argv);
            badop = 1;
            break;
        }
        argc--;
        argv++;
    }
    if (badop) {
    bad:
        if (stnerr)
            BIO_printf(bio_err, "invalid argument %s, errmsg=%s\n", *argv,
                       stnerr);
        else
            sc_usage();
        goto end;
    }

    OpenSSL_add_ssl_algorithms();
    SSL_load_error_strings();
    
    if (chain_file != NULL) {
        chain = load_certs(bio_err, chain_file, FORMAT_PEM, NULL, e,
                           "client certificate chain");
        if (chain == NULL)
            goto end;
    }
    
    if (crl_file != NULL) {
        X509_CRL *crl;
        crl = load_crl(crl_file, crl_format);
        if (crl == NULL) {
            BIO_puts(bio_err, "Error loading CRL\n");
            ERR_print_errors(bio_err);
            goto end;
        }
        crls = sk_X509_CRL_new_null();
        if (crls == NULL || !sk_X509_CRL_push(crls, crl)) {
            BIO_puts(bio_err, "Error adding CRL\n");
            ERR_print_errors(bio_err);
            X509_CRL_free(crl);
            goto end;
        }
    }
    
    if (!load_excert(&exc, bio_err))
        goto end;

    next_proto.status = -1;
    if (next_proto_neg_in) {
        next_proto.data = next_protos_parse(&next_proto.len, next_proto_neg_in);
        if (next_proto.data == NULL) {
            BIO_printf(bio_err, "Error parsing -nextprotoneg argument\n");
            goto end;
        }
    } else
        next_proto.data = NULL;

#ifndef OPENSSL_NO_ENGINE
    e = setup_engine(bio_err, engine_id, 1);
    if (ssl_client_engine_id) {
        ssl_client_engine = ENGINE_by_id(ssl_client_engine_id);
        if (!ssl_client_engine) {
            BIO_printf(bio_err, "Error getting client auth engine\n");
            goto end;
        }
    }

#endif
    if (!app_passwd(bio_err, passarg, NULL, &pass, NULL)) {
        BIO_printf(bio_err, "Error getting password\n");
        goto end;
    }

    if (key_file == NULL)
        key_file = cert_file;

    if (key_file)

    {

        key = load_key(bio_err, key_file, key_format, 0, pass, e,
                       "client certificate private key file");
        if (!key) {
            ERR_print_errors(bio_err);
            goto end;
        }
    }

    if (cert_file)

    {
        cert = load_cert(bio_err, cert_file, cert_format, NULL, e,
                         "client certificate file");

        if (!cert) {
            ERR_print_errors(bio_err);
            goto end;
        }
    }

    if (bio_c_out == NULL) {
        if (c_quiet && !c_debug) {
            bio_c_out = BIO_new(BIO_s_null());
            if (c_msg && !bio_c_msg)
                bio_c_msg = BIO_new_fp(stdout, BIO_NOCLOSE);
        } else {
            if (bio_c_out == NULL)
                bio_c_out = BIO_new_fp(stdout, BIO_NOCLOSE);
        }
    }

    ctx = SSL_CTX_new(meth);
    if (ctx == NULL) {
        ERR_print_errors(bio_err);
        goto end;
    }

    if (vpm)
        SSL_CTX_set1_param(ctx, vpm);
    
    if (!args_ssl_call(ctx, bio_err, cctx, ssl_args, 1)) {
        ERR_print_errors(bio_err);
        goto end;
    }
    
    if (!ssl_load_stores(ctx, vfyCApath, vfyCAfile, chCApath, chCAfile, crls,
                         crl_download))
    {
        BIO_printf(bio_err, "Error loading store locations\n");
        ERR_print_errors(bio_err);
        goto end;
    }

#ifndef OPENSSL_NO_ENGINE
    if (ssl_client_engine) {
        if (!SSL_CTX_set_client_cert_engine(ctx, ssl_client_engine)) {
            BIO_puts(bio_err, "Error setting client auth engine\n");
            ERR_print_errors(bio_err);
            ENGINE_free(ssl_client_engine);
            goto end;
        }
        ENGINE_free(ssl_client_engine);
    }
#endif

#ifndef OPENSSL_NO_SRTP
    if (srtp_profiles != NULL)
        SSL_CTX_set_tlsext_use_srtp(ctx, srtp_profiles);
#endif
    if (exc)
        ssl_ctx_set_excert(ctx, exc);

    if (next_proto.data)
        SSL_CTX_set_next_proto_select_cb(ctx, next_proto_cb, &next_proto);
    if (alpn_in) {
        unsigned short alpn_len;
        uint8_t *alpn = next_protos_parse(&alpn_len, alpn_in);

        if (alpn == NULL) {
            BIO_printf(bio_err, "Error parsing -alpn argument\n");
            goto end;
        }
        SSL_CTX_set_alpn_protos(ctx, alpn, alpn_len);
        free(alpn);
    }
    for (i = 0; i < serverinfo_types_count; i++) {
        SSL_CTX_add_client_custom_ext(ctx, serverinfo_types[i], NULL, NULL,
                                      NULL, serverinfo_cli_parse_cb, NULL);
    }

    if (state)
        SSL_CTX_set_info_callback(ctx, apps_ssl_info_callback);

    SSL_CTX_set_verify(ctx, verify, verify_callback);

    if ((CAfile || CApath) &&
        !SSL_CTX_load_verify_locations(ctx, CAfile, CApath))
    {
        ERR_print_errors(bio_err);
    }
    if (!SSL_CTX_set_default_verify_paths(ctx))
        ERR_print_errors(bio_err);

    ssl_ctx_add_crls(ctx, crls, crl_download);
    if (!set_cert_key_stuff(ctx,cert,key, chain, build_chain))
        goto end;

    if (servername != NULL) {
        tlsextcbp.biodebug = bio_err;
        SSL_CTX_set_tlsext_servername_callback(ctx, ssl_servername_cb);
        SSL_CTX_set_tlsext_servername_arg(ctx, &tlsextcbp);
    }

    con = SSL_new(ctx);
    if (sess_in) {
        SSL_SESSION *sess;
        BIO *stmp = BIO_new_file(sess_in, "r");
        if (!stmp) {
            BIO_printf(bio_err, "Can't open session file %s\n", sess_in);
            ERR_print_errors(bio_err);
            goto end;
        }
        sess = PEM_read_bio_SSL_SESSION(stmp, NULL, 0, NULL);
        BIO_free(stmp);
        if (!sess) {
            BIO_printf(bio_err, "Can't open session file %s\n", sess_in);
            ERR_print_errors(bio_err);
            goto end;
        }
        SSL_set_session(con, sess);
        SSL_SESSION_free(sess);
    }

    if (fallback_scsv)
        SSL_set_mode(con, SSL_MODE_SEND_FALLBACK_SCSV);
    if (servername != NULL) {
        if (!SSL_set_tlsext_host_name(con, servername)) {
            BIO_printf(bio_err, "Unable to set TLS servername extension.\n");
            ERR_print_errors(bio_err);
            goto end;
        }
    }
/*    SSL_set_cipher_list(con,"RC4-MD5"); */

re_start:

    if (init_client(&s, host, port, socket_type, af) == 0) {
        BIO_printf(bio_err, "connect:errno=%d\n", errno);
        shutdown((s), SHUT_RD);
        close((s));
        goto end;
    }
    BIO_printf(bio_c_out, "CONNECTED(%08X)\n", s);

    if (c_nbio) {
        unsigned long l = 1;
        BIO_printf(bio_c_out, "turning on non blocking io\n");
        if (BIO_socket_ioctl(s, FIONBIO, &l) < 0) {
            ERR_print_errors(bio_err);
            goto end;
        }
    }
    if (c_Pause & 0x01)
        SSL_set_debug(con, 1);

    if (socket_type == SOCK_DGRAM) {

        sbio = BIO_new_dgram(s, BIO_NOCLOSE);
        if (getsockname(s, &peer, (void *)&peerlen) < 0) {
            BIO_printf(bio_err, "getsockname:errno=%d\n", errno);
            shutdown((s), SHUT_RD);
            close((s));
            goto end;
        }

        (void)BIO_ctrl_set_connected(sbio, 1, &peer);

        if (enable_timeouts) {
            timeout.tv_sec = 0;
            timeout.tv_usec = DGRAM_RCV_TIMEOUT;
            BIO_ctrl(sbio, BIO_CTRL_DGRAM_SET_RECV_TIMEOUT, 0, &timeout);

            timeout.tv_sec = 0;
            timeout.tv_usec = DGRAM_SND_TIMEOUT;
            BIO_ctrl(sbio, BIO_CTRL_DGRAM_SET_SEND_TIMEOUT, 0, &timeout);
        }

        if (socket_mtu) {
            if (socket_mtu < DTLS_get_link_min_mtu(con)) {
                BIO_printf(bio_err, "MTU too small. Must be at least %ld\n",
                           DTLS_get_link_min_mtu(con));
                BIO_free(sbio);
                goto shut;
            }
            SSL_set_options(con, SSL_OP_NO_QUERY_MTU);
            if (!DTLS_set_link_mtu(con, socket_mtu)) {
                BIO_printf(bio_err, "Failed to set MTU\n");
                BIO_free(sbio);
                goto shut;
            }
        } else
            /* want to do MTU discovery */
            BIO_ctrl(sbio, BIO_CTRL_DGRAM_MTU_DISCOVER, 0, NULL);
    } else
        sbio = BIO_new_socket(s, BIO_NOCLOSE);

    if (c_debug) {
        SSL_set_debug(con, 1);
        BIO_set_callback(sbio, bio_dump_callback);
        BIO_set_callback_arg(sbio, (char *)bio_c_out);
    }
    if (c_msg) {
#ifndef OPENSSL_NO_SSL_TRACE
        if (c_msg == 2)
            SSL_set_msg_callback(con, SSL_trace);
        else
#endif
            SSL_set_msg_callback(con, msg_cb);
        SSL_set_msg_callback_arg(con, bio_c_msg ? bio_c_msg : bio_c_out);
    }
    if (c_tlsextdebug) {
        SSL_set_tlsext_debug_callback(con, tlsext_cb);
        SSL_set_tlsext_debug_arg(con, bio_c_out);
    }
    if (c_status_req) {
        SSL_set_tlsext_status_type(con, TLSEXT_STATUSTYPE_ocsp);
        SSL_CTX_set_tlsext_status_cb(ctx, ocsp_resp_cb);
        SSL_CTX_set_tlsext_status_arg(ctx, bio_c_out);
    }

    SSL_set_bio(con, sbio, sbio);
    SSL_set_connect_state(con);

    read_tty = 1;
    write_tty = 0;
    tty_on = 0;
    read_ssl = 1;
    write_ssl = 1;

    cbuf_len = 0;
    cbuf_off = 0;
    sbuf_len = 0;
    sbuf_off = 0;

    /* This is an ugly hack that does a lot of assumptions */
    /* We do have to handle multi-line responses which may come
        in a single packet or not. We therefore have to use
       BIO_gets() which does need a buffering BIO. So during
       the initial chitchat we do push a buffering BIO into the
       chain that is removed again later on to not disturb the
       rest of the s_client operation. */
    if (starttls_proto == PROTO_SMTP) {
        int foundit = 0;
        BIO *fbio = BIO_new(BIO_f_buffer());
        BIO_push(fbio, sbio);
        /* wait for multi-line response to end from SMTP */
        do {
            mbuf_len = BIO_gets(fbio, mbuf, BUFSIZZ);
        } while (mbuf_len > 3 && mbuf[3] == '-');
        /* STARTTLS command requires EHLO... */
        BIO_printf(fbio, "EHLO openssl.client.net\r\n");
        (void)BIO_flush(fbio);
        /* wait for multi-line response to end EHLO SMTP response */
        do {
            mbuf_len = BIO_gets(fbio, mbuf, BUFSIZZ);
            if (strstr(mbuf, "STARTTLS"))
                foundit = 1;
        } while (mbuf_len > 3 && mbuf[3] == '-');
        (void)BIO_flush(fbio);
        BIO_pop(fbio);
        BIO_free(fbio);
        if (!foundit)
            BIO_printf(bio_err, "didn't found starttls in server response,"
                                " try anyway...\n");
        BIO_printf(sbio, "STARTTLS\r\n");
        BIO_read(sbio, sbuf, BUFSIZZ);
    } else if (starttls_proto == PROTO_POP3) {
        BIO_read(sbio, mbuf, BUFSIZZ);
        BIO_printf(sbio, "STLS\r\n");
        BIO_read(sbio, sbuf, BUFSIZZ);
    } else if (starttls_proto == PROTO_IMAP) {
        int foundit = 0;
        BIO *fbio = BIO_new(BIO_f_buffer());
        BIO_push(fbio, sbio);
        BIO_gets(fbio, mbuf, BUFSIZZ);
        /* STARTTLS command requires CAPABILITY... */
        BIO_printf(fbio, ". CAPABILITY\r\n");
        (void)BIO_flush(fbio);
        /* wait for multi-line CAPABILITY response */
        do {
            mbuf_len = BIO_gets(fbio, mbuf, BUFSIZZ);
            if (strstr(mbuf, "STARTTLS"))
                foundit = 1;
        } while (mbuf_len > 3 && mbuf[0] != '.');
        (void)BIO_flush(fbio);
        BIO_pop(fbio);
        BIO_free(fbio);
        if (!foundit)
            BIO_printf(bio_err, "didn't found STARTTLS in server response,"
                                " try anyway...\n");
        BIO_printf(sbio, ". STARTTLS\r\n");
        BIO_read(sbio, sbuf, BUFSIZZ);
    } else if (starttls_proto == PROTO_FTP) {
        BIO *fbio = BIO_new(BIO_f_buffer());
        BIO_push(fbio, sbio);
        /* wait for multi-line response to end from FTP */
        do {
            mbuf_len = BIO_gets(fbio, mbuf, BUFSIZZ);
        } while (mbuf_len > 3 && mbuf[3] == '-');
        (void)BIO_flush(fbio);
        BIO_pop(fbio);
        BIO_free(fbio);
        BIO_printf(sbio, "AUTH TLS\r\n");
        BIO_read(sbio, sbuf, BUFSIZZ);
    }
    if (starttls_proto == PROTO_XMPP) {
        int seen = 0;
        BIO_printf(sbio, "<stream:stream "
                         "xmlns:stream='http://etherx.jabber.org/streams' "
                         "xmlns='jabber:client' to='%s' version='1.0'>",
                   host);
        seen = BIO_read(sbio, mbuf, BUFSIZZ);
        mbuf[seen] = 0;
        while (!strstr(mbuf,
                       "<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'")) {
            if (strstr(mbuf, "/stream:features>"))
                goto shut;
            seen = BIO_read(sbio, mbuf, BUFSIZZ);
            mbuf[seen] = 0;
        }
        BIO_printf(sbio, "<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>");
        seen = BIO_read(sbio, sbuf, BUFSIZZ);
        sbuf[seen] = 0;
        if (!strstr(sbuf, "<proceed"))
            goto shut;
        mbuf[0] = 0;
    }

    for (;;) {
        struct pollfd pfd[3]; /* stdin, stdout, socket */
        int ptimeout = -1;

        if ((SSL_version(con) == DTLS1_VERSION) &&
            DTLSv1_get_timeout(con, &timeout))
            ptimeout = timeout.tv_sec * 1000 + timeout.tv_usec / 1000;

        if (SSL_in_init(con) && !SSL_total_renegotiations(con)) {
            in_init = 1;
            tty_on = 0;
        } else {
            tty_on = 1;
            if (in_init) {
                in_init = 0;
                if (sess_out) {
                    BIO *stmp = BIO_new_file(sess_out, "w");
                    if (stmp) {
                        PEM_write_bio_SSL_SESSION(stmp, SSL_get_session(con));
                        BIO_free(stmp);
                    } else
                        BIO_printf(bio_err, "Error writing session file %s\n",
                                   sess_out);
                }
                if (c_brief) {
                    BIO_puts(bio_err, "CONNECTION ESTABLISHED\n");
                    print_ssl_summary(bio_err, con);
                }
                print_stuff(bio_c_out, con, full_log);
                if (full_log > 0)
                    full_log--;

                if (starttls_proto) {
                    BIO_printf(bio_err, "%s", mbuf);
                    /* We don't need to know any more */
                    starttls_proto = PROTO_OFF;
                }

                if (reconnect) {
                    reconnect--;
                    BIO_printf(bio_c_out,
                               "drop connection and then reconnect\n");
                    SSL_shutdown(con);
                    SSL_set_connect_state(con);
                    shutdown((SSL_get_fd(con)), SHUT_RD);
                    close((SSL_get_fd(con)));
                    goto re_start;
                }
            }
        }

        ssl_pending = read_ssl && SSL_pending(con);

        pfd[0].fd = -1;
        pfd[1].fd = -1;
        if (!ssl_pending) {
            if (tty_on) {
                if (read_tty) {
                    pfd[0].fd = fileno(stdin);
                    pfd[0].events = POLLIN;
                }
                if (write_tty) {
                    pfd[1].fd = fileno(stdout);
                    pfd[1].events = POLLOUT;
                }
            }

            pfd[2].fd = SSL_get_fd(con);
            pfd[2].events = 0;

            if (read_ssl)
                pfd[2].events |= POLLIN;
            if (write_ssl)
                pfd[2].events |= POLLOUT;

            /*            printf("mode tty(%d %d%d) ssl(%d%d)\n",
                tty_on,read_tty,write_tty,read_ssl,write_ssl);*/

            /* Note: under VMS with SOCKETSHR the second parameter
             * is currently of type (int *) whereas under other
             * systems it is (void *) if you don't have a cast it
             * will choke the compiler: if you do have a cast then
             * you can either go for (int *) or (void *).
             */
            i = poll(pfd, 3, ptimeout);
            if (i < 0) {
                BIO_printf(bio_err, "bad select %d\n", errno);
                goto shut;
                /* goto end; */
            }
        }

        if ((SSL_version(con) == DTLS1_VERSION) &&
            DTLSv1_handle_timeout(con) > 0) {
            BIO_printf(bio_err, "TIMEOUT occurred\n");
        }

        if (!ssl_pending && (pfd[2].revents & (POLLOUT | POLLERR | POLLNVAL))) {
            if (pfd[2].revents & (POLLERR | POLLNVAL)) {
                BIO_printf(bio_err, "poll error");
                goto shut;
            }
            k = SSL_write(con, &(cbuf[cbuf_off]), (unsigned int)cbuf_len);
            switch (SSL_get_error(con, k)) {
                case SSL_ERROR_NONE:
                    cbuf_off += k;
                    cbuf_len -= k;
                    if (k <= 0)
                        goto end;
                    /* we have done a  write(con,NULL,0); */
                    if (cbuf_len <= 0) {
                        read_tty = 1;
                        write_ssl = 0;
                    } else /* if (cbuf_len > 0) */
                    {
                        read_tty = 0;
                        write_ssl = 1;
                    }
                    break;
                case SSL_ERROR_WANT_WRITE:
                    BIO_printf(bio_c_out, "write W BLOCK\n");
                    write_ssl = 1;
                    read_tty = 0;
                    break;
                case SSL_ERROR_WANT_READ:
                    BIO_printf(bio_c_out, "write R BLOCK\n");
                    write_tty = 0;
                    read_ssl = 1;
                    write_ssl = 0;
                    break;
                case SSL_ERROR_WANT_X509_LOOKUP:
                    BIO_printf(bio_c_out, "write X BLOCK\n");
                    break;
                case SSL_ERROR_ZERO_RETURN:
                    if (cbuf_len != 0) {
                        BIO_printf(bio_c_out, "shutdown\n");
                        ret = 0;
                        goto shut;
                    } else {
                        read_tty = 1;
                        write_ssl = 0;
                        break;
                    }

                case SSL_ERROR_SYSCALL:
                    if ((k != 0) || (cbuf_len != 0)) {
                        BIO_printf(bio_err, "write:errno=%d\n", errno);
                        goto shut;
                    } else {
                        read_tty = 1;
                        write_ssl = 0;
                    }
                    break;
                case SSL_ERROR_SSL:
                    ERR_print_errors(bio_err);
                    goto shut;
            }
        } else if (!ssl_pending &&
                   (pfd[1].revents & (POLLOUT | POLLERR | POLLNVAL))) {
            if (pfd[1].revents & (POLLERR | POLLNVAL)) {
                BIO_printf(bio_err, "poll error");
                goto shut;
            }
            i = write(fileno(stdout), &(sbuf[sbuf_off]), sbuf_len);

            if (i <= 0) {
                BIO_printf(bio_c_out, "DONE\n");
                ret = 0;
                goto shut;
                /* goto end; */
            }

            sbuf_len -= i;
            ;
            sbuf_off += i;
            if (sbuf_len <= 0) {
                read_ssl = 1;
                write_tty = 0;
            }
        } else if (ssl_pending || (pfd[2].revents & (POLLIN | POLLHUP))) {
#ifdef RENEG
            {
                static int iiii;
                if (++iiii == 52) {
                    SSL_renegotiate(con);
                    iiii = 0;
                }
            }
#endif
            k = SSL_read(con, sbuf, 1024 /* BUFSIZZ */);

            switch (SSL_get_error(con, k)) {
                case SSL_ERROR_NONE:
                    if (k <= 0)
                        goto end;
                    sbuf_off = 0;
                    sbuf_len = k;

                    read_ssl = 0;
                    write_tty = 1;
                    break;
                case SSL_ERROR_WANT_WRITE:
                    BIO_printf(bio_c_out, "read W BLOCK\n");
                    write_ssl = 1;
                    read_tty = 0;
                    break;
                case SSL_ERROR_WANT_READ:
                    BIO_printf(bio_c_out, "read R BLOCK\n");
                    write_tty = 0;
                    read_ssl = 1;
                    if ((read_tty == 0) && (write_ssl == 0))
                        write_ssl = 1;
                    break;
                case SSL_ERROR_WANT_X509_LOOKUP:
                    BIO_printf(bio_c_out, "read X BLOCK\n");
                    break;
                case SSL_ERROR_SYSCALL:
                    ret = errno;
                    if (c_brief)
                        BIO_puts(bio_err, "CONNECTION CLOSED BY SERVER\n");
                    else
                        BIO_printf(bio_err, "read:errno=%d\n", ret);
                    goto shut;
                case SSL_ERROR_ZERO_RETURN:
                    BIO_printf(bio_c_out, "closed\n");
                    ret = 0;
                    goto shut;
                case SSL_ERROR_SSL:
                    ERR_print_errors(bio_err);
                    goto shut;
                    /* break; */
            }
        } else if (pfd[0].revents) {
            if (pfd[0].revents & (POLLERR | POLLNVAL)) {
                BIO_printf(bio_err, "poll error");
                goto shut;
            }
            if (crlf) {
                int j, lf_num;

                i = read(fileno(stdin), cbuf, BUFSIZZ / 2);
                lf_num = 0;
                /* both loops are skipped when i <= 0 */
                for (j = 0; j < i; j++)
                    if (cbuf[j] == '\n')
                        lf_num++;
                for (j = i - 1; j >= 0; j--) {
                    cbuf[j + lf_num] = cbuf[j];
                    if (cbuf[j] == '\n') {
                        lf_num--;
                        i++;
                        cbuf[j + lf_num] = '\r';
                    }
                }
                assert(lf_num == 0);
            } else
                i = read(fileno(stdin), cbuf, BUFSIZZ);

            if ((!c_ign_eof) && ((i <= 0) || (cbuf[0] == 'Q'))) {
                BIO_printf(bio_err, "DONE\n");
                ret = 0;
                goto shut;
            }

            if ((!c_ign_eof) && (cbuf[0] == 'R')) {
                BIO_printf(bio_err, "RENEGOTIATING\n");
                SSL_renegotiate(con);
                cbuf_len = 0;
            } else {
                cbuf_len = i;
                cbuf_off = 0;
            }

            write_ssl = 1;
            read_tty = 0;
        }
    }

    ret = 0;
shut:
    if (in_init)
        print_stuff(bio_c_out, con, full_log);
    SSL_shutdown(con);
    shutdown((SSL_get_fd(con)), SHUT_RD);
    close((SSL_get_fd(con)));
end:
    if (con != NULL) {
        if (prexit != 0)
            print_stuff(bio_c_out, con, 1);
        SSL_free(con);
    }
    free(next_proto.data);
    SSL_CTX_free(ctx);
    X509_free(cert);
    sk_X509_CRL_pop_free(crls, X509_CRL_free);
    EVP_PKEY_free(key);
    sk_X509_pop_free(chain, X509_free);
    free(pass);
    X509_VERIFY_PARAM_free(vpm);
    ssl_excert_free(exc);
    sk_OPENSSL_STRING_free(ssl_args);
    SSL_CONF_CTX_free(cctx);
    vigortls_zeroize(cbuf, BUFSIZZ);
    free(cbuf);
    vigortls_zeroize(sbuf, BUFSIZZ);
    free(sbuf);
    vigortls_zeroize(mbuf, BUFSIZZ);
    free(mbuf);
    BIO_free(bio_c_out);
    bio_c_out = NULL;
    BIO_free(bio_c_msg);
    bio_c_msg = NULL;
    return ret;
}

static void print_stuff(BIO *bio, SSL *s, int full)
{
    X509 *peer = NULL;
    char *p;
    static const char *space = "                ";
    char buf[BUFSIZ];
    STACK_OF(X509) *sk;
    STACK_OF(X509_NAME) *sk2;
    const SSL_CIPHER *c;
    X509_NAME *xn;
    int j, i;
    uint8_t *exportedkeymat;

    if (full) {
        int got_a_chain = 0;

        sk = SSL_get_peer_cert_chain(s);
        if (sk != NULL) {
            got_a_chain = 1;

            BIO_printf(bio, "---\nCertificate chain\n");
            for (i = 0; i < sk_X509_num(sk); i++) {
                X509_NAME_oneline(X509_get_subject_name(sk_X509_value(sk, i)),
                                  buf, sizeof buf);
                BIO_printf(bio, "%2d s:%s\n", i, buf);
                X509_NAME_oneline(X509_get_issuer_name(sk_X509_value(sk, i)),
                                  buf, sizeof buf);
                BIO_printf(bio, "   i:%s\n", buf);
                if (c_showcerts)
                    PEM_write_bio_X509(bio, sk_X509_value(sk, i));
            }
        }

        BIO_printf(bio, "---\n");
        peer = SSL_get_peer_certificate(s);
        if (peer != NULL) {
            BIO_printf(bio, "Server certificate\n");
            if (!(c_showcerts &&
                  got_a_chain)) /* Redundant if we showed the whole chain */
                PEM_write_bio_X509(bio, peer);
            X509_NAME_oneline(X509_get_subject_name(peer), buf, sizeof buf);
            BIO_printf(bio, "subject=%s\n", buf);
            X509_NAME_oneline(X509_get_issuer_name(peer), buf, sizeof buf);
            BIO_printf(bio, "issuer=%s\n", buf);
        } else
            BIO_printf(bio, "no peer certificate available\n");

        sk2 = SSL_get_client_CA_list(s);
        if ((sk2 != NULL) && (sk_X509_NAME_num(sk2) > 0)) {
            BIO_printf(bio, "---\nAcceptable client certificate CA names\n");
            for (i = 0; i < sk_X509_NAME_num(sk2); i++) {
                xn = sk_X509_NAME_value(sk2, i);
                X509_NAME_oneline(xn, buf, sizeof(buf));
                BIO_write(bio, buf, strlen(buf));
                BIO_write(bio, "\n", 1);
            }
        } else {
            BIO_printf(bio, "---\nNo client certificate CA names sent\n");
        }
        p = SSL_get_shared_ciphers(s, buf, sizeof buf);
        if (p != NULL) {
            /* This works only for SSL 2.  In later protocol
             * versions, the client does not know what other
             * ciphers (in addition to the one to be used
             * in the current connection) the server supports. */

            BIO_printf(bio,
                       "---\nCiphers common between both SSL endpoints:\n");
            j = i = 0;
            while (*p) {
                if (*p == ':') {
                    BIO_write(bio, space, 15 - j % 25);
                    i++;
                    j = 0;
                    BIO_write(bio, ((i % 3) ? " " : "\n"), 1);
                } else {
                    BIO_write(bio, p, 1);
                    j++;
                }
                p++;
            }
            BIO_write(bio, "\n", 1);
        }
        
        ssl_print_sigalgs(bio, s);
        ssl_print_tmp_key(bio, s);

        BIO_printf(
            bio,
            "---\nSSL handshake has read %ld bytes and written %ld bytes\n",
            BIO_number_read(SSL_get_rbio(s)),
            BIO_number_written(SSL_get_wbio(s)));
    }
    BIO_printf(bio, (SSL_cache_hit(s) ? "---\nReused, " : "---\nNew, "));
    c = SSL_get_current_cipher(s);
    BIO_printf(bio, "%s, Cipher is %s\n", SSL_CIPHER_get_version(c),
               SSL_CIPHER_get_name(c));
    if (peer != NULL) {
        EVP_PKEY *pktmp;
        pktmp = X509_get_pubkey(peer);
        BIO_printf(bio, "Server public key is %d bit\n", EVP_PKEY_bits(pktmp));
        EVP_PKEY_free(pktmp);
    }
    BIO_printf(bio, "Secure Renegotiation IS%s supported\n",
               SSL_get_secure_renegotiation_support(s) ? "" : " NOT");

    if (next_proto.status != -1) {
        const uint8_t *proto;
        unsigned int proto_len;
        SSL_get0_next_proto_negotiated(s, &proto, &proto_len);
        BIO_printf(bio, "Next protocol: (%d) ", next_proto.status);
        BIO_write(bio, proto, proto_len);
        BIO_write(bio, "\n", 1);
    }
    {
        const uint8_t *proto;
        unsigned int proto_len;
        SSL_get0_alpn_selected(s, &proto, &proto_len);
        if (proto_len > 0) {
            BIO_printf(bio, "ALPN protocol: ");
            BIO_write(bio, proto, proto_len);
            BIO_write(bio, "\n", 1);
        } else
            BIO_printf(bio, "No ALPN negotiated\n");
    }

#ifndef OPENSSL_NO_SRTP
    {
        SRTP_PROTECTION_PROFILE *srtp_profile =
            SSL_get_selected_srtp_profile(s);

        if (srtp_profile)
            BIO_printf(bio, "SRTP Extension negotiated, profile=%s\n",
                       srtp_profile->name);
    }
#endif

    SSL_SESSION_print(bio, SSL_get_session(s));
    if (keymatexportlabel != NULL) {
        BIO_printf(bio, "Keying material exporter:\n");
        BIO_printf(bio, "    Label: '%s'\n", keymatexportlabel);
        BIO_printf(bio, "    Length: %i bytes\n", keymatexportlen);
        exportedkeymat = malloc(keymatexportlen);
        if (exportedkeymat != NULL) {
            if (!SSL_export_keying_material(
                    s, exportedkeymat, keymatexportlen, keymatexportlabel,
                    strlen(keymatexportlabel), NULL, 0, 0)) {
                BIO_printf(bio, "    Error\n");
            } else {
                BIO_printf(bio, "    Keying material: ");
                for (i = 0; i < keymatexportlen; i++)
                    BIO_printf(bio, "%02X", exportedkeymat[i]);
                BIO_printf(bio, "\n");
            }
            free(exportedkeymat);
        }
    }
    BIO_printf(bio, "---\n");
    if (peer != NULL)
        X509_free(peer);
    /* flush, or debugging output gets mixed with http response */
    (void)BIO_flush(bio);
}

static int ocsp_resp_cb(SSL *s, void *arg)
{
    const uint8_t *p;
    int len;
    OCSP_RESPONSE *rsp;
    len = SSL_get_tlsext_status_ocsp_resp(s, &p);
    BIO_puts(arg, "OCSP response: ");
    if (!p) {
        BIO_puts(arg, "no response sent\n");
        return 1;
    }
    rsp = d2i_OCSP_RESPONSE(NULL, &p, len);
    if (!rsp) {
        BIO_puts(arg, "response parse error\n");
        BIO_dump_indent(arg, (char *)p, len, 4);
        return 0;
    }
    BIO_puts(arg, "\n======================================\n");
    OCSP_RESPONSE_print(arg, rsp, 0);
    BIO_puts(arg, "======================================\n");
    OCSP_RESPONSE_free(rsp);
    return 1;
}
