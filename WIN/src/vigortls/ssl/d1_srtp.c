/*
 * Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */
/*
 * Copyright (C) 2006, Network Resonance, Inc.
 * Copyright (C) 2011, RTFM, Inc.
 */

#include <openssl/opensslconf.h>

#ifndef OPENSSL_NO_SRTP

#include <stdio.h>

#include "ssl_locl.h"

#include <openssl/objects.h>
#include <openssl/srtp.h>

#include "bytestring.h"

static SRTP_PROTECTION_PROFILE srtp_known_profiles[] = {
    {
      .name = "SRTP_AES128_CM_SHA1_80",
      .id = SRTP_AES128_CM_SHA1_80,
    },
    {
      .name = "SRTP_AES128_CM_SHA1_32",
      .id = SRTP_AES128_CM_SHA1_32,
    },
    { 
      .name = 0,
      .id = 0,
    },
};

static int find_profile_by_name(char *profile_name,
                                SRTP_PROTECTION_PROFILE **pptr, unsigned len)
{
    SRTP_PROTECTION_PROFILE *p;

    p = srtp_known_profiles;
    while (p->name) {
        if ((len == strlen(p->name)) && strncmp(p->name, profile_name, len) == 0) {
            *pptr = p;
            return 0;
        }

        p++;
    }

    return 1;
}

static int find_profile_by_num(unsigned profile_num,
                               SRTP_PROTECTION_PROFILE **pptr)
{
    SRTP_PROTECTION_PROFILE *p;

    p = srtp_known_profiles;
    while (p->name) {
        if (p->id == profile_num) {
            *pptr = p;
            return 0;
        }
        p++;
    }

    return 1;
}

static int ssl_ctx_make_profiles(const char *profiles_string,
                                 STACK_OF(SRTP_PROTECTION_PROFILE) **out)
{
    STACK_OF(SRTP_PROTECTION_PROFILE) *profiles;

    char *col;
    char *ptr = (char *)profiles_string;

    SRTP_PROTECTION_PROFILE *p;

    if (!(profiles = sk_SRTP_PROTECTION_PROFILE_new_null())) {
        SSLerr(SSL_F_SSL_CTX_MAKE_PROFILES, SSL_R_SRTP_COULD_NOT_ALLOCATE_PROFILES);
        return 1;
    }

    do {
        col = strchr(ptr, ':');

        if (!find_profile_by_name(ptr, &p, col ? col - ptr : (int)strlen(ptr))) {
            sk_SRTP_PROTECTION_PROFILE_push(profiles, p);
        } else {
            SSLerr(SSL_F_SSL_CTX_MAKE_PROFILES,
                   SSL_R_SRTP_UNKNOWN_PROTECTION_PROFILE);
            sk_SRTP_PROTECTION_PROFILE_free(profiles);
            return 1;
        }

        if (col)
            ptr = col + 1;
    } while (col);

    *out = profiles;

    return 0;
}

int SSL_CTX_set_tlsext_use_srtp(SSL_CTX *ctx, const char *profiles)
{
    return ssl_ctx_make_profiles(profiles, &ctx->srtp_profiles);
}

int SSL_set_tlsext_use_srtp(SSL *s, const char *profiles)
{
    return ssl_ctx_make_profiles(profiles, &s->srtp_profiles);
}

STACK_OF(SRTP_PROTECTION_PROFILE) *SSL_get_srtp_profiles(SSL *s)
{
    if (s != NULL) {
        if (s->srtp_profiles != NULL) {
            return s->srtp_profiles;
        } else if ((s->ctx != NULL) && (s->ctx->srtp_profiles != NULL)) {
            return s->ctx->srtp_profiles;
        }
    }

    return NULL;
}

SRTP_PROTECTION_PROFILE *SSL_get_selected_srtp_profile(SSL *s)
{
    return s->srtp_profile;
}

/* Note: this function returns 0 length if there are no
   profiles specified */
int ssl_add_clienthello_use_srtp_ext(SSL *s, uint8_t *p, int *len,
                                     int maxlen)
{
    int ct = 0;
    int i;
    STACK_OF(SRTP_PROTECTION_PROFILE) *clnt = 0;
    SRTP_PROTECTION_PROFILE *prof;

    clnt = SSL_get_srtp_profiles(s);

    ct = sk_SRTP_PROTECTION_PROFILE_num(clnt); /* -1 if clnt == 0 */

    if (p) {
        if (ct == 0) {
            SSLerr(SSL_F_SSL_ADD_CLIENTHELLO_USE_SRTP_EXT,
                   SSL_R_EMPTY_SRTP_PROTECTION_PROFILE_LIST);
            return 1;
        }

        if ((2 + ct * 2 + 1) > maxlen) {
            SSLerr(SSL_F_SSL_ADD_CLIENTHELLO_USE_SRTP_EXT,
                   SSL_R_SRTP_PROTECTION_PROFILE_LIST_TOO_LONG);
            return 1;
        }

        /* Add the length */
        s2n(ct * 2, p);
        for (i = 0; i < ct; i++) {
            prof = sk_SRTP_PROTECTION_PROFILE_value(clnt, i);
            s2n(prof->id, p);
        }

        /* Add an empty use_mki value */
        *p++ = 0;
    }

    *len = 2 + ct * 2 + 1;

    return 0;
}

int ssl_parse_clienthello_use_srtp_ext(SSL *s, const uint8_t *d, int len,
                                       int *al)
{
    SRTP_PROTECTION_PROFILE *cprof, *sprof;
    STACK_OF(SRTP_PROTECTION_PROFILE) *clnt = 0, *srvr;
    int i, j;
    int ret = 1;
    uint16_t id;
    CBS cbs, ciphers, mki;

    CBS_init(&cbs, d, len);

    if (len < 0) {
        SSLerr(SSL_F_SSL_PARSE_CLIENTHELLO_USE_SRTP_EXT,
               SSL_R_BAD_SRTP_PROTECTION_PROFILE_LIST);
        *al = SSL_AD_DECODE_ERROR;
        goto done;
    }

    /* Pull off the cipher suite list */
    if (!CBS_get_u16_length_prefixed(&cbs, &ciphers) ||
        CBS_len(&ciphers) % 2) {
        SSLerr(SSL_F_SSL_PARSE_CLIENTHELLO_USE_SRTP_EXT,
               SSL_R_BAD_SRTP_PROTECTION_PROFILE_LIST);
        *al = SSL_AD_DECODE_ERROR;
        goto done;
    }

    clnt = sk_SRTP_PROTECTION_PROFILE_new_null();

    while (CBS_len(&ciphers) > 0) {
        if (!CBS_get_u16(&ciphers, &id)) {
            SSLerr(SSL_F_SSL_PARSE_CLIENTHELLO_USE_SRTP_EXT,
                   SSL_R_BAD_SRTP_PROTECTION_PROFILE_LIST);
            *al = SSL_AD_DECODE_ERROR;
            goto done;
        }

        if (!find_profile_by_num(id, &cprof))
            sk_SRTP_PROTECTION_PROFILE_push(clnt, cprof);
        else
            ; /* Ignore */
    }

    /* Extract the MKI value as a sanity check, but discard it for now. */
    if (!CBS_get_u8_length_prefixed(&cbs, &mki) ||
        CBS_len(&cbs) != 0) {
        SSLerr(SSL_F_SSL_PARSE_CLIENTHELLO_USE_SRTP_EXT, SSL_R_BAD_SRTP_MKI_VALUE);
        *al = SSL_AD_DECODE_ERROR;
        sk_SRTP_PROTECTION_PROFILE_free(clnt);
        goto done;
    }

    srvr = SSL_get_srtp_profiles(s);

    /*
     * Pick our most preferred profile. If no profiles have been
     * configured then the outer loop doesn't run
     * (sk_SRTP_PROTECTION_PROFILE_num() = -1)
     * and so we just return without doing anything.
     */
    for (i = 0; i < sk_SRTP_PROTECTION_PROFILE_num(srvr); i++) {
        sprof = sk_SRTP_PROTECTION_PROFILE_value(srvr, i);

        for (j = 0; j < sk_SRTP_PROTECTION_PROFILE_num(clnt); j++) {
            cprof = sk_SRTP_PROTECTION_PROFILE_value(clnt, j);

            if (cprof->id == sprof->id) {
                s->srtp_profile = sprof;
                *al = 0;
                ret = 0;
                goto done;
            }
        }
    }

    ret = 0;

done:
    if (clnt)
        sk_SRTP_PROTECTION_PROFILE_free(clnt);

    return ret;
}

int ssl_add_serverhello_use_srtp_ext(SSL *s, uint8_t *p, int *len,
                                     int maxlen)
{
    if (p) {
        if (maxlen < 5) {
            SSLerr(SSL_F_SSL_ADD_SERVERHELLO_USE_SRTP_EXT,
                   SSL_R_SRTP_PROTECTION_PROFILE_LIST_TOO_LONG);
            return 1;
        }

        if (s->srtp_profile == 0) {
            SSLerr(SSL_F_SSL_ADD_SERVERHELLO_USE_SRTP_EXT,
                   SSL_R_USE_SRTP_NOT_NEGOTIATED);
            return 1;
        }
        s2n(2, p);
        s2n(s->srtp_profile->id, p);
        *p++ = 0;
    }
    *len = 5;

    return 0;
}

int ssl_parse_serverhello_use_srtp_ext(SSL *s, const uint8_t *d, int len,
                                       int *al)
{
    STACK_OF(SRTP_PROTECTION_PROFILE) *clnt;
    SRTP_PROTECTION_PROFILE *prof;
    int i;
    uint16_t id;
    CBS cbs, profile_ids, mki;

    if (len < 0) {
        SSLerr(SSL_F_SSL_PARSE_SERVERHELLO_USE_SRTP_EXT,
               SSL_R_BAD_SRTP_PROTECTION_PROFILE_LIST);
        *al = SSL_AD_DECODE_ERROR;
        return 1;
    }

    CBS_init(&cbs, d, len);

    /*
     * As per RFC 5764 section 4.1.1, server response MUST be a single
     * profile id.
     */
    if (!CBS_get_u16_length_prefixed(&cbs, &profile_ids) ||
        !CBS_get_u16(&profile_ids, &id) || CBS_len(&profile_ids) != 0) {
        SSLerr(SSL_F_SSL_PARSE_SERVERHELLO_USE_SRTP_EXT,
               SSL_R_BAD_SRTP_PROTECTION_PROFILE_LIST);
        *al = SSL_AD_DECODE_ERROR;
        return 1;
    }

    /* Must be no MKI, since we never offer one. */
    if (!CBS_get_u8_length_prefixed(&cbs, &mki) || CBS_len(&mki) != 0) {
        SSLerr(SSL_F_SSL_PARSE_SERVERHELLO_USE_SRTP_EXT, SSL_R_BAD_SRTP_MKI_VALUE);
        *al = SSL_AD_ILLEGAL_PARAMETER;
        return 1;
    }

    clnt = SSL_get_srtp_profiles(s);

    /* Throw an error if the server gave us an unsolicited extension. */
    if (clnt == NULL) {
        SSLerr(SSL_F_SSL_PARSE_SERVERHELLO_USE_SRTP_EXT, SSL_R_NO_SRTP_PROFILES);
        *al = SSL_AD_DECODE_ERROR;
        return 1;
    }

    /*
     * Check to see if the server gave us something we support
     * (and presumably offered).
     */
    for (i = 0; i < sk_SRTP_PROTECTION_PROFILE_num(clnt); i++) {
        prof = sk_SRTP_PROTECTION_PROFILE_value(clnt, i);

        if (prof->id == id) {
            s->srtp_profile = prof;
            *al = 0;
            return 0;
        }
    }

    SSLerr(SSL_F_SSL_PARSE_SERVERHELLO_USE_SRTP_EXT,
           SSL_R_BAD_SRTP_PROTECTION_PROFILE_LIST);
    *al = SSL_AD_DECODE_ERROR;
    return 1;
}

#endif
