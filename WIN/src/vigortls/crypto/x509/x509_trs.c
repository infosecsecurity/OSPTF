/*
 * Copyright 1999-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <string.h>

#include <openssl/err.h>
#include <openssl/x509v3.h>

static int tr_cmp(const X509_TRUST *const *a,
                  const X509_TRUST *const *b);
static void trtable_free(X509_TRUST *p);

static int trust_1oidany(X509_TRUST *trust, X509 *x, int flags);
static int trust_1oid(X509_TRUST *trust, X509 *x, int flags);
static int trust_compat(X509_TRUST *trust, X509 *x, int flags);

static int obj_trust(int id, X509 *x, int flags);
static int (*default_trust)(int id, X509 *x, int flags) = obj_trust;

/* WARNING: the following table should be kept in order of trust
 * and without any gaps so we can just subtract the minimum trust
 * value to get an index into the table
 */

static X509_TRUST trstandard[] = {
    {
        X509_TRUST_COMPAT, 0, trust_compat,
        (char *)"compatible", 0, NULL
    },
    {
        X509_TRUST_SSL_CLIENT, 0, trust_1oidany,
        (char *)"SSL Client", NID_client_auth, NULL
    },
    {
        X509_TRUST_SSL_SERVER, 0, trust_1oidany,
        (char *)"SSL Server", NID_server_auth, NULL
    },
    {
        X509_TRUST_EMAIL, 0, trust_1oidany,
        (char *)"S/MIME email", NID_email_protect, NULL
    },
    {
        X509_TRUST_OBJECT_SIGN, 0, trust_1oidany,
        (char *)"Object Signer", NID_code_sign, NULL
    },
    {
        X509_TRUST_OCSP_SIGN, 0, trust_1oid,
        (char *)"OCSP responder", NID_OCSP_sign, NULL
    },
    {
        X509_TRUST_OCSP_REQUEST, 0, trust_1oid,
        (char *)"OCSP request", NID_ad_OCSP, NULL
    },
    {
        X509_TRUST_TSA, 0, trust_1oidany,
        (char *)"TSA server", NID_time_stamp, NULL
    }
};

#define X509_TRUST_COUNT (sizeof(trstandard) / sizeof(X509_TRUST))

static STACK_OF(X509_TRUST) *trtable = NULL;

static int tr_cmp(const X509_TRUST *const *a,
                  const X509_TRUST *const *b)
{
    return (*a)->trust - (*b)->trust;
}

int (*X509_TRUST_set_default(int (*trust)(int, X509 *, int)))(int, X509 *, int)
{
    int (*oldtrust)(int, X509 *, int);
    oldtrust = default_trust;
    default_trust = trust;
    return oldtrust;
}

int X509_check_trust(X509 *x, int id, int flags)
{
    X509_TRUST *pt;
    int idx;
    if (id == -1)
        return 1;
    /* We get this as a default value */
    if (id == 0) {
        int rv = obj_trust(NID_anyExtendedKeyUsage, x, 0);
        if (rv != X509_TRUST_UNTRUSTED)
            return rv;
        return trust_compat(NULL, x, 0);
    }
    idx = X509_TRUST_get_by_id(id);
    if (idx == -1)
        return default_trust(id, x, flags);
    pt = X509_TRUST_get0(idx);
    return pt->check_trust(pt, x, flags);
}

int X509_TRUST_get_count(void)
{
    if (!trtable)
        return X509_TRUST_COUNT;
    return sk_X509_TRUST_num(trtable) + X509_TRUST_COUNT;
}

X509_TRUST *X509_TRUST_get0(int idx)
{
    if (idx < 0)
        return NULL;
    if (idx < (int)X509_TRUST_COUNT)
        return trstandard + idx;
    return sk_X509_TRUST_value(trtable, idx - X509_TRUST_COUNT);
}

int X509_TRUST_get_by_id(int id)
{
    X509_TRUST tmp;
    int idx;
    if ((id >= X509_TRUST_MIN) && (id <= X509_TRUST_MAX))
        return id - X509_TRUST_MIN;
    tmp.trust = id;
    if (!trtable)
        return -1;
    idx = sk_X509_TRUST_find(trtable, &tmp);
    if (idx == -1)
        return -1;
    return idx + X509_TRUST_COUNT;
}

int X509_TRUST_set(int *t, int trust)
{
    if (X509_TRUST_get_by_id(trust) == -1) {
        X509err(X509_F_X509_TRUST_SET, X509_R_INVALID_TRUST);
        return 0;
    }
    *t = trust;
    return 1;
}

int X509_TRUST_add(int id, int flags, int (*ck)(X509_TRUST *, X509 *, int),
                   char *name, int arg1, void *arg2)
{
    int idx;
    X509_TRUST *trtmp;
    /* This is set according to what we change: application can't set it */
    flags &= ~X509_TRUST_DYNAMIC;
    /* This will always be set for application modified trust entries */
    flags |= X509_TRUST_DYNAMIC_NAME;
    /* Get existing entry if any */
    idx = X509_TRUST_get_by_id(id);
    /* Need a new entry */
    if (idx == -1) {
        if (!(trtmp = malloc(sizeof(X509_TRUST)))) {
            X509err(X509_F_X509_TRUST_ADD, ERR_R_MALLOC_FAILURE);
            return 0;
        }
        trtmp->flags = X509_TRUST_DYNAMIC;
    } else
        trtmp = X509_TRUST_get0(idx);

    /* free existing name if dynamic */
    if (trtmp->flags & X509_TRUST_DYNAMIC_NAME)
        free(trtmp->name);
    /* dup supplied name */
    if (name == NULL || (trtmp->name = strdup(name)) == NULL) {
        X509err(X509_F_X509_TRUST_ADD, ERR_R_MALLOC_FAILURE);
        return 0;
    }
    /* Keep the dynamic flag of existing entry */
    trtmp->flags &= X509_TRUST_DYNAMIC;
    /* Set all other flags */
    trtmp->flags |= flags;

    trtmp->trust = id;
    trtmp->check_trust = ck;
    trtmp->arg1 = arg1;
    trtmp->arg2 = arg2;

    /* If its a new entry manage the dynamic table */
    if (idx == -1) {
        if (!trtable && !(trtable = sk_X509_TRUST_new(tr_cmp))) {
            free(trtmp);
            X509err(X509_F_X509_TRUST_ADD, ERR_R_MALLOC_FAILURE);
            return 0;
        }
        if (!sk_X509_TRUST_push(trtable, trtmp)) {
            free(trtmp);
            X509err(X509_F_X509_TRUST_ADD, ERR_R_MALLOC_FAILURE);
            return 0;
        }
    }
    return 1;
}

static void trtable_free(X509_TRUST *p)
{
    if (!p)
        return;
    if (p->flags & X509_TRUST_DYNAMIC) {
        if (p->flags & X509_TRUST_DYNAMIC_NAME)
            free(p->name);
        free(p);
    }
}

void X509_TRUST_cleanup(void)
{
    unsigned int i;
    for (i = 0; i < X509_TRUST_COUNT; i++)
        trtable_free(trstandard + i);
    sk_X509_TRUST_pop_free(trtable, trtable_free);
    trtable = NULL;
}

int X509_TRUST_get_flags(X509_TRUST *xp)
{
    return xp->flags;
}

char *X509_TRUST_get0_name(X509_TRUST *xp)
{
    return xp->name;
}

int X509_TRUST_get_trust(X509_TRUST *xp)
{
    return xp->trust;
}

static int trust_1oidany(X509_TRUST *trust, X509 *x, int flags)
{
    if (x->aux && (x->aux->trust || x->aux->reject))
        return obj_trust(trust->arg1, x, flags);
    /* we don't have any trust settings: for compatibility
     * we return trusted if it is self signed
     */
    return trust_compat(trust, x, flags);
}

static int trust_1oid(X509_TRUST *trust, X509 *x, int flags)
{
    if (x->aux)
        return obj_trust(trust->arg1, x, flags);
    return X509_TRUST_UNTRUSTED;
}

static int trust_compat(X509_TRUST *trust, X509 *x, int flags)
{
    X509_check_purpose(x, -1, 0);
    if (x->ex_flags & EXFLAG_SS)
        return X509_TRUST_TRUSTED;
    else
        return X509_TRUST_UNTRUSTED;
}

static int obj_trust(int id, X509 *x, int flags)
{
    ASN1_OBJECT *obj;
    int i;
    X509_CERT_AUX *ax;
    ax = x->aux;
    if (!ax)
        return X509_TRUST_UNTRUSTED;
    if (ax->reject) {
        for (i = 0; i < sk_ASN1_OBJECT_num(ax->reject); i++) {
            obj = sk_ASN1_OBJECT_value(ax->reject, i);
            if (OBJ_obj2nid(obj) == id)
                return X509_TRUST_REJECTED;
        }
    }
    if (ax->trust) {
        for (i = 0; i < sk_ASN1_OBJECT_num(ax->trust); i++) {
            obj = sk_ASN1_OBJECT_value(ax->trust, i);
            if (OBJ_obj2nid(obj) == id)
                return X509_TRUST_TRUSTED;
        }
    }
    return X509_TRUST_UNTRUSTED;
}
