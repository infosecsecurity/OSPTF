/*
 * Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/conf.h>
#include <openssl/conf_api.h>

static void value_free_hash_doall_arg(CONF_VALUE *a,
                                      LHASH_OF(CONF_VALUE) *conf);
static void value_free_stack_doall(CONF_VALUE *a);
static IMPLEMENT_LHASH_DOALL_ARG_FN(value_free_hash, CONF_VALUE,
                                    LHASH_OF(CONF_VALUE))
static IMPLEMENT_LHASH_DOALL_FN(value_free_stack, CONF_VALUE)

CONF_VALUE *_CONF_get_section(const CONF *conf, const char *section)
{
    CONF_VALUE *v, vv;

    if ((conf == NULL) || (section == NULL))
        return (NULL);
    vv.name = NULL;
    vv.section = (char *)section;
    v = lh_CONF_VALUE_retrieve(conf->data, &vv);
    return (v);
}

STACK_OF(CONF_VALUE) *_CONF_get_section_values(const CONF *conf,
                                               const char *section)
{
    CONF_VALUE *v;

    v = _CONF_get_section(conf, section);
    if (v != NULL)
        return ((STACK_OF(CONF_VALUE) *)v->value);
    else
        return (NULL);
}

int _CONF_add_string(CONF *conf, CONF_VALUE *section, CONF_VALUE *value)
{
    CONF_VALUE *v = NULL;
    STACK_OF(CONF_VALUE) *ts;

    ts = (STACK_OF(CONF_VALUE) *)section->value;

    value->section = section->section;
    if (!sk_CONF_VALUE_push(ts, value)) {
        return 0;
    }

    v = lh_CONF_VALUE_insert(conf->data, value);
    if (v != NULL) {
        (void)sk_CONF_VALUE_delete_ptr(ts, v);
        free(v->name);
        free(v->value);
        free(v);
    }
    return 1;
}

char *_CONF_get_string(const CONF *conf, const char *section, const char *name)
{
    CONF_VALUE *v, vv;

    if (name == NULL)
        return (NULL);
    if (conf != NULL) {
        if (section != NULL) {
            vv.name = (char *)name;
            vv.section = (char *)section;
            v = lh_CONF_VALUE_retrieve(conf->data, &vv);
            if (v != NULL)
                return (v->value);
        }
        vv.section = (char *)"default";
        vv.name = (char *)name;
        v = lh_CONF_VALUE_retrieve(conf->data, &vv);
        if (v != NULL)
            return (v->value);
        else
            return NULL;
    } else
        return NULL;
}

static unsigned long conf_value_hash(const CONF_VALUE *v)
{
    return (lh_strhash(v->section) << 2) ^ lh_strhash(v->name);
}
static IMPLEMENT_LHASH_HASH_FN(conf_value, CONF_VALUE)

    static int conf_value_cmp(const CONF_VALUE *a, const CONF_VALUE *b)
{
    int i;

    if (a->section != b->section) {
        i = strcmp(a->section, b->section);
        if (i)
            return (i);
    }

    if ((a->name != NULL) && (b->name != NULL)) {
        i = strcmp(a->name, b->name);
        return (i);
    } else if (a->name == b->name)
        return (0);
    else
        return ((a->name == NULL) ? -1 : 1);
}
static IMPLEMENT_LHASH_COMP_FN(conf_value, CONF_VALUE)

    int _CONF_new_data(CONF *conf)
{
    if (conf == NULL) {
        return 0;
    }
    if (conf->data == NULL)
        if ((conf->data = lh_CONF_VALUE_new()) == NULL) {
            return 0;
        }
    return 1;
}

void _CONF_free_data(CONF *conf)
{
    if (conf == NULL || conf->data == NULL)
        return;

    lh_CONF_VALUE_down_load(conf->data) = 0; /* evil thing to make
                  * sure the 'free()' works as
                  * expected */
    lh_CONF_VALUE_doall_arg(conf->data,
                            LHASH_DOALL_ARG_FN(value_free_hash),
                            LHASH_OF(CONF_VALUE), conf->data);

    /* We now have only 'section' entries in the hash table.
     * Due to problems with */

    lh_CONF_VALUE_doall(conf->data, LHASH_DOALL_FN(value_free_stack));
    lh_CONF_VALUE_free(conf->data);
}

static void value_free_hash_doall_arg(CONF_VALUE *a, LHASH_OF(CONF_VALUE) *conf)
{
    if (a->name != NULL)
        (void)lh_CONF_VALUE_delete(conf, a);
}

static void value_free_stack_doall(CONF_VALUE *a)
{
    CONF_VALUE *vv;
    STACK_OF(CONF_VALUE) *sk;
    int i;

    if (a->name != NULL)
        return;

    sk = (STACK_OF(CONF_VALUE) *)a->value;
    for (i = sk_CONF_VALUE_num(sk) - 1; i >= 0; i--) {
        vv = sk_CONF_VALUE_value(sk, i);
        free(vv->value);
        free(vv->name);
        free(vv);
    }
    sk_CONF_VALUE_free(sk);
    free(a->section);
    free(a);
}

CONF_VALUE *_CONF_new_section(CONF *conf, const char *section)
{
    STACK_OF(CONF_VALUE) *sk = NULL;
    int ok = 0, i;
    CONF_VALUE *v = NULL, *vv;

    if ((sk = sk_CONF_VALUE_new_null()) == NULL)
        goto err;
    if ((v = malloc(sizeof(CONF_VALUE))) == NULL)
        goto err;
    i = strlen(section) + 1;
    if ((v->section = malloc(i)) == NULL)
        goto err;

    memcpy(v->section, section, i);
    v->name = NULL;
    v->value = (char *)sk;

    vv = lh_CONF_VALUE_insert(conf->data, v);
    OPENSSL_assert(vv == NULL);
    ok = 1;
err:
    if (!ok) {
        sk_CONF_VALUE_free(sk);
        free(v);
        v = NULL;
    }
    return (v);
}
