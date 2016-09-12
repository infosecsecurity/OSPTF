/*
 * Copyright 1999-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdcompat.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/buffer.h>
#include <stdcompat.h>
#include <pqueue.h>

/* remember to change the expected results if you change these values */
uint8_t prio1[8] = "trutheca";
uint8_t prio2[8] = "kapuvuxu";
uint8_t prio3[8] = "chusuwru";

const char prio1_expected[] = "6368757375777275";
const char prio2_expected[] = "6b61707576757875";
const char prio3_expected[] = "7472757468656361";

static void pqueue_print(pqueue pq)
{
    pitem *iter, *item;

    iter = pqueue_iterator(pq);
    for (item = pqueue_next(&iter); item != NULL; item = pqueue_next(&iter)) {
        printf("item\t%02x%02x%02x%02x%02x%02x%02x%02x\n",
               item->priority[0], item->priority[1],
               item->priority[2], item->priority[3],
               item->priority[4], item->priority[5],
               item->priority[6], item->priority[7]);
    }
}

static int pqueue_test(pqueue pq)
{
    pitem *iter, *item;
    char *buf = NULL;
    char *expected = NULL;
    int ret = 0, size, len = 0;

    size = asprintf(&expected, "%s%s%s", prio1_expected, prio2_expected, prio3_expected);
    
    if (size == -1)
        goto err;

    if ((buf = malloc(size)) == NULL)
        goto err;

    iter = pqueue_iterator(pq);
    for (item = pqueue_next(&iter); item != NULL; item = pqueue_next(&iter)) {
        len += snprintf(buf + len, size,
                        "%02x%02x%02x%02x%02x%02x%02x%02x",
                        item->priority[0], item->priority[1],
                        item->priority[2], item->priority[3],
                        item->priority[4], item->priority[5],
                        item->priority[6], item->priority[7]);
        if (len == -1)
            goto err;
    }

    if (strcmp(expected, buf) != 0) {
        printf("expected: %s\nresult:   %s\n", expected, buf);
        goto err;
    }

    ret = 1;

err:
    free(expected);
    return ret;
}

int main(void)
{
    pitem *item;
    pqueue pq;

    pq = pqueue_new();

    item = pitem_new(prio3, NULL);
    pqueue_insert(pq, item);

    item = pitem_new(prio1, NULL);
    pqueue_insert(pq, item);

    item = pitem_new(prio2, NULL);
    pqueue_insert(pq, item);

    item = pqueue_find(pq, prio1);
    fprintf(stderr, "found %p\n", item->priority);

    item = pqueue_find(pq, prio2);
    fprintf(stderr, "found %p\n", item->priority);

    item = pqueue_find(pq, prio3);
    fprintf(stderr, "found %p\n", item ? item->priority : 0);

    pqueue_print(pq);

    if (!pqueue_test(pq))
        return 1;

    for (item = pqueue_pop(pq); item != NULL; item = pqueue_pop(pq))
        pitem_free(item);

    pqueue_free(pq);

    return 0;
}
