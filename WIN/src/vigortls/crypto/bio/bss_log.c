/*
 * Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
    Why BIO_s_log?

    BIO_s_log is useful for system daemons (or services under NT).
    It is one-way BIO, it sends all stuff to syslogd (on system that
    commonly use that), or event log (on NT), or OPCOM (on OpenVMS).

*/

#ifndef NO_SYSLOG

#include <errno.h>
#include <stdio.h>
#include <string.h>

#include <syslog.h>

#include <openssl/buffer.h>
#include <openssl/err.h>
#include <stdcompat.h>

static void xopenlog(BIO *bp, const char *name, int level)
{
    openlog(name, LOG_PID | LOG_CONS, level);
}

static void xcloselog(BIO *bp)
{
    closelog();
}

static void xsyslog(BIO *bp, int priority, const char *string)
{
    syslog(priority, "%s", string);
}

static int slg_new(BIO *bi)
{
    bi->init = 1;
    bi->num = 0;
    bi->ptr = NULL;
    xopenlog(bi, "application", LOG_DAEMON);
    return (1);
}

static int slg_free(BIO *a)
{
    if (a == NULL)
        return (0);
    xcloselog(a);
    return (1);
}

static int slg_write(BIO *b, const char *in, int inl)
{
    int ret = inl;
    char *buf;
    char *pp;
    int priority, i;
    static const struct
    {
        int strl;
        char str[10];
        int log_level;
    } mapping[] = {
          { 6, "PANIC ", LOG_EMERG },
          { 6, "EMERG ", LOG_EMERG },
          { 4, "EMR ", LOG_EMERG },
          { 6, "ALERT ", LOG_ALERT },
          { 4, "ALR ", LOG_ALERT },
          { 5, "CRIT ", LOG_CRIT },
          { 4, "CRI ", LOG_CRIT },
          { 6, "ERROR ", LOG_ERR },
          { 4, "ERR ", LOG_ERR },
          { 8, "WARNING ", LOG_WARNING },
          { 5, "WARN ", LOG_WARNING },
          { 4, "WAR ", LOG_WARNING },
          { 7, "NOTICE ", LOG_NOTICE },
          { 5, "NOTE ", LOG_NOTICE },
          { 4, "NOT ", LOG_NOTICE },
          { 5, "INFO ", LOG_INFO },
          { 4, "INF ", LOG_INFO },
          { 6, "DEBUG ", LOG_DEBUG },
          { 4, "DBG ", LOG_DEBUG },
          { 0, "", LOG_ERR } /* The default */
      };

    if ((buf = malloc(inl + 1)) == NULL) {
        return (0);
    }
    strlcpy(buf, in, inl + 1);

    i = 0;
    while (strncmp(buf, mapping[i].str, mapping[i].strl) != 0)
        i++;
    priority = mapping[i].log_level;
    pp = buf + mapping[i].strl;

    xsyslog(b, priority, pp);

    free(buf);
    return (ret);
}

static long slg_ctrl(BIO *b, int cmd, long num, void *ptr)
{
    switch (cmd) {
        case BIO_CTRL_SET:
            xcloselog(b);
            xopenlog(b, ptr, num);
            break;
        default:
            break;
    }
    return (0);
}

static int slg_puts(BIO *bp, const char *str)
{
    int n, ret;

    n = strlen(str);
    ret = slg_write(bp, str, n);
    return (ret);
}

static BIO_METHOD methods_slg = {
    .type    = BIO_TYPE_MEM,
    .name    = "syslog",
    .bwrite  = slg_write,
    .bputs   = slg_puts,
    .ctrl    = slg_ctrl,
    .create  = slg_new,
    .destroy = slg_free,
};

BIO_METHOD *BIO_s_log(void)
{
    return (&methods_slg);
}

#endif /* NO_SYSLOG */
