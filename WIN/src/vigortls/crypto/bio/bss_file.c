/*
 * Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#if defined(__linux) || defined(__sun) || defined(__hpux)
/* Following definition aliases fopen to fopen64 on above mentioned
 * platforms. This makes it possible to open and sequentially access
 * files larger than 2GB from 32-bit application. It does not allow to
 * traverse them beyond 2GB with fseek/ftell, but on the other hand *no*
 * 32-bit platform permits that, not with fseek/ftell. Not to mention
 * that breaking 2GB limit for seeking would require surgery to *our*
 * API. But sequential access suffices for practical cases when you
 * can run into large files, such as fingerprinting, so we can let API
 * alone. For reference, the list of 32-bit platforms which allow for
 * sequential access of large files without extra "magic" comprise *BSD,
 * Darwin, IRIX...
 */
#ifndef _FILE_OFFSET_BITS
#define _FILE_OFFSET_BITS 64
#endif
#endif

#include <errno.h>
#include <stdio.h>
#include <string.h>

#include <openssl/buffer.h>
#include <openssl/err.h>
#include <stdcompat.h>

BIO *BIO_new_file(const char *filename, const char *mode)
{
    BIO *ret;
    FILE *file = NULL;

    file = fopen(filename, mode);

    if (file == NULL) {
        SYSerr(SYS_F_FOPEN, errno);
        ERR_asprintf_error_data("fopen('%s','%s')", filename, mode);
        if (errno == ENOENT)
            BIOerr(BIO_F_BIO_NEW_FILE, BIO_R_NO_SUCH_FILE);
        else
            BIOerr(BIO_F_BIO_NEW_FILE, ERR_R_SYS_LIB);
        return (NULL);
    }
    if ((ret = BIO_new(BIO_s_file())) == NULL) {
        fclose(file);
        return (NULL);
    }

    BIO_set_fp(ret, file, BIO_CLOSE);
    return (ret);
}

BIO *BIO_new_fp(FILE *stream, int close_flag)
{
    BIO *ret;

    if ((ret = BIO_new(BIO_s_file())) == NULL)
        return (NULL);

    BIO_set_fp(ret, stream, close_flag);
    return (ret);
}

static int file_new(BIO *bi)
{
    bi->init = 0;
    bi->num = 0;
    bi->ptr = NULL;
    return (1);
}

static int file_free(BIO *a)
{
    if (a == NULL)
        return (0);
    if (a->shutdown) {
        if ((a->init) && (a->ptr != NULL)) {
            fclose(a->ptr);
            a->ptr = NULL;
        }
        a->init = 0;
    }
    return (1);
}

static int file_read(BIO *b, char *out, int outl)
{
    int ret = 0;

    if (b->init && (out != NULL)) {
        ret = fread(out, 1, (int)outl, (FILE *)b->ptr);
        if (ret == 0 && ferror((FILE *)b->ptr)) {
            SYSerr(SYS_F_FREAD, errno);
            BIOerr(BIO_F_FILE_READ, ERR_R_SYS_LIB);
            ret = -1;
        }
    }
    return (ret);
}

static int file_write(BIO *b, const char *in, int inl)
{
    int ret = 0;

    if (b->init && (in != NULL))
        ret = fwrite(in, 1, inl, (FILE *)b->ptr);

    return ret;
}

static long file_ctrl(BIO *b, int cmd, long num, void *ptr)
{
    long ret = 1;
    FILE *fp = (FILE *)b->ptr;
    FILE **fpp;
    char p[4];

    switch (cmd) {
        case BIO_C_FILE_SEEK:
        case BIO_CTRL_RESET:
            ret = (long)fseek(fp, num, 0);
            break;
        case BIO_CTRL_EOF:
            ret = (long)feof(fp);
            break;
        case BIO_C_FILE_TELL:
        case BIO_CTRL_INFO:
            ret = ftell(fp);
            break;
        case BIO_C_SET_FILE_PTR:
            file_free(b);
            b->shutdown = (int)num & BIO_CLOSE;
            b->ptr = ptr;
            b->init = 1;
            break;
        case BIO_C_SET_FILENAME:
            file_free(b);
            b->shutdown = (int)num & BIO_CLOSE;
            if (num & BIO_FP_APPEND) {
                if (num & BIO_FP_READ)
                    strlcpy(p, "a+", sizeof p);
                else
                    strlcpy(p, "a", sizeof p);
            } else if ((num & BIO_FP_READ) && (num & BIO_FP_WRITE))
                strlcpy(p, "r+", sizeof p);
            else if (num & BIO_FP_WRITE)
                strlcpy(p, "w", sizeof p);
            else if (num & BIO_FP_READ)
                strlcpy(p, "r", sizeof p);
            else {
                BIOerr(BIO_F_FILE_CTRL, BIO_R_BAD_FOPEN_MODE);
                ret = 0;
                break;
            }
            fp = fopen(ptr, p);
            if (fp == NULL) {
                SYSerr(SYS_F_FOPEN, errno);
                ERR_asprintf_error_data("fopen('%s','%s')", ptr, p);
                BIOerr(BIO_F_FILE_CTRL, ERR_R_SYS_LIB);
                ret = 0;
                break;
            }
            b->ptr = fp;
            b->init = 1;
            break;
        case BIO_C_GET_FILE_PTR:
            /* the ptr parameter is actually a FILE ** in this case. */
            if (ptr != NULL) {
                fpp = (FILE **)ptr;
                *fpp = (FILE *)b->ptr;
            }
            break;
        case BIO_CTRL_GET_CLOSE:
            ret = (long)b->shutdown;
            break;
        case BIO_CTRL_SET_CLOSE:
            b->shutdown = (int)num;
            break;
        case BIO_CTRL_FLUSH:
            fflush((FILE *)b->ptr);
            break;
        case BIO_CTRL_DUP:
            ret = 1;
            break;

        case BIO_CTRL_WPENDING:
        case BIO_CTRL_PENDING:
        case BIO_CTRL_PUSH:
        case BIO_CTRL_POP:
        default:
            ret = 0;
            break;
    }
    return (ret);
}

static int file_gets(BIO *bp, char *buf, int size)
{
    int ret = 0;

    buf[0] = '\0';
    if (!fgets(buf, size, (FILE *)bp->ptr))
        goto err;
    if (buf[0] != '\0')
        ret = strlen(buf);
err:
    return (ret);
}

static int file_puts(BIO *bp, const char *str)
{
    int n, ret;

    n = strlen(str);
    ret = file_write(bp, str, n);
    return (ret);
}

static BIO_METHOD methods_filep = {
    .type = BIO_TYPE_FILE,
    .name = "FILE pointer",
    .bwrite = file_write,
    .bread = file_read,
    .bputs = file_puts,
    .bgets = file_gets,
    .ctrl = file_ctrl,
    .create = file_new,
    .destroy = file_free
};

BIO_METHOD *BIO_s_file(void)
{
    return (&methods_filep);
}
