/*
 * Copyright (c) 2015, Kurt Cancemi (kurt@x64architecture.com)
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

#include <stdcompat.h>

int vasprintf(char **buf, const char *format, va_list args)
{
    int wanted = vsnprintf(*buf = NULL, 0, format, args);
    if ((wanted < 0) || ((*buf = malloc(wanted + 1)) == NULL))
        return -1;
    return vsprintf(*buf, format, args);
}

int asprintf(char **buf, const char *format, ...)
{
    va_list args;
    int ret;

    *buf = NULL;
    va_start(args, format);
    ret = vasprintf(buf, format, args);
    va_end(args);

    return ret;
}
