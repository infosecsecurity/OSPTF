/*
 * Copyright (C) 2016, Kurt Cancemi
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

#include <string.h>

#include "time_support.h"

/*
 * Take a tm structure and add an offset to it. This avoids any OS issues
 * with restricted date types and overflows which cause the year 2038
 * problem.
 */

#define SECS_PER_DAY (24 * 60 * 60)

static long date_to_julian(int y, int m, int d);
static void julian_to_date(long jd, int *y, int *m, int *d);

int gmtime_r_adj(struct tm *tm, int off_day, long offset_sec)
{
    int offset_hms, offset_day;
    long time_jd;
    int time_year, time_month, time_day;
    /* Split offset into days and day seconds */
    offset_day = offset_sec / SECS_PER_DAY;
    /* Avoid sign issues with % operator */
    offset_hms = offset_sec - (offset_day * SECS_PER_DAY);
    offset_day += off_day;
    /* Add current time seconds to offset */
    offset_hms += tm->tm_hour * 3600 + tm->tm_min * 60 + tm->tm_sec;
    /* Adjust day seconds if overflow */
    if (offset_hms >= SECS_PER_DAY) {
        offset_day++;
        offset_hms -= SECS_PER_DAY;
    } else if (offset_hms < 0) {
        offset_day--;
        offset_hms += SECS_PER_DAY;
    }

    /* Convert date of time structure into a Julian day number. */

    time_year = tm->tm_year + 1900;
    time_month = tm->tm_mon + 1;
    time_day = tm->tm_mday;

    time_jd = date_to_julian(time_year, time_month, time_day);

    /* Work out Julian day of new date */
    time_jd += offset_day;

    if (time_jd < 0)
        return 0;

    /* Convert Julian day back to date */

    julian_to_date(time_jd, &time_year, &time_month, &time_day);

    if (time_year < 1900 || time_year > 9999)
        return 0;

    /* Update tm structure */

    tm->tm_year = time_year - 1900;
    tm->tm_mon = time_month - 1;
    tm->tm_mday = time_day;

    tm->tm_hour = offset_hms / 3600;
    tm->tm_min = (offset_hms / 60) % 60;
    tm->tm_sec = offset_hms % 60;

    return 1;
}

/*
 * Convert date to julian
 * Uses Fliegel & Van Flandern Algorithm
 */
static long date_to_julian(int y, int m, int d)
{
    int m1 = (m - 14) / 12;
    int y1 = y + 4800;

    return (1461 * (y1 + m1) / 4 + 367 * (m - 2 - 12 * m1) / 12 - (3 * ((y1 + m1 + 100) / 100)) / 4 + d - 32075);
}

/*
 * Convert julian to date
 * Uses Fliegel & Van Flandern Algorithm
 */
static void julian_to_date(long jd, int *y, int *m, int *d)
{
    long l, n, i, j;

    l = jd + 68569;
    n = (4 * l) / 146097;
    l = l - (146097 * n + 3) / 4;
    i = (4000 * (l + 1)) / 1461001;
    l = l - (1461 * i) / 4 + 31;
    j = (80 * l) / 2447;
    *d = l - (2447 * j) / 80;
    l = j / 11;
    *m = j + 2 - (12 * l);
    *y = 100 * (n - 49) + i + l;
}
