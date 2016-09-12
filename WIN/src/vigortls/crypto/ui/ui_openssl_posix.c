/*
 * Copyright 2001-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#if !defined(_WIN32)

#include <sys/ioctl.h>

#include <openssl/opensslconf.h>

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>

#include "ui_locl.h"

#ifndef NX509_SIG
#define NX509_SIG 32
#endif

/* Define globals.  They are protected by a lock */
static struct sigaction savsig[NX509_SIG];

static struct termios tty_orig;
static FILE *tty_in, *tty_out;
static int is_a_tty;

/* Declare static functions */
static int read_till_nl(FILE *);
static void recsig(int);
static void pushsig(void);
static void popsig(void);
static int read_string_inner(UI *ui, UI_STRING *uis, int echo, int strip_nl);

static int read_string(UI *ui, UI_STRING *uis);
static int write_string(UI *ui, UI_STRING *uis);

static int open_console(UI *ui);
static int echo_console(UI *ui);
static int noecho_console(UI *ui);
static int close_console(UI *ui);

static UI_METHOD ui_openssl = {
    .name = (char *)"OpenSSL default user interface",
    .ui_open_session = open_console,
    .ui_write_string = write_string,
    .ui_read_string = read_string,
    .ui_close_session = close_console,
};

/* The method with all the built-in thingies */
UI_METHOD *UI_OpenSSL(void)
{
    return &ui_openssl;
}

/* The following function makes sure that info and error strings are printed
   before any prompt. */
static int write_string(UI *ui, UI_STRING *uis)
{
    switch (UI_get_string_type(uis)) {
        case UIT_ERROR:
        case UIT_INFO:
            fputs(UI_get0_output_string(uis), tty_out);
            fflush(tty_out);
            break;
        default:
            break;
    }
    return 1;
}

static int read_string(UI *ui, UI_STRING *uis)
{
    int ok = 0;

    switch (UI_get_string_type(uis)) {
        case UIT_BOOLEAN:
            fputs(UI_get0_output_string(uis), tty_out);
            fputs(UI_get0_action_string(uis), tty_out);
            fflush(tty_out);
            return read_string_inner(ui, uis,
                                     UI_get_input_flags(uis) & UI_INPUT_FLAG_ECHO, 0);
        case UIT_PROMPT:
            fputs(UI_get0_output_string(uis), tty_out);
            fflush(tty_out);
            return read_string_inner(ui, uis,
                                     UI_get_input_flags(uis) & UI_INPUT_FLAG_ECHO, 1);
        case UIT_VERIFY:
            fprintf(tty_out, "Verifying - %s",
                    UI_get0_output_string(uis));
            fflush(tty_out);
            if ((ok = read_string_inner(ui, uis, UI_get_input_flags(uis) 
                & UI_INPUT_FLAG_ECHO, 1)) <= 0)
                return ok;
            if (strcmp(UI_get0_result_string(uis),
                       UI_get0_test_string(uis)) != 0) {
                fprintf(tty_out, "Verify failure\n");
                fflush(tty_out);
                return 0;
            }
            break;
        default:
            break;
    }
    return 1;
}

/* Internal functions to read a string without echoing */
static int read_till_nl(FILE *in)
{
#define SIZE 4
    char buf[SIZE + 1];

    do {
        if (!fgets(buf, SIZE, in))
            return 0;
    } while (strchr(buf, '\n') == NULL);
    return 1;
}

static volatile sig_atomic_t intr_signal;

static int read_string_inner(UI *ui, UI_STRING *uis, int echo, int strip_nl)
{
    static int ps;
    int ok;
    char result[BUFSIZ];
    int maxsize = BUFSIZ - 1;
    char *p;

    intr_signal = 0;
    ok = 0;
    ps = 0;

    pushsig();
    ps = 1;

    if (!echo && !noecho_console(ui))
        goto error;
    ps = 2;

    result[0] = '\0';
    p = fgets(result, maxsize, tty_in);
    if (!p)
        goto error;
    if (feof(tty_in))
        goto error;
    if (ferror(tty_in))
        goto error;
    if ((p = strchr(result, '\n')) != NULL) {
        if (strip_nl)
            *p = '\0';
    } else if (!read_till_nl(tty_in))
        goto error;
    if (UI_set_result(ui, uis, result) >= 0)
        ok = 1;

error:
    if (intr_signal == SIGINT)
        ok = -1;
    if (!echo)
        fprintf(tty_out, "\n");
    if (ps >= 2 && !echo && !echo_console(ui))
        ok = 0;

    if (ps >= 1)
        popsig();

    vigortls_zeroize(result, BUFSIZ);
    return ok;
}

/* Internal functions to open, handle and close a channel to the console.  */
static int open_console(UI *ui)
{
    CRYPTO_thread_write_lock(ui->lock);
    is_a_tty = 1;

#define DEV_TTY "/dev/tty"
    if ((tty_in = fopen(DEV_TTY, "r")) == NULL)
        tty_in = stdin;
    if ((tty_out = fopen(DEV_TTY, "w")) == NULL)
        tty_out = stderr;

    if (tcgetattr(fileno(tty_in), &tty_orig) == -1) {
        if (errno == ENOTTY)
            is_a_tty = 0;
        else
        /* Ariel Glenn ariel@columbia.edu reports that solaris
         * can return EINVAL instead. This should be OK */
        if (errno == EINVAL)
            is_a_tty = 0;
        else
            return 0;
    }

    return 1;
}

static int noecho_console(UI *ui)
{
    struct termios tty_new = tty_orig;

    tty_new.c_lflag &= ~ECHO;
    if (is_a_tty && (tcsetattr(fileno(tty_in), TCSANOW, &tty_new) == -1))
        return 0;
    return 1;
}

static int echo_console(UI *ui)
{
    if (is_a_tty && (tcsetattr(fileno(tty_in), TCSANOW, &tty_orig) == -1))
        return 0;
    return 1;
}

static int close_console(UI *ui)
{
    if (tty_in != stdin)
        fclose(tty_in);
    if (tty_out != stderr)
        fclose(tty_out);
    CRYPTO_thread_unlock(ui->lock);

    return 1;
}

/* Internal functions to handle signals and act on them */
static void pushsig(void)
{
    int i;
    struct sigaction sa;

    memset(&sa, 0, sizeof sa);
    sa.sa_handler = recsig;

    for (i = 1; i < NX509_SIG; i++) {
        if (i == SIGUSR1)
            continue;
        if (i == SIGUSR2)
            continue;
        if (i == SIGKILL) /* We can't make any action on that. */
            continue;
        sigaction(i, &sa, &savsig[i]);
    }

    signal(SIGWINCH, SIG_DFL);
}

static void popsig(void)
{
    int i;
    for (i = 1; i < NX509_SIG; i++) {
        if (i == SIGUSR1)
            continue;
        if (i == SIGUSR2)
            continue;
        sigaction(i, &savsig[i], NULL);
    }
}

static void recsig(int i)
{
    intr_signal = i;
}

#endif /* !defined(_WIN32) */
