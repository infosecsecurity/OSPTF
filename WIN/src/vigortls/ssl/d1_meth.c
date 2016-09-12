/*
 * Copyright 1999-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <openssl/objects.h>
#include "ssl_locl.h"

static const SSL_METHOD *dtls1_get_method(int ver);

const SSL_METHOD DTLSv1_method_data = {
    .version = DTLS1_VERSION,
    .ssl_new = dtls1_new,
    .ssl_clear = dtls1_clear,
    .ssl_free = dtls1_free,
    .ssl_accept = dtls1_accept,
    .ssl_connect = dtls1_connect,
    .ssl_read = ssl3_read,
    .ssl_peek = ssl3_peek,
    .ssl_write = ssl3_write,
    .ssl_shutdown = dtls1_shutdown,
    .ssl_renegotiate = ssl3_renegotiate,
    .ssl_renegotiate_check = ssl3_renegotiate_check,
    .ssl_get_message = dtls1_get_message,
    .ssl_read_bytes = dtls1_read_bytes,
    .ssl_write_bytes = dtls1_write_app_data_bytes,
    .ssl_dispatch_alert = dtls1_dispatch_alert,
    .ssl_ctrl = dtls1_ctrl,
    .ssl_ctx_ctrl = ssl3_ctx_ctrl,
    .get_cipher_by_char = ssl3_get_cipher_by_char,
    .put_cipher_by_char = ssl3_put_cipher_by_char,
    .ssl_pending = ssl3_pending,
    .num_ciphers = ssl3_num_ciphers,
    .get_cipher = dtls1_get_cipher,
    .get_ssl_method = dtls1_get_method,
    .get_timeout = dtls1_default_timeout,
    .ssl3_enc = &DTLSv1_enc_data,
    .ssl_version = ssl_undefined_void_function,
    .ssl_callback_ctrl = ssl3_callback_ctrl,
    .ssl_ctx_callback_ctrl = ssl3_ctx_callback_ctrl,
};

const SSL_METHOD *DTLSv1_method(void)
{
    return &DTLSv1_method_data;
}

const SSL_METHOD DTLSv1_2_method_data = {
    .version = DTLS1_2_VERSION,
    .ssl_new = dtls1_new,
    .ssl_clear = dtls1_clear,
    .ssl_free = dtls1_free,
    .ssl_accept = dtls1_accept,
    .ssl_connect = dtls1_connect,
    .ssl_read = ssl3_read,
    .ssl_peek = ssl3_peek,
    .ssl_write = ssl3_write,
    .ssl_shutdown = dtls1_shutdown,
    .ssl_renegotiate = ssl3_renegotiate,
    .ssl_renegotiate_check = ssl3_renegotiate_check,
    .ssl_get_message = dtls1_get_message,
    .ssl_read_bytes = dtls1_read_bytes,
    .ssl_write_bytes = dtls1_write_app_data_bytes,
    .ssl_dispatch_alert = dtls1_dispatch_alert,
    .ssl_ctrl = dtls1_ctrl,
    .ssl_ctx_ctrl = ssl3_ctx_ctrl,
    .get_cipher_by_char = ssl3_get_cipher_by_char,
    .put_cipher_by_char = ssl3_put_cipher_by_char,
    .ssl_pending = ssl3_pending,
    .num_ciphers = ssl3_num_ciphers,
    .get_cipher = dtls1_get_cipher,
    .get_ssl_method = dtls1_get_method,
    .get_timeout = dtls1_default_timeout,
    .ssl3_enc = &DTLSv1_2_enc_data,
    .ssl_version = ssl_undefined_void_function,
    .ssl_callback_ctrl = ssl3_callback_ctrl,
    .ssl_ctx_callback_ctrl = ssl3_ctx_callback_ctrl,
};

const SSL_METHOD *DTLSv1_2_method(void)
{
    return &DTLSv1_2_method_data;
}

const SSL_METHOD DTLS_method_data = {
    .version = DTLS_ANY_VERSION,
    .ssl_new = dtls1_new,
    .ssl_clear = dtls1_clear,
    .ssl_free = dtls1_free,
    .ssl_accept = dtls1_accept,
    .ssl_connect = dtls1_connect,
    .ssl_read = ssl3_read,
    .ssl_peek = ssl3_peek,
    .ssl_write = ssl3_write,
    .ssl_shutdown = dtls1_shutdown,
    .ssl_renegotiate = ssl3_renegotiate,
    .ssl_renegotiate_check = ssl3_renegotiate_check,
    .ssl_get_message = dtls1_get_message,
    .ssl_read_bytes = dtls1_read_bytes,
    .ssl_write_bytes = dtls1_write_app_data_bytes,
    .ssl_dispatch_alert = dtls1_dispatch_alert,
    .ssl_ctrl = dtls1_ctrl,
    .ssl_ctx_ctrl = ssl3_ctx_ctrl,
    .get_cipher_by_char = ssl3_get_cipher_by_char,
    .put_cipher_by_char = ssl3_put_cipher_by_char,
    .ssl_pending = ssl3_pending,
    .num_ciphers = ssl3_num_ciphers,
    .get_cipher = dtls1_get_cipher,
    .get_ssl_method = dtls1_get_method,
    .get_timeout = dtls1_default_timeout,
    .ssl3_enc = &DTLSv1_2_enc_data,
    .ssl_version = ssl_undefined_void_function,
    .ssl_callback_ctrl = ssl3_callback_ctrl,
    .ssl_ctx_callback_ctrl = ssl3_ctx_callback_ctrl,
};

const SSL_METHOD *DTLS_method(void)
{
    return &DTLS_method_data;
}

static const SSL_METHOD *dtls1_get_method(int ver)
{
    switch (ver) {
        case DTLS_ANY_VERSION:
            return DTLS_method();
        case DTLS1_VERSION:
            return DTLSv1_method();
        case DTLS1_2_VERSION:
            return DTLSv1_2_method();
        default:
            return NULL;
    }
}
