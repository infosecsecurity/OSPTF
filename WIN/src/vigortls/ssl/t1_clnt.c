/*
 * Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "ssl_locl.h"
#include <openssl/buffer.h>
#include <openssl/rand.h>
#include <openssl/objects.h>
#include <openssl/evp.h>

static const SSL_METHOD *tls1_get_client_method(int ver);

const SSL_METHOD TLS_client_method_data = {
    .version = TLS1_2_VERSION,
    .ssl_new = tls1_new,
    .ssl_clear = tls1_clear,
    .ssl_free = tls1_free,
    .ssl_accept = ssl_undefined_function,
    .ssl_connect = ssl23_connect,
    .ssl_read = ssl23_read,
    .ssl_peek = ssl23_peek,
    .ssl_write = ssl23_write,
    .ssl_shutdown = ssl_undefined_function,
    .ssl_renegotiate = ssl_undefined_function,
    .ssl_renegotiate_check = ssl_ok,
    .ssl_get_message = ssl3_get_message,
    .ssl_read_bytes = ssl3_read_bytes,
    .ssl_write_bytes = ssl3_write_bytes,
    .ssl_dispatch_alert = ssl3_dispatch_alert,
    .ssl_ctrl = ssl3_ctrl,
    .ssl_ctx_ctrl = ssl3_ctx_ctrl,
    .get_cipher_by_char = ssl3_get_cipher_by_char,
    .put_cipher_by_char = ssl3_put_cipher_by_char,
    .ssl_pending = ssl_undefined_const_function,
    .num_ciphers = ssl3_num_ciphers,
    .get_cipher = ssl3_get_cipher,
    .get_ssl_method = tls1_get_client_method,
    .get_timeout = ssl23_default_timeout,
    .ssl3_enc = &ssl3_undef_enc_method,
    .ssl_version = ssl_undefined_void_function,
    .ssl_callback_ctrl = ssl3_callback_ctrl,
    .ssl_ctx_callback_ctrl = ssl3_ctx_callback_ctrl,
};

const SSL_METHOD TLSv1_client_method_data = {
    .version = TLS1_VERSION,
    .ssl_new = tls1_new,
    .ssl_clear = tls1_clear,
    .ssl_free = tls1_free,
    .ssl_accept = ssl_undefined_function,
    .ssl_connect = ssl3_connect,
    .ssl_read = ssl3_read,
    .ssl_peek = ssl3_peek,
    .ssl_write = ssl3_write,
    .ssl_shutdown = ssl3_shutdown,
    .ssl_renegotiate = ssl3_renegotiate,
    .ssl_renegotiate_check = ssl3_renegotiate_check,
    .ssl_get_message = ssl3_get_message,
    .ssl_read_bytes = ssl3_read_bytes,
    .ssl_write_bytes = ssl3_write_bytes,
    .ssl_dispatch_alert = ssl3_dispatch_alert,
    .ssl_ctrl = ssl3_ctrl,
    .ssl_ctx_ctrl = ssl3_ctx_ctrl,
    .get_cipher_by_char = ssl3_get_cipher_by_char,
    .put_cipher_by_char = ssl3_put_cipher_by_char,
    .ssl_pending = ssl3_pending,
    .num_ciphers = ssl3_num_ciphers,
    .get_cipher = ssl3_get_cipher,
    .get_ssl_method = tls1_get_client_method,
    .get_timeout = tls1_default_timeout,
    .ssl3_enc = &TLSv1_enc_data,
    .ssl_version = ssl_undefined_void_function,
    .ssl_callback_ctrl = ssl3_callback_ctrl,
    .ssl_ctx_callback_ctrl = ssl3_ctx_callback_ctrl,
};

const SSL_METHOD TLSv1_1_client_method_data = {
    .version = TLS1_1_VERSION,
    .ssl_new = tls1_new,
    .ssl_clear = tls1_clear,
    .ssl_free = tls1_free,
    .ssl_accept = ssl_undefined_function,
    .ssl_connect = ssl3_connect,
    .ssl_read = ssl3_read,
    .ssl_peek = ssl3_peek,
    .ssl_write = ssl3_write,
    .ssl_shutdown = ssl3_shutdown,
    .ssl_renegotiate = ssl3_renegotiate,
    .ssl_renegotiate_check = ssl3_renegotiate_check,
    .ssl_get_message = ssl3_get_message,
    .ssl_read_bytes = ssl3_read_bytes,
    .ssl_write_bytes = ssl3_write_bytes,
    .ssl_dispatch_alert = ssl3_dispatch_alert,
    .ssl_ctrl = ssl3_ctrl,
    .ssl_ctx_ctrl = ssl3_ctx_ctrl,
    .get_cipher_by_char = ssl3_get_cipher_by_char,
    .put_cipher_by_char = ssl3_put_cipher_by_char,
    .ssl_pending = ssl3_pending,
    .num_ciphers = ssl3_num_ciphers,
    .get_cipher = ssl3_get_cipher,
    .get_ssl_method = tls1_get_client_method,
    .get_timeout = tls1_default_timeout,
    .ssl3_enc = &TLSv1_1_enc_data,
    .ssl_version = ssl_undefined_void_function,
    .ssl_callback_ctrl = ssl3_callback_ctrl,
    .ssl_ctx_callback_ctrl = ssl3_ctx_callback_ctrl,
};

const SSL_METHOD TLSv1_2_client_method_data = {
    .version = TLS1_2_VERSION,
    .ssl_new = tls1_new,
    .ssl_clear = tls1_clear,
    .ssl_free = tls1_free,
    .ssl_accept = ssl_undefined_function,
    .ssl_connect = ssl3_connect,
    .ssl_read = ssl3_read,
    .ssl_peek = ssl3_peek,
    .ssl_write = ssl3_write,
    .ssl_shutdown = ssl3_shutdown,
    .ssl_renegotiate = ssl3_renegotiate,
    .ssl_renegotiate_check = ssl3_renegotiate_check,
    .ssl_get_message = ssl3_get_message,
    .ssl_read_bytes = ssl3_read_bytes,
    .ssl_write_bytes = ssl3_write_bytes,
    .ssl_dispatch_alert = ssl3_dispatch_alert,
    .ssl_ctrl = ssl3_ctrl,
    .ssl_ctx_ctrl = ssl3_ctx_ctrl,
    .get_cipher_by_char = ssl3_get_cipher_by_char,
    .put_cipher_by_char = ssl3_put_cipher_by_char,
    .ssl_pending = ssl3_pending,
    .num_ciphers = ssl3_num_ciphers,
    .get_cipher = ssl3_get_cipher,
    .get_ssl_method = tls1_get_client_method,
    .get_timeout = tls1_default_timeout,
    .ssl3_enc = &TLSv1_2_enc_data,
    .ssl_version = ssl_undefined_void_function,
    .ssl_callback_ctrl = ssl3_callback_ctrl,
    .ssl_ctx_callback_ctrl = ssl3_ctx_callback_ctrl,
};

static const SSL_METHOD *tls1_get_client_method(int ver)
{
    if (ver == TLS1_2_VERSION)
        return TLSv1_2_client_method();
    if (ver == TLS1_1_VERSION)
        return TLSv1_1_client_method();
    if (ver == TLS1_VERSION)
        return TLSv1_client_method();

    return NULL;
}

const SSL_METHOD *SSLv23_client_method(void)
{
    return TLS_client_method();
}

const SSL_METHOD *TLS_client_method(void)
{
    return &TLS_client_method_data;

}

const SSL_METHOD *TLSv1_client_method(void)
{
    return &TLSv1_client_method_data;
}

const SSL_METHOD *TLSv1_1_client_method(void)
{
    return &TLSv1_1_client_method_data;
}

const SSL_METHOD *TLSv1_2_client_method(void)
{
    return &TLSv1_2_client_method_data;
}
