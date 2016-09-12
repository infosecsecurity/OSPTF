/*
 * Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <sys/socket.h>

#include <netinet/in.h>

#include <errno.h>
#include <netdb.h>
#include <stdcompat.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "apps.h"

#include <openssl/ssl.h>

#include "s_apps.h"
#include "socket_win.h"

static int ssl_sock_init(void);
static int init_server(int *sock, int port, int type);
static int init_server_long(int *sock, int port, char *ip, int type);
static int do_accept(int acc_sock, int *sock, char **host);

#define SOCKET_PROTOCOL IPPROTO_TCP

#if !defined(_WIN32)
static int ssl_sock_init(void)
{
    return 1;
}
#endif

int init_client(int *sock, char *host, char *port, int type, int af)
{
    struct addrinfo hints, *ai_top, *ai;
    int i, s = 0;
    
    if (!ssl_sock_init())
        return 0;
    
    memset(&hints, '\0', sizeof(hints));
    hints.ai_family = af;
    hints.ai_socktype = type;
    
    if ((i = getaddrinfo(host, port, &hints, &ai_top)) != 0) {
        BIO_printf(bio_err, "getaddrinfo: %s\n", gai_strerror(i));
        return 0;
    }
    if (ai_top == NULL || ai_top->ai_addr == NULL) {
        BIO_printf(bio_err, "getaddrinfo returned no addresses\n");
        if (ai_top != NULL) {
            freeaddrinfo(ai_top);
        }
        return 0;
    }
    for (ai = ai_top; ai != NULL; ai = ai->ai_next) {
        s = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (s == -1) {
            continue;
        }
        if (type == SOCK_STREAM) {
            i = 0;
            i = setsockopt(s, SOL_SOCKET, SO_KEEPALIVE,
                           (char *)&i, sizeof(i));
            if (i < 0) {
                perror("keepalive");
                goto out;
            }
        }
        if ((i = connect(s, ai->ai_addr, ai->ai_addrlen)) == 0) {
            *sock = s;
            freeaddrinfo(ai_top);
            return 1;
        }
        close(s);
        s = -1;
    }
    
    perror("connect");
out:
    if (s != -1)
        close(s);
    freeaddrinfo(ai_top);
    return 0;
}

int do_server(int port, int type, int *ret,
              int (*cb)(char *hostname, int s, int stype, uint8_t *context),
              uint8_t *context, int naccept)
{
    int sock = 0;
    char *name = NULL;
    int accept_socket = 0;
    int i;
    
    if (!init_server(&accept_socket, port, type))
        return 0;
    
    if (ret != NULL) {
        *ret = accept_socket;
        /* return 1; */
    }
    for (;;) {
        if (type == SOCK_STREAM) {
            if (do_accept(accept_socket, &sock, &name) == 0) {
                shutdown(accept_socket, SHUT_RDWR);
                close(accept_socket);
                return 0;
            }
        } else
            sock = accept_socket;
        i = (*cb)(name, sock, type, context);
        free(name);
        if (type == SOCK_STREAM) {
            shutdown((sock), SHUT_RDWR);
            close(sock);
        }
        if (naccept != -1)
            naccept--;
        if (i < 0 || naccept == 0) {
            shutdown((accept_socket), SHUT_RDWR);
            close(accept_socket);
            return i;
        }
    }
}

static int init_server_long(int *sock, int port, char *ip, int type)
{
    int ret = 0;
    struct sockaddr_in server;
    int s = -1;

    if (!ssl_sock_init())
        return (0);

    memset((char *)&server, 0, sizeof(server));
    server.sin_family = AF_INET;
    server.sin_port = htons((unsigned short)port);
    if (ip == NULL)
        server.sin_addr.s_addr = INADDR_ANY;
    else
        memcpy(&server.sin_addr.s_addr, ip, 4);

    if (type == SOCK_STREAM)
        s = socket(AF_INET, SOCK_STREAM, SOCKET_PROTOCOL);
    else /* type == SOCK_DGRAM */
        s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

    if (s == INVALID_SOCKET)
        goto err;
#if defined SOL_SOCKET && defined SO_REUSEADDR
    {
        int j = 1;
        setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (void *)&j, sizeof j);
    }
#endif
    if (bind(s, (struct sockaddr *)&server, sizeof(server)) == -1) {
        perror("bind");
        goto err;
    }
    /* Make it 128 for linux */
    if (type == SOCK_STREAM && listen(s, 128) == -1)
        goto err;
    *sock = s;
    ret = 1;
err:
    if ((ret == 0) && (s != -1)) {
        shutdown((s), SHUT_RD);
        close((s));
    }
    return (ret);
}

static int init_server(int *sock, int port, int type)
{
    return (init_server_long(sock, port, NULL, type));
}

static int do_accept(int acc_sock, int *sock, char **host)
{
    int ret;
    struct hostent *h1, *h2;
    static struct sockaddr_in from;
    socklen_t len;
    /* struct linger ling; */

    if (!ssl_sock_init())
        return (0);

redoit:

    memset((char *)&from, 0, sizeof(from));
    len = sizeof(from);
    ret = accept(acc_sock, (struct sockaddr *)&from, &len);
    if (ret == -1) {
        if (errno == EINTR) {
            /* check_timeout(); */
            goto redoit;
        }
        fprintf(stderr, "errno=%d ", errno);
        perror("accept");
        return (0);
    }
    /*
    ling.l_onoff=1;
    ling.l_linger=0;
    i=setsockopt(ret,SOL_SOCKET,SO_LINGER,(char *)&ling,sizeof(ling));
    if (i < 0) { perror("linger"); return(0); }
    i=0;
    i=setsockopt(ret,SOL_SOCKET,SO_KEEPALIVE,(char *)&i,sizeof(i));
    if (i < 0) { perror("keepalive"); return(0); }
*/

    if (host == NULL)
        goto end;
    h1 = gethostbyaddr((char *)&from.sin_addr.s_addr,
                       sizeof(from.sin_addr.s_addr), AF_INET);
    if (h1 == NULL) {
        BIO_printf(bio_err, "bad gethostbyaddr\n");
        *host = NULL;
        /* return(0); */
    } else {
        if ((*host = strdup(h1->h_name)) == NULL) {
            perror("strdup");
            close(ret);
            return (0);
        }

        h2 = gethostbyname(*host);
        if (h2 == NULL) {
            BIO_printf(bio_err, "gethostbyname failure\n");
            close(ret);
            return (0);
        }
        if (h2->h_addrtype != AF_INET) {
            BIO_printf(bio_err, "gethostbyname addr is not AF_INET\n");
            close(ret);
            return (0);
        }
    }

end:
    *sock = ret;
    return (1);
}

int extract_host_port(char *str, char **host_ptr, uint8_t *ip, char **port_ptr)
{
    char *h, *p;

    h = str;
    p = strrchr(str, '/'); /* ipv6 */
    if (p == NULL) {
        p = strrchr(str, ':');
    }
    if (p == NULL) {
        BIO_printf(bio_err, "no port defined\n");
        return (0);
    }
    *(p++) = '\0';

    if (host_ptr != NULL)
        *host_ptr = h;

    if (port_ptr != NULL && p != NULL && *p != '\0')
        *port_ptr = p;

    return (1);
}

int extract_port(char *str, short *port_ptr)
{
    int i;
    const char *stnerr = NULL;
    struct servent *s;

    i = strtonum(str, 1, 65535, &stnerr);
    if (!stnerr)
        *port_ptr = (unsigned short)i;
    else {
        s = getservbyname(str, "tcp");
        if (s == NULL) {
            BIO_printf(bio_err, "getservbyname failure for %s\n", str);
            return (0);
        }
        *port_ptr = ntohs((unsigned short)s->s_port);
    }
    return (1);
}
