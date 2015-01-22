/*
 * Copyright (C) Tildeslash Ltd. All rights reserved.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License version 3.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * In addition, as a special exception, the copyright holders give
 * permission to link the code of portions of this program with the
 * OpenSSL library under certain conditions as described in each
 * individual source file, and distribute linked combinations
 * including the two.
 *
 * You must obey the GNU Affero General Public License in all respects
 * for all of the code used other than OpenSSL.
 */

#include "config.h"

#ifdef HAVE_STDIO_H
#include <stdio.h>
#endif

#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif

#ifdef HAVE_ERRNO_H
#include <errno.h>
#endif

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif

#if TIME_WITH_SYS_TIME
# include <sys/time.h>
# include <time.h>
#else
# if HAVE_SYS_TIME_H
#  include <sys/time.h>
# else
#  include <time.h>
# endif
#endif

#ifdef HAVE_NETDB_H
#include <netdb.h>
#endif

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif

#ifdef HAVE_STRING_H
#include <string.h>
#endif

#ifdef HAVE_CTYPE_H
#include <ctype.h>
#endif

#ifdef HAVE_STRINGS_H
#include <strings.h>
#endif

#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif

#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif

#include "engine.h"
#include "net.h"
#include "processor.h"
#include "cervlet.h"
#include "socket.h"

// libmonit
#include "system/Net.h"
#include "exceptions/AssertException.h"


/**
 *  A naive http 1.0 server. The server delegates handling of a HTTP
 *  request and response to the processor module.
 *
 *  NOTE
 *    This server does not use threads or forks; Requests are
 *    serialized and pending requests will be popped from the
 *    connection queue when the current request finish.
 *
 *    Since this server is written for monit, low traffic is expected.
 *    Connect from not-authenicated clients will be closed down
 *    promptly. The authentication schema or access control is based
 *    on client name/address/pam and only requests from known clients are
 *    accepted. Hosts allowed to connect to this server should be
 *    added to the access control list by calling Engine_addHostAllow().
 *
 *  @file
 */


/* ------------------------------------------------------------- Definitions */


typedef struct HostsAllow_T {
        unsigned long network;
        unsigned long mask;
        /* For internal use */
        struct HostsAllow_T *next;
} *HostsAllow_T;


static volatile int stopped = FALSE;
static int myServerSocket = 0;
ssl_server_connection *mySSLServerConnection = NULL;
static HostsAllow_T hostlist = NULL;
static Mutex_T mutex = PTHREAD_MUTEX_INITIALIZER;


/* ----------------------------------------------------------------- Private */


/**
 * Parse network string and return numeric IP and netmask
 * @param pattern A network identifier in IP/mask format to be parsed
 * @param net A structure holding IP and mask of the network
 * @return FALSE if parsing fails otherwise TRUE
 */
static int _parseNetwork(char *pattern, HostsAllow_T net) {
        ASSERT(pattern);
        ASSERT(net);

        char *longmask = NULL;
        int shortmask = 0;
        int slashcount = 0;
        int dotcount = 0;
        int count = 0;

        char buf[STRLEN];
        snprintf(buf, STRLEN, "%s", pattern);
        char *temp = buf;
        /* decide if we have xxx.xxx.xxx.xxx/yyy or xxx.xxx.xxx.xxx/yyy.yyy.yyy.yyy */
        while (*temp) {
                if (*temp == '/') {
                        /* We have found a "/" -> we are preceeding to the netmask */
                        if ((slashcount == 1) || (dotcount != 3))
                                /* We have already found a "/" or we haven't had enough dots before finding the slash -> Error! */
                                return FALSE;
                        *temp = 0;
                        longmask = *(temp + 1) ? temp + 1 : NULL;
                        count = 0;
                        slashcount = 1;
                        dotcount = 0;
                } else if (*temp == '.') {
                        /* We have found the next dot! */
                        dotcount++;
                } else if (! isdigit((int)*temp)) {
                        /* No number, "." or "/" -> Error! */
                        return FALSE;
                }
                count++;
                temp++;
        }
        if (slashcount == 0) {
                /* We have just host portion */
                shortmask = 32;
        } else if ((dotcount == 0) && (count > 1) && (count < 4)) {
                /* We have no dots but 1 or 2 numbers after the slash -> short netmask */
                if (longmask != NULL) {
                        shortmask = atoi(longmask);
                        longmask = NULL;
                }
        } else if (dotcount != 3) {
                /* A long netmask requires three dots */
                return FALSE;
        }
        /* Parse the network */
        struct in_addr inp;
        if (! inet_aton(buf, &inp))
                return FALSE;
        net->network = inp.s_addr;
        /* Convert short netmasks to integer */
        if (longmask == NULL) {
                if ((shortmask > 32) || (shortmask < 0)) {
                        return FALSE;
                } else if ( shortmask == 32 ) {
                        net->mask = -1;
                } else {
                        net->mask = (1 << shortmask) - 1;
                        net->mask = htonl(net->mask << (32 - shortmask));
                }
        } else {
                /* Parse long netmasks */
                if (! inet_aton(longmask, &inp))
                        return FALSE;
                net->mask = inp.s_addr;
        }
        /* Remove bogus network components */
        net->network &= net->mask;
        return TRUE;
}


static int _hasHostAllow(HostsAllow_T host) {
        for (HostsAllow_T p = hostlist; p; p = p->next)
                if ((p->network == host->network) && ((p->mask == host->mask)))
                        return TRUE;
        return FALSE;
}


static void _destroyHostAllow(HostsAllow_T p) {
        HostsAllow_T a = p;
        if (a->next)
                _destroyHostAllow(a->next);
        FREE(a);
}


/**
 * Returns TRUE if remote host is allowed to connect, otherwise return FALSE
 */
static int _authenticateHost(const struct in_addr addr) {
        int allow = FALSE;
        LOCK(mutex)
        {
                if (! hostlist) {
                        allow = TRUE;
                } else  {
                        for (HostsAllow_T p = hostlist; p; p = p->next) {
                                if ((p->network & p->mask) == (addr.s_addr & p->mask)) {
                                        allow = TRUE;
                                        break;
                                }
                        }
                }
        }
        END_LOCK;
        if (! allow)
                LogError("Denied connection from non-authorized client [%s]\n", inet_ntoa(addr));
        return allow;
}


/**
 * Accept connections from Clients and create a Socket_T object for each successful accept. If accept fails, return a NULL object
 */
static Socket_T _socketProducer(int server, int port, void *sslserver) {
        int client;
        struct sockaddr_in in;

        if (can_read(server, 1000)) {
                socklen_t len = sizeof(struct sockaddr_in);
                if ((client = accept(server, (struct sockaddr*)&in, &len)) < 0) {
                        if (stopped)
                                LogError("HTTP server: service stopped\n");
                        else
                                LogError("HTTP server: cannot accept connection -- %s\n", STRERROR);
                        return NULL;
                }
        } else {
                /* If timeout or error occured, return NULL to allow the caller to handle various states (such as stopped) which can occure in the meantime */
                return NULL;
        }
        if (Net_setNonBlocking(client) < 0 || ! check_socket(client) || ! _authenticateHost(in.sin_addr)) {
                Net_abort(client);
                return NULL;
        }
        return socket_create_a(client, inet_ntoa(in.sin_addr), port, sslserver);
}


/* ------------------------------------------------------------------ Public */


void Engine_start(int port, int backlog, char *addr) {
        stopped = Run.stopped;
        if ((myServerSocket = create_server_socket(port, backlog, addr)) >= 0) {
                init_service();
                if (Run.httpdssl) {
                        if (! (mySSLServerConnection = init_ssl_server(Run.httpsslpem, Run.httpsslclientpem))) {
                                LogError("HTTP server: not available -- could not initialize SSL engine\n");
                                return;
                        }
#ifdef HAVE_OPENSSL
                        mySSLServerConnection->server_socket = myServerSocket;
#endif
                }
                while (! stopped) {
                        Socket_T S = _socketProducer(myServerSocket, port, mySSLServerConnection);
                        if (S)
                                http_processor(S);
                }
                delete_ssl_server_socket(mySSLServerConnection);
                Net_close(myServerSocket);
        } else {
                LogError("HTTP server: not available -- could not create a socket at port %d -- %s\n", port, STRERROR);
        }
}


void Engine_stop() {
        stopped = TRUE;
}


int Engine_addHostAllow(char *pattern) {
        ASSERT(pattern);

        struct addrinfo hints;
        memset(&hints, 0, sizeof(struct addrinfo));
        hints.ai_family = AI_ADDRCONFIG;
        struct addrinfo *res;
        if (getaddrinfo(pattern, NULL, &hints, &res) != 0)
                return FALSE;
        int added = 0;
        for (struct addrinfo *_res = res; _res; _res = _res->ai_next) {
                if (_res->ai_family == AF_INET) {
                        struct sockaddr_in *sin = (struct sockaddr_in *)_res->ai_addr;
                        HostsAllow_T h;
                        NEW(h);
                        memcpy(&h->network, &sin->sin_addr, 4);
                        h->mask = 0xffffffff;
                        LOCK(mutex)
                        {
                                if (_hasHostAllow(h))  {
                                        DEBUG("Skipping redundant host '%s'\n", pattern);
                                        FREE(h);
                                } else {
                                        DEBUG("Adding host allow '%s'\n", pattern);
                                        h->next = hostlist;
                                        hostlist = h;
                                        added++;
                                }
                        }
                        END_LOCK;
                }
        }
        freeaddrinfo(res);
        return added ? TRUE : FALSE;
}


int Engine_addNetAllow(char *pattern) {
        ASSERT(pattern);

        HostsAllow_T h;
        NEW(h);
        if (_parseNetwork(pattern, h)) {
                int added = 0;
                LOCK(mutex)
                {
                        if (_hasHostAllow(h)) {
                                DEBUG("Skipping redundant net '%s'\n", pattern);
                                FREE(h);
                        } else {
                                DEBUG("Adding net allow '%s'\n", pattern);
                                h->next = hostlist;
                                hostlist = h;
                                added++;
                        }
                }
                END_LOCK;
                return added ? TRUE : FALSE;
        }
        FREE(h);
        return FALSE;
}


int Engine_hasHostsAllow() {
        int rv;
        LOCK(mutex)
        {
                rv = hostlist ? TRUE : FALSE;
        }
        END_LOCK;
        return rv;
}


void Engine_destroyHostsAllow() {
        if (Engine_hasHostsAllow()) {
                LOCK(mutex)
                {
                        _destroyHostAllow(hostlist);
                        hostlist = NULL;
                }
                END_LOCK;
        }
}

