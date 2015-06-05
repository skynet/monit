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

#ifdef HAVE_SYS_UN_H
#include <sys/un.h>
#endif

#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif

#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif

#include "monit.h"
#include "engine.h"
#include "net.h"
#include "processor.h"
#include "cervlet.h"
#include "socket.h"
#include "SslServer.h"

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


static volatile boolean_t stopped = false;
static int myServerSocket = 0;
#ifdef HAVE_OPENSSL
SslServer_T mySSLServerConnection = NULL;
#endif
static HostsAllow_T hostlist = NULL;
static Mutex_T mutex = PTHREAD_MUTEX_INITIALIZER;


/* ----------------------------------------------------------------- Private */


/**
 * Parse network string and return numeric IP and netmask
 * @param pattern A network identifier in IP/mask format to be parsed
 * @param net A structure holding IP and mask of the network
 * @return false if parsing fails otherwise true
 */
static boolean_t _parseNetwork(char *pattern, HostsAllow_T net) {
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
                                return false;
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
                        return false;
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
                return false;
        }
        /* Parse the network */
        struct in_addr inp;
        if (! inet_aton(buf, &inp))
                return false;
        net->network = inp.s_addr;
        /* Convert short netmasks to integer */
        if (longmask == NULL) {
                if ((shortmask > 32) || (shortmask < 0)) {
                        return false;
                } else if ( shortmask == 32 ) {
                        net->mask = -1;
                } else {
                        net->mask = (1 << shortmask) - 1;
                        net->mask = htonl(net->mask << (32 - shortmask));
                }
        } else {
                /* Parse long netmasks */
                if (! inet_aton(longmask, &inp))
                        return false;
                net->mask = inp.s_addr;
        }
        /* Remove bogus network components */
        net->network &= net->mask;
        return true;
}


static boolean_t _hasHostAllow(HostsAllow_T host) {
        for (HostsAllow_T p = hostlist; p; p = p->next)
                if ((p->network == host->network) && ((p->mask == host->mask)))
                        return true;
        return false;
}


static void _destroyHostAllow(HostsAllow_T p) {
        HostsAllow_T a = p;
        if (a->next)
                _destroyHostAllow(a->next);
        FREE(a);
}


/**
 * Returns true if remote host is allowed to connect, otherwise return false
 */
static boolean_t _authenticateHost(struct sockaddr *addr) {
        if (addr->sa_family == AF_INET) { //FIXME: we support only IPv4 currently
                boolean_t allow = false;
                struct sockaddr_in *a = (struct sockaddr_in *)addr;
                LOCK(mutex)
                {
                        if (! hostlist) {
                                allow = true;
                        } else  {
                                for (HostsAllow_T p = hostlist; p; p = p->next) {
                                        if ((p->network & p->mask) == (a->sin_addr.s_addr & p->mask)) {
                                                allow = true;
                                                break;
                                        }
                                }
                        }
                }
                END_LOCK;
                if (! allow)
                        LogError("Denied connection from non-authorized client [%s]\n", inet_ntoa(a->sin_addr));
                return allow;
        } else if (addr->sa_family == AF_UNIX) {
                return true;
        } else {
                return false;
        }
}


/**
 * Accept connections from Clients and create a Socket_T object for each successful accept. If accept fails, return a NULL object
 */
static Socket_T _socketProducer(int server, Httpd_Flags flags) {
        int client;
        struct sockaddr_storage addr_in;
        struct sockaddr_un addr_un;
        struct sockaddr *addr = NULL;
        socklen_t addrlen;
        if (Net_canRead(server, 1000)) {
                if (flags & Httpd_Net) {
                        addr = (struct sockaddr *)&addr_in;
                        addrlen = sizeof(struct sockaddr_storage);
                } else {
                        addr = (struct sockaddr *)&addr_un;
                        addrlen = sizeof(struct sockaddr_un);
                }
                if ((client = accept(server, addr, &addrlen)) < 0) {
                        LogError("HTTP server: cannot accept connection -- %s\n", stopped ? "service stopped" : STRERROR);
                        return NULL;
                }
                if (Net_setNonBlocking(client) < 0 || ! Net_canRead(client, 500) || ! Net_canWrite(client, 500) || ! _authenticateHost(addr)) {
                        Net_abort(client);
                        return NULL;
                }
#ifdef HAVE_OPENSSL
                return Socket_createAccepted(client, addr, addrlen, mySSLServerConnection);
#else
                return Socket_createAccepted(client, addr, addrlen, NULL);
#endif
        }
        return NULL;
}


/* ------------------------------------------------------------------ Public */


void Engine_start() {
        Engine_cleanup();
        stopped = Run.flags & Run_Stopped;
        init_service();
        //FIXME: we listen currently only on one server socket: either on IP or unix socket ... should support listening on multiple sockets (IPv4, IPv6, unix)
        if (Run.httpd.flags & Httpd_Net) {
                if ((myServerSocket = create_server_socket(Run.httpd.socket.net.address, Run.httpd.socket.net.port, 1024)) >= 0) {
#ifdef HAVE_OPENSSL
                        if (Run.httpd.flags & Httpd_Ssl) {
                                if (! (mySSLServerConnection = SslServer_new(Run.httpd.socket.net.ssl.pem, Run.httpd.socket.net.ssl.clientpem, myServerSocket))) {
                                        LogError("HTTP server: not available -- could not initialize SSL engine\n");
                                        Net_close(myServerSocket);
                                        return;
                                }
                        }
#endif
                        while (! stopped) {
                                Socket_T S = _socketProducer(myServerSocket, Run.httpd.flags);
                                if (S)
                                        http_processor(S);
                        }
#ifdef HAVE_OPENSSL
                        if (Run.httpd.flags & Httpd_Ssl)
                                SslServer_free(&mySSLServerConnection);
#endif
                        Net_close(myServerSocket);
                } else {
                        LogError("HTTP server: not available -- could not create a server socket at port %d -- %s\n", Run.httpd.socket.net.port, STRERROR);
                }
        } else if (Run.httpd.flags & Httpd_Unix) {
                if ((myServerSocket = create_server_socket_unix(Run.httpd.socket.unix.path, 1024)) >= 0) {
                        while (! stopped) {
                                Socket_T S = _socketProducer(myServerSocket, Run.httpd.flags);
                                if (S)
                                        http_processor(S);
                        }
                        Net_close(myServerSocket);
                } else {
                        LogError("HTTP server: not available -- could not create a server socket at %s -- %s\n", Run.httpd.socket.unix.path, STRERROR);
                }
        }
        Engine_cleanup();
}


void Engine_stop() {
        stopped = true;
}


void Engine_cleanup() {
        if (Run.httpd.flags & Httpd_Unix)
                unlink(Run.httpd.socket.unix.path);
}


//FIXME: don't store the translated hostname->IPaddress on Monit startup to support DHCP hosts ... resolve the hostname in _authenticateHost()
boolean_t Engine_addHostAllow(char *pattern) {
        ASSERT(pattern);
        struct addrinfo *res, hints = {
                .ai_family = AF_INET, /* we support just IPv4 currently */
                .ai_protocol = IPPROTO_TCP
        };
        int added = 0;
        if (! getaddrinfo(pattern, NULL, &hints, &res)) {
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
        }
        return added ? true : false;
}


boolean_t Engine_addNetAllow(char *pattern) {
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
                return added ? true : false;
        }
        FREE(h);
        return false;
}


boolean_t Engine_hasHostsAllow() {
        int rv;
        LOCK(mutex)
        {
                rv = hostlist ? true : false;
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

