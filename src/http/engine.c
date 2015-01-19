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


struct ulong_net {
        unsigned long network;
        unsigned long mask;
};


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
static pthread_mutex_t hostlist_mutex = PTHREAD_MUTEX_INITIALIZER;


/* ----------------------------------------------------------------- Private */


/**
 * Abort if no Service implementors are found
 */
static void _checkImplementation() {
        if (! Impl.doGet || ! Impl.doPost) {
                LogError("http server: Service Methods not implemented\n");
                _exit(1);
        }
}


/**
 * Setup the cervlet service and verify that a cervlet implementation exist. Only one cervlet is supported in this version. In a standalone versions this function will load cervlets from a repository and initialize each cervlet.
 */
static void _initializeService() {
        init_service();
        _checkImplementation();
}


/**
 * Parse network string and return numeric IP and netmask
 * @param s_network A network identifier in IP/mask format to be parsed
 * @param net A structure holding IP and mask of the network
 * @return FALSE if parsing fails otherwise TRUE
 */
static int _parseNetwork(char *s_network, struct ulong_net *net) {
        ASSERT(s_network);
        ASSERT(net);

        char *copy = Str_dup(s_network);
        char *temp = copy;
        char *longmask = NULL;
        int   shortmask = 0;
        int   slashcount = 0;
        int   dotcount = 0;
        int   count = 0;
        int   rv = FALSE;

        /* decide if we have xxx.xxx.xxx.xxx/yyy or xxx.xxx.xxx.xxx/yyy.yyy.yyy.yyy */
        while (*temp) {
                if (*temp == '/') {
                        /* We have found a "/" -> we are preceeding to the netmask */
                        if ((slashcount == 1) || (dotcount != 3))
                                /* We have already found a "/" or we haven't had enough dots before finding the slash -> Error! */
                                goto done;
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
                        goto done;
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
                goto done;
        }
        /* Parse the network */
        struct in_addr inp;
        if (inet_aton(copy, &inp) == 0) {
                /* Failed! */
                goto done;
        }
        net->network = inp.s_addr;
        /* Convert short netmasks to integer */
        if (longmask == NULL) {
                if ((shortmask > 32) || (shortmask < 0)) {
                        goto done;
                } else if ( shortmask == 32 ) {
                        net->mask = -1;
                } else {
                        net->mask = (1 << shortmask) - 1;
                        net->mask = htonl(net->mask << (32 - shortmask));
                }
        } else {
                /* Parse long netmasks */
                if (inet_aton(longmask, &inp) == 0) {
                        goto done;
                }
                net->mask = inp.s_addr;
        }
        /* Remove bogus network components */
        net->network &= net->mask;
        /* Everything went fine, so we return TRUE! */
        rv = TRUE;
done:
        FREE(copy);
        return rv;
}


/**
 * Returns TRUE if host is allowed to connect to this server
 */
static int _isHostAllow(const struct in_addr addr) {
        int rv = FALSE;

        LOCK(hostlist_mutex)
        for (HostsAllow_T p = hostlist; p; p = p->next) {
                if ((p->network & p->mask) == (addr.s_addr & p->mask)) {
                        rv = TRUE;
                        break;
                }
        }
        END_LOCK;
        return rv;
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
        if (_isHostAllow(addr))
                return TRUE;
        LogError("Denied connection from non-authorized client [%s]\n", inet_ntoa(addr));
        return FALSE;
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
                                LogError("http server: service stopped\n");
                        else
                                LogError("http server: cannot accept connection -- %s\n", STRERROR);
                        return NULL;
                }
        } else {
                /* If timeout or error occured, return NULL to allow the caller to handle various states (such as stopped) which can occure in the meantime */
                return NULL;
        }
        if (Net_setNonBlocking(client) < 0)
                goto error;
        if (! check_socket(client))
                goto error;
        if (! _authenticateHost(in.sin_addr))
                goto error;
        return socket_create_a(client, inet_ntoa(in.sin_addr), port, sslserver);
error:
        Net_abort(client);
        return NULL;
}


/* ------------------------------------------------------------------ Public */


void Engine_start(int port, int backlog, char *bindAddr) {
        Socket_T S = NULL;
        stopped = Run.stopped;
        if ((myServerSocket = create_server_socket(port, backlog, bindAddr)) < 0) {
                LogError("http server: Could not create a server socket at port %d -- %s\nMonit HTTP server not available\n", port, STRERROR);
                if (Run.init) {
                        sleep(1);
                        kill_daemon(SIGTERM);
                }
        } else {
                _initializeService();
                if (Run.httpdssl) {
                        mySSLServerConnection = init_ssl_server( Run.httpsslpem, Run.httpsslclientpem);
                        if (mySSLServerConnection == NULL) {
                                LogError("HTTP server: Could not initialize SSL engine\nMonit HTTP server not available\n");
                                return;
                        }
#ifdef HAVE_OPENSSL
                        mySSLServerConnection->server_socket = myServerSocket;
#endif
                }
                while (! stopped) {
                        if (! (S = _socketProducer(myServerSocket, port, mySSLServerConnection)))
                                continue;
                        http_processor(S);
                }
                delete_ssl_server_socket(mySSLServerConnection);
                Net_close(myServerSocket);
        }
}


void Engine_stop() {
        stopped = TRUE;
}


int Engine_addHostAllow(char *name) {
        ASSERT(name);

        struct addrinfo hints;
        struct addrinfo *res;

        memset(&hints, 0, sizeof(struct addrinfo));
        hints.ai_family = PF_INET; /* we support just IPv4 currently */

        if (getaddrinfo(name, NULL, &hints, &res) != 0)
                return FALSE;

        for (struct addrinfo *_res = res; _res; _res = _res->ai_next) {
                if (_res->ai_family == AF_INET) {
                        struct sockaddr_in *sin = (struct sockaddr_in *)_res->ai_addr;

                        HostsAllow_T h;
                        NEW(h);
                        memcpy(&h->network, &sin->sin_addr, 4);
                        h->mask = 0xffffffff;
                        LOCK(hostlist_mutex)
                        if (hostlist) {
                                HostsAllow_T p, n;
                                for (n = p = hostlist; p; n = p, p = p->next) {
                                        if ((p->network == h->network) && ((p->mask == h->mask))) {
                                                DEBUG("Skipping redundant host '%s'\n", name);
                                                _destroyHostAllow(h);
                                                goto done;
                                        }
                                }
                                DEBUG("Adding host allow '%s'\n", name);
                                n->next = h;
                        } else {
                                DEBUG("Adding host allow '%s'\n", name);
                                hostlist = h;
                        }
done:
                        END_LOCK;
                }
        }
        freeaddrinfo(res);
        return TRUE;
}


int Engine_addNetAllow(char *s_network) {
        ASSERT(s_network);

        /* Add the network */
        struct ulong_net net = {0, 0};
        if (! _parseNetwork(s_network, &net))
                return FALSE;

        HostsAllow_T h;
        NEW(h);
        h->network = net.network;
        h->mask = net.mask;
        LOCK(hostlist_mutex)
        if (hostlist) {
                HostsAllow_T p, n;
                for (n = p = hostlist; p; n = p, p = p->next) {
                        if ((p->network == net.network) && ((p->mask == net.mask))) {
                                DEBUG("Skipping redundant net '%s'\n", s_network);
                                _destroyHostAllow(h);
                                goto done;
                        }
                }
                DEBUG("Adding net allow '%s'\n", s_network);
                n->next = h;
        } else {
                DEBUG("Adding net allow '%s'\n", s_network);
                hostlist = h;
        }
done:
        END_LOCK;
        return TRUE;
}


int Engine_hasHostsAllow() {
        int rv;

        LOCK(hostlist_mutex)
        rv = (hostlist != NULL);
        END_LOCK;
        return rv;
}


void Engine_destroyHostsAllow() {
        if (Engine_hasHostsAllow()) {
                LOCK(hostlist_mutex)
                _destroyHostAllow(hostlist);
                hostlist = NULL;
                END_LOCK;
        }
}

