/*
 * Copyright (C) Tildeslash Ltd. All rights reserved.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License version 3.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
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


#include "Config.h"

#include <stdio.h>
#include <netdb.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <signal.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netinet/tcp.h>
#include <limits.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <poll.h>
#include <stdarg.h>
#include <sys/uio.h>
#include <sys/stat.h>
#ifdef HAVE_STROPTS_H
#include <stropts.h>
#endif
#ifdef HAVE_SYS_IOCTL_H
#include <sys/ioctl.h>
#endif
#ifdef HAVE_SYS_FILIO_H
#include <sys/filio.h>
#endif

#include "system/Net.h"
#include "system/Time.h"
#include "system/System.h"
#include "Str.h"


/**
 * Implementation of the Net Facade for Unix Systems.
 *
 * @author http://www.tildeslash.com/
 * @see http://www.mmonit.com/
 * @file
 */


/* ------------------------------------------------------------- Definitions */


static struct {
        struct ifaddrs *addrs;
        time_t timestamp;
} _stats;


/* --------------------------------------- Static constructor and destructor */


static void __attribute__ ((constructor)) _Constructor() {
        _stats.addrs = NULL;
}


static void __attribute__ ((destructor)) _Destructor() {
        if (_stats.addrs)
                freeifaddrs(_stats.addrs);
}


/* --------------------------------------------------------------- Private */


static void _refreshStats() {
        time_t now = time(NULL);
        if (_stats.timestamp != now || ! _stats.addrs) {
                if (_stats.addrs)
                        freeifaddrs(_stats.addrs);
                if (getifaddrs(&(_stats.addrs)) == -1) {
                        _stats.timestamp = 0;
                        THROW(AssertException, "Cannot get network statistics -- %s", System_getError(errno));
                }
                _stats.timestamp = now;
        }
}


static void _updateStats(const char *interface, NetStatistics_T *stats) {
        for (struct ifaddrs *a = _stats.addrs; a != NULL; a = a->ifa_next) {
                if (a->ifa_addr == NULL)
                        continue;
                if (Str_isEqual(interface, a->ifa_name) && a->ifa_addr->sa_family == PF_LINK) {
                        struct if_data *data = (struct if_data *)a->ifa_data;
                        stats->timestamp.last = stats->timestamp.now;
                        stats->timestamp.now = Time_milli();
                        stats->ipackets.last = stats->ipackets.now;
                        stats->ipackets.now = data->ifi_ipackets;
                        stats->ibytes.last = stats->ibytes.now;
                        stats->ibytes.now = data->ifi_ibytes;
                        stats->ierrors.last = stats->ierrors.now;
                        stats->ierrors.now = data->ifi_ierrors;
                        stats->opackets.last = stats->opackets.now;
                        stats->opackets.now = data->ifi_opackets;
                        stats->obytes.last = stats->obytes.now;
                        stats->obytes.now = data->ifi_obytes;
                        stats->oerrors.last = stats->oerrors.now;
                        stats->oerrors.now = data->ifi_oerrors;
                        return;
                }
        }
        THROW(AssertException, "Interface %s not found", interface);
}


static const char *_findInterfaceForAddress(const char *address) {
        for (struct ifaddrs *a = _stats.addrs; a != NULL; a = a->ifa_next) {
                if (a->ifa_addr == NULL)
                        continue;
                int s;
                char host[NI_MAXHOST];
                if (a->ifa_addr->sa_family == PF_INET)
                        s = getnameinfo(a->ifa_addr, sizeof(struct sockaddr_in), host, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);
                else if (a->ifa_addr->sa_family == PF_INET6)
                        s = getnameinfo(a->ifa_addr, sizeof(struct sockaddr_in6), host, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);
                else
                        continue;
                if (s != 0)
                        THROW(AssertException, "Cannot translate address to name -- %s", gai_strerror(s));
                if (Str_isEqual(address, host))
                        return a->ifa_name;
        }
        THROW(AssertException, "Address %s not found", address);
        return NULL; // Will be never reached
}


/* ---------------------------------------------------------------- Public */


int Net_setNonBlocking(int socket) {
        return (fcntl(socket, F_SETFL, fcntl(socket, F_GETFL, 0) | O_NONBLOCK) != -1);
}


int Net_setBlocking(int socket) {
        return (fcntl(socket, F_SETFL, fcntl(socket, F_GETFL, 0) & ~O_NONBLOCK) != -1);
}


int Net_canRead(int socket, time_t milliseconds) {
        int r = 0;
        struct pollfd fds[1];
        fds[0].fd = socket;
        fds[0].events = POLLIN;
        do {
                r = poll(fds, 1, (int)milliseconds);
        } while (r == -1 && errno == EINTR);
        return (r > 0);
}


int Net_canWrite(int socket, time_t milliseconds) {
        int r = 0;
        struct pollfd fds[1];
        fds[0].fd = socket;
        fds[0].events = POLLOUT;
        do {
                r = poll(fds, 1, (int)milliseconds);
        } while (r == -1 && errno == EINTR);
        return (r > 0);
}


ssize_t Net_read(int socket, void *buffer, size_t size, time_t timeout) {
	ssize_t n = 0;
        if (size > 0) {
                do {
                        n = read(socket, buffer, size);
                } while (n == -1 && errno == EINTR);
                if (n == -1 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
                        if ((timeout == 0) || (Net_canRead(socket, timeout) == false))
                                return 0;
                        do {
                                n = read(socket, buffer, size);
                        } while (n == -1 && errno == EINTR);
                }
        }
	return n;
}


ssize_t Net_write(int socket, const void *buffer, size_t size, time_t timeout) {
	ssize_t n = 0;
        if (size > 0) {
                do {
                        n = write(socket, buffer, size);
                } while (n == -1 && errno == EINTR);
                if (n == -1 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
                        if ((timeout == 0) || (Net_canWrite(socket, timeout) == false))
                                return 0;
                        do {
                                n = write(socket, buffer, size);
                        } while (n == -1 && errno == EINTR);
                }
        }
	return n;
}


int Net_shutdown(int socket, int how) {
        return (shutdown(socket, how) == 0);
}


int Net_close(int socket) {
	int r = 0;
        do {
                r = close(socket);
        } while (r == -1 && errno == EINTR);
	return (r == 0);
}


int Net_abort(int socket) {
   	int r;
        struct linger linger = {1, 0};
        setsockopt(socket, SOL_SOCKET, SO_LINGER, &linger, sizeof linger);
        do {
                r = close(socket);
        } while (r == -1 && errno == EINTR);
	return (r == 0);
}


void Net_getStatisticsByAddress(const char *address, NetStatistics_T *stats) {
        assert(address);
        assert(stats);
        _refreshStats();
        _updateStats(_findInterfaceForAddress(address), stats);
}


void Net_getStatisticsByInterface(const char *interface, NetStatistics_T *stats) {
        assert(interface);
        assert(stats);
        _refreshStats();
        _updateStats(interface, stats);
}

