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

#ifdef HAVE_POLL_H
#include <poll.h>
#endif

#ifdef HAVE_STDARG_H
#include <stdarg.h>
#endif

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

#ifdef NEED_SOCKLEN_T_DEFINED
#define _BSD_SOCKLEN_T_
#endif

#ifdef HAVE_NETINET_IN_SYSTM_H
#include <netinet/in_systm.h>
#endif

#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif

#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif

#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif

#ifdef HAVE_ERRNO_H
#include <errno.h>
#endif

#ifdef HAVE_SIGNAL_H
#include <signal.h>
#endif

#ifdef HAVE_NET_IF_H
#include <net/if.h>
#endif

#ifdef HAVE_SYS_UN_H
#include <sys/un.h>
#endif

#ifdef HAVE_NETDB_H
#include <netdb.h>
#endif

#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif

#ifdef HAVE_SYS_FILIO_H
#include <sys/filio.h>
#endif

#ifdef HAVE_SYS_IOCTL_H
#include <sys/ioctl.h>
#endif

#ifdef HAVE_SYS_FILIO_H
#include <sys/filio.h>
#endif

#ifdef HAVE_NETINET_IP_H
#include <netinet/ip.h>
#endif

#ifdef HAVE_NETINET_IP_ICMP_H
#include <netinet/ip_icmp.h>
#endif

#ifdef HAVE_NETINET_ICMP6_H
#include <netinet/icmp6.h>
#endif

#ifdef HAVE_STRING_H
#include <string.h>
#endif

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#ifdef HAVE_STDDEF_H
#include <stddef.h>
#else
#define offsetof(st, m) ((size_t) ( (char *)&((st *)(0))->m - (char *)0 ))
#endif

#ifdef HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif

#ifndef __dietlibc__
#ifdef HAVE_STROPTS_H
#include <stropts.h>
#endif
#endif

#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif

#include "monit.h"
#include "net.h"

// libmonit
#include "system/Net.h"
#include "exceptions/IOException.h"


/**
 *  General purpose Network and Socket methods.
 *
 *  @file
 */


/* ------------------------------------------------------------- Definitions */


#define DATALEN 64


/* ----------------------------------------------------------------- Private */


static char *_addressToString(const struct sockaddr *addr, socklen_t addrlen, char *buf, int buflen) {
        int oerrno = errno;
        if (addr->sa_family == AF_UNIX) {
                snprintf(buf, buflen, "%s", ((struct sockaddr_un *)addr)->sun_path);
        } else {
                char ip[46], port[6];
                int status = getnameinfo(addr, addrlen, ip, sizeof(ip), port, sizeof(port), NI_NUMERICHOST | NI_NUMERICSERV);
                if (status) {
                        LogError("Cannot get address string -- %s\n", status == EAI_SYSTEM ? STRERROR : gai_strerror(status));
                        *buf = 0;
                } else {
                        snprintf(buf, buflen, "[%s]:%s", ip, port);
                }
        }
        errno = oerrno;
        return buf;
}


/*
 * Do a non blocking connect, timeout if not connected within timeout milliseconds
 */
static boolean_t do_connect(int s, const struct sockaddr *addr, socklen_t addrlen, int timeout, char *error, int errorlen) {
        int rv = connect(s, addr, addrlen);
        if (! rv) {
                return true;
        } else if (errno != EINPROGRESS) {
                snprintf(error, errorlen, "Connection to %s -- failed: %s\n", _addressToString(addr, addrlen, (char[STRLEN]){}, STRLEN), STRERROR);
                return false;
        }
        struct pollfd fds[1];
        fds[0].fd = s;
        fds[0].events = POLLIN | POLLOUT;
        rv = poll(fds, 1, timeout);
        if (rv == 0) {
                snprintf(error, errorlen, "Connection to %s -- timed out\n", _addressToString(addr, addrlen, (char[STRLEN]){}, STRLEN));
                return false;
        } else if (rv == -1) {
                snprintf(error, errorlen, "Connection to %s -- poll failed: %s\n", _addressToString(addr, addrlen, (char[STRLEN]){}, STRLEN), STRERROR);
                return false;
        }
        if (fds[0].events & POLLIN || fds[0].events & POLLOUT) {
                socklen_t rvlen = sizeof(rv);
                if (getsockopt(s, SOL_SOCKET, SO_ERROR, &rv, &rvlen) < 0) {
                        snprintf(error, errorlen, "Connection to %s -- read of error details failed: %s\n", _addressToString(addr, addrlen, (char[STRLEN]){}, STRLEN), STRERROR);
                        return false;
                } else if (rv) {
                        snprintf(error, errorlen, "Connection to %s -- error: %s\n", _addressToString(addr, addrlen, (char[STRLEN]){}, STRLEN), strerror(rv));
                        return false;
                }
        } else {
                snprintf(error, errorlen, "Connection to %s -- not ready for I/O\n", _addressToString(addr, addrlen, (char[STRLEN]){}, STRLEN));
                return false;
        }
        return true;
}


/*
 * Compute Internet Checksum for "count" bytes beginning at location "addr".
 * Based on RFC1071.
 */
static unsigned short checksum_ip(unsigned char *_addr, int count) {
        register long sum = 0;
        unsigned short *addr = (unsigned short *)_addr;
        while (count > 1) {
                sum += *addr++;
                count -= 2;
        }
        /* Add left-over byte, if any */
        if (count > 0)
                sum += *(unsigned char *)addr;
        /* Fold 32-bit sum to 16 bits */
        while (sum >> 16)
                sum = (sum & 0xffff) + (sum >> 16);
        return ~sum;
}




/* ------------------------------------------------------------------ Public */


boolean_t check_host(const char *hostname) {
        ASSERT(hostname);
        struct addrinfo hints = {
#ifdef AI_ADDRCONFIG
                .ai_flags = AI_ADDRCONFIG
#endif
        };
        struct addrinfo *res;
        if (getaddrinfo(hostname, NULL, &hints, &res) != 0)
                return false;
        freeaddrinfo(res);
        return true;
}


boolean_t check_socket(int socket) {
        return (Net_canRead(socket, 500) || Net_canWrite(socket, 500)); // wait ms
}


boolean_t check_udp_socket(int socket) {
        char token[1] = {};
        /* We have to send something and if the UDP server is down/unreachable
         *  the remote host should send an ICMP error. We then need to call read
         *  to get the ICMP error as a ECONNREFUSED errno. This test is asynchronous
         *  so we must wait, but we do not want to block to long either and it is
         *  probably better to report a server falsely up than to block too long.
         */
        Net_write(socket, token, 1, 0);
        if (Net_read(socket, token, 1, 1200) < 0) {
                switch (errno) {
                        case ECONNREFUSED:
                                return false;
                        default:
                                break;
                }
        }
        return true;
}


int create_socket(const char *hostname, int port, int type, Socket_Family family, int timeout) {
        ASSERT(hostname);

        struct addrinfo *result, *r, hints = {
#ifdef AI_ADDRCONFIG
                .ai_flags = AI_ADDRCONFIG,
#endif
                .ai_socktype = type,
                .ai_protocol = type == SOCK_DGRAM ? IPPROTO_UDP : IPPROTO_TCP
        };
        switch (family) {
                case Socket_Ip:
                        hints.ai_family = AF_UNSPEC;
                        break;
                case Socket_Ip4:
                        hints.ai_family = AF_INET;
                        break;
#ifdef IPV6
                case Socket_Ip6:
                        hints.ai_family = AF_INET6;
                        break;
#endif
                default:
                        LogError("create_socket: Invalid socket family %d\n", family);
                        return -1;
        }
        char _port[6];
        snprintf(_port, sizeof(_port), "%d", port);
        int status = getaddrinfo(hostname, _port, &hints, &result);
        if (status) {
                LogError("Cannot translate '%s' to IP address -- %s\n", hostname, status == EAI_SYSTEM ? STRERROR : gai_strerror(status));
                return -1;
        }
        int s = -1;
        char error[STRLEN];
        // Try to connect until succeeded. We log only the last error - the host may resolve to multiple IPs (or IP families) and if at least one succeeded, we have no problem and don't have to flood the log with partial errors
        for (r = result; r; r = r->ai_next) {
                if ((s = socket(r->ai_family, r->ai_socktype, r->ai_protocol)) >= 0) {
                        if (s >= 0) {
                                if (Net_setNonBlocking(s)) {
                                        if (fcntl(s, F_SETFD, FD_CLOEXEC) != -1) {
                                                if (do_connect(s, r->ai_addr, r->ai_addrlen, timeout, error, sizeof(error))) {
                                                        freeaddrinfo(result);
                                                        return s;
                                                }
                                        } else {
                                                snprintf(error, sizeof(error), "Cannot set socket close on exec -- %s\n", STRERROR);
                                        }
                                } else {
                                        snprintf(error, sizeof(error), "Cannot set nonblocking socket -- %s\n", STRERROR);
                                }
                                Net_close(s);
                        }
                } else {
                        snprintf(error, sizeof(error), "Cannot create socket for [%s]:%d -- %s\n", hostname, port, STRERROR);
                }
                DEBUG("%s", error);
        }
        freeaddrinfo(result);
        LogError("%s", error);
        return -1;
}


int create_unix_socket(const char *pathname, int type, int timeout) {
        struct sockaddr_un unixsocket;
        ASSERT(pathname);
        int s = socket(PF_UNIX, type, 0);
        if (s >= 0) {
                unixsocket.sun_family = AF_UNIX;
                snprintf(unixsocket.sun_path, sizeof(unixsocket.sun_path), "%s", pathname);
                if (Net_setNonBlocking(s)) {
                        char error[STRLEN];
                        if (do_connect(s, (struct sockaddr *)&unixsocket, sizeof(unixsocket), timeout, error, sizeof(error)))
                                return s;
                        LogError("%s", error);
                } else {
                        LogError("Cannot set nonblocking unix socket %s -- %s\n", pathname, STRERROR);
                }
                Net_close(s);
        } else {
                LogError("Cannot create unix socket %s -- %s", pathname, STRERROR);
        }
        return -1;
}


//FIXME: we support IPv4 only currently
int create_server_socket(const char *address, int port, int backlog) {
        int s = socket(AF_INET, SOCK_STREAM, 0);
        if (s < 0) {
                LogError("Cannot create socket -- %s\n", STRERROR);
                return -1;
        }
        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(struct sockaddr_in));
        if (address) {
                struct addrinfo *result, hints = {
                        .ai_family = AF_INET
                };
                int status = getaddrinfo(address, NULL, &hints, &result);
                if (status) {
                        LogError("Cannot translate '%s' to IP address -- %s\n", address, status == EAI_SYSTEM ? STRERROR : gai_strerror(status));
                        goto error;
                }
                memcpy(&addr, result->ai_addr, result->ai_addrlen);
                freeaddrinfo(result);
        } else {
                addr.sin_addr.s_addr = htonl(INADDR_ANY);
        }
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        int flag = 1;
        if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (char *)&flag, sizeof(flag)) < 0)  {
                LogError("Cannot set reuseaddr option -- %s\n", STRERROR);
                goto error;
        }
        if (! Net_setNonBlocking(s))
                goto error;
        if (fcntl(s, F_SETFD, FD_CLOEXEC) == -1) {
                LogError("Cannot set close on exec option -- %s\n", STRERROR);
                goto error;
        }
        if (bind(s, (struct sockaddr *)&addr, sizeof(struct sockaddr_in)) < 0) {
                LogError("Cannot bind -- %s\n", STRERROR);
                goto error;
        }
        if (listen(s, backlog) < 0) {
                LogError("Cannot listen -- %s\n", STRERROR);
                goto error;
        }
        return s;
error:
        if (close(s) < 0)
                LogError("Socket %d close failed -- %s\n", s, STRERROR);
        return -1;
}


int create_server_socket_unix(const char *path, int backlog) {
        int s = socket(AF_UNIX, SOCK_STREAM, 0);
        if (s < 0) {
                LogError("Cannot create socket -- %s\n", STRERROR);
                return -1;
        }
        struct sockaddr_un addr = {
                .sun_family = AF_UNIX
        };
        snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", path);
        if (! Net_setNonBlocking(s))
                goto error;
        if (fcntl(s, F_SETFD, FD_CLOEXEC) == -1) {
                LogError("Cannot set close on exec option -- %s\n", STRERROR);
                goto error;
        }
        if (bind(s, (struct sockaddr *)&addr, sizeof(struct sockaddr_un)) < 0) {
                LogError("Cannot bind -- %s\n", STRERROR);
                goto error;
        }
        if (listen(s, backlog) < 0) {
                LogError("Cannot listen -- %s\n", STRERROR);
                goto error;
        }
        return s;
error:
        if (close(s) < 0)
                LogError("Socket %d close failed -- %s\n", s, STRERROR);
        return -1;
}


ssize_t sock_write(int socket, const void *buffer, size_t size, int timeout) {
        return Net_write(socket, buffer, size, timeout);
}


ssize_t sock_read(int socket, void *buffer, int size, int timeout) {
        return Net_read(socket, buffer, size, timeout);
}


int udp_write(int socket, void *b, size_t len, int timeout) {
        return (int)Net_write(socket, b, len, timeout);
}


/*
 * Create a ICMP socket against hostname, send echo and wait for response.
 * The 'count' echo requests is send and we expect at least one reply.
 * @param hostname The host to open a socket at
 * @param timeout If response will not come within timeout milliseconds abort
 * @param count How many pings to send
 * @return response time on succes, -1 on error, -2 when monit has no
 * permissions for raw socket (normally requires root or net_icmpaccess
 * privilege on Solaris)
 */
double icmp_echo(const char *hostname, int timeout, int count) {
        ASSERT(hostname);
        double response = -1.;
        struct addrinfo *result, hints = {
#ifdef AI_ADDRCONFIG
                .ai_flags = AI_ADDRCONFIG
#endif
        };
#ifdef IPV6
        struct icmp6_filter filter;
        ICMP6_FILTER_SETBLOCKALL(&filter);
        ICMP6_FILTER_SETPASS(ICMP6_ECHO_REPLY, &filter);
        hints.ai_family = AF_UNSPEC;
#else
        hints.ai_family = AF_INET;
#endif
        int status = getaddrinfo(hostname, NULL, &hints, &result);
        if (status) {
                LogError("Ping for %s -- getaddrinfo failed: %s\n", hostname, status == EAI_SYSTEM ? STRERROR : gai_strerror(status));
                return response;
        }
        struct addrinfo *r = result;
        int s = -1;
        while (r && s < 0) {
                switch (r->ai_family) {
                        case AF_INET:
                                s = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
                                break;
#ifdef IPV6
                        case AF_INET6:
                                s = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
                                break;
#endif
                        default:
                                break;
                }
                if (s < 0)
                        r = r->ai_next;
        }
        if (s < 0) {
                if (errno == EACCES || errno == EPERM) {
                        DEBUG("Ping for %s -- cannot create socket: %s\n", hostname, STRERROR);
                        response = -2.;
                } else {
                        LogError("Ping for %s -- canot create socket: %s\n", hostname, STRERROR);
                }
                goto error2;
        }
        int rv = -1;
        int ttl = 255;
        switch (r->ai_family) {
                case AF_INET:
                        setsockopt(s, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl));
                        break;
#ifdef IPV6
                case AF_INET6:
                        setsockopt(s, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, &ttl, sizeof(ttl));
                        setsockopt(s, IPPROTO_IPV6, IPV6_UNICAST_HOPS, &ttl, sizeof(ttl));
                        setsockopt(s, IPPROTO_ICMPV6, ICMP6_FILTER, &filter, sizeof(struct icmp6_filter));
                        break;
#endif
                default:
                        break;
        }
        uint16_t id_out = getpid() & 0xFFFF;
        for (int i = 0; i < count; i++) {
                char buf[STRLEN];
                memset(buf, 0, sizeof(buf));
                int in_len = 0, out_len;
                uint16_t in_id = 0, in_seq = 0;
                struct timeval out_time;
                gettimeofday(&out_time, NULL);
                void *out_icmp = NULL;
                unsigned char *data = NULL;
                struct icmp *in_icmp4, *out_icmp4;
                struct ip *in_iphdr4;
#ifdef IPV6
                struct icmp6_hdr *in_icmp6, *out_icmp6;
#endif
                switch (r->ai_family) {
                        case AF_INET:
                                out_icmp4 = (struct icmp *)buf;
                                out_icmp4->icmp_type = ICMP_ECHO;
                                out_icmp4->icmp_code = 0;
                                out_icmp4->icmp_cksum = 0;
                                out_icmp4->icmp_id = htons(id_out);
                                out_icmp4->icmp_seq = htons(i);
                                gettimeofday((struct timeval *)(out_icmp4->icmp_data), NULL); // set data to timestamp
                                in_len = sizeof(struct ip) + sizeof(struct icmp);
                                out_len = offsetof(struct icmp, icmp_data) + DATALEN;
                                out_icmp4->icmp_cksum = checksum_ip((unsigned char *)out_icmp4, out_len); // IPv4 requires checksum computation
                                out_icmp = out_icmp4;
                                break;
#ifdef IPV6
                        case AF_INET6:
                                out_icmp6 = (struct icmp6_hdr *)buf;
                                out_icmp6->icmp6_type = ICMP6_ECHO_REQUEST;
                                out_icmp6->icmp6_code = 0;
                                out_icmp6->icmp6_cksum = 0;
                                out_icmp6->icmp6_id = htons(id_out);
                                out_icmp6->icmp6_seq = htons(i);
                                gettimeofday((struct timeval *)(out_icmp6 + 1), NULL); // set data to timestamp
                                in_len = sizeof(struct icmp6_hdr);
                                out_len = sizeof(struct icmp6_hdr) + DATALEN;
                                out_icmp = out_icmp6;
                                break;
#endif
                        default:
                                break;
                }
                if (! out_icmp) {
                        LogError("Ping request for %s %d/%d failed -- unable to prepare echo request\n", hostname, i + 1, count);
                        continue;
                }
                ssize_t n;
                do {
                        n = sendto(s, out_icmp, out_len, 0, r->ai_addr, r->ai_addrlen);
                } while (n == -1 && errno == EINTR);
                if (n < 0) {
                        LogError("Ping request for %s %d/%d failed -- %s\n", hostname, i + 1, count, STRERROR);
                        continue;
                }
                int read_timeout = timeout;
readnext:
                if (Net_canRead(s, read_timeout)) {
                        struct sockaddr_storage addr;
                        socklen_t addrlen = sizeof(addr);
                        do {
                                n = recvfrom(s, buf, STRLEN, 0, (struct sockaddr *)&addr, &addrlen);
                        } while (n == -1 && errno == EINTR);
                        if (n < 0) {
                                LogError("Ping response for %s %d/%d failed -- %s\n", hostname, i + 1, count, STRERROR);
                                continue;
                        } else if (n < in_len) {
                                LogError("Ping response for %s %d/%d failed -- received %ld bytes, expected at least %d bytes\n", hostname, i + 1, count, n, in_len);
                                continue;
                        }
                        boolean_t in_addrmatch = false, in_typematch = false;
                        struct timeval in_time, out_time = {.tv_sec = 0, .tv_usec = 0};
                        gettimeofday(&in_time, NULL);
                        /* read from raw socket via recvfrom() provides messages regardless of origin, we have to check the IP and skip responses belonging to other conversations */
                        switch (addr.ss_family) {
                                case AF_INET:
                                        in_addrmatch = memcmp(&((struct sockaddr_in *)&addr)->sin_addr, &((struct sockaddr_in *)(r->ai_addr))->sin_addr, sizeof(struct in_addr)) ? false : true;
                                        in_iphdr4 = (struct ip *)buf;
                                        in_icmp4 = (struct icmp *)(buf + in_iphdr4->ip_hl * 4);
                                        in_typematch = in_icmp4->icmp_type == ICMP_ECHOREPLY ? true : false;
                                        in_id = ntohs(in_icmp4->icmp_id);
                                        in_seq = ntohs(in_icmp4->icmp_seq);
                                        data = (unsigned char *)in_icmp4->icmp_data;
                                        break;
#ifdef IPV6
                                case AF_INET6:
                                        in_addrmatch = memcmp(&((struct sockaddr_in6 *)&addr)->sin6_addr, &((struct sockaddr_in6 *)(r->ai_addr))->sin6_addr, sizeof(struct in6_addr)) ? false : true;
                                        in_icmp6 = (struct icmp6_hdr *)buf;
                                        in_typematch = in_icmp6->icmp6_type == ICMP6_ECHO_REPLY ? true : false;
                                        in_id = ntohs(in_icmp6->icmp6_id);
                                        in_seq = ntohs(in_icmp6->icmp6_seq);
                                        data = (unsigned char *)(in_icmp6 + 1);
                                        break;
#endif
                                default:
                                        LogError("Invalid address family: %d\n", addr.ss_family);
                                        break;
                        }
                        if (addr.ss_family != r->ai_family || ! in_addrmatch || ! in_typematch || in_id != id_out || in_seq >= (uint16_t)count) {
                                if ((read_timeout = timeout - ((in_time.tv_sec - out_time.tv_sec) * 1000 + (in_time.tv_usec - out_time.tv_usec) / 1000.)) > 0)
                                        goto readnext; // Try to read next packet, but don't exceed the timeout while waiting for our response so we won't loop forever if the socket is flooded with other ICMP packets
                        } else {
                                memcpy(&out_time, data, sizeof(struct timeval));
                                response = (double)(in_time.tv_sec - out_time.tv_sec) + (double)(in_time.tv_usec - out_time.tv_usec) / 1000000;
                                DEBUG("Ping response for %s %d/%d succeeded -- received id=%d sequence=%d response_time=%fs\n", hostname, i + 1, count, in_id, in_seq, response);
                                break; // Wait for one response only
                        }
                } else
                        LogError("Ping response for %s %d/%d timed out -- no response within %d seconds\n", hostname, i + 1, count, timeout / 1000);
        }
error1:
        do {
                rv = close(s);
        } while (rv == -1 && errno == EINTR);
        if (rv == -1)
                LogError("Socket %d close failed -- %s\n", s, STRERROR);
error2:
        freeaddrinfo(result);
        return response;
}

