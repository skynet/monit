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

#include <arpa/inet.h>

#include "monit.h"
#include "net.h"
#include "ssl.h"

// libmonit
#include "system/Net.h"


/**
 *  General purpose Network and Socket methods.
 *
 *  @file
 */


/* ------------------------------------------------------------- Definitions */


#define DATALEN 64


/* ----------------------------------------------------------------- Private */


/*
 * Do a non blocking connect, timeout if not connected within timeout milliseconds
 */
static int do_connect(int s, const struct sockaddr *addr, socklen_t addrlen, int timeout) {
        int error = 0;
        struct pollfd fds[1];
        error = connect(s, addr, addrlen);
        if (error == 0) {
                return 0;
        } else if (errno != EINPROGRESS) {
                LogError("Connection failed -- %s\n", STRERROR);
                return -1;
        }
        fds[0].fd = s;
        fds[0].events = POLLIN|POLLOUT;
        error = poll(fds, 1, timeout);
        if (error == 0) {
                LogError("Connection timed out\n");
                return -1;
        } else if (error == -1) {
                LogError("Poll failed -- %s\n", STRERROR);
                return -1;
        }
        if (fds[0].events & POLLIN || fds[0].events & POLLOUT) {
                socklen_t len = sizeof(error);
                if (getsockopt(s, SOL_SOCKET, SO_ERROR, &error, &len) < 0) {
                        LogError("Cannot get socket error -- %s\n", STRERROR);
                        return -1;
                } else if (error) {
                        errno = error;
                        LogError("Socket error -- %s\n", STRERROR);
                        return -1;
                }
        } else {
                LogError("Socket not ready for I/O\n");
                return -1;
        }
        return 0;
}


/*
 * Compute Internet Checksum for "count" bytes beginning at location "addr".
 * Based on RFC1071.
 */
static unsigned short checksum_ip(unsigned char *_addr, int count) {
        register long sum = 0;
        unsigned short *addr = (unsigned short *)_addr;
        while(count > 1) {
                sum += *addr++;
                count -= 2;
        }
        /* Add left-over byte, if any */
        if(count > 0)
                sum += *(unsigned char *)addr;
        /* Fold 32-bit sum to 16 bits */
        while(sum >> 16)
                sum = (sum & 0xffff) + (sum >> 16);
        return ~sum;
}




/* ------------------------------------------------------------------ Public */


int check_host(const char *hostname) {
        struct addrinfo hints;
        struct addrinfo *res;
        ASSERT(hostname);
        memset(&hints, 0, sizeof(struct addrinfo));
        hints.ai_family = PF_INET; /* we support just IPv4 currently */
        if(getaddrinfo(hostname, NULL, &hints, &res) != 0)
                return FALSE;
        freeaddrinfo(res);
        return TRUE;
}


int check_socket(int socket) {
        return (Net_canRead(socket, 500) || Net_canWrite(socket, 500)); // wait ms
}


int check_udp_socket(int socket) {
        char token[1] = {};
        /* We have to send something and if the UDP server is down/unreachable
         *  the remote host should send an ICMP error. We then need to call read
         *  to get the ICMP error as a ECONNREFUSED errno. This test is asynchronous
         *  so we must wait, but we do not want to block to long either and it is
         *  probably better to report a server falsely up than to block too long.
         */
        Net_write(socket, token, 1, 0);
        if (Net_read(socket, token, 1, 1200) < 0) {
                switch(errno) {
                        case ECONNREFUSED:
                                return FALSE;
                        default:
                                break;
                }
        }
        return TRUE;
}


int create_socket(const char *hostname, int port, int type, int timeout) {
        int s, status;
        struct sockaddr_in sin;
        struct sockaddr_in *sa;
        struct addrinfo hints;
        struct addrinfo *result;
        ASSERT(hostname);
        memset(&hints, 0, sizeof(struct addrinfo));
        hints.ai_family = AF_INET;

        if((status = getaddrinfo(hostname, NULL, &hints, &result)) != 0) {
                LogError("Cannot translate '%s' to IP address -- %s\n", hostname, status == EAI_SYSTEM ? STRERROR : gai_strerror(status));
                return -1;
        }
        if((s = socket(AF_INET, type, 0)) < 0) {
                LogError("Cannot create socket -- %s\n", STRERROR);
                freeaddrinfo(result);
                return -1;
        }
        sa = (struct sockaddr_in *)result->ai_addr;
        memcpy(&sin, sa, result->ai_addrlen);
        sin.sin_family = AF_INET;
        sin.sin_port = htons(port);
        freeaddrinfo(result);
        if(! Net_setNonBlocking(s)) {
                LogError("Cannot set nonblocking socket -- %s\n", STRERROR);
                goto error;
        }
        if (fcntl(s, F_SETFD, FD_CLOEXEC) == -1) {
                LogError("Cannot set socket close on exec -- %s\n", STRERROR);
                goto error;
        }
        if (do_connect(s, (struct sockaddr *)&sin, sizeof(sin), timeout) < 0) {
                goto error;
        }
        return s;
error:
        Net_close(s);
        return -1;
}


int create_unix_socket(const char *pathname, int type, int timeout) {
        int s;
        struct sockaddr_un unixsocket;
        ASSERT(pathname);
        if((s = socket(PF_UNIX, type, 0)) < 0)
                return -1;
        unixsocket.sun_family = AF_UNIX;
        snprintf(unixsocket.sun_path, sizeof(unixsocket.sun_path), "%s", pathname);
        if(! Net_setNonBlocking(s)) {
                goto error;
        }
        if(do_connect(s, (struct sockaddr *)&unixsocket, sizeof(unixsocket), timeout) < 0) {
                goto error;
        }
        return s;
error:
        Net_close(s);
        return -1;
}


int create_server_socket(int port, int backlog, const char *bindAddr) {
        int s, status, flag = 1;
        struct sockaddr_in myaddr;
        if((s = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
                LogError("Cannot create socket -- %s\n", STRERROR);
                return -1;
        }
        memset(&myaddr, 0, sizeof(struct sockaddr_in));
        if(bindAddr) {
                struct sockaddr_in *sa;
                struct addrinfo hints;
                struct addrinfo *result;
                
                memset(&hints, 0, sizeof(struct addrinfo));
                hints.ai_family = AF_INET;
                if((status = getaddrinfo(bindAddr, NULL, &hints, &result)) != 0) {
                        LogError("Cannot translate '%s' to IP address -- %s\n", bindAddr, status == EAI_SYSTEM ? STRERROR : gai_strerror(status));
                        goto error;
                }
                sa = (struct sockaddr_in *)result->ai_addr;
                memcpy(&myaddr, sa, result->ai_addrlen);
                freeaddrinfo(result);
        } else {
                myaddr.sin_addr.s_addr = htonl(INADDR_ANY);
        }
        myaddr.sin_family = AF_INET;
        myaddr.sin_port = htons(port);
        if(setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (char *)&flag, sizeof(flag)) < 0)  {
                LogError("Cannot set reuseaddr option -- %s\n", STRERROR);
                goto error;
        }
        if(! Net_setNonBlocking(s))
                goto error;
        if(fcntl(s, F_SETFD, FD_CLOEXEC) == -1) {
                LogError("Cannot set close on exec option -- %s\n", STRERROR);
                goto error;
        }
        if(bind(s, (struct sockaddr *)&myaddr, sizeof(struct sockaddr_in)) < 0) {
                LogError("Cannot bind -- %s\n", STRERROR);
                goto error;
        }
        if(listen(s, backlog) < 0) {
                LogError("Cannot listen -- %s\n", STRERROR);
                goto error;
        }
        return s;
error:
        if (close(s) < 0)
                LogError("Socket %d close failed -- %s\n", s, STRERROR);
        return -1;
}


int can_read(int socket, int timeout) {
        return Net_canRead(socket, timeout);
}


int can_write(int socket, int timeout) {
        return Net_canWrite(socket, timeout);
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
 * The 'count' echo requests  is send and we expect at least one reply.
 * @param hostname The host to open a socket at
 * @param timeout If response will not come within timeout milliseconds abort
 * @param count How many pings to send
 * @return response time on succes, -1 on error, -2 when monit has no
 * permissions for raw socket (normally requires root or net_icmpaccess
 * privilege on Solaris)
 */
double icmp_echo(const char *hostname, int timeout, int count) {
        struct sockaddr_in sout;
        struct sockaddr_in *sa;
        struct addrinfo hints;
        struct addrinfo *result;
        struct ip *iphdrin;
        int len_out = offsetof(struct icmp, icmp_data) + DATALEN;
        int len_in = sizeof(struct ip) + sizeof(struct icmp);
        struct icmp *icmpin = NULL;
        struct icmp *icmpout = NULL;
        uint16_t id_in, id_out, seq_in;
        int r, i, s, n = 0, status, read_timeout;
        struct timeval t_in, t_out;
        char buf[STRLEN];
        double response = -1.;
#if ! defined NETBSD && ! defined AIX
        int sol_ip;
        unsigned ttl = 255;
#endif
        ASSERT(hostname);
        ASSERT(len_out < sizeof(buf));
        memset(&hints, 0, sizeof(struct addrinfo));
        hints.ai_family = AF_INET;
        if ((status = getaddrinfo(hostname, NULL, &hints, &result)) != 0) {
                LogError("Ping for %s -- getaddrinfo failed: %s\n", hostname, status == EAI_SYSTEM ? STRERROR : gai_strerror(status));
                return response;
        }
        if ((s = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) < 0) {
                if (errno == EACCES || errno == EPERM) {
                        DEBUG("Ping for %s -- cannot create socket: %s\n", hostname, STRERROR);
                        response = -2.;
                } else {
                        LogError("Ping for %s -- canot create socket: %s\n", hostname, STRERROR);
                }
                goto error2;
        }
#if ! defined NETBSD && ! defined AIX
#ifdef HAVE_SOL_IP
        sol_ip = SOL_IP;
#else
        {
                struct protoent *pent;
                pent = getprotobyname("ip");
                sol_ip = pent ? pent->p_proto : 0;
        }
#endif
        if (setsockopt(s, sol_ip, IP_TTL, (char *)&ttl, sizeof(ttl)) < 0) {
                LogError("Ping for %s -- setsockopt failed: %s\n", hostname, STRERROR);
                goto error1;
        }
#endif
        id_out = getpid() & 0xFFFF;
        icmpout = (struct icmp *)buf;
        for (i = 0; i < count; i++) {
                unsigned char *data = (unsigned char *)icmpout->icmp_data;
                icmpout->icmp_code  = 0;
                icmpout->icmp_type  = ICMP_ECHO;
                icmpout->icmp_id    = htons(id_out);
                icmpout->icmp_seq   = htons(i);
                icmpout->icmp_cksum = 0;
                /* Add originate timestamp to data section */
                gettimeofday(&t_out, NULL);
                memcpy(data, &t_out, sizeof(struct timeval));
                data += sizeof(struct timeval);
                /* Initialize rest of data section to numeric sequence */
                for (int j = 0; j < DATALEN - sizeof(struct timeval); j++)
                        data[j] = j;
                icmpout->icmp_cksum = checksum_ip((unsigned char *)icmpout, len_out);
                sa = (struct sockaddr_in *)result->ai_addr;
                memcpy(&sout, sa, result->ai_addrlen);
                sout.sin_family = AF_INET;
                sout.sin_port   = 0;
                do {
                        n = (int)sendto(s, (char *)icmpout, len_out, 0, (struct sockaddr *)&sout, sizeof(struct sockaddr));
                } while(n == -1 && errno == EINTR);
                if (n < 0) {
                        LogError("Ping request for %s %d/%d failed -- %s\n", hostname, i + 1, count, STRERROR);
                        continue;
                }
                read_timeout = timeout;
        readnext:
                if (Net_canRead(s, read_timeout)) {
                        socklen_t size = sizeof(struct sockaddr_in);
                        do {
                                n = (int)recvfrom(s, buf, STRLEN, 0, (struct sockaddr *)&sout, &size);
                        } while(n == -1 && errno == EINTR);
                        if (n < 0) {
                                LogError("Ping response for %s %d/%d failed -- %s\n", hostname, i + 1, count, STRERROR);
                                continue;
                        } else if (n < len_in) {
                                LogError("Ping response for %s %d/%d failed -- received %d bytes, expected at least %d bytes\n", hostname, i + 1, count, n, len_in);
                                continue;
                        }
                        iphdrin = (struct ip *)buf;
                        icmpin  = (struct icmp *)(buf + iphdrin->ip_hl * 4);
                        id_in   = ntohs(icmpin->icmp_id);
                        seq_in  = ntohs(icmpin->icmp_seq);
                        gettimeofday(&t_in, NULL);
                        /* The read from connection-less raw socket via recvfrom() provides messages regardless of origin, the source IP address is set in sout, we have to check the IP and skip responses belonging to other ICMP conversations */
                        if (sout.sin_addr.s_addr != sa->sin_addr.s_addr || icmpin->icmp_type != ICMP_ECHOREPLY || id_in != id_out || seq_in >= (uint16_t)count) {
                                if ((read_timeout = timeout - ((t_in.tv_sec - t_out.tv_sec) + (t_in.tv_usec - t_out.tv_usec) / 1000.)) > 0)
                                        goto readnext; // Try to read next packet, but don't exceed the timeout while waiting for our response so we won't loop forever if the socket is flooded with other ICMP packets
                        } else {
                                data = (unsigned char *)icmpin->icmp_data;
                                memcpy(&t_out, data, sizeof(struct timeval));
                                response = (double)(t_in.tv_sec - t_out.tv_sec) + (double)(t_in.tv_usec - t_out.tv_usec) / 1000000;
                                DEBUG("Ping response for %s %d/%d succeeded -- received id=%d sequence=%d response_time=%fs\n", hostname, i + 1, count, id_in, seq_in, response);
                                break; // Wait for one response only
                        }
                } else
                        LogError("Ping response for %s %d/%d timed out -- no response within %d seconds\n", hostname, i + 1, count, timeout);
        }
error1:
        do {
                r = close(s);
        } while(r == -1 && errno == EINTR);
        if (r == -1)
                LogError("Socket %d close failed -- %s\n", s, STRERROR);
error2:
        freeaddrinfo(result);
        return response;
}
