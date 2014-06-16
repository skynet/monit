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


/**
 * Implementation of the Net Facade for Unix Systems.
 *
 * @author http://www.tildeslash.com/
 * @see http://www.mmonit.com/
 * @file
 */


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

