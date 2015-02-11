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

#ifdef HAVE_STRING_H
#include <string.h>
#endif

#include "protocol.h"

/**
 *  A simple 'SSH protocol version exchange' implemetation based on
 *  RFC (http://www.openssh.com/txt/draft-ietf-secsh-transport-14.txt)
 *
 *  @file
 */
boolean_t check_ssh(Socket_T socket) {

        char  buf[STRLEN];

        ASSERT(socket);

        if (! socket_readln(socket, buf, sizeof(buf))) {
                socket_setError(socket, "SSH: error receiving identification string -- %s", STRERROR);
                return false;
        }

        if (! Str_startsWith(buf, "SSH-")) {
                socket_setError(socket, "SSH: protocol error %s", buf);
                return false;
        }

        /* send identification string back to server */
        if (socket_write(socket, buf, strlen(buf)) <= 0) {
                socket_setError(socket, "SSH: error sending identification string -- %s", STRERROR);
                return false;
        }

        /* Read one extra line to prevent the "Read from socket failed" warning */
        socket_readln(socket, buf, sizeof(buf));

        return true;

}
