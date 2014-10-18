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

#include "protocol.h"


/* --------------------------------------------------------------- Public */


/**
 * Simple redis RESP protocol ping test:
 *
 *     1. send a PING command
 *     2. expect a PONG response
 *     3. send a QUIT command
 *
 * If passed return TRUE else return FALSE.
 *
 * @see http://redis.io/topics/protocol
 *
 * @file
 */
int check_redis(Socket_T socket) {
        ASSERT(socket);
        char buf[STRLEN];

        if (socket_print(socket, "*1\r\n$4\r\nPING\r\n") < 0) {
                socket_setError(socket, "REDIS: PING command error -- %s", STRERROR);
                return FALSE;
        }
        if(! socket_readln(socket, buf, sizeof(buf))) {
                socket_setError(socket, "REDIS: PING response error -- %s", STRERROR);
                return FALSE;
        }
        Str_chomp(buf);
        if (! Str_isEqual(buf, "+PONG") && ! Str_startsWith(buf, "-NOAUTH")) { // We accept authentication error (-NOAUTH Authentication required): redis responded to request, but requires authentication => we assume it works
                socket_setError(socket, "REDIS: PING error -- %s", buf);
                return FALSE;
        }
        if (socket_print(socket, "*1\r\n$4\r\nQUIT\r\n") < 0) {
                socket_setError(socket, "REDIS: QUIT command error -- %s", STRERROR);
                return FALSE;
        }
        return TRUE;
}

