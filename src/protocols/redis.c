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

// libmonit
#include "exceptions/IOException.h"


/* --------------------------------------------------------------- Public */


/**
 * Simple redis RESP protocol ping test:
 *
 *     1. send a PING command
 *     2. expect a PONG response
 *     3. send a QUIT command
 *
 * @see http://redis.io/topics/protocol
 *
 * @file
 */
void check_redis(Socket_T socket) {
        ASSERT(socket);
        char buf[STRLEN];

        if (Socket_print(socket, "*1\r\n$4\r\nPING\r\n") < 0)
                THROW(IOException, "REDIS: PING command error -- %s", STRERROR);
        if (! Socket_readLine(socket, buf, sizeof(buf)))
                THROW(IOException, "REDIS: PING response error -- %s", STRERROR);
        Str_chomp(buf);
        if (! Str_isEqual(buf, "+PONG") && ! Str_startsWith(buf, "-NOAUTH")) // We accept authentication error (-NOAUTH Authentication required): redis responded to request, but requires authentication => we assume it works
                THROW(IOException, "REDIS: PING error -- %s", buf);
        if (Socket_print(socket, "*1\r\n$4\r\nQUIT\r\n") < 0)
                THROW(IOException, "REDIS: QUIT command error -- %s", STRERROR);
}

