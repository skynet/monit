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


/* --------------------------------------------------------------- Public */


/**
 * Sieve protocol test. Expect "OK" when connected, send "LOGOUT" to quit.
 *
 * If passed return TRUE else return FALSE.
 *
 * @see RFC 5804
 *
 * @file
 */
int check_sieve(Socket_T socket) {
        ASSERT(socket);

        char buf[STRLEN];
        do {
                if (! socket_readln(socket, buf, STRLEN)) {
                        socket_setError(socket, "SIEVE: error receiving server capabilities -- %s", STRERROR);
                        return FALSE;
                }
                Str_chomp(buf);
                if (Str_startsWith(buf, "OK")) {
                        if (socket_print(socket, "LOGOUT\r\n") < 0) {
                                socket_setError(socket, "SIEVE: error sending LOGOUT command  -- %s", STRERROR);
                                return FALSE;
                        }
                        if (! socket_readln(socket, buf, STRLEN)) {
                                socket_setError(socket, "SIEVE: error receiving LOGOUT response -- %s", STRERROR);
                                return FALSE;
                        }
                        Str_chomp(buf);
                        if (! Str_startsWith(buf, "OK")) {
                                socket_setError(socket, "SIEVE: invalid LOGOUT response -- %s", buf);
                                return FALSE;
                        }
                        return TRUE;
                }
        } while (TRUE); // Discard all server capabilities until we receive "OK"
        return FALSE;
}

