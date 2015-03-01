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

// libmonit
#include "exceptions/IOException.h"


/* --------------------------------------------------------------- Public */


/**
 * Sieve protocol test. Expect "OK" when connected, send "LOGOUT" to quit.
 *
 * @see RFC 5804
 *
 * @file
 */
void check_sieve(Socket_T socket) {
        ASSERT(socket);

        char buf[STRLEN];
        do {
                if (! Socket_readLine(socket, buf, STRLEN))
                        THROW(IOException, "SIEVE: error receiving server capabilities -- %s", STRERROR);
                Str_chomp(buf);
                if (Str_startsWith(buf, "OK")) {
                        if (Socket_print(socket, "LOGOUT\r\n") < 0)
                                THROW(IOException, "SIEVE: error sending LOGOUT command  -- %s", STRERROR);
                        if (! Socket_readLine(socket, buf, STRLEN))
                                THROW(IOException, "SIEVE: error receiving LOGOUT response -- %s", STRERROR);
                        Str_chomp(buf);
                        if (! Str_startsWith(buf, "OK"))
                                THROW(IOException, "SIEVE: invalid LOGOUT response -- %s", buf);
                        return;
                }
        } while (true); // Discard all server capabilities until we receive "OK"
        THROW(IOException, "SIEVE: data error");
}

