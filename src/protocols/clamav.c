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

/**
 *  Send PING and check for PONG.
 *
 *  @file
 */
void check_clamav(Socket_T socket) {
        ASSERT(socket);

        // Send PING
        if (Socket_print(socket, "PING\r\n") < 0)
                THROW(IOException, "CLAMAV: PING command error -- %s", STRERROR);

        // Read and check PONG
        char buf[STRLEN];
        if (! Socket_readLine(socket, buf, sizeof(buf)))
                THROW(IOException, "CLAMAV: PONG read error -- %s", STRERROR);
        Str_chomp(buf);
        if (strncasecmp(buf, "PONG", 4) != 0)
                THROW(IOException, "CLAMAV: invalid PONG response -- %s", buf);
}

