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
 *  Check the server for greeting code '* OK' and then send LOGOUT and check for code '* BYE'
 *
 *  @file
 */
void check_imap(Socket_T socket) {
        char buf[STRLEN];
        const char *ok = "* OK";
        const char *bye = "* BYE";

        ASSERT(socket);

        // Read and check IMAP greeting
        if (! Socket_readLine(socket, buf, sizeof(buf)))
                THROW(IOException, "IMAP: greeting read error -- %s", errno ? STRERROR : "no data");
        Str_chomp(buf);
        if (strncasecmp(buf, ok, strlen(ok)) != 0)
                THROW(IOException, "IMAP: invalid greeting -- %s", buf);

        // Logout and check response
        if (Socket_print(socket, "001 LOGOUT\r\n") < 0)
                THROW(IOException, "IMAP: logout command error -- %s", STRERROR);
        if (! Socket_readLine(socket, buf, sizeof(buf)))
                THROW(IOException, "IMAP: logout response read error -- %s", errno ? STRERROR : "no data");
        Str_chomp(buf);
        if (strncasecmp(buf, bye, strlen(bye)) != 0)
                THROW(IOException, "IMAP: invalid logout response: %s", buf);
}

