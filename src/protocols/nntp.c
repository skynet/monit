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
 *  Check the server for greeting code 200 and then send a QUIT and check for code 205
 *
 *  @file
 */
void check_nntp(Socket_T socket) {

        int status = 0;
        char buf[STRLEN];

        ASSERT(socket);

        if (! Socket_readLine(socket, buf, sizeof(buf)))
                THROW(IOException, "NNTP: error receiving data -- %s", STRERROR);

        Str_chomp(buf);

        sscanf(buf, "%d %*s", &status);
        if (status != 200)
                THROW(IOException, "NNTP error: %s", buf);

        if (Socket_print(socket, "QUIT\r\n") < 0)
                THROW(IOException, "NNTP: error sending data -- %s", STRERROR);

        if (! Socket_readLine(socket, buf, sizeof(buf)))
                THROW(IOException, "NNTP: error receiving data -- %s", STRERROR);

        Str_chomp(buf);

        sscanf(buf, "%d %*s", &status);
        if (status != 205)
                THROW(IOException, "NNTP error: %s", buf);
}

