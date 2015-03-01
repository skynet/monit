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
 *  PostgreSQL test.
 *
 *  @file
 */
void check_pgsql(Socket_T socket) {

        unsigned char buf[STRLEN];

        unsigned char requestLogin[33] = {
                0x00,                              /** Length */
                0x00,
                0x00,
                0x21,

                0x00,                              /** ProtoVer 3.0 */
                0x03,
                0x00,
                0x00,

                0x75, 0x73, 0x65, 0x72, 0x00,      /** user */
                0x72, 0x6f, 0x6f, 0x74, 0x00,      /** root */

                0x64, 0x61, 0x74, 0x61, 0x62, 0x61, 0x73, 0x65, 0x00,  /** database */
                0x72, 0x6f, 0x6f, 0x74, 0x00,                          /** root */

                0x00
        };

        /** Doing this is too suspicious maybe.
         * Type Q, Length 19 and QUERY select 1 as a; */
        /**
         unsigned char requestQuery[20] = {
         0x51,

         0x00,
         0x00,
         0x00,
         0x13,

         0x73, 0x65, 0x6c, 0x65, 0x63, 0x74, 0x20,
         0x31, 0x20, 0x61, 0x73, 0x20, 0x61, 0x3b,

         0x00
         };
         */

        unsigned char requestTerm[5] = {
                0x58,                              /** Type X */

                0x00,                              /** Length */
                0x00,
                0x00,
                0x04
        };

        unsigned char responseAuthOk[9] = {
                0x52,                              /** Type R */

                0x00,                              /** Length */
                0x00,
                0x00,
                0x08,

                0x00,                              /** OK code 0 */
                0x00,
                0x00,
                0x00
        };

        ASSERT(socket);

        if (Socket_write(socket, (unsigned char *)requestLogin, sizeof(requestLogin)) <= 0)
                THROW(IOException, "PGSQL: error sending data -- %s", STRERROR);

        /** Nine-byte is enough to hold Auth-Ok */
        if (Socket_read(socket, buf, 9) <= 0)
                THROW(IOException, "PGSQL: error receiving data -- %s", STRERROR);

        /** If server insists on auth error it is working anyway */
        if (*buf == 'E')
                return;

        /** Successful connection */
        if (! memcmp((unsigned char *)buf, (unsigned char *)responseAuthOk, 9)) {
                /** This is where suspicious people can do SELECT query that I dont */
                Socket_write(socket, (unsigned char *)requestTerm, sizeof(requestTerm));
                return;
        }

        /** The last possibility must be that server is demanding password */
        if (*buf == 'R')
                return;

        THROW(IOException, "PGSQL: unknown error");
}

