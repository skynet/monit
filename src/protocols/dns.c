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

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif

#include "protocol.h"

// libmonit
#include "exceptions/IOException.h"

/**
 *  Simple DNS test.
 *
 *  The nameserver is queried for NS record of DNS root.
 *
 *  @file
 */
void check_dns(Socket_T socket) {
        int            offset_request  = 0;
        int            offset_response = 0;
        int            rc;
        unsigned char  buf[STRLEN];
        unsigned char *response = NULL;
        unsigned char  request[19] = {
                0x00,          /** Request Length field for DNS via TCP */
                0x11,

                0x00,                                /** Transaction ID */
                0x01,

                0x01,                                         /** Flags */
                0x00,

                0x00,                                 /** Queries count */
                0x01,

                0x00,                 /** Answer resource records count */
                0x00,

                0x00,              /** Authority resource records count */
                0x00,

                0x00,             /** Additional resource records count */
                0x00,

                /** Query: */

                0x00,                 /** Name: DNS root (empty string) */

                0x00,                                      /** Type: NS */
                0x02,

                0x00,                                     /** Class: IN */
                0x01
        };

        ASSERT(socket);

        switch (Socket_getType(socket)) {
                case Socket_Udp:
                        offset_request  = 2; /*  Skip Length field in request */
                        offset_response = 0;
                        break;
                case Socket_Tcp:
                        offset_request  = 0;
                        offset_response = 2; /*  Skip Length field in response */
                        break;
                default:
                        THROW(IOException, "DNS: unsupported socket type -- protocol test skipped");
                        break;
        }

        if (Socket_write(socket, (unsigned char *)request + offset_request, sizeof(request) - offset_request) < 0)
                THROW(IOException, "DNS: error sending query -- %s", STRERROR);

        /* Response should have at least 14 bytes */
        if (Socket_read(socket, (unsigned char *)buf, 15) <= 14)
                THROW(IOException, "DNS: error receiving response -- %s", STRERROR);

        response = buf + offset_response;

        /* Compare transaction ID (it should be the same as in our request): */
        if (response[0] != 0x00 && response[1] != 0x01)
                THROW(IOException, "DNS: response transaction ID mismatch -- received 0x%x%x, expected 0x1", response[0], response[1]);

        /* Compare flags: */

        /* Response type */
        if ((response[2] & 0x80) != 0x80)
                THROW(IOException, "DNS: invalid response type: 0x%x", response[2] & 0x80);

        /* Response code: accept request refusal as correct response as the server may disallow NS root query but the negative response means, it reacts to requests */
        rc = response[3] & 0x0F;
        if (rc != 0x0 && rc != 0x5)
                THROW(IOException, "DNS: invalid response code: 0x%x", rc);

        /* Compare queries count (it should be one as in our request): */
        if (response[4] != 0x00 && response[5] != 0x01)
                THROW(IOException, "DNS: invalid query count in response -- received 0x%x%x, expected 1", response[4], response[5]);

        /* Compare answer and authority resource record counts (they shouldn't be both zero) */
        if (rc == 0 && response[6] == 0x00 && response[7] == 0x00 && response[8] == 0x00 && response[9] == 0x00)
                THROW(IOException, "DNS: no answer or authority records returned");
}

