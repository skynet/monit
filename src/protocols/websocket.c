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

#include "base64.h"
#include "protocol.h"


/**
 *  A WebSocket test.
 *
 *  http://tools.ietf.org/html/rfc6455
 *
 *  If the status code is >= 400, an error has occurred.
 *
 *  Return TRUE if the status code is OK, otherwise FALSE.
 *  @file
 */


/* ------------------------------------------------------------------ Public */


int check_websocket(Socket_T socket) {
        ASSERT(socket);

        Port_T P = socket_get_Port(socket);
        ASSERT(P);

        // Establish websocket connection
        char buf[STRLEN];
        if (socket_print(socket,
                        "GET %s HTTP/1.1\r\n"
                        "Host: %s\r\n"
                        "Upgrade: websocket\r\n"
                        "Connection: Upgrade\r\n"
                        "Sec-WebSocket-Key: x3JJHMbDL1EzLkh9GBhXDw==\r\n"
                        "Sec-WebSocket-Version: %d\r\n"
                        "Origin: %s\r\n"
                        "Pragma: no-cache\r\n"
                        "Cache-Control: no-cache\r\n"
                        "\r\n",
                        P->request ? P->request : "/",
                        P->request_hostheader ? P->request_hostheader : Util_getHTTPHostHeader(socket, buf, sizeof(buf)),
                        P->version,
                        P->pathname ? P->pathname : "http://www.mmonit.com") < 0)
        {
                socket_setError(socket, "WEBSOCKET: error sending data -- %s", STRERROR);
                return FALSE;
        }
        if (! socket_readln(socket, buf, sizeof(buf))) {
                socket_setError(socket, "WEBSOCKET: error receiving data -- %s", STRERROR);
                return FALSE;
        }
        int status;
        if (! sscanf(buf, "%*s %d", &status) || (status != 101)) {
                socket_setError(socket, "WEBSOCKET: error -- %s", buf);
                return FALSE;
        }

        // Ping
        unsigned char ping[2] = {
                0x89, // Fin:True, Opcode:Ping
                0x00  // Mask:False, Payload:0
        };
        if (socket_write(socket, (unsigned char *)ping, sizeof(ping)) < 0) {
                socket_setError(socket, "WEBSOCKET: error sending ping -- %s", STRERROR);
                return FALSE;
        }

        // Pong: verify response opcode is Pong (0xA)
        if (socket_read(socket, (unsigned char *)buf, 2) <= 0) {
                socket_setError(socket, "WEBSOCKET: error receiving pong -- %s", STRERROR);
                return FALSE;
        }
        if ((*buf & 0xF) != 0xA) {
                socket_setError(socket, "WEBSOCKET: pong error -- opcode 0x%x", *buf & 0xF);
                return FALSE;
        }

        // Close request
        unsigned char close_request[2] = {
                0x88, // Fin:True, Opcode:Close
                0x00  // Mask:False, Payload:0
        };
        if (socket_write(socket, (unsigned char *)close_request, sizeof(close_request)) < 0) {
                socket_setError(socket, "WEBSOCKET: error sending close -- %s", STRERROR);
                return FALSE;
        }

        // Close response
        if (socket_read(socket, (unsigned char *)buf, 2) <= 0) {
                socket_setError(socket, "WEBSOCKET: error receiving close response -- %s", STRERROR);
                return FALSE;
        }
        if ((*buf & 0xF) != 0x8) {
                socket_setError(socket, "WEBSOCKET: close response error -- opcode 0x%x", *buf & 0xF);
                return FALSE;
        }

        return TRUE;
}

