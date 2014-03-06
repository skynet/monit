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


/**
 *  A WebSocket test.
 *
 *  http://tools.ietf.org/html/rfc6455
 *
 *  Establish websocket connection, send ping and close.
 *
 *  Return TRUE if the status code is OK, otherwise FALSE.
 *  @file
 */


/* ----------------------------------------------------------------- Private */


static int read_response(Socket_T socket, int opcode) {
        int n;
        do {
                char buf[STRLEN];
                // Read frame header
                if ((n = socket_read(socket, buf, 2)) != 2) {
                        socket_setError(socket, "WEBSOCKET: response header read error -- %s", STRERROR);
                        return FALSE;
                }
                /*
                 * As we don't know the specific protocol used by this websocket server, the pipeline
                 * may contain some frames sent by server before the response we're waiting for (such
                 * as chat prompt sent by the server on connect) => drain frames until we find what
                 * we need or timeout
                 */
                if ((*buf & 0xF) != opcode) {
                        // Skip payload of current frame
                        unsigned payload_size = *(buf + 1) & 0x7F;
                        if (payload_size <= sizeof(buf)) {
                                if ((n = socket_read(socket, buf, payload_size)) != payload_size) {
                                        socket_setError(socket, "WEBSOCKET: response data read error");
                                        return FALSE;
                                }
                        } else {
                                /* STRLEN buffer should be sufficient for any frame spuriously sent by
                                 * the server. Guard against too large frames. If in real life such
                                 * situation will be valid (payload > STRLEN), then fix */
                                socket_setError(socket, "WEBSOCKET: response data read error -- unexpected payload size: %d", payload_size);
                                return FALSE;
                        }
                } else {
                        break; // Found frame with matching opcode
                }
        } while (n > 0);
        return TRUE;
}


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
        if (socket_write(socket, ping, sizeof(ping)) < 0) {
                socket_setError(socket, "WEBSOCKET: error sending ping -- %s", STRERROR);
                return FALSE;
        }

        // Pong: verify response opcode is Pong (0xA)
        if (! read_response(socket, 0xA))
                return FALSE;

        // Close request
        unsigned char close_request[2] = {
                0x88, // Fin:True, Opcode:Close
                0x00  // Mask:False, Payload:0
        };
        if (socket_write(socket, close_request, sizeof(close_request)) < 0) {
                socket_setError(socket, "WEBSOCKET: error sending close -- %s", STRERROR);
                return FALSE;
        }

        // Close response (0x8)
        if (! read_response(socket, 0x8))
                return FALSE;

        return TRUE;
}

