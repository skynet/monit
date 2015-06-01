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
 *  A WebSocket test.
 *
 *  http://tools.ietf.org/html/rfc6455
 *
 *  Establish websocket connection, send ping and close.
 *
 *  @file
 */


/* ----------------------------------------------------------------- Private */


static void read_response(Socket_T socket, int opcode) {
        int n;
        do {
                char buf[STRLEN];
                // Read frame header
                if ((n = Socket_read(socket, buf, 2)) != 2)
                        THROW(IOException, "WEBSOCKET: response header read error -- %s", STRERROR);
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
                                if ((n = Socket_read(socket, buf, payload_size)) != payload_size)
                                        THROW(IOException, "WEBSOCKET: response data read error");
                        } else {
                                /* STRLEN buffer should be sufficient for any frame spuriously sent by
                                 * the server. Guard against too large frames. If in real life such
                                 * situation will be valid (payload > STRLEN), then fix */
                                THROW(IOException, "WEBSOCKET: response data read error -- unexpected payload size: %d", payload_size);
                        }
                } else {
                        break; // Found frame with matching opcode
                }
        } while (n > 0);
}


/* ------------------------------------------------------------------ Public */


void check_websocket(Socket_T socket) {
        ASSERT(socket);

        Port_T P = Socket_getPort(socket);
        ASSERT(P);

        // Establish websocket connection
        char buf[STRLEN];
        if (Socket_print(socket,
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
                         P->parameters.websocket.request ? P->parameters.websocket.request : "/",
                         P->parameters.websocket.host ? P->parameters.websocket.host : Util_getHTTPHostHeader(socket, buf, sizeof(buf)),
                         P->parameters.websocket.version,
                         P->parameters.websocket.origin ? P->parameters.websocket.origin : "http://www.mmonit.com") < 0)
        {
                THROW(IOException, "WEBSOCKET: error sending data -- %s", STRERROR);
        }
        if (! Socket_readLine(socket, buf, sizeof(buf)))
                THROW(IOException, "WEBSOCKET: error receiving data -- %s", STRERROR);
        int status;
        if (! sscanf(buf, "%*s %d", &status) || (status != 101))
                THROW(IOException, "WEBSOCKET: error -- %s", buf);
        while (Socket_readLine(socket, buf, sizeof(buf)) && ! Str_isEqual(buf, "\r\n"))
                ; // drop remaining HTTP response headers from the pipeline

        // Ping
        unsigned char ping[6] = {
                0x89,                  // Fin:True, Opcode:Ping
                0x80,                  // Mask:True, Payload:0
                0x5b, 0x63, 0x68, 0x84 // Key
        };
        if (Socket_write(socket, ping, sizeof(ping)) < 0)
                THROW(IOException, "WEBSOCKET: error sending ping -- %s", STRERROR);

        // Pong: verify response opcode is Pong (0xA)
        read_response(socket, 0xA);

        // Close request
        unsigned char close_request[6] = {
                0x88,                  // Fin:True, Opcode:Close
                0x80,                  // Mask:True, Payload:0
                0x5b, 0x63, 0x68, 0x84 // Key
        };
        if (Socket_write(socket, close_request, sizeof(close_request)) < 0)
                THROW(IOException, "WEBSOCKET: error sending close -- %s", STRERROR);

        // Close response (0x8)
        read_response(socket, 0x8);
}

