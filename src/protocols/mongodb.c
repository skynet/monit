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

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif

#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif

#ifdef HAVE_STRING_H
#include <string.h>
#endif

#include "protocol.h"


/* ----------------------------------------------------------- Definitions */


typedef struct {
        // header
        int32_t messageSize;     // total message size
        int32_t messageId;       // message id (set by server)
        int32_t responseToId;    // response to id (from the original request)
        int32_t operation;       // operation type
        // OP_REPLY
        int32_t flags;           // flags
        int64_t cursorId;        // cursor id
        int32_t cursorStart;     // cursor start
        int32_t returned;        // returned documents count
        unsigned char *response; // BSON encoded response object
} op_reply_t;


/* --------------------------------------------------------------- Private */


static unsigned int B4(unsigned char *b) {
        unsigned int x;
        *(((char *)&x) + 0) = b[3];
        *(((char *)&x) + 1) = b[2];
        *(((char *)&x) + 2) = b[1];
        *(((char *)&x) + 3) = b[0];
        return ntohl(x);
}


static int _ping(Socket_T socket) {
        unsigned char ping[58] = {
                // Message header
                0x3a, 0x00, 0x00, 0x00,                                           // total message size (58 bytes)
                0x01, 0x00, 0x00, 0x00,                                           // message id (1)
                0xff, 0xff, 0xff, 0xff,                                           // response to id (not used in request)
                0xd4, 0x07, 0x00, 0x00,                                           // operation type (OP_QUERY = 2004)
                // Query
                0x00, 0x00, 0x00, 0x00,                                           // flags
                0x61, 0x64, 0x6d, 0x69, 0x6e, 0x2e, 0x24, 0x63, 0x6d, 0x64, 0x00, // db.collection C-string ("admin.$cmd")
                0x00, 0x00, 0x00, 0x00,                                           // number of documents to skip
                0xff, 0xff, 0xff, 0xff,                                           // number of documents to return
                // BSON encoded PING command: {ping:1}
                0x13, 0x00, 0x00, 0x00,                                           // total document length (19 bytes)
                0x01,                                                             // element type (double = 0x1)
                0x70, 0x69, 0x6e, 0x67, 0x00,                                     // element name C-string ("ping")
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0x3f,                   // element value (1)
                0x00                                                              // BSON document terminal
        };
        if (socket_write(socket, (unsigned char *)ping, sizeof(ping)) < 0) {
                socket_setError(socket, "MONGODB: ping command error -- %s", STRERROR);
                return FALSE;
        }
        return TRUE;
}


static int _pong(Socket_T socket) {
        op_reply_t pong;
        unsigned char buf[STRLEN + 1];
        memset(&pong, 0, sizeof(op_reply_t));
        if (socket_read(socket, buf, 16) < 16) { // read the header
                socket_setError(socket, "MONGODB: error receiving PING response -- %s", STRERROR);
                return FALSE;
        }
        // check response ID: should be 1 (hardcoded in _ping request above)
        pong.responseToId = B4(buf + 8);
        if (pong.responseToId != 1) {
                socket_setError(socket, "MONGODB: PING response error -- unexpected response id (%d)", pong.responseToId);
                return FALSE;
        }
        // check operation type: should be OP_REPLY == 0x1
        pong.operation = B4(buf + 12);
        if (pong.operation != 1) {
                socket_setError(socket, "MONGODB: PING response error -- unexpected operation type (0x%x)", pong.operation);
                return FALSE;
        }
        // read OP_REPLY
        pong.messageSize = B4(buf);
        int len = pong.messageSize - 16 > STRLEN ? STRLEN : pong.messageSize - 16; // Adjust message size for this buffer (minus 16 bytes of header - already read)
        if (socket_read(socket, buf, len) != len) {
                socket_setError(socket, "MONGODB: error receiving OP_REPLY data -- %s", STRERROR);
                return FALSE;
        }
        // check BSON encoded OK response: {ok:1}
        pong.response = buf + 20;
        unsigned char ok[17] = {
                0x11, 0x00, 0x00, 0x00,                         // total document length (17 bytes)
                0x01,                                           // element type (double = 0x1)
                0x6f, 0x6b, 0x00,                               // element name C-string ("ok")
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0x3f, // element value (1)
                0x00                                            // BSON document terminal
        };
        if(memcmp(pong.response, ok, sizeof(ok))) {
                socket_setError(socket, "MONGODB: PING response error -- invalid reply");
                return FALSE;
        }
        return TRUE;
}


/* ---------------------------------------------------------------- Public */


/**
 * Simple mongoDB ping test.
 *
 *     1. send a {ping:1} request to "admin.$cmd"
 *     2. expect a {ok:1} response
 *
 * If passed return TRUE else return FALSE.
 *
 * @see http://docs.mongodb.org/meta-driver/latest/legacy/mongodb-wire-protocol/ and http://bsonspec.org/spec.html
 *
 * @file
 */
int check_mongodb(Socket_T socket) {
        ASSERT(socket);
        if (_ping(socket) && _pong(socket))
                return TRUE;
        return FALSE;
}

