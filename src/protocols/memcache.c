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

#define MEMCACHELEN 24

/* Magic Byte */
#define MAGIC_REQUEST      0x80
#define MAGIC_RESPONSE     0x81

/* Response Status */
#define NO_ERROR           0x0000
#define KEY_NOT_FOUND      0x0001
#define KEY_EXISTS         0x0002
#define VALUE_TOO_BIG      0x0003
#define INVALID_ARGUMENTS  0x0004
#define ITEM_NOT_STORED    0x0005
#define UNKNOWN_COMMAND    0x0081
#define OUT_OF_MEMORY      0x0082

/**
 *  Memcache binary protocol
 *
 *  Send No-op request
 *
 *  @file
 */
void check_memcache(Socket_T socket) {
        unsigned int length;
        unsigned char response[MEMCACHELEN];
        unsigned int status;

        unsigned char request[MEMCACHELEN] = {
                MAGIC_REQUEST,                    /** Magic */
                0x0a,                             /** Opcode */
                0x00, 0x00,                       /** Key length */
                0x00,                             /** Extra length */
                0x00,                             /** Data type */
                0x00, 0x00,                       /** request Reserved / response Status */
                0x00, 0x00, 0x00, 0x00,           /** Total body */
                0x00, 0x00, 0x00, 0x00,           /** Opaque */
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00    /** CAS */
        };

        ASSERT(socket);

        if (Socket_write(socket, (unsigned char *)request, sizeof(request)) <= 0)
                THROW(IOException, "MEMCACHE: error sending data -- %s", STRERROR);

        /* Response should have at least MEMCACHELEN bytes */
        length = Socket_read(socket, (unsigned char *)response, sizeof(response));
        if (length != MEMCACHELEN)
                THROW(IOException, "MEMCACHE: Received %d bytes from server, expected %d bytes", length, MEMCACHELEN);

        if (response[0] != MAGIC_RESPONSE)
                THROW(IOException, "MEMCACHELEN: Invalid response code -- error occured");

        status = (response[6] << 8) | response[7];
        switch (status ) {
                case NO_ERROR:
                        break;
                case OUT_OF_MEMORY:
                        THROW(IOException, "MEMCACHELEN: Invalid response code -- Out of memory");
                        break;
                case UNKNOWN_COMMAND:
                        THROW(IOException, "MEMCACHELEN: Invalid response code -- Unknown command");
                        break;
                case INVALID_ARGUMENTS:
                        THROW(IOException, "MEMCACHELEN: Invalid response code -- Invalid arguments");
                        break;
                case VALUE_TOO_BIG:
                        THROW(IOException, "MEMCACHELEN: Invalid response code -- Value too big");
                        break;
                case ITEM_NOT_STORED:
                        THROW(IOException, "MEMCACHELEN: Invalid response code -- Item not stored");
                        break;
                case KEY_NOT_FOUND:
                        THROW(IOException, "MEMCACHELEN: Invalid response code -- Key not found");
                        break;
                case KEY_EXISTS:
                        THROW(IOException, "MEMCACHELEN: Invalid response code -- Key exists");
                        break;
                default:
                        THROW(IOException, "MEMCACHELEN: Unknow response code %u -- error occured", status);
                        break;
        }
}


