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
int check_memcache(Socket_T socket) {
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

  if(socket_write(socket, (unsigned char *)request, sizeof(request)) <= 0) {
    socket_setError(socket, "MEMCACHE: error sending data -- %s", STRERROR);
    return FALSE;
  }

  /* Response should have at least MEMCACHELEN bytes */
  length = socket_read(socket, (unsigned char *)response, sizeof(response));
  if (length != MEMCACHELEN) {
    socket_setError(socket, "MEMCACHE: Received %d bytes from server, expected %d bytes", length, MEMCACHELEN);
    return FALSE;
  }

  if(response[0] != MAGIC_RESPONSE) {
    socket_setError(socket, "MEMCACHELEN: Invalid response code -- error occured");
    return FALSE;
  }

  status = (response[6] << 8) | response[7];
  switch( status ) {
    case NO_ERROR:
      return TRUE;
    case OUT_OF_MEMORY:
      socket_setError(socket, "MEMCACHELEN: Invalid response code -- Out of memory");
      return FALSE;
    case UNKNOWN_COMMAND:
      socket_setError(socket, "MEMCACHELEN: Invalid response code -- Unknown command");
      return FALSE;
    case INVALID_ARGUMENTS:
      socket_setError(socket, "MEMCACHELEN: Invalid response code -- Invalid arguments");
      return FALSE;
    case VALUE_TOO_BIG:
      socket_setError(socket, "MEMCACHELEN: Invalid response code -- Value too big");
      return FALSE;
    case ITEM_NOT_STORED:
      socket_setError(socket, "MEMCACHELEN: Invalid response code -- Item not stored");
      return FALSE;
    case KEY_NOT_FOUND:
      socket_setError(socket, "MEMCACHELEN: Invalid response code -- Key not found");
      return FALSE;
    case KEY_EXISTS:
      socket_setError(socket, "MEMCACHELEN: Invalid response code -- Key exists");
      return FALSE;
    default:
      socket_setError(socket, "MEMCACHELEN: Unknow response code %u -- error occured", status);
      return FALSE;
  }
}


