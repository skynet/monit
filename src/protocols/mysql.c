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
 *  Simple MySQL test.
 *
 *  In the case that the anonymous login is possible,
 *  we will perform MySQL ping. If authentication failed
 *  we suppose the anonymous login is denied and we will
 *  return success, because the server at least performed
 *  authentication => it seems it works.
 *
 *  @file
 */
int check_mysql(Socket_T socket) {


  unsigned char buf[STRLEN];

  unsigned char requestLogin[39] = {
    0x23, 0x00, 0x00,       // packet_length, 3 bytes
    0x01,                   // packet_number, 1 byte
    0x00, 0xa2, 0x00, 0x00, // client_flags, 4 bytes (do+auth 4.1, transact)
    0x00, 0x00, 0x00, 0x40, // max_packet_size, 4 bytes
    0x08,                   // charset_number (latin1), 1 byte
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // filler, 23 bytes
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x4d, 0x00,             // user "M" null terminated, 2 bytes
    0x00,                   // scramble, 1 byte
  };

  unsigned char requestPing[5] = {
    0x01, 0x00, 0x00,       // packet_length, 3 bytes
    0x00,                   // packet_number, 1 byte
    0x0e                    // command ping (14), 1 byte
  };

  unsigned char responsePing[5] = {
    0x07, 0x00, 0x00,       // packet_length, 3 bytes
    0x01,                   // packet_number, 1 byte
    0x00                    // affected_rows, 1 byte
                            // remaining 4 bytes ignored
  };

  unsigned char requestQuit[5] = {
    0x01, 0x00, 0x00,       // packet_length, 3 bytes
    0x00,                   // packet_number, 1 byte
    0x01                    // command quit (1), 1 byte
  };

  ASSERT(socket);

  if(!socket_readln(socket, (char *)buf, sizeof(buf))) {
    socket_setError(socket, "MYSQL: error receiving greeting -- %s", STRERROR);
    return FALSE;
  }

  if(socket_write(socket, requestLogin, sizeof(requestLogin)) < 0) {
    socket_setError(socket, "MYSQL: error sending login -- %s", STRERROR);
    return FALSE;
  }

  /* read just first few bytes  which contains enough information */
  errno = 0;
  if(socket_read(socket, buf, 7) <= 6) {
    socket_setError(socket, "MYSQL: error receiving login response");
    return FALSE;
  }

  /* Compare Packet Number: */
  if(buf[3] != 0x02) {
    socket_setError(socket, "MYSQL: invalid response packet number");
    return FALSE;
  }

  /* Compare Response Code: */
  if(buf[4] == 0x00) {
    /* If OK, we are loged in and will perform MySQL ping */
    if(socket_write(socket, (unsigned char *)requestPing, sizeof(requestPing)) < 0) {
      socket_setError(socket, "MYSQL: error sending ping -- %s", STRERROR);
      return FALSE;
    }

    if(socket_read(socket, buf, sizeof(responsePing)) <= 0) {
      socket_setError(socket, "MYSQL: error receiving ping response -- %s", STRERROR);
      return FALSE;
    }

    if(memcmp((unsigned char *)buf,
                (unsigned char *)responsePing, sizeof(responsePing))) {
      socket_setError(socket, "MYSQL: ping failed");
      return FALSE;
    }

    if(socket_write(socket, (unsigned char *)requestQuit, sizeof(requestQuit)) < 0) {
      socket_setError(socket, "MYSQL: error sending quit -- %s", STRERROR);
      return FALSE;
    }

    return TRUE;
  } else if((buf[4] == 0xFF) && ((buf[5] == 0x15 && buf[6] == 0x04) || (buf[5] == 0xE3 && buf[6] == 0x04) || (buf[5] == 0x13 && buf[6] == 0x04))) {
    /* If access denied (1045) or server requires newer authentication protocol (1251) or bad handshake (1043) return success immediately */
    return TRUE;
  }

  socket_setError(socket, "MYSQL: login failed (error code %d)", buf[6] * 256 + buf[5]);

  return FALSE;
}

