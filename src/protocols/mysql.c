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

#ifdef HAVE_STDIO_H
#include <stdio.h>
#endif

#ifdef HAVE_ERRNO_H
#include <errno.h>
#endif

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

  unsigned char requestLogin[10] = {
    0x06,                                 /** Packet Length */
    0x00,
    0x00,

    0x01,                                 /** Packet Number */

    0x00,                                         /** Flags */

    0x00,                                    /** Max Packet */
    0x00,
    0x00,

    0x00,                                       /** Username*/

    0x00                                        /** Password*/
  };

  unsigned char requestPing[5] = {
    0x01,                                 /** Packet Length */
    0x00,
    0x00,

    0x00,                                 /** Packet Number */

    0x0E                                   /** Command Ping */
  };

  unsigned char responsePing[5] = {
    0x03,                                 /** Packet Length */
    0x00,
    0x00,

    0x01,                                 /** Packet Number */

    0x00                               /** Response Code OK */

                                        /** Padding Ignored */
  };

  unsigned char requestQuit[5] = {
    0x01,                                 /** Packet Length */
    0x00,
    0x00,

    0x00,                                 /** Packet Number */

    0x01                                   /** Command Quit */
  };

  ASSERT(socket);

  if(!socket_readln(socket, (char *)buf, sizeof(buf))) {
    socket_setError(socket, "MYSQL: error receiving greeting -- %s\n", STRERROR);
    return FALSE;
  }

  if(socket_write(socket, requestLogin, sizeof(requestLogin)) < 0) {
    socket_setError(socket, "MYSQL: error sending login -- %s\n", STRERROR);
    return FALSE;
  }

  /* read just first few bytes  which contains enough information */
  errno = 0;
  if(socket_read(socket, buf, 7) <= 6) {
    socket_setError(socket, "MYSQL: error receiving login response\n");
    return FALSE;
  }

  /* Compare Packet Number: */
  if(buf[3] != 0x02) {
    socket_setError(socket, "MYSQL: invalid response packet number\n");
    return FALSE;
  }

  /* Compare Response Code: */
  if(buf[4] == 0x00) {
    /* If OK, we are loged in and will perform MySQL ping */
    if(socket_write(socket, (unsigned char *)requestPing, sizeof(requestPing)) < 0) {
      socket_setError(socket, "MYSQL: error sending ping -- %s\n", STRERROR);
      return FALSE;
    }

    if(socket_read(socket, buf, sizeof(responsePing)) <= 0) {
      socket_setError(socket, "MYSQL: error receiving ping response -- %s\n", STRERROR);
      return FALSE;
    }

    if(memcmp((unsigned char *)buf,
                (unsigned char *)responsePing, sizeof(responsePing))) {
      socket_setError(socket, "MYSQL: ping failed\n");
      return FALSE;
    }

    if(socket_write(socket, (unsigned char *)requestQuit, sizeof(requestQuit)) < 0) {
      socket_setError(socket, "MYSQL: error sending quit -- %s\n", STRERROR);
      return FALSE;
    }

    return TRUE;
  } else if((buf[4] == 0xFF) && ((buf[5] == 0x15 && buf[6] == 0x04) || (buf[5] == 0xE3 && buf[6] == 0x04) || (buf[5] == 0x13 && buf[6] == 0x04))) {
    /* If access denied (1045) or server requires newer authentication protocol (1251) or bad handshake (1043) return success immediately */
    return TRUE;
  }

  socket_setError(socket, "MYSQL: login failed (error code %d)\n", buf[6] * 256 + buf[5]);

  return FALSE;
}

