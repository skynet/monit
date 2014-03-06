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
 *  Check the server for greeting code 220 and then send a QUIT and
 *  check for code 221. If alive return TRUE, else, return FALSE.
 *
 *  @file
 */
int check_ftp(Socket_T socket) {
  int status;
  char buf[STRLEN];

  ASSERT(socket);

  do {
    if (! socket_readln(socket, buf, STRLEN)) {
      socket_setError(socket, "FTP: error receiving data -- %s", STRERROR);
      return FALSE;
    }
    Str_chomp(buf);
  } while(buf[3] == '-'); // Discard multi-line response
  if (sscanf(buf, "%d", &status) != 1 || status != 220) {
    socket_setError(socket, "FTP greeting error: %s", buf);
    return FALSE;
  }

  if (socket_print(socket, "QUIT\r\n") < 0) {
    socket_setError(socket, "FTP: error sending data -- %s", STRERROR);
    return FALSE;
  }

  if (! socket_readln(socket, buf, STRLEN)) {
    socket_setError(socket, "FTP: error receiving data -- %s", STRERROR);
    return FALSE;
  }
  Str_chomp(buf);
  if (sscanf(buf, "%d", &status) != 1 || status != 221) {
    socket_setError(socket, "FTP quit error: %s", buf);
    return FALSE;
  }

  return TRUE;
}

