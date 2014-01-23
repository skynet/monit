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
#include <ctype.h>

#ifdef HAVE_STRING_H
#include <string.h>
#endif

#ifdef HAVE_STDIO_H
#include <stdio.h>
#endif

#ifdef HAVE_ERRNO_H
#include <errno.h>
#endif

#include "protocol.h"

/**
 *  Check the server for greeting "@RSYNCD: XX, then send this greeting back
 *  to server, send command '#list' to get a listing of modules.
 *
 *  @file
 */
int check_rsync(Socket_T socket) {
  char  buf[64];
  char  header[11];
  int   rc, version_major, version_minor;
  char  *rsyncd = "@RSYNCD:";
  char  *rsyncd_exit = "@RSYNCD: EXIT";

  ASSERT(socket);

  /* Read and check the greeting */
  if (!socket_readln(socket, buf, sizeof(buf))) {
    socket_setError(socket, "RSYNC: did not see server greeting  -- %s\n", STRERROR);
    return FALSE;
  }
  Str_chomp(buf);
  rc = sscanf(buf, "%10s %d.%d", header, &version_major, &version_minor);
  if ((rc == EOF) || (rc != 3)) {
    socket_setError(socket, "RSYNC: server greeting parse error %s\n", buf);
    return FALSE;
  }
  if (strncasecmp(header, rsyncd, strlen(rsyncd)) != 0) {
    socket_setError(socket, "RSYNC: server sent unexpected greeting -- %s\n", buf);
    return FALSE;
  }

  /* Send back the greeting */
  if (socket_print(socket, "%s\n", buf) <= 0) {
    socket_setError(socket, "RSYNC: identification string send failed -- %s\n", STRERROR);
    return FALSE;
  }

  /* Send #list command */
  if (socket_print(socket, "#list\n") < 0) {
    socket_setError(socket, "RSYNC: #list command failed -- %s\n", STRERROR);
    return FALSE;
  }

  /* Read response: discard list output and check that we've received successful exit */
  do {
    if (! socket_readln(socket, buf, sizeof(buf))) {
      socket_setError(socket, "RSYNC: error receiving data -- %s\n", STRERROR);
      return FALSE;
    }
    Str_chomp(buf);
  } while (strncasecmp(buf, rsyncd, strlen(rsyncd)));
  if (strncasecmp(buf, rsyncd_exit, strlen(rsyncd_exit)) != 0) {
    socket_setError(socket, "RSYNC: server sent unexpected response -- %s\n", buf);
    return FALSE;
  }

  return TRUE;

}

