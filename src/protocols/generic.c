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

#ifdef HAVE_ERRNO_H
#include <errno.h>
#endif

#ifdef HAVE_PCRE
#include <pcre.h>
#endif

#ifdef HAVE_STRING_H
#include <string.h>
#endif

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

#ifdef HAVE_REGEX_H
#include <regex.h>
#endif

#include "protocol.h"

/**
 *  Generic service test.
 *
 *  @file
 */
int check_generic(Socket_T socket) {
  Generic_T g= NULL;
  char *buf;
#ifdef HAVE_REGEX_H
  int regex_return;
#endif

  ASSERT(socket);

  if(socket_get_Port(socket))
    g = ((Port_T)(socket_get_Port(socket)))->generic;

  buf = CALLOC(sizeof(char), Run.expectbuffer + 1);

  while (g != NULL) {

    if (g->send != NULL) {

      /* Unescape any \0x00 escaped chars in g's send string
      to allow sending a string containing \0 bytes also */
      char *X = Str_dup(g->send);
      int l = Util_handle0Escapes(X);

      if(socket_write(socket, X, l) < 0) {
        socket_setError(socket, "GENERIC: error sending data -- %s\n", STRERROR);
        FREE(X);
        FREE(buf);
        return FALSE;
      } else
        DEBUG("GENERIC: successfully sent: '%s'\n", g->send);

      FREE(X);

    } else if (g->expect != NULL) {
      int n;

      /* Need read, not readln here */
      if((n= socket_read(socket, buf, Run.expectbuffer))<0) {
        socket_setError(socket, "GENERIC: error receiving data -- %s\n", STRERROR);
        FREE(buf);
        return FALSE;
      }
      buf[n]= 0;

#ifdef HAVE_REGEX_H
      regex_return= regexec(g->expect, buf, 0, NULL, 0);
      if (regex_return != 0) {
        char e[STRLEN];
        regerror(regex_return, g->expect, e, STRLEN);
        socket_setError(socket, "GENERIC: receiving unexpected data [%s] -- %s\n", Str_trunc(buf, STRLEN - 4), e);
        FREE(buf);
        return FALSE;
      } else
        DEBUG("GENERIC: successfully received: '%s'\n", Str_trunc(buf, STRLEN - 4));

#else
      /* w/o regex support */

      if (strncmp(buf, g->expect, strlen(g->expect)) != 0) {
        socket_setError(socket, "GENERIC: receiving unexpected data [%s]\n", Str_trunc(buf, STRLEN - 4));
        FREE(buf);
        return FALSE;
      } else
        DEBUG("GENERIC: successfully received: '%s'\n", Str_trunc(buf, STRLEN - 4));

#endif

    } else {
      /* This should not happen */
      socket_setError(socket, "GENERIC: unexpected strangeness\n");
      FREE(buf);
      return FALSE;
    }
    g= g->next;
  }

  FREE(buf);
  return TRUE;

}

