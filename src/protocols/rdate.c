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

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif

#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif

#include "protocol.h"

/**
 *  Check the server response, check the time it returns and accept a
 *  TIME_TOLERANCE sec delta with the current system time.
 *
 *  This test is based on RFC868. Rdate returns number of seconds since
 *  00:00:00 UTC, January 1, 1900.
 *
 *  @file
 */
int check_rdate(Socket_T socket) {

/* Offset of 00:00:00 UTC, January 1, 1970 from 00:00:00 UTC, January 1, 1900 */
#define  TIME_OFFSET    2208988800UL
#define  TIME_TOLERANCE (time_t)3

  time_t delta;
  time_t rdatet;
  time_t systemt;

  ASSERT(socket);

  if(socket_read(socket,(char*) &rdatet, sizeof(time_t)) <= 0) {
    socket_setError(socket, "RDATE: error receiving data -- %s", STRERROR);
    return FALSE;
  }

  /* Get remote time and substract offset to allow unix time comparision */
  rdatet = ntohl(rdatet) - TIME_OFFSET;

  if((systemt = time(NULL)) == -1) {
    socket_setError(socket, "RDATE error: cannot get system time -- %s", STRERROR);
    return FALSE;
  }

  if(rdatet >= systemt)
    delta = (rdatet-systemt);
  else
    delta = (systemt-rdatet);

  if(delta > TIME_TOLERANCE) {
    socket_setError(socket, "RDATE error: time does not match system time -- %s", STRERROR);
    return FALSE;
  }

  return TRUE;

}

