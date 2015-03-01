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

// libmonit
#include "system/Time.h"
#include "exceptions/IOException.h"


/**
 *  Check the server time with three seconds difference tolerance
 *
 *  This test is based on RFC868
 *
 *  @file
 */
void check_rdate(Socket_T socket) {
        ASSERT(socket);
        time_t time;
        if (Socket_read(socket, (char *)&time, sizeof(time)) <= 0)
                THROW(IOException, "RDATE: error receiving data -- %s", STRERROR);
        // Compare system time with the RDATE server time (RDATE starts at 00:00:00 UTC, January 1, 1900 => add offset to 00:00:00 UTC, January 1, 1970)
        if (llabs((long long)Time_now() + 2208988800LL - (long long)ntohl(time)) > 3LL)
                THROW(IOException, "RDATE error: time does not match system time");
}

