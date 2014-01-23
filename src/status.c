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

#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif

#ifdef HAVE_STRING_H
#include <string.h>
#endif

#ifdef HAVE_STRINGS_H
#include <strings.h>
#endif

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include "ssl.h"
#include "net.h"
#include "socket.h"
#include "monit.h"
#include "process.h"
#include "device.h"


/**
 *  Obtain status from the monit daemon
 *
 *  @file
 */


/* ------------------------------------------------------------------ Public */


/**
 * Show all services in the service list.
 */
int status(char *level) {

#define LINE 1024

        int status = FALSE;
        Socket_T S = NULL;
        char buf[LINE];
        char *auth = NULL;

        if(!exist_daemon()) {
                LogError("%s: Status not available -- the monit daemon is not running\n", prog);
                return status;
        }
        S = socket_create_t(Run.bind_addr ? Run.bind_addr : "localhost", Run.httpdport, SOCKET_TCP,
                            (Ssl_T){.use_ssl = Run.httpdssl, .clientpemfile = Run.httpsslclientpem}, NET_TIMEOUT);
        if (! S) {
                LogError("%s: error connecting to the monit daemon\n", prog);
                return status;
        }

        auth = Util_getBasicAuthHeaderMonit();
        socket_print(S,
                     "GET /_status?format=text&level=%s HTTP/1.0\r\n%s\r\n",
                     level, auth?auth:"");
        FREE(auth);

        /* Read past HTTP headers and check status */
        while(socket_readln(S, buf, LINE)) {
                if(*buf == '\n' || *buf == '\r')
                        break;
                if(Str_startsWith(buf, "HTTP/1.0 200"))
                        status= TRUE;
        }

        if(!status) {
                LogError("%s: cannot read status from the monit daemon\n", prog);
        } else {
                while(socket_readln(S, buf, LINE)) {
                        printf("%s", buf);
                }
        }
        socket_free(&S);

        return status;
}
