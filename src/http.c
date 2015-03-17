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

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif

#ifdef HAVE_ERRNO_H
#include <errno.h>
#endif

#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif

#ifdef HAVE_STRING_H
#include <string.h>
#endif

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#ifdef HAVE_SYS_WAIT_H
#include <sys/wait.h>
#endif

#include "monit.h"
#include "net.h"
#include "engine.h"

// libmonit
#include "exceptions/AssertException.h"


/* Private prototypes */
static void *thread_wrapper(void *arg);

/* The HTTP Thread */
static Thread_T thread;

static volatile boolean_t running = false;


/**
 *  Facade functions for the cervlet sub-system. Start/Stop the monit
 *  http server and check if monit http can start.
 *
 *  @file
 */


/* ------------------------------------------------------------------ Public */


/**
 * @return true if the monit http can start and is specified in the
 * controlfile to start, otherwise return false. Print an error
 * message if monit httpd _should_ start but can't.
 */
boolean_t can_http() {
        if ((Run.httpd.flags & Httpd_Net || Run.httpd.flags & Httpd_Unix) && Run.isdaemon) {
                if (! Engine_hasHostsAllow() && ! Run.httpd.credentials) {
                        LogError("%s: monit httpd not started since no connect allowed\n", prog);
                        return false;

                }
                return true;
        }
        return false;
}


/**
 * Start and stop the monit http server
 * @param action Httpd_Action
 */
void monit_http(Httpd_Action action) {
        switch (action) {
                case Httpd_Stop:
                        if (! running)
                                break;
                        LogInfo("Shutting down Monit HTTP server\n");
                        Engine_stop();
                        Thread_join(thread);
                        LogInfo("Monit HTTP server stopped\n");
                        running = false;
                        break;
                case Httpd_Start:
                        if (Run.httpd.flags & Httpd_Net)
                                LogInfo("Starting Monit HTTP server at [%s]:%d\n", Run.httpd.socket.net.address ? Run.httpd.socket.net.address : "*", Run.httpd.socket.net.port);
                        else if (Run.httpd.flags & Httpd_Unix)
                                LogInfo("Starting Monit HTTP server at %s\n", Run.httpd.socket.unix.path);
                        Thread_create(thread, thread_wrapper, NULL);
                        LogInfo("Monit HTTP server started\n");
                        running = true;
                        break;
                default:
                        LogError("Monit: Unknown http server action\n");
                        break;
        }
}


/* ----------------------------------------------------------------- Private */


static void *thread_wrapper(void *arg) {
        Engine_start();
#ifdef HAVE_OPENSSL
        Ssl_threadCleanup();
#endif
        return NULL;
}

