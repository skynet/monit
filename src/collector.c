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

#ifdef HAVE_STRING_H
#include <string.h>
#endif

#ifdef HAVE_SIGNAL_H
#include <signal.h>
#endif

#ifdef HAVE_ERRNO_H
#include <errno.h>
#endif

#include "monit.h"
#include "socket.h"
#include "event.h"


/**
 *  Connect to a data collector servlet and send the event or status message.
 *
 *  @file
 */


/* ----------------------------------------------------------------- Private */


/**
 * Send message to the server
 * @param C An mmonit object
 * @param D Data to send
 * @return TRUE if the message sending succeeded otherwise FALSE
 */
static int data_send(Socket_T socket, Mmonit_T C, const char *D) {
        char *auth = Util_getBasicAuthHeader(C->url->user, C->url->password);
        int rv = socket_print(socket,
                              "POST %s HTTP/1.1\r\n"
                              "Host: %s:%d\r\n"
                              "Content-Type: text/xml\r\n"
                              "Content-Length: %d\r\n"
                              "Pragma: no-cache\r\n"
                              "Accept: */*\r\n"
                              "User-Agent: %s/%s\r\n"
                              "%s"
                              "\r\n"
                              "%s",
                              C->url->path,
                              C->url->hostname, C->url->port,
                              strlen(D),
                              prog, VERSION,
                              auth?auth:"",
                              D);
        FREE(auth);
        if (rv <0) {
                LogError("M/Monit: error sending data to %s -- %s\n", C->url->url, STRERROR);
                return FALSE;
        }
        return TRUE;
}


/**
 * Check that the server returns a valid HTTP response
 * @param C An mmonit object
 * @return TRUE if the response is valid otherwise FALSE
 */
static int data_check(Socket_T socket, Mmonit_T C) {
        int  status;
        char buf[STRLEN];
        if (! socket_readln(socket, buf, sizeof(buf))) {
                LogError("M/Monit: error receiving data from %s -- %s\n", C->url->url, STRERROR);
                return FALSE;
        }
        Str_chomp(buf);
        int n = sscanf(buf, "%*s %d", &status);
        if (n != 1 || (status >= 400)) {
                LogError("M/Monit: message sending failed to %s -- %s\n", C->url->url, buf);
                return FALSE;
        }
        return TRUE;
}


/* ------------------------------------------------------------------ Public */


/**
 * Post event or status data message to mmonit
 * @param E An event object or NULL for status data
 * @return If failed, return HANDLER_MMONIT flag or HANDLER_SUCCEEDED flag if succeeded
 */
int handle_mmonit(Event_T E) {
        int       rv = HANDLER_MMONIT;
        Socket_T  socket = NULL;
        Mmonit_T  C = Run.mmonits;
        /* The event is sent to mmonit just once - only in the case that the state changed */
        if (! C || (E && ! E->state_changed))
                return HANDLER_SUCCEEDED;
        StringBuffer_T sb = StringBuffer_create(256);
        for (; C; C = C->next) {
                if (! (socket = socket_create_t(C->url->hostname, C->url->port, SOCKET_TCP, C->ssl, C->timeout))) {
                        LogError("M/Monit: cannot open a connection to %s\n", C->url->url);
                        goto error;
                }
                if (! socket_set_tcp_nodelay(socket)) {
                    LogError("M/Monit: error setting TCP_NODELAY on socket: %s -- %s\n", C->url->url, STRERROR);
                }
                status_xml(sb, E, E ? LEVEL_SUMMARY : LEVEL_FULL, 2, socket_get_local_host(socket));
                if (! data_send(socket, C, StringBuffer_toString(sb))) {
                        LogError("M/Monit: cannot send %s message to %s\n", E ? "event" : "status", C->url->url);
                        goto error;
                }
                StringBuffer_clear(sb);
                if (! data_check(socket, C)) {
                        LogError("M/Monit: %s message to %s failed\n", E ? "event" : "status", C->url->url);
                        goto error;
                }
                rv = HANDLER_SUCCEEDED; // Return success if at least one M/Monit succeeded
                DEBUG("M/Monit: %s message sent to %s\n", E ? "event" : "status", C->url->url);
error:
                if (socket)
                        socket_free(&socket);
        }
        StringBuffer_free(&sb);
        return rv;
}

