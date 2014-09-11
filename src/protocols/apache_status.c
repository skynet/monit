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
 * Check an Apache server status using the server-status report from
 * mod_status.
 *
 * @file
 */


/* ----------------------------------------------------------------- Private */


static int parse_scoreboard(Socket_T socket, char *scoreboard) {
        int logging = 0, close = 0, dns = 0, keepalive = 0, reply = 0, request = 0, start = 0, wait = 0, graceful = 0, cleanup = 0, open = 0;
        for (char *state = scoreboard; *state; state++) {
                switch (*state) {
                        case 'S':
                                start++;
                                break;
                        case 'R':
                                request++;
                                break;
                        case 'W':
                                reply++;
                                break;
                        case 'K':
                                keepalive++;
                                break;
                        case 'D':
                                dns++;
                                break;
                        case 'C':
                                close++;
                                break;
                        case 'L':
                                logging++;
                                break;
                        case 'G':
                                graceful++;
                                break;
                        case 'I':
                                cleanup++;
                                break;
                        case '_':
                                wait++;
                                break;
                        case '.':
                                open++;
                                break;
                }
        }

        int total = logging + close + dns + keepalive + reply + request + start + wait + graceful + cleanup + open;
        if (! total)
                return TRUE; // Idle server

        int errors = 0;
        Port_T p = socket_get_Port(socket);
        ASSERT(p);

        //FIXME: socket_setError overrides previous => either stop on first error, or append errors and set error at the end (convert error buffer to stringbuffer?)
        if (p->ApacheStatus.loglimit > 0 && Util_evalQExpression(p->ApacheStatus.loglimitOP, (100 * logging / total), p->ApacheStatus.loglimit)) {
                socket_setError(socket, "APACHE-STATUS: error -- %d percent of processes are logging", 100 * logging / total);
                errors++;
        }
        if (p->ApacheStatus.startlimit > 0 && Util_evalQExpression(p->ApacheStatus.startlimitOP, (100 * start / total), p->ApacheStatus.startlimit)) {
                socket_setError(socket, "APACHE-STATUS: error -- %d percent of processes are starting", 100 * start / total);
                errors++;
        }
        if (p->ApacheStatus.requestlimit > 0 && Util_evalQExpression(p->ApacheStatus.requestlimitOP, (100 * request / total), p->ApacheStatus.requestlimit)) {
                socket_setError(socket, "APACHE-STATUS: error -- %d percent of processes are reading requests", 100 * request / total);
                errors++;
        }
        if (p->ApacheStatus.replylimit > 0 && Util_evalQExpression(p->ApacheStatus.replylimitOP, (100 * reply / total), p->ApacheStatus.replylimit)) {
                socket_setError(socket, "APACHE-STATUS: error -- %d percent of processes are sending a reply", 100 * reply / total);
                errors++;
        }
        if (p->ApacheStatus.keepalivelimit > 0 && Util_evalQExpression(p->ApacheStatus.keepalivelimitOP, (100 * keepalive / total), p->ApacheStatus.keepalivelimit)) {
                socket_setError(socket, "APACHE-STATUS: error -- %d percent of processes are in keepalive", 100 * keepalive / total);
                errors++;
        }
        if (p->ApacheStatus.dnslimit > 0 && Util_evalQExpression(p->ApacheStatus.dnslimitOP, (100 * dns / total), p->ApacheStatus.dnslimit)) {
                socket_setError(socket, "APACHE-STATUS: error -- %d percent of processes are waiting for DNS", 100 * dns / total);
                errors++;
        }
        if (p->ApacheStatus.closelimit > 0 && Util_evalQExpression(p->ApacheStatus.closelimitOP, (100 * close / total), p->ApacheStatus.closelimit)) {
                socket_setError(socket, "APACHE-STATUS: error -- %d percent of processes are closing connections", 100 * close / total);
                errors++;
        }
        if (p->ApacheStatus.gracefullimit > 0 && Util_evalQExpression(p->ApacheStatus.gracefullimitOP, (100 * graceful / total), p->ApacheStatus.gracefullimit)) {
                socket_setError(socket, "APACHE-STATUS: error -- %d percent of processes are finishing gracefully", 100 * graceful / total);
                errors++;
        }
        if (p->ApacheStatus.cleanuplimit > 0 && Util_evalQExpression(p->ApacheStatus.cleanuplimitOP, (100 * cleanup / total), p->ApacheStatus.cleanuplimit)) {
                socket_setError(socket, "APACHE-STATUS: error -- %d percent of processes are in idle cleanup", 100 * cleanup / total);
                errors++;
        }
        if (p->ApacheStatus.waitlimit > 0 && Util_evalQExpression(p->ApacheStatus.waitlimitOP, (100 * wait / total), p->ApacheStatus.waitlimit)) {
                socket_setError(socket, "APACHE-STATUS: error -- %d percent of processes are waiting for a connection", 100 * wait / total);
                errors++;
        }

        return (errors == 0);
}


/* ------------------------------------------------------------------ Public */


int check_apache_status(Socket_T socket) {
        ASSERT(socket);
        char host[STRLEN];
        if (socket_print(socket,
                "GET /server-status?auto HTTP/1.1\r\n"
                "Host: %s\r\n"
                "Accept: */*\r\n"
                "User-Agent: Monit/%s\r\n"
                "Connection: close\r\n\r\n",
                Util_getHTTPHostHeader(socket, host, STRLEN), VERSION) < 0)
        {
                socket_setError(socket, "HTTP: error sending data -- %s", STRERROR);
                return FALSE;
        }
        char buffer[4096] = {0};
        while (socket_readln(socket, buffer, sizeof(buffer))) {
                if (Str_startsWith(buffer, "Scoreboard: ")) {
                        char *scoreboard = buffer + 12; // skip header
                        return parse_scoreboard(socket, scoreboard);
                }
        }
        socket_setError(socket, "APACHE-STATUS: error -- no scoreboard found");
        return FALSE;
}

