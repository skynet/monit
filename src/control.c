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

#ifdef HAVE_STDLIB_H
#include <stdlib.h>
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

#include "monit.h"
#include "net.h"
#include "socket.h"
#include "event.h"
#include "system/Time.h"


/**
 *  Methods for controlling services managed by monit.
 *
 *  @file
 */


/* ------------------------------------------------------------- Definitions */


typedef enum {
        Process_Stopped = 0,
        Process_Started
} Process_Status;


/* ----------------------------------------------------------------- Private */


/*
 * This function waits for the process to stop. If the process doesn't stop a failed event is posted
 * to notify the user. The time is saved on enter so in the case that the time steps backwards/forwards,
 * the wait_stop will wait for absolute time and not stall or prematurely exit.
 * @param service A Service to wait for
 * @return Either Process_Started if the process is running or Process_Stopped if it's not running
 */
static Process_Status wait_stop(Service_T s) {
        unsigned long now = Time_now() * 1000, wait = 50;
        assert(s->stop);
        unsigned long timeout = s->stop->timeout * 1000 + now;
        int pid = Util_isProcessRunning(s, TRUE);
        do {
                Time_usleep(wait * USEC_PER_MSEC);
                now += wait;
                wait = wait < 1000 ? wait * 2 : 1000; // double the wait during each cycle until 1s is reached
                if (! pid || (getpgid(pid) == -1 && errno != EPERM)) {
                        Event_post(s, Event_Exec, STATE_SUCCEEDED, s->action_EXEC, "stopped");
                        return Process_Stopped;
                }
        } while (now < timeout && ! Run.stopped);
        Event_post(s, Event_Exec, STATE_FAILED, s->action_EXEC, "failed to stop");
        return Process_Started;
}


/*
 * This function waits for the process to start. If the process doesn't start a failed event is posted
 * to notify the user. The time is saved on enter so in the case that the time steps backwards/forwards,
 * the wait_start will wait for absolute time and not stall or prematurely exit.
 * @param service A Service to wait for
 * @return Either Process_Started if the process is running or Process_Stopped if it's not running
 */
static Process_Status wait_start(Service_T s) {
        unsigned long now = Time_now() * 1000, wait = 50;
        assert(s->start || s->restart);
        unsigned long timeout = (s->start ? s->start->timeout : s->restart->timeout) * 1000 + now;
        do {
                Time_usleep(wait * USEC_PER_MSEC);
                now += wait;
                wait = wait < 1000 ? wait * 2 : 1000; // double the wait during each cycle until 1s is reached
                if (Util_isProcessRunning(s, TRUE)) {
                        Event_post(s, Event_Exec, STATE_SUCCEEDED, s->action_EXEC, "started");
                        return Process_Started;
                }
        } while (now < timeout && ! Run.stopped);
        Event_post(s, Event_Exec, STATE_FAILED, s->action_EXEC, "failed to start");
        return Process_Stopped;
}


/*
 * This is a post- fix recursive function for starting every service
 * that s depends on before starting s.
 * @param s A Service_T object
 */
static void do_start(Service_T s) {
        ASSERT(s);
        if (s->visited)
                return;
        s->visited = TRUE;
        if (s->dependantlist) {
                Dependant_T d;
                for (d = s->dependantlist; d; d = d->next ) {
                        Service_T parent = Util_getService(d->dependant);
                        ASSERT(parent);
                        do_start(parent);
                }
        }
        if (s->start) {
                if (s->type != TYPE_PROCESS || ! Util_isProcessRunning(s, FALSE)) {
                        LogInfo("'%s' start: %s\n", s->name, s->start->arg[0]);
                        spawn(s, s->start, NULL);
                        /* We only wait for a process type, other service types does not have a pid file to watch */
                        if (s->type == TYPE_PROCESS)
                                wait_start(s);
                }
        } else {
                LogDebug("'%s' start skipped -- method not defined\n", s->name);
        }
        Util_monitorSet(s);
}


/*
 * This function simply stops the service p.
 * @param s A Service_T object
 * @param flag TRUE if the monitoring should be disabled or FALSE if monitoring should continue (when stop is part of restart)
 * @return TRUE if the service was stopped otherwise FALSE
 */
static int do_stop(Service_T s, int flag) {
        int rv = TRUE;
        ASSERT(s);
        if (s->depend_visited)
                return rv;
        s->depend_visited = TRUE;
        if (s->stop) {
                if (s->type != TYPE_PROCESS || Util_isProcessRunning(s, FALSE)) {
                        LogInfo("'%s' stop: %s\n", s->name, s->stop->arg[0]);
                        spawn(s, s->stop, NULL);
                        if (s->type == TYPE_PROCESS && (wait_stop(s) != Process_Stopped)) // Only wait for process service types stop
                                rv = FALSE;
                }
        } else {
                LogDebug("'%s' stop skipped -- method not defined\n", s->name);
        }
        if (flag)
                Util_monitorUnset(s);
        else
                Util_resetInfo(s);
        
        return rv;
}


/*
 * This function simply restarts the service s.
 * @param s A Service_T object
 */
static void do_restart(Service_T s) {
        if (s->restart) {
                LogInfo("'%s' restart: %s\n", s->name, s->restart->arg[0]);
                spawn(s, s->restart, NULL);
                /* We only wait for a process type, other service types does not have a pid file to watch */
                if (s->type == TYPE_PROCESS)
                        wait_start(s);
        } else {
                LogDebug("'%s' restart skipped -- method not defined\n", s->name);
        }
        Util_monitorSet(s);
}


/*
 * This is a post- fix recursive function for enabling monitoring every service
 * that s depends on before monitor s.
 * @param s A Service_T object
 * @param flag A Custom flag
 */
static void do_monitor(Service_T s, int flag) {
        ASSERT(s);
        if (s->visited)
                return;
        s->visited = TRUE;
        if (s->dependantlist) {
                Dependant_T d;
                for (d = s->dependantlist; d; d = d->next ) {
                        Service_T parent = Util_getService(d->dependant);
                        ASSERT(parent);
                        do_monitor(parent, flag);
                }
        }
        Util_monitorSet(s);
}


/*
 * This is a function for disabling monitoring
 * @param s A Service_T object
 * @param flag A Custom flag
 */
static void do_unmonitor(Service_T s, int flag) {
        ASSERT(s);
        if (s->depend_visited)
                return;
        s->depend_visited = TRUE;
        Util_monitorUnset(s);
}


/*
 * This is an in-fix recursive function called before s is started to
 * stop every service that depends on s, in reverse order *or* after s
 * was started to start again every service that depends on s. The
 * action parametere controls if this function should start or stop
 * the procceses that depends on s.
 * @param s A Service_T object
 * @param action An action to do on the dependant services
 * @param flag A Custom flag
 */
static void do_depend(Service_T s, int action, int flag) {
        Service_T child;
        ASSERT(s);
        for (child = servicelist; child; child = child->next) {
                if (child->dependantlist) {
                        Dependant_T d;
                        for (d = child->dependantlist; d; d = d->next) {
                                if (IS(d->dependant, s->name)) {
                                        if (action == ACTION_START)
                                                do_start(child);
                                        else if (action == ACTION_MONITOR)
                                                do_monitor(child, flag);
                                        do_depend(child, action, flag);
                                        if (action == ACTION_STOP)
                                                do_stop(child, flag);
                                        else if (action == ACTION_UNMONITOR)
                                                do_unmonitor(child, flag);
                                        break;
                                }
                        }
                }
        }
}




/* ------------------------------------------------------------------ Public */


/**
 * Pass on to methods in http/cervlet.c to start/stop services
 * @param S A service name as stated in the config file
 * @param action A string describing the action to execute
 * @return FALSE for error, otherwise TRUE
 */
int control_service_daemon(const char *S, const char *action) {
        int rv = FALSE;
        int status, content_length = 0;
        Socket_T socket;
        char *auth;
        char buf[STRLEN];
        ASSERT(S);
        ASSERT(action);
        if (Util_getAction(action) == ACTION_IGNORE) {
                LogError("Cannot %s service '%s' -- invalid action %s\n", action, S, action);
                return FALSE;
        }
        socket = socket_create_t(Run.bind_addr ? Run.bind_addr : "localhost", Run.httpdport, SOCKET_TCP,
                            (Ssl_T){.use_ssl = Run.httpdssl, .clientpemfile = Run.httpsslclientpem}, NET_TIMEOUT);
        if (! socket) {
                LogError("Cannot connect to the monit daemon. Did you start it with http support?\n");
                return FALSE;
        }

        /* Send request */
        auth = Util_getBasicAuthHeaderMonit();
        if (socket_print(socket,
                "POST /%s HTTP/1.0\r\n"
                "Content-Type: application/x-www-form-urlencoded\r\n"
                "Content-Length: %d\r\n"
                "%s"
                "\r\n"
                "action=%s",
                S,
                strlen("action=") + strlen(action),
                auth ? auth : "",
                action) < 0)
        {
                LogError("Cannot send the command '%s' to the monit daemon -- %s", action ? action : "null", STRERROR);
                goto err1;
        }

        /* Process response */
        if (! socket_readln(socket, buf, STRLEN)) {
                LogError("Error receiving data -- %s\n", STRERROR);
                goto err1;
        }
        Str_chomp(buf);
        if (! sscanf(buf, "%*s %d", &status)) {
                LogError("Cannot parse status in response: %s\n", buf);
                goto err1;
        }
        if (status >= 300) {
                char *message = NULL;

                /* Skip headers */
                while (socket_readln(socket, buf, STRLEN)) {
                        if (! strncmp(buf, "\r\n", sizeof(buf)))
                                break;
                        if (Str_startsWith(buf, "Content-Length") && ! sscanf(buf, "%*s%*[: ]%d", &content_length))
                                goto err1;
                }
                if (content_length > 0 && content_length < 1024 && socket_readln(socket, buf, STRLEN)) {
                        char token[] = "</h2>";
                        char *p = strstr(buf, token);
                        if (strlen(p) <= strlen(token))
                                goto err2;
                        p += strlen(token);
                        message = CALLOC(1, content_length + 1);
                        snprintf(message, content_length + 1, "%s", p);
                        p = strstr(message, "<p>");
                        if (p)
                                *p = 0;
                }
err2:
                LogError("Action failed -- %s\n", message ? message : "unable to parse response");
                FREE(message);
        } else
                rv = TRUE;
err1:
        FREE(auth);
        socket_free(&socket);
        return rv;
}


/**
 * Check to see if we should try to start/stop service
 * @param S A service name as stated in the config file
 * @param A A string describing the action to execute
 * @return FALSE for error, otherwise TRUE
 */
int control_service_string(const char *S, const char *A) {
        int a;
        ASSERT(S);
        ASSERT(A);
        if ((a = Util_getAction(A)) == ACTION_IGNORE) {
                LogError("Service '%s' -- invalid action %s\n", S, A);
                return FALSE;
        }
        return control_service(S, a);
}


/**
 * Check to see if we should try to start/stop service
 * @param S A service name as stated in the config file
 * @param A An action id describing the action to execute
 * @return FALSE for error, otherwise TRUE
 */
int control_service(const char *S, int A) {
        Service_T s = NULL;
        ASSERT(S);
        if (! (s = Util_getService(S))) {
                LogError("Service '%s' -- doesn't exist\n", S);
                return FALSE;
        }
        switch(A) {
                case ACTION_START:
                        do_depend(s, ACTION_STOP, FALSE);
                        do_start(s);
                        do_depend(s, ACTION_START, 0);
                        break;

                case ACTION_STOP:
                        do_depend(s, ACTION_STOP, TRUE);
                        do_stop(s, TRUE);
                        break;

                case ACTION_RESTART:
                        LogInfo("'%s' trying to restart\n", s->name);
                        do_depend(s, ACTION_STOP, FALSE);
                        if (s->restart) {
                                do_restart(s);
                                do_depend(s, ACTION_START, 0);
                        } else {
                                if (do_stop(s, FALSE)) {
                                        /* Only start if stop succeeded */
                                        do_start(s);
                                        do_depend(s, ACTION_START, 0);
                                } else {
                                        /* enable monitoring of this service again to allow the restart retry in the next cycle up to timeout limit */
                                        Util_monitorSet(s);
                                }
                        }
                        break;

                case ACTION_MONITOR:
                        /* We only enable monitoring of this service and all prerequisite services. Chain of services which depends on this service keep its state */
                        do_monitor(s, 0);
                        break;

                case ACTION_UNMONITOR:
                        /* We disable monitoring of this service and all services which depends on it */
                        do_depend(s, ACTION_UNMONITOR, 0);
                        do_unmonitor(s, 0);
                        break;

                default:
                        LogError("Service '%s' -- invalid action %s\n", S, A);
                        return FALSE;
        }
        return TRUE;
}


/*
 * Reset the visited flags used when handling dependencies
 */
void reset_depend() {
        Service_T s;
        for (s = servicelist; s; s = s->next) {
                s->visited = FALSE;
                s->depend_visited = FALSE;
        }
}
