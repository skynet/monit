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

#ifdef HAVE_ERRNO_H
#include <errno.h>
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

#ifdef HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif

#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif

#include "monit.h"
#include "cervlet.h"
#include "engine.h"
#include "processor.h"
#include "base64.h"
#include "event.h"
#include "alert.h"
#include "process.h"
#include "device.h"

// libmonit
#include "system/Time.h"

#define ACTION(c) !strncasecmp(req->url, c, sizeof(c))

/* URL Commands supported */
#define HOME        "/"
#define TEST        "/_monit"
#define ABOUT       "/_about"
#define PING        "/_ping"
#define GETID       "/_getid"
#define STATUS      "/_status"
#define STATUS2     "/_status2"
#define RUN         "/_runtime"
#define VIEWLOG     "/_viewlog"
#define DOACTION    "/_doaction"
#define FAVICON     "/favicon.ico"

/* Private prototypes */
static int is_readonly(HttpRequest);
static void printFavicon(HttpResponse);
static void doGet(HttpRequest, HttpResponse);
static void doPost(HttpRequest, HttpResponse);
static void do_head(HttpResponse res, const char *path, const char *name, int refresh);
static void do_foot(HttpResponse res);
static void do_home(HttpRequest, HttpResponse);
static void do_home_system(HttpRequest, HttpResponse);
static void do_home_filesystem(HttpRequest, HttpResponse);
static void do_home_directory(HttpRequest, HttpResponse);
static void do_home_file(HttpRequest, HttpResponse);
static void do_home_fifo(HttpRequest, HttpResponse);
static void do_home_process(HttpRequest, HttpResponse);
static void do_home_program(HttpRequest, HttpResponse);
static void do_home_host(HttpRequest, HttpResponse);
static void do_about(HttpRequest, HttpResponse);
static void do_ping(HttpRequest, HttpResponse);
static void do_getid(HttpRequest, HttpResponse);
static void do_runtime(HttpRequest, HttpResponse);
static void do_viewlog(HttpRequest, HttpResponse);
static void handle_action(HttpRequest, HttpResponse);
static void handle_do_action(HttpRequest, HttpResponse);
static void handle_run(HttpRequest, HttpResponse);
static void is_monit_running(HttpRequest, HttpResponse);
static void do_service(HttpRequest, HttpResponse, Service_T);
static void print_alerts(HttpResponse, Mail_T);
static void print_buttons(HttpRequest, HttpResponse, Service_T);
static void print_service_rules_port(HttpResponse, Service_T);
static void print_service_rules_icmp(HttpResponse, Service_T);
static void print_service_rules_perm(HttpResponse, Service_T);
static void print_service_rules_uid(HttpResponse, Service_T);
static void print_service_rules_euid(HttpResponse, Service_T);
static void print_service_rules_gid(HttpResponse, Service_T);
static void print_service_rules_timestamp(HttpResponse, Service_T);
static void print_service_rules_filesystem(HttpResponse, Service_T);
static void print_service_rules_size(HttpResponse, Service_T);
static void print_service_rules_uptime(HttpResponse, Service_T);
static void print_service_rules_match(HttpResponse, Service_T);
static void print_service_rules_checksum(HttpResponse, Service_T);
static void print_service_rules_process(HttpResponse, Service_T);
static void print_service_rules_program(HttpResponse, Service_T);
static void print_service_rules_resource(HttpResponse, Service_T);
static void print_service_params_port(HttpResponse, Service_T);
static void print_service_params_icmp(HttpResponse, Service_T);
static void print_service_params_perm(HttpResponse, Service_T);
static void print_service_params_uid(HttpResponse, Service_T);
static void print_service_params_gid(HttpResponse, Service_T);
static void print_service_params_timestamp(HttpResponse, Service_T);
static void print_service_params_filesystem(HttpResponse, Service_T);
static void print_service_params_size(HttpResponse, Service_T);
static void print_service_params_match(HttpResponse, Service_T);
static void print_service_params_checksum(HttpResponse, Service_T);
static void print_service_params_process(HttpResponse, Service_T);
static void print_service_params_resource(HttpResponse, Service_T);
static void print_service_params_program(HttpResponse, Service_T);
static void print_status(HttpRequest, HttpResponse, int);
static void status_service_txt(Service_T, HttpResponse, short);
static char *get_monitoring_status(Service_T s, char *, int);
static char *get_service_status(Service_T, char *, int);
static char *get_service_status_html(Service_T, char *, int);


/**
 *  Implementation of doGet and doPost routines used by the cervlet
 *  processor module. This particilary cervlet will provide
 *  information about the monit deamon and programs monitored by
 *  monit.
 *
 *  @file
 */


/* ------------------------------------------------------------------ Public */


/**
 * Callback hook to the Processor module for registering this modules
 * doGet and doPost methods.
 */
void init_service() {

        add_Impl(doGet, doPost);

}


/* ----------------------------------------------------------------- Private */


/**
 * Called by the Processor (via the service method)
 * to handle a POST request.
 */
static void doPost(HttpRequest req, HttpResponse res) {

        set_content_type(res, "text/html");

        if(ACTION(RUN)) {
                handle_run(req, res);
        } else if(ACTION(DOACTION)) {
                handle_do_action(req, res);
        } else {
                handle_action(req, res);
        }

}


/**
 * Called by the Processor (via the service method)
 * to handle a GET request.
 */
static void doGet(HttpRequest req, HttpResponse res) {

        set_content_type(res, "text/html");

        if(ACTION(HOME)) {
                LOCK(Run.mutex)
                do_home(req, res);
                END_LOCK;
        } else if(ACTION(RUN)) {
                handle_run(req, res);
        } else if(ACTION(TEST)) {
                is_monit_running(req, res);
        } else if(ACTION(VIEWLOG)) {
                do_viewlog(req, res);
        } else if(ACTION(ABOUT)) {
                do_about(req, res);
        } else if(ACTION(FAVICON)) {
                printFavicon(res);
        } else if(ACTION(PING)) {
                do_ping(req, res);
        } else if(ACTION(GETID)) {
                do_getid(req, res);
        } else if(ACTION(STATUS)) {
                print_status(req, res, 1);
        } else if(ACTION(STATUS2)) {
                print_status(req, res, 2);
        } else if(ACTION(DOACTION)) {
                handle_do_action(req, res);
        } else {
                handle_action(req, res);
        }

}


/* ----------------------------------------------------------------- Helpers */


static void is_monit_running(HttpRequest req, HttpResponse res) {

        int status;
        int monit = exist_daemon();

        if(monit) {
                status = SC_OK;
        } else {
                status = SC_GONE;
        }

        set_status(res, status);

}


static void printFavicon(HttpResponse res) {
        static size_t l;
        Socket_T S = res->S;
        static unsigned char *favicon = NULL;

        if (! favicon) {
                favicon = CALLOC(sizeof(unsigned char), strlen(FAVICON_ICO));
                l = decode_base64(favicon, FAVICON_ICO);
        }
        if (l) {
                res->is_committed = TRUE;
                socket_print(S, "HTTP/1.0 200 OK\r\n");
                socket_print(S, "Content-length: %d\r\n", l);
                socket_print(S, "Content-Type: image/x-icon\r\n");
                socket_print(S, "Connection: close\r\n\r\n");
                socket_write(S, favicon, l);
        }
}


static void do_head(HttpResponse res, const char *path, const char *name, int refresh) {
        StringBuffer_append(res->outputbuffer,
                "<!DOCTYPE html>"\
                "<html>"\
                "<head>"\
                "<title>Monit: %s</title> "\
                "<style type=\"text/css\"> "\
                " html, body {height: 100%%;margin: 0;} "\
                " body {background-color: white;font: normal normal normal 16px/20px 'HelveticaNeue', Helvetica, Arial, sans-serif; color:#222;} "\
                " h1 {padding:30px 0 10px 0; text-align:center;color:#222;font-size:28px;} "\
                " h2 {padding:20px 0 10px 0; text-align:center;color:#555;font-size:22px;} "\
                " a:hover {text-decoration: none;} "\
                " a {text-decoration: underline;color:#222} "\
                " table {border-collapse:collapse; border:0;} "\
                " .stripe {background:#EDF5FF} "\
                " .red-text {color:#ff0000;} "\
                " .green-text {color:#00ff00;} "\
                " .gray-text {color:#999999;} "\
                " .blue-text {color:#0000ff;} "\
                " .orange-text {color:#ff8800;} "\
                " #wrap {min-height: 100%%;} "\
                " #main {overflow:auto; padding-bottom:50px;} "\
                " /*Opera Fix*/body:before {content:\"\";height:100%%;float:left;width:0;margin-top:-32767px;/} "\
                " #footer {position: relative;margin-top: -50px; height: 50px; clear:both; font-size:11px;color:#777;text-align:center;} "\
                " #footer a {color:#333;} #footer a:hover {text-decoration: none;} "\
                " #nav {background:#ddd;font:normal normal normal 14px/0px 'HelveticaNeue', Helvetica;} "\
                " #nav td {padding:5px 10px;} "\
                " #header {margin-bottom:30px;background:#EFF7FF} "\
                " #nav, #header {border-bottom:1px solid #ccc;} "\
                " #header-row {width:95%%;} "\
                " #header-row th {padding:30px 10px 10px 10px;font-size:120%%;} "\
                " #header-row td {padding:3px 10px;} "\
                " #header-row .first {min-width:200px;width:200px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;} "\
                " #status-table {width:95%%;} "\
                " #status-table th {text-align:left;background:#edf5ff;font-weight:normal;} "\
                " #status-table th, #status-table td, #status-table tr {border:1px solid #ccc;padding:5px;} "\
                " #buttons {font-size:20px; margin:40px 0 20px 0;} "\
                " #buttons td {padding-right:50px;} "\
                " #buttons input {font-size:18px;padding:5px;} "\
                "</style>"\
                "<meta HTTP-EQUIV='REFRESH' CONTENT=%d> "\
                "<meta HTTP-EQUIV='Expires' Content=0> "\
                "<meta HTTP-EQUIV='Pragma' CONTENT='no-cache'> "\
                "</head>"\
                "<body><div id='wrap'><div id='main'>" \
                "<table id='nav' width='100%%'>"\
                "  <tr>"\
                "    <td width='20%%'><a href='.'>Home</a>&nbsp;&gt;&nbsp;<a href='%s'>%s</a></td>"\
                "    <td width='60%%' style='text-align:center;'>Use <a href='http://mmonit.com/'>M/Monit</a> to manage all your Monit instances</td>"\
                "    <td width='20%%'><p align='right'><a href='_about'>Monit %s</a></td>"\
                "  </tr>"\
                "</table>"\
                "<center>",
                Run.system->name, refresh, path, name, VERSION);
}


static void do_foot(HttpResponse res) {
        StringBuffer_append(res->outputbuffer,
                "</center></div></div>"
                "<div id='footer'>"
                "Copyright &copy; 2001-2014 <a href=\"http://tildeslash.com/\">Tildeslash</a>. All rights reserved. "
                "<span style='margin-left:5px;'></span>"
                "<a href=\"http://mmonit.com/monit/\">Monit web site</a> | "
                "<a href=\"http://mmonit.com/wiki/\">Monit Wiki</a> | "
                "<a href=\"http://mmonit.com/\">M/Monit</a>"
                "</div></body></html>");
}


static void do_home(HttpRequest req, HttpResponse res) {
        char *uptime = Util_getUptime(Util_getProcessUptime(Run.pidfile), "&nbsp;");

        do_head(res, "", "", Run.polltime);
        StringBuffer_append(res->outputbuffer,
                  "<table id='header' width='100%%'>"
                  " <tr>"
                  "  <td colspan=2 valign='top' align='left' width='100%%'>"
                  "  <h1>Monit Service Manager</h1>"
                  "  <p align='center'>Monit is <a href='_runtime'>running</a> on %s with <i>uptime, %s</i> and monitoring:</p><br>"
                  "  </td>"
                  " </tr>"
                  "</table>", Run.system->name, uptime);

        FREE(uptime);

        do_home_system(req, res);
        do_home_process(req, res);
        do_home_program(req, res);
        do_home_filesystem(req, res);
        do_home_file(req, res);
        do_home_fifo(req, res);
        do_home_directory(req, res);
        do_home_host(req, res);

        do_foot(res);
}


static void do_about(HttpRequest req, HttpResponse res) {

        StringBuffer_append(res->outputbuffer,
                  "<html><head><title>about monit</title></head><body bgcolor=white>"
                  "<br><h1><center><a href='http://mmonit.com/monit/'>"
                  "monit " VERSION "</a></center></h1>");
        StringBuffer_append(res->outputbuffer,
                  "<ul>"
                  "<li style='padding-bottom:10px;'>Copyright &copy; 2001-2014 <a "
                  "href='http://tildeslash.com/'>Tildeslash Ltd"
                  "</a>. All Rights Reserved.</li></ul>");
        StringBuffer_append(res->outputbuffer, "<hr size='1'>");
        StringBuffer_append(res->outputbuffer,
                  "<p>This program is free software; you can redistribute it and/or "
                  "modify it under the terms of the GNU Affero General Public License version 3</p>"
                  "<p>This program is distributed in the hope that it will be useful, but "
                  "WITHOUT ANY WARRANTY; without even the implied warranty of "
                  "MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the "
                  "<a href='http://www.gnu.org/licenses/agpl.html'>"
                  "GNU AFFERO GENERAL PUBLIC LICENSE</a> for more details.</p>");
        StringBuffer_append(res->outputbuffer,
                  "<center><p style='padding-top:20px;'>[<a href='.'>Back to Monit</a>]</p></body></html>");

}


static void do_ping(HttpRequest req, HttpResponse res) {
        StringBuffer_append(res->outputbuffer, "pong");
}


static void do_getid(HttpRequest req, HttpResponse res) {
        StringBuffer_append(res->outputbuffer, "%s", Run.id);
}

static void do_runtime(HttpRequest req, HttpResponse res) {

        int pid =  exist_daemon();

        do_head(res, "_runtime", "Runtime", 1000);
        StringBuffer_append(res->outputbuffer,
                  "<h2>Monit runtime status</h2>");
        StringBuffer_append(res->outputbuffer, "<table id='status-table'><tr>"
                  "<th width='40%%'>Parameter</th>"
                  "<th width='60%%'>Value</th></tr>");
        StringBuffer_append(res->outputbuffer, "<tr><td>Monit ID</td><td>%s</td></tr>", Run.id);
        StringBuffer_append(res->outputbuffer, "<tr><td>Host</td><td>%s</td></tr>",  Run.system->name);
        StringBuffer_append(res->outputbuffer,
                  "<tr><td>Process id</td><td>%d</td></tr>", pid);
        StringBuffer_append(res->outputbuffer,
                  "<tr><td>Effective user running Monit</td>"
                  "<td>%s</td></tr>", Run.Env.user);
        StringBuffer_append(res->outputbuffer,
                  "<tr><td>Controlfile</td><td>%s</td></tr>", Run.controlfile);
        if(Run.logfile)
                StringBuffer_append(res->outputbuffer,
                          "<tr><td>Logfile</td><td>%s</td></tr>", Run.logfile);
        StringBuffer_append(res->outputbuffer,
                  "<tr><td>Pidfile</td><td>%s</td></tr>", Run.pidfile);
        StringBuffer_append(res->outputbuffer,
                  "<tr><td>State file</td><td>%s</td></tr>", Run.statefile);
        StringBuffer_append(res->outputbuffer,
                  "<tr><td>Debug</td><td>%s</td></tr>",
                  Run.debug?"True":"False");
        StringBuffer_append(res->outputbuffer,
                  "<tr><td>Log</td><td>%s</td></tr>", Run.dolog?"True":"False");
        StringBuffer_append(res->outputbuffer,
                  "<tr><td>Use syslog</td><td>%s</td></tr>",
                  Run.use_syslog?"True":"False");

        if(Run.eventlist_dir) {
                char slots[STRLEN];
                if(Run.eventlist_slots < 0)
                        snprintf(slots, STRLEN, "unlimited");
                else
                        snprintf(slots, STRLEN, "%d", Run.eventlist_slots);
                StringBuffer_append(res->outputbuffer,
                          "<tr><td>Event queue</td>"
                          "<td>base directory %s with %d slots</td></tr>",
                          Run.eventlist_dir, Run.eventlist_slots);
        }

        if(Run.mmonits) {
                Mmonit_T c;
                StringBuffer_append(res->outputbuffer, "<tr><td>M/Monit server(s)</td><td>");
                for(c = Run.mmonits; c; c = c->next)
                {
                        StringBuffer_append(res->outputbuffer,
                                  "%s with timeout %d seconds%s%s%s%s</td></tr>%s",
                                  c->url->url,
                                  c->timeout,
                                  c->ssl.use_ssl?" ssl version ":"",
                                  c->ssl.use_ssl?sslnames[c->ssl.version]:"",
                                  c->ssl.certmd5?" server cert md5 sum ":"",
                                  c->ssl.certmd5?c->ssl.certmd5:"",
                                  c->next?"<tr><td>&nbsp;</td><td>":"");
                }
                printf("\n");
        }

        if(Run.mailservers) {
                MailServer_T mta;
                StringBuffer_append(res->outputbuffer, "<tr><td>Mail server(s)</td><td>");
                for(mta = Run.mailservers; mta; mta = mta->next)
                        StringBuffer_append(res->outputbuffer, "%s:%d%s&nbsp;",
                                  mta->host, mta->port, mta->ssl.use_ssl?"(ssl)":"");
                StringBuffer_append(res->outputbuffer, "</td></tr>");
        }

        if(Run.MailFormat.from)
                StringBuffer_append(res->outputbuffer,
                          "<tr><td>Default mail from</td><td>%s</td></tr>",
                          Run.MailFormat.from);
        if(Run.MailFormat.subject)
                StringBuffer_append(res->outputbuffer,
                          "<tr><td>Default mail subject</td><td>%s</td></tr>",
                          Run.MailFormat.subject);
        if(Run.MailFormat.message)
                StringBuffer_append(res->outputbuffer,
                          "<tr><td>Default mail message</td><td>%s</td></tr>",
                          Run.MailFormat.message);

        StringBuffer_append(res->outputbuffer,
                  "<tr><td>Poll time</td><td>%d seconds with start delay %d seconds</td></tr>",
                  Run.polltime, Run.startdelay);
        StringBuffer_append(res->outputbuffer,
                  "<tr><td>httpd bind address</td><td>%s</td></tr>",
                  Run.bind_addr?Run.bind_addr:"Any/All");
        StringBuffer_append(res->outputbuffer,
                  "<tr><td>httpd portnumber</td><td>%d</td></tr>", Run.httpdport);
        StringBuffer_append(res->outputbuffer,
                  "<tr><td>httpd signature</td><td>%s</td></tr>",
                  Run.httpdsig?"True":"False");
        StringBuffer_append(res->outputbuffer,
                  "<tr><td>Use ssl encryption</td><td>%s</td></tr>",
                  Run.httpdssl?"True":"False");
        if (Run.httpdssl) {
                StringBuffer_append(res->outputbuffer,
                          "<tr><td>PEM key/certificate file</td><td>%s</td></tr>",
                          Run.httpsslpem);

                if (Run.httpsslclientpem!=NULL) {
                        StringBuffer_append(res->outputbuffer,
                                  "<tr><td>Client PEM key/certification"
                                  "</td><td>%s</td></tr>", "Enabled");
                        StringBuffer_append(res->outputbuffer,
                                  "<tr><td>Client PEM key/certificate file"
                                  "</td><td>%s</td></tr>", Run.httpsslclientpem);
                } else {
                        StringBuffer_append(res->outputbuffer,
                                  "<tr><td>Client PEM key/certification"
                                  "</td><td>%s</td></tr>", "Disabled");
                }
                StringBuffer_append(res->outputbuffer,
                          "<tr><td>Allow self certified certificates "
                          "</td><td>%s</td></tr>", Run.allowselfcert?"True":"False");
        }

        StringBuffer_append(res->outputbuffer,
                  "<tr><td>httpd auth. style</td><td>%s</td></tr>",
                  (Run.credentials!=NULL)&&(has_hosts_allow())?
                  "Basic Authentication and Host/Net allow list":
                  (Run.credentials!=NULL)?"Basic Authentication":
                  (has_hosts_allow())?"Host/Net allow list":
                  "No authentication");

        print_alerts(res, Run.maillist);

        StringBuffer_append(res->outputbuffer, "</table>");

        if(!is_readonly(req)) {
                StringBuffer_append(res->outputbuffer,
                          "<table id='buttons'><tr>");
                StringBuffer_append(res->outputbuffer,
                          "<td style='color:red;'><form method=POST action='_runtime'>Stop Monit http server? "
                          "<input type=hidden name='action' value='stop'><input type=submit value='Go'></form></td>");
                StringBuffer_append(res->outputbuffer,
                          "<td><form method=POST action='_runtime'>Force validate now? <input type=hidden name='action' value='validate'>"
                          "<input type=submit value='Go'></form></td>");

                if(Run.dolog && !Run.use_syslog) {
                        StringBuffer_append(res->outputbuffer,
                                  "<td><form method=GET action='_viewlog'>View Monit logfile? <input type=submit value='Go'></form></td>");
                }
                StringBuffer_append(res->outputbuffer,
                          "</tr></table>");
        }

        do_foot(res);

}


static void do_viewlog(HttpRequest req, HttpResponse res) {

        if(is_readonly(req)) {
                send_error(res, SC_FORBIDDEN,
                           "You do not have sufficent privileges to access this page");
                return;
        }

        do_head(res, "_viewlog", "View log", 100);

        if(Run.dolog && !Run.use_syslog) {

                struct stat sb;

                if(!stat(Run.logfile, &sb)) {

                        FILE *f = fopen(Run.logfile, "r");
                        if(f) {
#define BUFSIZE 512
                                size_t n;
                                char buf[BUFSIZE+1];
                                StringBuffer_append(res->outputbuffer, "<br><p><form><textarea cols=120 rows=30 readonly>");
                                while((n = fread(buf, sizeof(char), BUFSIZE, f)) > 0) {
                                        buf[n] = 0;
                                        StringBuffer_append(res->outputbuffer, "%s", buf);
                                }
                                fclose(f);
                                StringBuffer_append(res->outputbuffer, "</textarea></form>");
                        } else {
                                StringBuffer_append(res->outputbuffer, "Error opening logfile: %s", STRERROR);
                        }
                } else {
                        StringBuffer_append(res->outputbuffer, "Error stating logfile: %s", STRERROR);
                }
        } else {

                StringBuffer_append(res->outputbuffer,
                          "<b>Cannot view logfile:</b><br>");
                if(!Run.dolog) {

                        StringBuffer_append(res->outputbuffer, "Monit was started without logging");

                } else {

                        StringBuffer_append(res->outputbuffer, "Monit uses syslog");

                }

        }

        do_foot(res);

}


static void handle_action(HttpRequest req, HttpResponse res) {
        int doaction;
        char *name = req->url;
        const char *action;
        Service_T s;

        if(!(s = Util_getService(++name))) {
                send_error(res, SC_NOT_FOUND, "There is no service by that name");
                return;
        }
        if((action = get_parameter(req, "action"))) {
                const char *token = NULL;

                if(is_readonly(req)) {
                        send_error(res, SC_FORBIDDEN, "You do not have sufficent privileges to access this page");
                        return;
                }
                doaction = Util_getAction(action);
                if(doaction == ACTION_IGNORE) {
                        send_error(res, SC_BAD_REQUEST, "Invalid action");
                        return;
                }
                if(s->doaction != ACTION_IGNORE) {
                        send_error(res, SC_SERVICE_UNAVAILABLE, "Other action already in progress -- please try again later");
                        return;
                }
                s->doaction = doaction;
                token = get_parameter(req, "token");
                if (token) {
                        FREE(s->token);
                        s->token = Str_dup(token);
                }
                LogInfo("'%s' %s on user request\n", s->name, action);
                Run.doaction = TRUE; /* set the global flag */
                do_wakeupcall();
        }
        do_service(req, res, s);
}


static void handle_do_action(HttpRequest req, HttpResponse res) {
        Service_T s;
        int doaction = ACTION_IGNORE;
        const char *action = get_parameter(req, "action");
        const char *token = get_parameter(req, "token");

        if(action) {
                HttpParameter p;

                if(is_readonly(req)) {
                        send_error(res, SC_FORBIDDEN, "You do not have sufficent privileges to access this page");
                        return;
                }
                if((doaction = Util_getAction(action)) == ACTION_IGNORE) {
                        send_error(res, SC_BAD_REQUEST, "Invalid action");
                        return;
                }

                for(p = req->params; p; p = p->next) {

                        if(!strcasecmp(p->name, "service")) {
                                s  = Util_getService(p->value);

                                if(!s) {
                                        send_error(res, SC_BAD_REQUEST, "There is no service by that name");
                                        return;
                                }
                                if(s->doaction != ACTION_IGNORE) {
                                        send_error(res, SC_SERVICE_UNAVAILABLE, "Other action already in progress -- please try again later");
                                        return;
                                }
                                s->doaction = doaction;
                                LogInfo("'%s' %s on user request\n", s->name, action);
                        }
                }

                /* Set token for last service only so we'll get it back after all services were handled */
                if (token) {
                        Service_T q = NULL;
                        for (s = servicelist; s; s = s->next)
                                if (s->doaction == doaction)
                                        q = s;
                        if (q) {
                                FREE(q->token);
                                q->token = Str_dup(token);
                        }
                }

                Run.doaction = TRUE;
                do_wakeupcall();
        }
}


static void handle_run(HttpRequest req, HttpResponse res) {

        const char *action = get_parameter(req, "action");

        if(action) {
                if(is_readonly(req)) {
                        send_error(res, SC_FORBIDDEN,
                                   "You do not have sufficent privileges to access this page");
                        return;
                }
                if(IS(action, "validate")) {
                        LogInfo("The Monit http server woke up on user request\n");
                        do_wakeupcall();
                } else if(IS(action, "stop")) {
                        LogInfo("The Monit http server stopped on user request\n");
                        send_error(res, SC_SERVICE_UNAVAILABLE,
                                   "The Monit http server is stopped");
                        stop_httpd();
                        return;
                }
        }

        LOCK(Run.mutex)
        do_runtime(req, res);
        END_LOCK;

}


static void do_service(HttpRequest req, HttpResponse res, Service_T s) {
        Dependant_T d;
        ActionRate_T ar;
        ServiceGroup_T sg;
        ServiceGroupMember_T sgm;
        char buf[STRLEN];

        ASSERT(s);

        do_head(res, s->name, s->name, Run.polltime);

        StringBuffer_append(res->outputbuffer,
                  "<h2>%s status</h2>"
                  "<table id='status-table'>"
                  "<tr>"
                  "<th width='30%%'>Parameter</th>"
                  "<th width='70%%'>Value</th>"
                  "</tr>"
                  "<tr>"
                  "<td>Name</td>"
                  "<td>%s</td>"
                  "</tr>",
                  servicetypes[s->type],
                  s->name);

        if(s->type == TYPE_PROCESS)
                StringBuffer_append(res->outputbuffer, "<tr><td>%s</td><td>%s</td></tr>", s->matchlist ? "Match" : "Pid file", s->path);
        else if(s->type != TYPE_HOST && s->type != TYPE_SYSTEM)
                StringBuffer_append(res->outputbuffer, "<tr><td>Path</td><td>%s</td></tr>", s->path);

        StringBuffer_append(res->outputbuffer,
                  "<tr><td>Status</td><td>%s</td></tr>", get_service_status_html(s, buf, sizeof(buf)));

        for (sg = servicegrouplist; sg; sg = sg->next)
                for (sgm = sg->members; sgm; sgm = sgm->next)
                        if (! strcasecmp(sgm->name, s->name))
                                StringBuffer_append(res->outputbuffer, "<tr><td>Group</td><td class='blue-text'>%s</td></tr>", sg->name);

        StringBuffer_append(res->outputbuffer,
                  "<tr><td>Monitoring mode</td><td>%s</td></tr>", modenames[s->mode]);

        StringBuffer_append(res->outputbuffer,
                  "<tr><td>Monitoring status</td><td>%s</td></tr>", get_monitoring_status(s, buf, sizeof(buf)));

        for(d = s->dependantlist; d; d = d->next) {
                if(d->dependant != NULL) {
                        StringBuffer_append(res->outputbuffer,
                                  "<tr><td>Depends on service </td><td> <a href=%s> %s </a></td></tr>",
                                  d->dependant, d->dependant);
                }
        }

        if(s->start) {
                int i = 0;
                StringBuffer_append(res->outputbuffer, "<tr><td>Start program</td><td>'");
                while(s->start->arg[i]) {
                        if(i) StringBuffer_append(res->outputbuffer, " ");
                        StringBuffer_append(res->outputbuffer, "%s", s->start->arg[i++]);
                }
                StringBuffer_append(res->outputbuffer, "'");
                if(s->start->has_uid)
                        StringBuffer_append(res->outputbuffer, " as uid %d", s->start->uid);
                if(s->start->has_gid)
                        StringBuffer_append(res->outputbuffer, " as gid %d", s->start->gid);
                StringBuffer_append(res->outputbuffer, " timeout %d second(s)", s->start->timeout);
                StringBuffer_append(res->outputbuffer, "</td></tr>");
        }

        if(s->stop) {
                int i = 0;
                StringBuffer_append(res->outputbuffer, "<tr><td>Stop program</td><td>'");
                while(s->stop->arg[i]) {
                        if(i) StringBuffer_append(res->outputbuffer, " ");
                        StringBuffer_append(res->outputbuffer, "%s", s->stop->arg[i++]);
                }
                StringBuffer_append(res->outputbuffer, "'");
                if(s->stop->has_uid)
                        StringBuffer_append(res->outputbuffer, " as uid %d", s->stop->uid);
                if(s->stop->has_gid)
                        StringBuffer_append(res->outputbuffer, " as gid %d", s->stop->gid);
                StringBuffer_append(res->outputbuffer, " timeout %d second(s)", s->stop->timeout);
                StringBuffer_append(res->outputbuffer, "</td></tr>");
        }
        if(s->restart) {
                int i = 0;
                StringBuffer_append(res->outputbuffer, "<tr><td>Restart program</td><td>'");
                while(s->restart->arg[i]) {
                        if(i) StringBuffer_append(res->outputbuffer, " ");
                        StringBuffer_append(res->outputbuffer, "%s", s->restart->arg[i++]);
                }
                StringBuffer_append(res->outputbuffer, "'");
                if(s->restart->has_uid)
                        StringBuffer_append(res->outputbuffer, " as uid %d", s->restart->uid);
                if(s->restart->has_gid)
                        StringBuffer_append(res->outputbuffer, " as gid %d", s->restart->gid);
                StringBuffer_append(res->outputbuffer, " timeout %d second(s)", s->restart->timeout);
                StringBuffer_append(res->outputbuffer, "</td></tr>");
        }

        if(s->type != TYPE_SYSTEM && s->type != TYPE_PROGRAM) {
                StringBuffer_append(res->outputbuffer, "<tr><td>Existence</td><td>");
                Util_printRule(res->outputbuffer, s->action_NONEXIST, "If doesn't exist");
                StringBuffer_append(res->outputbuffer, "</td></tr>");
        }

        if (s->every.type != EVERY_CYCLE) {
                StringBuffer_append(res->outputbuffer, "<tr><td>Check service</td><td>");
                if (s->every.type == EVERY_SKIPCYCLES)
                        StringBuffer_append(res->outputbuffer, "every %d cycle", s->every.spec.cycle.number);
                else if (s->every.type == EVERY_CRON)
                        StringBuffer_append(res->outputbuffer, "every <code>\"%s\"</code>", s->every.spec.cron);
                else if (s->every.type == EVERY_NOTINCRON)
                        StringBuffer_append(res->outputbuffer, "not every <code>\"%s\"</code>", s->every.spec.cron);
                StringBuffer_append(res->outputbuffer, "</td></tr>");
        }

        for (ar = s->actionratelist; ar; ar = ar->next) {
                StringBuffer_append(res->outputbuffer, "<tr><td>Timeout</td><td>If restarted %d times within %d cycle(s) then ", ar->count, ar->cycle);
                Util_printAction(ar->action->failed, res->outputbuffer);
                StringBuffer_append(res->outputbuffer, "</td></tr>");
        }

        StringBuffer_append(res->outputbuffer, "<tr><td>Data collected</td><td>%s</td></tr>", Time_string(s->collected.tv_sec, buf));

        /* Parameters */
        print_service_params_icmp(res, s);
        print_service_params_port(res, s);
        print_service_params_perm(res, s);
        print_service_params_uid(res, s);
        print_service_params_gid(res, s);
        print_service_params_timestamp(res, s);
        print_service_params_filesystem(res, s);
        print_service_params_size(res, s);
        print_service_params_match(res, s);
        print_service_params_checksum(res, s);
        print_service_params_process(res, s);
        print_service_params_resource(res, s);
        print_service_params_program(res, s);

        /* Rules */
        print_service_rules_icmp(res, s);
        print_service_rules_port(res, s);
        print_service_rules_perm(res, s);
        print_service_rules_uid(res, s);
        print_service_rules_euid(res, s);
        print_service_rules_gid(res, s);
        print_service_rules_timestamp(res, s);
        print_service_rules_filesystem(res, s);
        print_service_rules_size(res, s);
        print_service_rules_uptime(res, s);
        print_service_rules_match(res, s);
        print_service_rules_checksum(res, s);
        print_service_rules_process(res, s);
        print_service_rules_program(res, s);
        print_service_rules_resource(res, s);

        print_alerts(res, s->maillist);

        StringBuffer_append(res->outputbuffer, "</table>");

        print_buttons(req, res, s);

        do_foot(res);
}


static void do_home_system(HttpRequest req, HttpResponse res) {
        Service_T s = Run.system;
        char buf[STRLEN];

        StringBuffer_append(res->outputbuffer,
                  "<table id='header-row'>"
                  "<tr>"
                  "<th align='left' class='first'>System</th>"
                  "<th align='left'>Status</th>");

        if(Run.doprocess) {
                StringBuffer_append(res->outputbuffer,
                          "<th align='right'>Load</th>"
                          "<th align='right'>CPU</th>"
                          "<th align='right'>Memory</th>"
                          "<th align='right'>Swap</th>");
        }

        StringBuffer_append(res->outputbuffer,
                  "</tr>"
                  "<tr class='stripe'>"
                  "<td align='left'><a href='%s'>%s</a></td>"
                  "<td align='left'>%s</td>",
                  s->name, s->name, get_service_status_html(s, buf, sizeof(buf)));

        if(Run.doprocess) {
                StringBuffer_append(res->outputbuffer,
                          "<td align='right'>[%.2f]&nbsp;[%.2f]&nbsp;[%.2f]</td>"
                          "<td align='right'>"
                          "%.1f%%us,&nbsp;%.1f%%sy"
#ifdef HAVE_CPU_WAIT
                          ",&nbsp;%.1f%%wa"
#endif
                          "</td>"
                          "<td align='right'>%.1f%% [%ld&nbsp;kB]</td>"
                          "<td align='right'>%.1f%% [%ld&nbsp;kB]</td>",
                          systeminfo.loadavg[0], systeminfo.loadavg[1], systeminfo.loadavg[2],
                          systeminfo.total_cpu_user_percent > 0 ? systeminfo.total_cpu_user_percent/10. : 0,
                          systeminfo.total_cpu_syst_percent > 0 ? systeminfo.total_cpu_syst_percent/10. : 0,
#ifdef HAVE_CPU_WAIT
                          systeminfo.total_cpu_wait_percent > 0 ? systeminfo.total_cpu_wait_percent/10. : 0,
#endif
                          systeminfo.total_mem_percent/10., systeminfo.total_mem_kbyte,
                          systeminfo.total_swap_percent/10., systeminfo.total_swap_kbyte);
        }

        StringBuffer_append(res->outputbuffer,
                  "</tr>"
                  "</table>");
}


static void do_home_process(HttpRequest req, HttpResponse res) {

        Service_T      s;
        char           buf[STRLEN];
        int            on = TRUE;
        int            header = TRUE;

        for(s = servicelist_conf; s; s = s->next_conf) {

                if(s->type != TYPE_PROCESS) continue;

                if(header) {

                        StringBuffer_append(res->outputbuffer,
                                  "<table id='header-row'>"
                                  "<tr>"
                                  "<th align='left' class='first'>Process</th>"
                                  "<th align='left'>Status</th>"
                                  "<th align='right'>Uptime</th>");

                        if(Run.doprocess) {
                                StringBuffer_append(res->outputbuffer,
                                          "<th align='right'>CPU Total</b></th>"
                                          "<th align='right'>Memory Total</th>");
                        }

                        StringBuffer_append(res->outputbuffer, "</tr>");


                        header = FALSE;

                }

                StringBuffer_append(res->outputbuffer,
                          "<tr %s>"
                          "<td align='left'><a href='%s'>%s</a></td>"
                          "<td align='left'>%s</td>",
                          on?"class='stripe'":"",
                          s->name, s->name, get_service_status_html(s, buf, sizeof(buf)));

                if(!Util_hasServiceStatus(s)) {

                        StringBuffer_append(res->outputbuffer,
                                  "<td align='right'>-</td>");

                        if(Run.doprocess) {
                                StringBuffer_append(res->outputbuffer,
                                          "<td align='right'>-</td>"
                                          "<td align='right'>-</td>");
                        }

                } else {

                        char *uptime = Util_getUptime(s->inf->priv.process.uptime, "&nbsp;");
                        StringBuffer_append(res->outputbuffer,
                                  "<td align='right'>%s</td>", uptime);
                        FREE(uptime);

                        if(Run.doprocess) {
                                StringBuffer_append(res->outputbuffer,
                                          "<td align='right' class='%s'>%.1f%%</td>",
                                          (s->error & Event_Resource)?"red-text":"",
                                          s->inf->priv.process.total_cpu_percent/10.0);
                                StringBuffer_append(res->outputbuffer,
                                          "<td align='right' class='%s'>%.1f%% [%ld&nbsp;kB]</td>",
                                          (s->error & Event_Resource)?"red-text":"",
                                          s->inf->priv.process.total_mem_percent/10.0, s->inf->priv.process.total_mem_kbyte);
                        }

                }

                StringBuffer_append(res->outputbuffer, "</tr>");

                on = on?FALSE:TRUE;

        }

        if(!header)
                StringBuffer_append(res->outputbuffer, "</table>");

}


static void do_home_program(HttpRequest req, HttpResponse res) {

        Service_T      s;
        char           buf[STRLEN];
        int            on = TRUE;
        int            header = TRUE;

        for(s = servicelist_conf; s; s = s->next_conf) {

                if(s->type != TYPE_PROGRAM) continue;

                if(header) {

                        StringBuffer_append(res->outputbuffer,
                                  "<table id='header-row'>"
                                  "<tr>"
                                  "<th align='left' class='first'>Program</th>"
                                  "<th align='left'>Status</th>"
                                  "<th align='right'>Last started</th>"
                                  "<th align='right'>Exit value</th>");

                        StringBuffer_append(res->outputbuffer, "</tr>");

                        header = FALSE;

                }

                StringBuffer_append(res->outputbuffer,
                          "<tr %s>"
                          "<td align='left'><a href='%s'>%s</a></td>"
                          "<td align='left'>%s</td>",
                          on?"class='stripe'":"",
                          s->name, s->name, get_service_status_html(s, buf, sizeof(buf)));

                if(!Util_hasServiceStatus(s)) {
                        StringBuffer_append(res->outputbuffer, "<td align='right'>-</td>");
                        StringBuffer_append(res->outputbuffer, "<td align='right'>-</td>");
                } else {
                        if (s->program->started) {
                                char t[32];
                                StringBuffer_append(res->outputbuffer, "<td align='right'>%s</td>", Time_string(s->program->started, t));
                                StringBuffer_append(res->outputbuffer, "<td align='right'>%d</td>", s->program->exitStatus);
                        } else {
                                StringBuffer_append(res->outputbuffer, "<td align='right'>Not yet started</td>");
                                StringBuffer_append(res->outputbuffer, "<td align='right'>N/A</td>");
                        }
                }

                StringBuffer_append(res->outputbuffer, "</tr>");

                on = on?FALSE:TRUE;

        }

        if(!header)
                StringBuffer_append(res->outputbuffer, "</table>");

}


static void do_home_filesystem(HttpRequest req, HttpResponse res) {
        Service_T     s;
        char          buf[STRLEN];
        int           on = TRUE;
        int           header = TRUE;

        for(s = servicelist_conf; s; s = s->next_conf) {

                if(s->type != TYPE_FILESYSTEM) continue;

                if(header) {

                        StringBuffer_append(res->outputbuffer,
                                  "<table id='header-row'>"
                                  "<tr>"
                                  "<th align='left' class='first'>Filesystem</th>"
                                  "<th align='left'>Status</th>"
                                  "<th align='right'>Space usage</th>"
                                  "<th align='right'>Inodes usage</th>"
                                  "</tr>");

                        header = FALSE;

                }

                StringBuffer_append(res->outputbuffer,
                          "<tr %s>"
                          "<td align='left'><a href='%s'>%s</a></td>"
                          "<td align='left'>%s</td>",
                          on?"class='stripe'":"",
                          s->name, s->name, get_service_status_html(s, buf, sizeof(buf)));

                if(!Util_hasServiceStatus(s)) {

                        StringBuffer_append(res->outputbuffer,
                                  "<td align='right'>- [-]</td>"
                                  "<td align='right'>- [-]</td>");

                } else {

                        StringBuffer_append(res->outputbuffer,
                                  "<td align='right'>%.1f%% [%.1f&nbsp;MB]</td>",
                                  s->inf->priv.filesystem.space_percent/10.,
                                  s->inf->priv.filesystem.f_bsize > 0 ? ((float)s->inf->priv.filesystem.space_total / (float)1048576 * (float)s->inf->priv.filesystem.f_bsize) : 0);

                        if(s->inf->priv.filesystem.f_files > 0) {

                                StringBuffer_append(res->outputbuffer,
                                          "<td align='right'>%.1f%% [%ld&nbsp;objects]</td>",
                                          s->inf->priv.filesystem.inode_percent/10.,
                                          s->inf->priv.filesystem.inode_total);

                        } else {

                                StringBuffer_append(res->outputbuffer,
                                          "<td align='right'>not supported by filesystem</td>");

                        }

                }

                StringBuffer_append(res->outputbuffer, "</tr>");

                on = on?FALSE:TRUE;

        }

        if(!header)
                StringBuffer_append(res->outputbuffer, "</table>");

}


static void do_home_file(HttpRequest req, HttpResponse res) {

        Service_T  s;
        char       buf[STRLEN];
        int        on = TRUE;
        int        header = TRUE;

        for(s = servicelist_conf; s; s = s->next_conf) {

                if(s->type != TYPE_FILE) continue;

                if(header) {

                        StringBuffer_append(res->outputbuffer,
                                  "<table id='header-row'>"
                                  "<tr>"
                                  "<th align='left' class='first'>File</th>"
                                  "<th align='left'>Status</th>"
                                  "<th align='right'>Size</th>"
                                  "<th align='right'>Permission</th>"
                                  "<th align='right'>UID</th>"
                                  "<th align='right'>GID</th>"
                                  "</tr>");

                        header = FALSE;

                }

                StringBuffer_append(res->outputbuffer,
                          "<tr %s>"
                          "<td align='left'><a href='%s'>%s</a></td>"
                          "<td align='left'>%s</td>",
                          on?"class='stripe'":"",
                          s->name, s->name, get_service_status_html(s, buf, sizeof(buf)));

                if(!Util_hasServiceStatus(s)) {

                        StringBuffer_append(res->outputbuffer,
                                  "<td align='right'>-</td>"
                                  "<td align='right'>-</td>"
                                  "<td align='right'>-</td>"
                                  "<td align='right'>-</td>");

                } else {

                        StringBuffer_append(res->outputbuffer,
                                  "<td align='right'>%llu&nbsp;B</td>"
                                  "<td align='right'>%04o</td>"
                                  "<td align='right'>%d</td>"
                                  "<td align='right'>%d</td>",
                                  (unsigned long long)s->inf->priv.file.st_size,
                                  s->inf->st_mode & 07777,
                                  s->inf->st_uid,
                                  s->inf->st_gid);

                }

                StringBuffer_append(res->outputbuffer, "</tr>");

                on = on?FALSE:TRUE;

        }

        if(!header)
                StringBuffer_append(res->outputbuffer, "</table>");

}


static void do_home_fifo(HttpRequest req, HttpResponse res) {

        Service_T  s;
        char       buf[STRLEN];
        int        on = TRUE;
        int        header = TRUE;

        for(s = servicelist_conf; s; s = s->next_conf) {

                if(s->type != TYPE_FIFO) continue;

                if(header) {

                        StringBuffer_append(res->outputbuffer,
                                  "<table id='header-row'>"
                                  "<tr>"
                                  "<th align='left' class='first'>Fifo</th>"
                                  "<th align='left'>Status</th>"
                                  "<th align='right'>Permission</th>"
                                  "<th align='right'>UID</th>"
                                  "<th align='right'>GID</th>"
                                  "</tr>");

                        header = FALSE;

                }

                StringBuffer_append(res->outputbuffer,
                          "<tr %s>"
                          "<td align='left'><a href='%s'>%s</a></td>"
                          "<td align='left'>%s</td>",
                          on?"class='stripe'":"",
                          s->name, s->name, get_service_status_html(s, buf, sizeof(buf)));

                if(!Util_hasServiceStatus(s)) {

                        StringBuffer_append(res->outputbuffer,
                                  "<td align='right'>-</td>"
                                  "<td align='right'>-</td>"
                                  "<td align='right'>-</td>");

                } else {

                        StringBuffer_append(res->outputbuffer,
                                  "<td align='right'>%o</td>"
                                  "<td align='right'>%d</td>"
                                  "<td align='right'>%d</td>",
                                  s->inf->st_mode & 07777,
                                  s->inf->st_uid,
                                  s->inf->st_gid);

                }

                StringBuffer_append(res->outputbuffer, "</tr>");

                on = on?FALSE:TRUE;

        }

        if(!header)
                StringBuffer_append(res->outputbuffer, "</table>");

}


static void do_home_directory(HttpRequest req, HttpResponse res) {

        Service_T        s;
        char             buf[STRLEN];
        int              on = TRUE;
        int              header = TRUE;

        for(s = servicelist_conf; s; s = s->next_conf) {

                if(s->type != TYPE_DIRECTORY) continue;

                if(header) {

                        StringBuffer_append(res->outputbuffer,
                                  "<table id='header-row'>"
                                  "<tr>"
                                  "<th align='left' class='first'>Directory</th>"
                                  "<th align='left'>Status</th>"
                                  "<th align='right'>Permission</th>"
                                  "<th align='right'>UID</th>"
                                  "<th align='right'>GID</th>"
                                  "</tr>");

                        header = FALSE;

                }

                StringBuffer_append(res->outputbuffer,
                          "<tr %s>"
                          "<td align='left'><a href='%s'>%s</a></td>"
                          "<td align='left'>%s</td>",
                          on?"class='stripe'":"",
                          s->name, s->name, get_service_status_html(s, buf, sizeof(buf)));

                if(!Util_hasServiceStatus(s)) {

                        StringBuffer_append(res->outputbuffer,
                                  "<td align='right'>-</td>"
                                  "<td align='right'>-</td>"
                                  "<td align='right'>-</td>");

                } else {

                        StringBuffer_append(res->outputbuffer,
                                  "<td align='right'>%o</td>"
                                  "<td align='right'>%d</td>"
                                  "<td align='right'>%d</td>",
                                  s->inf->st_mode & 07777,
                                  s->inf->st_uid,
                                  s->inf->st_gid);

                }

                StringBuffer_append(res->outputbuffer, "</tr>");

                on = on?FALSE:TRUE;

        }

        if(!header)
                StringBuffer_append(res->outputbuffer, "</table>");

}


static void do_home_host(HttpRequest req, HttpResponse res) {

        Service_T  s;
        Icmp_T     icmp;
        Port_T     port;
        char       buf[STRLEN];
        int        on = TRUE;
        int        header = TRUE;

        for(s = servicelist_conf; s; s = s->next_conf) {

                if(s->type != TYPE_HOST) continue;

                if(header) {

                        StringBuffer_append(res->outputbuffer,
                                  "<table id='header-row'>"
                                  "<tr>"
                                  "<th align='left' class='first'>Host</th>"
                                  "<th align='left'>Status</th>"
                                  "<th align='right'>Protocol(s)</th>"
                                  "</tr>");

                        header = FALSE;

                }

                StringBuffer_append(res->outputbuffer,
                          "<tr %s>"
                          "<td align='left'><a href='%s'>%s</a></td>"
                          "<td align='left'>%s</td>",
                          on?"class='stripe'":"",
                          s->name, s->name, get_service_status_html(s, buf, sizeof(buf)));

                if(!Util_hasServiceStatus(s)) {

                        StringBuffer_append(res->outputbuffer,
                                  "<td align='right'>-</td>");

                } else {

                        StringBuffer_append(res->outputbuffer,
                                  "<td align='right'>");

                        if(s->icmplist) {
                                for(icmp = s->icmplist; icmp; icmp = icmp->next) {
                                        if(icmp != s->icmplist)
                                                StringBuffer_append(res->outputbuffer, "&nbsp;&nbsp;<b>|</b>&nbsp;&nbsp;");
                                        StringBuffer_append(res->outputbuffer, "<span class='%s'>[ICMP %s]</span>",
                                                  (icmp->is_available)?"":"red-text",
                                                  icmpnames[icmp->type]);
                                }
                        }

                        if(s->icmplist && s->portlist)
                                StringBuffer_append(res->outputbuffer, "&nbsp;&nbsp;<b>|</b>&nbsp;&nbsp;");

                        if(s->portlist) {
                                for(port = s->portlist; port; port = port->next) {
                                        if(port != s->portlist)
                                                StringBuffer_append(res->outputbuffer, "&nbsp;&nbsp;<b>|</b>&nbsp;&nbsp;");
                                        StringBuffer_append(res->outputbuffer, "<span class='%s'>[%s] at port %d</span>",
                                                  (port->is_available)?"":"red-text",
                                                  port->protocol->name, port->port);
                                }
                        }

                        StringBuffer_append(res->outputbuffer, "</td>");

                }

                StringBuffer_append(res->outputbuffer, "</tr>");

                on = on?FALSE:TRUE;

        }

        if(!header)
                StringBuffer_append(res->outputbuffer, "</table>");

}


/* ------------------------------------------------------------------------- */


static void print_alerts(HttpResponse res, Mail_T s) {

        Mail_T r;

        for(r = s; r; r = r->next) {
                StringBuffer_append(res->outputbuffer,
                          "<tr class='stripe'><td>Alert mail to</td>"
                          "<td>%s</td></tr>", r->to?r->to:"");
                StringBuffer_append(res->outputbuffer, "<tr><td>Alert on</td><td>");

                if(r->events == Event_Null) {
                        StringBuffer_append(res->outputbuffer, "No events");
                } else if(r->events == Event_All) {
                        StringBuffer_append(res->outputbuffer, "All events");
                } else {
                        if(IS_EVENT_SET(r->events, Event_Action))
                                StringBuffer_append(res->outputbuffer, "Action ");
                        if(IS_EVENT_SET(r->events, Event_Checksum))
                                StringBuffer_append(res->outputbuffer, "Checksum ");
                        if(IS_EVENT_SET(r->events, Event_Connection))
                                StringBuffer_append(res->outputbuffer, "Connection ");
                        if(IS_EVENT_SET(r->events, Event_Content))
                                StringBuffer_append(res->outputbuffer, "Content ");
                        if(IS_EVENT_SET(r->events, Event_Data))
                                StringBuffer_append(res->outputbuffer, "Data ");
                        if(IS_EVENT_SET(r->events, Event_Exec))
                                StringBuffer_append(res->outputbuffer, "Exec ");
                        if(IS_EVENT_SET(r->events, Event_Fsflag))
                                StringBuffer_append(res->outputbuffer, "Fsflags ");
                        if(IS_EVENT_SET(r->events, Event_Gid))
                                StringBuffer_append(res->outputbuffer, "Gid ");
                        if(IS_EVENT_SET(r->events, Event_Icmp))
                                StringBuffer_append(res->outputbuffer, "Icmp ");
                        if(IS_EVENT_SET(r->events, Event_Instance))
                                StringBuffer_append(res->outputbuffer, "Instance ");
                        if(IS_EVENT_SET(r->events, Event_Invalid))
                                StringBuffer_append(res->outputbuffer, "Invalid ");
                        if(IS_EVENT_SET(r->events, Event_Nonexist))
                                StringBuffer_append(res->outputbuffer, "Nonexist ");
                        if(IS_EVENT_SET(r->events, Event_Permission))
                                StringBuffer_append(res->outputbuffer, "Permission ");
                        if(IS_EVENT_SET(r->events, Event_Pid))
                                StringBuffer_append(res->outputbuffer, "PID ");
                        if(IS_EVENT_SET(r->events, Event_PPid))
                                StringBuffer_append(res->outputbuffer, "PPID ");
                        if(IS_EVENT_SET(r->events, Event_Resource))
                                StringBuffer_append(res->outputbuffer, "Resource ");
                        if(IS_EVENT_SET(r->events, Event_Size))
                                StringBuffer_append(res->outputbuffer, "Size ");
                        if(IS_EVENT_SET(r->events, Event_Status))
                                StringBuffer_append(res->outputbuffer, "Status ");
                        if(IS_EVENT_SET(r->events, Event_Timeout))
                                StringBuffer_append(res->outputbuffer, "Timeout ");
                        if(IS_EVENT_SET(r->events, Event_Timestamp))
                                StringBuffer_append(res->outputbuffer, "Timestamp ");
                        if(IS_EVENT_SET(r->events, Event_Uid))
                                StringBuffer_append(res->outputbuffer, "Uid ");
                        if(IS_EVENT_SET(r->events, Event_Uptime))
                                StringBuffer_append(res->outputbuffer, "Uptime ");
                }

                StringBuffer_append(res->outputbuffer, "</td></tr>");

                if(r->reminder) {
                        StringBuffer_append(res->outputbuffer,
                                  "<tr><td>Alert reminder</td><td>%u cycles</td></tr>",
                                  r->reminder);
                }

        }

}


static void print_buttons(HttpRequest req, HttpResponse res, Service_T s) {

        if(is_readonly(req)) {
                /*
                 * A read-only REMOTE_USER does not get access to these buttons
                 */
                return;
        }

        StringBuffer_append(res->outputbuffer, "<table id='buttons'><tr>");
        /* Start program */
        if(s->start)
                StringBuffer_append(res->outputbuffer,
                          "<td><form method=POST action=%s>"
                          "<input type=hidden value='start' name=action>"
                          "<input type=submit value='Start service'></form></td>", s->name);
        /* Stop program */
        if(s->stop)
                StringBuffer_append(res->outputbuffer,
                          "<td><form method=POST action=%s>"
                          "<input type=hidden value='stop' name=action>"
                          "<input type=submit value='Stop service'></form></td>", s->name);
        /* Restart program */
        if((s->start && s->stop) || s->restart)
                StringBuffer_append(res->outputbuffer,
                          "<td><form method=POST action=%s>"
                          "<input type=hidden value='restart' name=action>"
                          "<input type=submit value='Restart service'></form></td>", s->name);
        /* (un)monitor */
        StringBuffer_append(res->outputbuffer,
                  "<td><form method=POST action=%s>"
                  "<input type=hidden value='%s' name=action>"
                  "<input type=submit value='%s'></form></td></tr></table>",
                  s->name,
                  s->monitor ? "unmonitor" : "monitor",
                  s->monitor ? "Disable monitoring" : "Enable monitoring");
}


static void print_service_rules_port(HttpResponse res, Service_T s) {
        if (s->portlist) {
                for (Port_T p = s->portlist; p; p = p->next) {
                        if (p->family == AF_INET) {
                                StringBuffer_append(res->outputbuffer, "<tr><td>Port</td><td>");
                                if (p->retry > 1)
                                        Util_printRule(res->outputbuffer, p->action, "If failed [%s:%d%s [%s via %s] with timeout %d seconds and retry %d time(s)]", p->hostname, p->port, p->request ? p->request : "", p->protocol->name, Util_portTypeDescription(p), p->timeout, p->retry);
                                else
                                        Util_printRule(res->outputbuffer, p->action, "If failed [%s:%d%s [%s via %s] with timeout %d seconds]", p->hostname, p->port, p->request ? p->request : "", p->protocol->name, Util_portTypeDescription(p), p->timeout);
                                StringBuffer_append(res->outputbuffer, "</td></tr>");
                                if(p->SSL.certmd5 != NULL)
                                        StringBuffer_append(res->outputbuffer, "<tr><td>Server certificate md5 sum</td><td>%s</td></tr>", p->SSL.certmd5);
                        } else if (p->family == AF_UNIX) {
                                StringBuffer_append(res->outputbuffer, "<tr><td>Unix Socket</td><td>");
                                if (p->retry > 1)
                                        Util_printRule(res->outputbuffer, p->action, "If failed [%s [%s] with timeout %ds and retry %d time(s)]", p->pathname, p->protocol->name, p->timeout, p->retry);
                                else
                                        Util_printRule(res->outputbuffer, p->action, "If failed [%s [%s] with timeout %ds]", p->pathname, p->protocol->name, p->timeout);
                                StringBuffer_append(res->outputbuffer, "</td></tr>");
                        }
                }
        }
}


static void print_service_rules_icmp(HttpResponse res, Service_T s) {
        if (s->icmplist) {
                for (Icmp_T i = s->icmplist; i; i = i->next) {
                        StringBuffer_append(res->outputbuffer, "<tr><td>ICMP</td><td>");
                        Util_printRule(res->outputbuffer, i->action, "If failed [%s count %d with timeout %d seconds]", icmpnames[i->type], i->count, i->timeout);
                        StringBuffer_append(res->outputbuffer, "</td></tr>");
                }
        }
}


static void print_service_rules_perm(HttpResponse res, Service_T s) {
        if (s->perm) {
                StringBuffer_append(res->outputbuffer, "<tr><td>Permissions</td><td>");
                Util_printRule(res->outputbuffer, s->perm->action, "If failed %o", s->perm->perm);
                StringBuffer_append(res->outputbuffer, "</td></tr>");
        }
}


static void print_service_rules_uid(HttpResponse res, Service_T s) {
        if (s->uid) {
                StringBuffer_append(res->outputbuffer, "<tr><td>UID</td><td>");
                Util_printRule(res->outputbuffer, s->uid->action, "If failed %d", s->uid->uid);
                StringBuffer_append(res->outputbuffer, "</td></tr>");
        }
}


static void print_service_rules_euid(HttpResponse res, Service_T s) {
        if (s->euid) {
                StringBuffer_append(res->outputbuffer, "<tr><td>EUID</td><td>");
                Util_printRule(res->outputbuffer, s->euid->action, "If failed %d", s->euid->uid);
                StringBuffer_append(res->outputbuffer, "</td></tr>");
        }
}


static void print_service_rules_gid(HttpResponse res, Service_T s) {
        if (s->gid) {
                StringBuffer_append(res->outputbuffer, "<tr><td>GID</td><td>");
                Util_printRule(res->outputbuffer, s->gid->action, "If failed %d", s->gid->gid);
                StringBuffer_append(res->outputbuffer, "</td></tr>");
        }
}


static void print_service_rules_timestamp(HttpResponse res, Service_T s) {
        if (s->timestamplist) {
                for(Timestamp_T t = s->timestamplist; t; t = t->next) {
                        StringBuffer_append(res->outputbuffer, "<tr><td>Timestamp</td><td>");
                        if(t->test_changes)
                                Util_printRule(res->outputbuffer, t->action, "If changed");
                        else
                                Util_printRule(res->outputbuffer, t->action, "If %s %d second(s)", operatornames[t->operator], t->time);
                        StringBuffer_append(res->outputbuffer, "</td></tr>");
                }
        }
}


static void print_service_rules_filesystem(HttpResponse res, Service_T s) {
        if (s->type == TYPE_FILESYSTEM) {
                StringBuffer_append(res->outputbuffer, "<tr><td>Filesystem flags</td><td>");
                Util_printRule(res->outputbuffer, s->action_FSFLAG, "If changed");
                StringBuffer_append(res->outputbuffer, "</td></tr>");
        }
        if (s->filesystemlist) {
                for (Filesystem_T dl = s->filesystemlist; dl; dl = dl->next) {
                        if (dl->resource == RESOURCE_ID_INODE) {
                                StringBuffer_append(res->outputbuffer, "<tr><td>Inodes usage limit</td><td>");
                                if (dl->limit_absolute > -1)
                                        Util_printRule(res->outputbuffer, dl->action, "If %s %ld", operatornames[dl->operator], dl->limit_absolute);
                                else
                                        Util_printRule(res->outputbuffer, dl->action, "If %s %.1f%%", operatornames[dl->operator], dl->limit_percent / 10.);
                                StringBuffer_append(res->outputbuffer, "</td></tr>");
                        } else if (dl->resource == RESOURCE_ID_SPACE) {
                                StringBuffer_append(res->outputbuffer, "<tr><td>Space usage limit</td><td>");
                                if (dl->limit_absolute > -1)
                                        Util_printRule(res->outputbuffer, dl->action, "If %s %ld blocks", operatornames[dl->operator], dl->limit_absolute);
                                else
                                        Util_printRule(res->outputbuffer, dl->action, "If %s %.1f%%", operatornames[dl->operator], dl->limit_percent / 10.);
                                StringBuffer_append(res->outputbuffer, "</td></tr>");
                        }
                }
        }
}


static void print_service_rules_size(HttpResponse res, Service_T s) {
        if (s->sizelist) {
                for (Size_T sl = s->sizelist; sl; sl = sl->next) {
                        StringBuffer_append(res->outputbuffer, "<tr><td>Size</td><td>");
                        if(sl->test_changes)
                                Util_printRule(res->outputbuffer, sl->action, "If changed");
                        else
                                Util_printRule(res->outputbuffer, sl->action, "If %s %llu byte(s)", operatornames[sl->operator], sl->size);
                        StringBuffer_append(res->outputbuffer, "</td></tr>");
                }
        }
}


static void print_service_rules_uptime(HttpResponse res, Service_T s) {
        if (s->uptimelist) {
                for (Uptime_T ul = s->uptimelist; ul; ul = ul->next) {
                        StringBuffer_append(res->outputbuffer, "<tr><td>Uptime</td><td>");
                        Util_printRule(res->outputbuffer, ul->action, "If %s %llu second(s)", operatornames[ul->operator], ul->uptime);
                        StringBuffer_append(res->outputbuffer, "</td></tr>");
                }
        }
}

static void print_service_rules_match(HttpResponse res, Service_T s) {
        if (s->type != TYPE_PROCESS) {
                for (Match_T ml = s->matchignorelist; ml; ml = ml->next) {
                        StringBuffer_append(res->outputbuffer, "<tr><td>Ignore pattern</td><td>");
                        Util_printRule(res->outputbuffer, ml->action, "If %smatch \"%s\"", ml->not ? "not " : "", ml->match_string);
                        StringBuffer_append(res->outputbuffer, "</td></tr>");
                }
                for (Match_T ml = s->matchlist; ml; ml = ml->next) {
                        StringBuffer_append(res->outputbuffer, "<tr><td>Pattern</td><td>");
                        Util_printRule(res->outputbuffer, ml->action, "If %smatch \"%s\"", ml->not ? "not " : "", ml->match_string);
                        StringBuffer_append(res->outputbuffer, "</td></tr>");
                }
        }
}


static void print_service_rules_checksum(HttpResponse res, Service_T s) {
        if (s->checksum) {
                StringBuffer_append(res->outputbuffer, "<tr><td>Checksum</td><td>");
                if (s->checksum->test_changes)
                        Util_printRule(res->outputbuffer, s->checksum->action, "If changed %s", checksumnames[s->checksum->type]);
                else
                        Util_printRule(res->outputbuffer, s->checksum->action, "If failed %s(%s)", s->checksum->hash, checksumnames[s->checksum->type]);
                StringBuffer_append(res->outputbuffer, "</td></tr>");
        }
}


static void print_service_rules_process(HttpResponse res, Service_T s) {
        if (s->type == TYPE_PROCESS) {
                StringBuffer_append(res->outputbuffer, "<tr><td>PID</td><td>");
                Util_printRule(res->outputbuffer, s->action_PID, "If changed");
                StringBuffer_append(res->outputbuffer, "</td></tr>");
                StringBuffer_append(res->outputbuffer, "<tr><td>PPID</td><td>");
                Util_printRule(res->outputbuffer, s->action_PPID, "If changed");
                StringBuffer_append(res->outputbuffer, "</td></tr>");
        }
}


static void print_service_rules_program(HttpResponse res, Service_T s) {
        if (s->type == TYPE_PROGRAM) {
                StringBuffer_append(res->outputbuffer, "<tr><td>Program timeout</td><td>Terminate the program if not finished within %d seconds</td></tr>", s->program->timeout);
                for (Status_T status = s->statuslist; status; status = status->next) {
                        StringBuffer_append(res->outputbuffer, "<tr><td>Test Exit value</td><td>");
                        Util_printRule(res->outputbuffer, status->action, "If exit value %s %d", operatorshortnames[status->operator], status->return_value);
                        StringBuffer_append(res->outputbuffer, "</td></tr>");
                }
        }
}


static void print_service_rules_resource(HttpResponse res, Service_T s) {
        if (s->resourcelist) {
                for (Resource_T q = s->resourcelist; q; q = q->next) {
                        StringBuffer_append(res->outputbuffer, "<tr><td>");
                        switch (q->resource_id) {
                                case RESOURCE_ID_CPU_PERCENT:
                                        StringBuffer_append(res->outputbuffer, "CPU usage limit");
                                        break;

                                case RESOURCE_ID_TOTAL_CPU_PERCENT:
                                        StringBuffer_append(res->outputbuffer, "CPU usage limit (incl. children)");
                                        break;

                                case RESOURCE_ID_CPUUSER:
                                        StringBuffer_append(res->outputbuffer, "CPU user limit");
                                        break;

                                case RESOURCE_ID_CPUSYSTEM:
                                        StringBuffer_append(res->outputbuffer, "CPU system limit");
                                        break;

                                case RESOURCE_ID_CPUWAIT:
                                        StringBuffer_append(res->outputbuffer, "CPU wait limit");
                                        break;

                                case RESOURCE_ID_MEM_PERCENT:
                                        StringBuffer_append(res->outputbuffer, "Memory usage limit");
                                        break;

                                case RESOURCE_ID_MEM_KBYTE:
                                        StringBuffer_append(res->outputbuffer, "Memory amount limit");
                                        break;

                                case RESOURCE_ID_SWAP_PERCENT:
                                        StringBuffer_append(res->outputbuffer, "Swap usage limit");
                                        break;

                                case RESOURCE_ID_SWAP_KBYTE:
                                        StringBuffer_append(res->outputbuffer, "Swap amount limit");
                                        break;

                                case RESOURCE_ID_LOAD1:
                                        StringBuffer_append(res->outputbuffer, "Load average (1min)");
                                        break;

                                case RESOURCE_ID_LOAD5:
                                        StringBuffer_append(res->outputbuffer, "Load average (5min)");
                                        break;

                                case RESOURCE_ID_LOAD15:
                                        StringBuffer_append(res->outputbuffer, "Load average (15min)");
                                        break;

                                case RESOURCE_ID_CHILDREN:
                                        StringBuffer_append(res->outputbuffer, "Children");
                                        break;

                                case RESOURCE_ID_TOTAL_MEM_KBYTE:
                                        StringBuffer_append(res->outputbuffer, "Memory amount limit (incl. children)");
                                        break;

                                case RESOURCE_ID_TOTAL_MEM_PERCENT:
                                        StringBuffer_append(res->outputbuffer, "Memory usage limit (incl. children)");
                                        break;
                        }
                        StringBuffer_append(res->outputbuffer, "</td><td>");
                        switch (q->resource_id) {
                                case RESOURCE_ID_CPU_PERCENT:
                                case RESOURCE_ID_TOTAL_CPU_PERCENT:
                                case RESOURCE_ID_TOTAL_MEM_PERCENT:
                                case RESOURCE_ID_CPUUSER:
                                case RESOURCE_ID_CPUSYSTEM:
                                case RESOURCE_ID_CPUWAIT:
                                case RESOURCE_ID_MEM_PERCENT:
                                case RESOURCE_ID_SWAP_PERCENT:
                                        Util_printRule(res->outputbuffer, q->action, "If %s %.1f%%", operatornames[q->operator], q->limit / 10.);
                                        break;

                                case RESOURCE_ID_MEM_KBYTE:
                                case RESOURCE_ID_SWAP_KBYTE:
                                        Util_printRule(res->outputbuffer, q->action, "If %s %ldkB", operatornames[q->operator], q->limit);
                                        break;

                                case RESOURCE_ID_LOAD1:
                                case RESOURCE_ID_LOAD5:
                                case RESOURCE_ID_LOAD15:
                                        Util_printRule(res->outputbuffer, q->action, "If %s %.1f", operatornames[q->operator], q->limit / 10.);
                                        break;

                                case RESOURCE_ID_CHILDREN:
                                case RESOURCE_ID_TOTAL_MEM_KBYTE:
                                        Util_printRule(res->outputbuffer, q->action, "If %s %ld", operatornames[q->operator], q->limit);
                                        break;
                        }
                        StringBuffer_append(res->outputbuffer, "</td></tr>");
                }
        }
}


static void print_service_params_port(HttpResponse res, Service_T s) {

        if((s->type == TYPE_HOST ||
            s->type == TYPE_PROCESS) &&
           s-> portlist) {

                Port_T p;

                if(!Util_hasServiceStatus(s)) {

                        for(p = s->portlist; p; p = p->next)
                                if(p->family == AF_INET) {
                                        StringBuffer_append(res->outputbuffer, "<tr><td>Port Response time</td><td>-</td></tr>");
                                } else if(p->family == AF_UNIX) {
                                        StringBuffer_append(res->outputbuffer, "<tr><td>Unix Socket Response time</td><td>-</td></tr>");
                                }

                } else {

                        for(p = s->portlist; p; p = p->next) {
                                if(p->family == AF_INET) {
                                        if(!p->is_available) {
                                                StringBuffer_append(res->outputbuffer,
                                                          "<tr><td>Port Response time</td>"
                                                          "<td class='red-text'>connection failed to %s:%d%s [%s via %s]</td>"
                                                          "</tr>",
                                                          p->hostname, p->port, p->request?p->request:"",
                                                          p->protocol->name, Util_portTypeDescription(p));
                                        } else {
                                                StringBuffer_append(res->outputbuffer,
                                                          "<tr><td>Port Response time</td>"
                                                          "<td>%.3fs to %s:%d%s [%s via %s]</td></tr>",
                                                          p->response, p->hostname, p->port, p->request?p->request:"",
                                                          p->protocol->name, Util_portTypeDescription(p));
                                        }
                                } else if(p->family == AF_UNIX) {
                                        if(!p->is_available) {
                                                StringBuffer_append(res->outputbuffer,
                                                          "<tr><td>Unix Socket Response time</td>"
                                                          "<td class='red-text'>connection failed to %s [%s]</td>"
                                                          "</tr>",
                                                          p->pathname, p->protocol->name);
                                        } else {
                                                StringBuffer_append(res->outputbuffer,
                                                          "<tr><td>Unix Socket Response time</td>"
                                                          "<td>%.3fs to %s [%s]</td></tr>",
                                                          p->response, p->pathname, p->protocol->name);
                                        }
                                }
                        }
                }
        }
}


static void print_service_params_icmp(HttpResponse res, Service_T s) {

        if(s->type == TYPE_HOST && s->icmplist) {

                Icmp_T i;

                if(!Util_hasServiceStatus(s)) {

                        for(i = s->icmplist; i; i = i->next)
                                StringBuffer_append(res->outputbuffer, "<tr><td>ICMP Response time</td><td>-</td></tr>");

                } else {

                        for(i = s->icmplist; i; i = i->next) {
                                if(!i->is_available) {
                                        StringBuffer_append(res->outputbuffer, "<tr><td>ICMP Response time</td><td class='red-text'>connection failed [%s]</td></tr>", icmpnames[i->type]);
                                } else {
                                        StringBuffer_append(res->outputbuffer, "<tr><td>ICMP Response time</td><td>%.3fs [%s]</td></tr>", i->response, icmpnames[i->type]);
                                }
                        }
                }
        }
}


static void print_service_params_perm(HttpResponse res, Service_T s) {

        if(s->type == TYPE_FILE ||
           s->type == TYPE_FIFO ||
           s->type == TYPE_DIRECTORY ||
           s->type == TYPE_FILESYSTEM) {

                if(!Util_hasServiceStatus(s)) {

                        StringBuffer_append(res->outputbuffer, "<tr><td>Permission</td><td>-</td></tr>");

                } else {

                        StringBuffer_append(res->outputbuffer,
                                  "<tr><td>Permission</td><td class='%s'>%o</td></tr>",
                                  (s->error & Event_Permission)?"red-text":"",
                                  s->inf->st_mode & 07777);

                }
        }
}


static void print_service_params_uid(HttpResponse res, Service_T s) {

        if(s->type == TYPE_FILE ||
           s->type == TYPE_FIFO ||
           s->type == TYPE_DIRECTORY ||
           s->type == TYPE_FILESYSTEM) {

                if(!Util_hasServiceStatus(s)) {

                        StringBuffer_append(res->outputbuffer, "<tr><td>UID</td><td>-</td></tr>");

                } else {

                        StringBuffer_append(res->outputbuffer,
                                  "<tr><td>UID</td><td class='%s'>%d</td></tr>",
                                  (s->error & Event_Uid)?"red-text":"",
                                  (int)s->inf->st_uid);

                }
        }
}


static void print_service_params_gid(HttpResponse res, Service_T s) {

        if(s->type == TYPE_FILE ||
           s->type == TYPE_FIFO ||
           s->type == TYPE_DIRECTORY ||
           s->type == TYPE_FILESYSTEM) {

                if(!Util_hasServiceStatus(s)) {

                        StringBuffer_append(res->outputbuffer, "<tr><td>GID</td><td>-</td></tr>");

                } else {

                        StringBuffer_append(res->outputbuffer,
                                  "<tr><td>GID</td><td class='%s'>%d</td></tr>",
                                  (s->error & Event_Gid)?"red-text":"",
                                  (int)s->inf->st_gid);

                }
        }
}


static void print_service_params_timestamp(HttpResponse res, Service_T s) {

        if(s->type == TYPE_FILE ||
           s->type == TYPE_FIFO ||
           s->type == TYPE_DIRECTORY) {

                if(!Util_hasServiceStatus(s)) {

                        StringBuffer_append(res->outputbuffer, "<tr><td>Timestamp</td><td>-</td></tr>");

                } else {
                        char t[32];
                        StringBuffer_append(res->outputbuffer,
                                  "<tr><td>Timestamp</td><td class='%s'>%s</td></tr>",
                                  (s->error & Event_Timestamp)?"red-text":"", Time_string(s->inf->timestamp, t));
                }
        }
}


static void print_service_params_filesystem(HttpResponse res, Service_T s) {

        if(s->type == TYPE_FILESYSTEM) {

                if(!Util_hasServiceStatus(s)) {

                        StringBuffer_append(res->outputbuffer,
                                  "<tr><td>Filesystem flags</td><td>-</td></tr>");
                        StringBuffer_append(res->outputbuffer,
                                  "<tr><td>Blocks total</td><td>-</td></tr>");
                        StringBuffer_append(res->outputbuffer,
                                  "<tr><td>Blocks free for non superuser</td><td>-</td></tr>");
                        StringBuffer_append(res->outputbuffer,
                                  "<tr><td>Blocks free total</td><td>-</td></tr>");
                        StringBuffer_append(res->outputbuffer,
                                  "<tr><td>Block size</td><td>-</td></tr>");
                        StringBuffer_append(res->outputbuffer,
                                  "<tr><td>Inodes total</td><td>-</td></tr>");
                        StringBuffer_append(res->outputbuffer,
                                  "<tr><td>Inodes free</td><td>-</td></tr>");

                } else {

                        StringBuffer_append(res->outputbuffer,
                                  "<tr><td>Filesystem flags</td><td>0x%x</td></tr>",
                                  s->inf->priv.filesystem.flags);
                        StringBuffer_append(res->outputbuffer,
                                  "<tr><td>Blocks total</td><td>%ld [%.1f MB]</td></tr>",
                                  s->inf->priv.filesystem.f_blocks,
                                  s->inf->priv.filesystem.f_bsize > 0 ? ((float) s->inf->priv.filesystem.f_blocks/1048576*s->inf->priv.filesystem.f_bsize) : 0);
                        StringBuffer_append(res->outputbuffer,
                                  "<tr><td>Blocks free for non superuser</td>"
                                  "<td>%ld [%.1f MB] [%.1f%%]</td></tr>",
                                  s->inf->priv.filesystem.f_blocksfree,
                                  s->inf->priv.filesystem.f_bsize > 0 ? ((float)s->inf->priv.filesystem.f_blocksfree / (float)1048576 * (float)s->inf->priv.filesystem.f_bsize) : 0,
                                  s->inf->priv.filesystem.f_blocks > 0 ? ((float)100 * (float)s->inf->priv.filesystem.f_blocksfree / (float)s->inf->priv.filesystem.f_blocks) : 0);
                        StringBuffer_append(res->outputbuffer,
                                  "<tr><td>Blocks free total</td>"
                                  "<td class='%s'>%ld [%.1f MB] [%.1f%%]</td></tr>",
                                  (s->error & Event_Resource)?"red-text":"",
                                  s->inf->priv.filesystem.f_blocksfreetotal,
                                  s->inf->priv.filesystem.f_bsize > 0 ? ((float)s->inf->priv.filesystem.f_blocksfreetotal / (float)1048576 * (float)s->inf->priv.filesystem.f_bsize) : 0,
                                  s->inf->priv.filesystem.f_blocks > 0 ? ((float)100 * (float)s->inf->priv.filesystem.f_blocksfreetotal / (float)s->inf->priv.filesystem.f_blocks) : 0);
                        StringBuffer_append(res->outputbuffer,
                                  "<tr><td>Block size</td><td>%ld B</td></tr>", s->inf->priv.filesystem.f_bsize);

                        if(s->inf->priv.filesystem.f_files > 0) {

                                StringBuffer_append(res->outputbuffer,
                                          "<tr><td>Inodes total</td><td>%ld</td></tr>", s->inf->priv.filesystem.f_files);
                                StringBuffer_append(res->outputbuffer,
                                          "<tr><td>Inodes free</td><td class='%s'>%ld [%.1f%%]</td></tr>",
                                          (s->error & Event_Resource)?"red-text":"",
                                          s->inf->priv.filesystem.f_filesfree,
                                          (float)100 * (float)s->inf->priv.filesystem.f_filesfree / (float)s->inf->priv.filesystem.f_files);

                        }
                }
        }
}


static void print_service_params_size(HttpResponse res, Service_T s) {

        if(s->type == TYPE_FILE) {

                if(!Util_hasServiceStatus(s)) {

                        StringBuffer_append(res->outputbuffer,
                                  "<tr><td>Size</td><td>-</td></tr>");

                } else {

                        StringBuffer_append(res->outputbuffer,
                                  "<tr><td>Size</td><td class='%s'>%llu B</td></tr>",
                                  (s->error & Event_Size)?"red-text":"",
                                  (unsigned long long) s->inf->priv.file.st_size);

                }
        }
}

static void print_service_params_match(HttpResponse res, Service_T s) {

        if(s->type == TYPE_FILE) {

                if(!Util_hasServiceStatus(s)) {

                        StringBuffer_append(res->outputbuffer,
                                  "<tr><td>Match regex</td><td>-</td></tr>");

                } else {

                        StringBuffer_append(res->outputbuffer,
                                  "<tr><td>Match regex</td><td class='%s'>%s</td></tr>",
                                  (s->error & Event_Content)?"red-text":"",
                                  (s->error & Event_Content)?"yes":"no");
                }
        }
}


static void print_service_params_checksum(HttpResponse res, Service_T s) {

        if(s->type == TYPE_FILE && s->checksum) {

                if(!Util_hasServiceStatus(s)) {

                        StringBuffer_append(res->outputbuffer, "<tr><td>Checksum</td><td>-</td></tr>");

                } else {

                        StringBuffer_append(res->outputbuffer,
                                  "<tr><td>Checksum</td><td class='%s'>%s(%s)</td></tr>",
                                  (s->error & Event_Checksum)?"red-text":"", s->inf->priv.file.cs_sum,
                                  checksumnames[s->checksum->type]);

                }
        }
}


static void print_service_params_process(HttpResponse res, Service_T s) {

        if(s->type == TYPE_PROCESS) {

                if(!Util_hasServiceStatus(s)) {

                        StringBuffer_append(res->outputbuffer,
                                  "<tr><td>Process id </td><td>-</td></tr>"
                                  "<tr><td>Parent process id </td><td>-</td></tr>"
                                  "<tr><td>Process uptime</td><td>-</td></tr>");

                } else {

                        char *uptime;

                        StringBuffer_append(res->outputbuffer,
                                  "<tr><td>Process id </td><td>%d</td></tr>",
                                  s->inf->priv.process.pid > 0 ? s->inf->priv.process.pid : 0);
                        StringBuffer_append(res->outputbuffer,
                                  "<tr><td>Parent process id </td><td>%d</td></tr>",
                                  s->inf->priv.process.ppid > 0 ? s->inf->priv.process.ppid : 0);
                        StringBuffer_append(res->outputbuffer,
                                  "<tr><td>UID</td><td>%d</td></tr>",
                                  s->inf->priv.process.uid);
                        StringBuffer_append(res->outputbuffer,
                                  "<tr><td>Effective UID</td><td>%d</td></tr>",
                                  s->inf->priv.process.euid);
                        StringBuffer_append(res->outputbuffer,
                                  "<tr><td>GID</td><td>%d</td></tr>",
                                  s->inf->priv.process.gid);

                        uptime = Util_getUptime(s->inf->priv.process.uptime, "&nbsp;");
                        StringBuffer_append(res->outputbuffer,
                                  "<tr><td>Process uptime</td><td>%s</td></tr>",
                                  uptime);
                        FREE(uptime);
                }
        }
}


static void print_service_params_resource(HttpResponse res, Service_T s) {

        if(Run.doprocess && (s->type == TYPE_PROCESS || s->type == TYPE_SYSTEM) ) {

                if(!Util_hasServiceStatus(s)) {
                        if(s->type == TYPE_PROCESS) {
                                StringBuffer_append(res->outputbuffer,
                                          "<tr><td>CPU usage</td><td>-</td></tr>"
                                          "<tr><td>Memory usage</td><td>-</td></tr>"
                                          "<tr><td>Children</td><td>-</td></tr>"
                                          "<tr><td>Total CPU usage (incl. children)</td><td>-</td></tr>"
                                          "<tr><td>Total memory usage (incl. children)</td><td>-</td></tr>");
                        } else if(s->type == TYPE_SYSTEM) {
                                StringBuffer_append(res->outputbuffer,
                                          "<tr><td>Load average</td><td>-</td></tr>"
                                          "<tr><td>CPU usage</td><td>-</td></tr>"
                                          "<tr><td>Memory usage</td><td>-</td></tr>");
                        }
                } else {

                        if(s->type == TYPE_PROCESS) {
                                StringBuffer_append(res->outputbuffer,
                                          "<tr><td>Children</td><td class='%s'>%d</td></tr>",
                                          (s->error & Event_Resource)?"red-text":"",
                                          s->inf->priv.process.children);
                                StringBuffer_append(res->outputbuffer,
                                          "<tr><td>CPU usage</td><td class='%s'>%.1f%%  &nbsp;&nbsp;(Usage / Number of CPUs)</td></tr>",
                                          (s->error & Event_Resource)?"red-text":"",
                                          s->inf->priv.process.cpu_percent/10.0);
                                StringBuffer_append(res->outputbuffer,
                                          "<tr><td>Total CPU usage (incl. children)</td><td class='%s'>%.1f%%</td></tr>",
                                          (s->error & Event_Resource)?"red-text":"",
                                          s->inf->priv.process.total_cpu_percent/10.0);
                                StringBuffer_append(res->outputbuffer,
                                          "<tr><td>Memory usage</td><td class='%s'>%.1f%% [%ldkB]</td></tr>",
                                          (s->error & Event_Resource)?"red-text":"",
                                          s->inf->priv.process.mem_percent/10.0, s->inf->priv.process.mem_kbyte);
                                StringBuffer_append(res->outputbuffer,
                                          "<tr><td>Total memory usage (incl. children)</td><td class='%s'>%.1f%% [%ldkB]</td></tr>",
                                          (s->error & Event_Resource)?"red-text":"",
                                          s->inf->priv.process.total_mem_percent/10.0, s->inf->priv.process.total_mem_kbyte);
                        } else if(s->type == TYPE_SYSTEM) {
                                StringBuffer_append(res->outputbuffer,
                                          "<tr><td>Load average</td><td class='%s'>[%.2f] [%.2f] [%.2f]</td></tr>",
                                          (s->error & Event_Resource)?"red-text":"",
                                          systeminfo.loadavg[0],
                                          systeminfo.loadavg[1],
                                          systeminfo.loadavg[2]);
                                StringBuffer_append(res->outputbuffer,
                                          "<tr><td>CPU usage</td><td class='%s'>%.1f%%us %.1f%%sy"
#ifdef HAVE_CPU_WAIT
                                          " %.1f%%wa"
#endif
                                          "%s",
                                          (s->error & Event_Resource)?"red-text":"",
                                          systeminfo.total_cpu_user_percent > 0 ? systeminfo.total_cpu_user_percent/10. : 0,
                                          systeminfo.total_cpu_syst_percent > 0 ? systeminfo.total_cpu_syst_percent/10. : 0,
#ifdef HAVE_CPU_WAIT
                                          systeminfo.total_cpu_wait_percent > 0 ? systeminfo.total_cpu_wait_percent/10. : 0,
#endif
                                          "</td></tr>");
                                StringBuffer_append(res->outputbuffer,
                                          "<tr><td>Memory usage</td><td class='%s'>%ld kB [%.1f%%]</td></tr>",
                                          (s->error & Event_Resource)?"red-text":"",
                                          systeminfo.total_mem_kbyte,
                                          systeminfo.total_mem_percent/10.);
                                StringBuffer_append(res->outputbuffer,
                                          "<tr><td>Swap usage</td><td class='%s'>%ld kB [%.1f%%]</td></tr>",
                                          (s->error & Event_Resource)?"red-text":"",
                                          systeminfo.total_swap_kbyte,
                                          systeminfo.total_swap_percent/10.);
                        }
                }
        }
}


static void print_service_params_program(HttpResponse res, Service_T s) {

        if(s->type == TYPE_PROGRAM) {

                if(!Util_hasServiceStatus(s)) {

                        StringBuffer_append(res->outputbuffer,
                                  "<tr><td>Last started</td><td>-</td></tr>"
                                  "<tr><td>Last Exit value</td><td>-</td></tr>");

                } else {
                        if (s->program->started) {
                                char t[32];
                                StringBuffer_append(res->outputbuffer, "<tr><td>Last started</td><td>%s</td></tr>", Time_string(s->program->started, t));
                                StringBuffer_append(res->outputbuffer, "<tr><td>Last Exit value</td><td>%d</td></tr>", s->program->exitStatus);
                        } else {
                                StringBuffer_append(res->outputbuffer, "<tr><td>Last started</td><td>Not yet started</td></tr>");
                                StringBuffer_append(res->outputbuffer, "<tr><td>Last Exit value</td><td>N/A</td></tr>");
                        }
                }
        }
}


static int is_readonly(HttpRequest req) {

        if(req->remote_user) {
                Auth_T user_creds = Util_getUserCredentials(req->remote_user);
                return ( user_creds?user_creds->is_readonly:TRUE );
        }

        return FALSE;

}


/* ----------------------------------------------------------- Status output */


/* Print status in the given format. Text status is default. */
static void print_status(HttpRequest req, HttpResponse res, int version)
{
        Service_T s;
        short level = LEVEL_FULL;
        const char *stringFormat = get_parameter(req, "format");
        const char *stringLevel = get_parameter(req, "level");

        if(stringLevel && Str_startsWith(stringLevel, LEVEL_NAME_SUMMARY))
        {
                level = LEVEL_SUMMARY;
        }

        if(stringFormat && Str_startsWith(stringFormat, "xml"))
        {
                StringBuffer_T sb = StringBuffer_create(256);
                status_xml(sb, NULL, level, version, socket_get_local_host(req->S));
                StringBuffer_append(res->outputbuffer, "%s", StringBuffer_toString(sb));
                StringBuffer_free(&sb);
                set_content_type(res, "text/xml");
        }
        else
        {
                char *uptime = Util_getUptime(Util_getProcessUptime(Run.pidfile), " ");
                StringBuffer_append(res->outputbuffer, "The Monit daemon %s uptime: %s\n\n", VERSION, uptime);
                FREE(uptime);

                for(s = servicelist_conf; s; s = s->next_conf)
                {
                        status_service_txt(s, res, level);
                }
                set_content_type(res, "text/plain");
        }
}


static void status_service_txt(Service_T s, HttpResponse res, short level) {
        char buf[STRLEN];
        if(level == LEVEL_SUMMARY)
        {
                char prefix[STRLEN];
                snprintf(prefix, STRLEN, "%s '%s'", servicetypes[s->type], s->name);
                StringBuffer_append(res->outputbuffer, "%-35s %s\n", prefix, get_service_status(s, buf, sizeof(buf)));
        }
        else
        {
                StringBuffer_append(res->outputbuffer,
                          "%s '%s'\n"
                          "  %-33s %s\n",
                          servicetypes[s->type], s->name,
                          "status", get_service_status(s, buf, sizeof(buf)));
                StringBuffer_append(res->outputbuffer,
                          "  %-33s %s\n",
                          "monitoring status", get_monitoring_status(s, buf, sizeof(buf)));

                if(Util_hasServiceStatus(s)) {
                        if(s->type == TYPE_FILE ||
                           s->type == TYPE_FIFO ||
                           s->type == TYPE_DIRECTORY ||
                           s->type == TYPE_FILESYSTEM) {
                                StringBuffer_append(res->outputbuffer,
                                          "  %-33s %o\n"
                                          "  %-33s %d\n"
                                          "  %-33s %d\n",
                                          "permission", s->inf->st_mode & 07777,
                                          "uid", (int)s->inf->st_uid,
                                          "gid", (int)s->inf->st_gid);
                        }
                        if(s->type == TYPE_FILE ||
                           s->type == TYPE_FIFO ||
                           s->type == TYPE_DIRECTORY) {
                                StringBuffer_append(res->outputbuffer,
                                          "  %-33s %s\n",
                                          "timestamp", Time_string(s->inf->timestamp, buf));
                        }
                        if(s->type == TYPE_FILE) {
                                StringBuffer_append(res->outputbuffer,
                                          "  %-33s %llu B\n",
                                          "size", (unsigned long long) s->inf->priv.file.st_size);
                                if(s->checksum) {
                                        StringBuffer_append(res->outputbuffer,
                                                  "  %-33s %s (%s)\n",
                                                  "checksum", s->inf->priv.file.cs_sum,
                                                  checksumnames[s->checksum->type]);
                                }
                        }
                        if(s->type == TYPE_FILESYSTEM) {
                                StringBuffer_append(res->outputbuffer,
                                          "  %-33s 0x%x\n"
                                          "  %-33s %ld B\n"
                                          "  %-33s %ld [%.1f MB]\n"
                                          "  %-33s %ld [%.1f MB] [%.1f%%]\n"
                                          "  %-33s %ld [%.1f MB] [%.1f%%]\n",
                                          "filesystem flags",
                                          s->inf->priv.filesystem.flags,
                                          "block size",
                                          s->inf->priv.filesystem.f_bsize,
                                          "blocks total",
                                          s->inf->priv.filesystem.f_blocks,
                                          s->inf->priv.filesystem.f_bsize > 0 ? ((float)s->inf->priv.filesystem.f_blocks / (float)1048576* (float)s->inf->priv.filesystem.f_bsize) : 0,
                                          "blocks free for non superuser",
                                          s->inf->priv.filesystem.f_blocksfree,
                                          s->inf->priv.filesystem.f_bsize > 0 ? ((float)s->inf->priv.filesystem.f_blocksfree / (float)1048576* (float)s->inf->priv.filesystem.f_bsize) : 0,
                                          s->inf->priv.filesystem.f_blocks > 0 ? ((float)100 * (float)s->inf->priv.filesystem.f_blocksfree / (float)s->inf->priv.filesystem.f_blocks) : 0,
                                          "blocks free total",
                                          s->inf->priv.filesystem.f_blocksfreetotal,
                                          s->inf->priv.filesystem.f_bsize > 0 ? ((float)s->inf->priv.filesystem.f_blocksfreetotal/(float)1048576* (float)s->inf->priv.filesystem.f_bsize) : 0,
                                          s->inf->priv.filesystem.f_blocks > 0 ? ((float)100 * (float)s->inf->priv.filesystem.f_blocksfreetotal / (float)s->inf->priv.filesystem.f_blocks) : 0);
                                if(s->inf->priv.filesystem.f_files > 0) {
                                        StringBuffer_append(res->outputbuffer,
                                                  "  %-33s %ld\n"
                                                  "  %-33s %ld [%.1f%%]\n",
                                                  "inodes total",
                                                  s->inf->priv.filesystem.f_files,
                                                  "inodes free",
                                                  s->inf->priv.filesystem.f_filesfree,
                                                  ((float)100*(float)s->inf->priv.filesystem.f_filesfree/ (float)s->inf->priv.filesystem.f_files));
                                }
                        }
                        if(s->type == TYPE_PROCESS) {
                                char *uptime = Util_getUptime(s->inf->priv.process.uptime, " ");
                                StringBuffer_append(res->outputbuffer,
                                          "  %-33s %d\n"
                                          "  %-33s %d\n"
                                          "  %-33s %d\n"
                                          "  %-33s %d\n"
                                          "  %-33s %d\n"
                                          "  %-33s %s\n",
                                          "pid", s->inf->priv.process.pid > 0 ? s->inf->priv.process.pid : 0,
                                          "parent pid", s->inf->priv.process.ppid > 0 ? s->inf->priv.process.ppid : 0,
                                          "uid", s->inf->priv.process.uid,
                                          "effective uid", s->inf->priv.process.euid,
                                          "gid", s->inf->priv.process.gid,
                                          "uptime", uptime);
                                FREE(uptime);
                                if(Run.doprocess)        {
                                        StringBuffer_append(res->outputbuffer,
                                                  "  %-33s %d\n"
                                                  "  %-33s %ld\n"
                                                  "  %-33s %ld\n"
                                                  "  %-33s %.1f%%\n"
                                                  "  %-33s %.1f%%\n"
                                                  "  %-33s %.1f%%\n"
                                                  "  %-33s %.1f%%\n",
                                                  "children", s->inf->priv.process.children,
                                                  "memory kilobytes", s->inf->priv.process.mem_kbyte,
                                                  "memory kilobytes total", s->inf->priv.process.total_mem_kbyte,
                                                  "memory percent", s->inf->priv.process.mem_percent/10.0,
                                                  "memory percent total", s->inf->priv.process.total_mem_percent/10.0,
                                                  "cpu percent", s->inf->priv.process.cpu_percent/10.0,
                                                  "cpu percent total", s->inf->priv.process.total_cpu_percent/10.0);
                                }
                        }
                        if(s->type == TYPE_HOST && s->icmplist) {
                                Icmp_T i;
                                for(i = s->icmplist; i; i = i->next) {
                                        StringBuffer_append(res->outputbuffer,
                                                  "  %-33s %.3fs [%s]\n",
                                                  "icmp response time", i->is_available ? i->response : 0.,
                                                  icmpnames[i->type]);
                                }
                        }
                        if((s->type == TYPE_HOST || s->type == TYPE_PROCESS) && s-> portlist) {
                                Port_T p;
                                for(p = s->portlist; p; p = p->next) {
                                        if(p->family == AF_INET) {
                                                StringBuffer_append(res->outputbuffer,
                                                          "  %-33s %.3fs to %s:%d%s [%s via %s]\n",
                                                          "port response time", p->is_available ? p->response : 0.,
                                                          p->hostname,
                                                          p->port, p->request?p->request:"", p->protocol->name,
                                                          Util_portTypeDescription(p));
                                        } else if(p->family == AF_UNIX) {
                                                StringBuffer_append(res->outputbuffer,
                                                          "  %-33s %.3fs to %s [%s]\n",
                                                          "unix socket response time", p->is_available ? p->response : 0.,
                                                          p->pathname, p->protocol->name);
                                        }
                                }
                        }
                        if(s->type == TYPE_SYSTEM && Run.doprocess) {
                                StringBuffer_append(res->outputbuffer,
                                          "  %-33s [%.2f] [%.2f] [%.2f]\n"
                                          "  %-33s %.1f%%us %.1f%%sy"
#ifdef HAVE_CPU_WAIT
                                          " %.1f%%wa"
#endif
                                          "\n"
                                          "  %-33s %ld kB [%.1f%%]\n"
                                          "  %-33s %ld kB [%.1f%%]\n",
                                          "load average",
                                          systeminfo.loadavg[0],
                                          systeminfo.loadavg[1],
                                          systeminfo.loadavg[2],
                                          "cpu",
                                          systeminfo.total_cpu_user_percent > 0 ? systeminfo.total_cpu_user_percent/10. : 0,
                                          systeminfo.total_cpu_syst_percent > 0 ? systeminfo.total_cpu_syst_percent/10. : 0,
#ifdef HAVE_CPU_WAIT
                                          systeminfo.total_cpu_wait_percent > 0 ? systeminfo.total_cpu_wait_percent/10. : 0,
#endif
                                          "memory usage",
                                          systeminfo.total_mem_kbyte,
                                          systeminfo.total_mem_percent/10.,
                                          "swap usage",
                                          systeminfo.total_swap_kbyte,
                                          systeminfo.total_swap_percent/10.);
                        }
                        if(s->type == TYPE_PROGRAM) {
                                if (s->program->started) {
                                        char t[32];
                                        StringBuffer_append(res->outputbuffer,
                                                  "  %-33s %s\n"
                                                  "  %-33s %d\n",
                                                  "last started", Time_string(s->program->started, t),
                                                  "last exit value", s->program->exitStatus);
                                } else
                                        StringBuffer_append(res->outputbuffer,
                                                  "  %-33s\n",
                                                  "not yet started");
                        }
                }
                StringBuffer_append(res->outputbuffer, "  %-33s %s\n\n", "data collected", Time_string(s->collected.tv_sec, buf));
        }
}


static char *get_monitoring_status(Service_T s, char *buf, int buflen) {
        ASSERT(s);
        ASSERT(buf);
        if (s->monitor == MONITOR_NOT)
                snprintf(buf, buflen, "Not monitored");
        else if (s->monitor & MONITOR_WAITING)
                snprintf(buf, buflen, "Waiting");
        else if (s->monitor & MONITOR_INIT)
                snprintf(buf, buflen, "Initializing");
        else if (s->monitor & MONITOR_YES)
                snprintf(buf, buflen, "Monitored");
        return buf;
}


static char *get_service_status(Service_T s, char *buf, int buflen) {
        EventTable_T *et = Event_Table;
        ASSERT(s);
        ASSERT(buf);
        if(s->monitor == MONITOR_NOT || s->monitor & MONITOR_INIT || s->monitor & MONITOR_WAITING) {
                get_monitoring_status(s, buf, buflen);
        } else if (s->error == 0) {
                snprintf(buf, buflen, "%s", statusnames[s->type]);
        } else {
                // In the case that the service has actualy some failure, error will be non zero. We will check the bitmap and print the description of the first error found
                while((*et).id) {
                        if(s->error & (*et).id) {
                                snprintf(buf, buflen, "%s", (s->error_hint & (*et).id) ? (*et).description_changed : (*et).description_failed);
                                break;
                        }
                        et++;
                }
        }
        if(s->doaction)
                snprintf(buf + strlen(buf), buflen - strlen(buf), " - %s pending", actionnames[s->doaction]);

        return buf;
}


static char *get_service_status_html(Service_T s, char *buf, int buflen) {
        ASSERT(s);
        ASSERT(buf);
        snprintf(buf, buflen, "<span class='%s-text'>", (s->monitor == MONITOR_NOT || s->monitor & MONITOR_INIT || s->monitor & MONITOR_WAITING) ? "gray" : ((! s->error) ? "green" : "red"));
        get_service_status(s, buf + strlen(buf), buflen - (int)strlen(buf));
        snprintf(buf + strlen(buf), buflen - strlen(buf), "</span>");
        return buf;
}

