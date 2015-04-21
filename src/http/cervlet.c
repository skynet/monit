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

#define ACTION(c) ! strncasecmp(req->url, c, sizeof(c))

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
static boolean_t is_readonly(HttpRequest);
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
static void do_home_net(HttpRequest, HttpResponse);
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
static void print_service_rules_timeout(HttpResponse, Service_T);
static void print_service_rules_existence(HttpResponse, Service_T);
static void print_service_rules_port(HttpResponse, Service_T);
static void print_service_rules_socket(HttpResponse, Service_T);
static void print_service_rules_icmp(HttpResponse, Service_T);
static void print_service_rules_perm(HttpResponse, Service_T);
static void print_service_rules_uid(HttpResponse, Service_T);
static void print_service_rules_euid(HttpResponse, Service_T);
static void print_service_rules_gid(HttpResponse, Service_T);
static void print_service_rules_timestamp(HttpResponse, Service_T);
static void print_service_rules_fsflags(HttpResponse, Service_T);
static void print_service_rules_filesystem(HttpResponse, Service_T);
static void print_service_rules_size(HttpResponse, Service_T);
static void print_service_rules_linkstatus(HttpResponse, Service_T);
static void print_service_rules_linkspeed(HttpResponse, Service_T);
static void print_service_rules_linksaturation(HttpResponse, Service_T);
static void print_service_rules_uploadbytes(HttpResponse, Service_T);
static void print_service_rules_uploadpackets(HttpResponse, Service_T);
static void print_service_rules_downloadbytes(HttpResponse, Service_T);
static void print_service_rules_downloadpackets(HttpResponse, Service_T);
static void print_service_rules_uptime(HttpResponse, Service_T);
static void print_service_rules_match(HttpResponse, Service_T);
static void print_service_rules_checksum(HttpResponse, Service_T);
static void print_service_rules_pid(HttpResponse, Service_T);
static void print_service_rules_ppid(HttpResponse, Service_T);
static void print_service_rules_program(HttpResponse, Service_T);
static void print_service_rules_resource(HttpResponse, Service_T);
static void print_service_status_port(HttpResponse, Service_T);
static void print_service_status_socket(HttpResponse, Service_T);
static void print_service_status_icmp(HttpResponse, Service_T);
static void print_service_status_perm(HttpResponse, Service_T, mode_t);
static void print_service_status_uid(HttpResponse, Service_T, uid_t);
static void print_service_status_gid(HttpResponse, Service_T, gid_t);
static void print_service_status_timestamp(HttpResponse, Service_T, time_t);
static void print_service_status_filesystem_flags(HttpResponse, Service_T);
static void print_service_status_filesystem_blockstotal(HttpResponse, Service_T);
static void print_service_status_filesystem_blocksfree(HttpResponse, Service_T);
static void print_service_status_filesystem_blocksfreetotal(HttpResponse, Service_T);
static void print_service_status_filesystem_blocksize(HttpResponse, Service_T);
static void print_service_status_filesystem_inodestotal(HttpResponse, Service_T);
static void print_service_status_filesystem_inodesfree(HttpResponse, Service_T);
static void print_service_status_file_size(HttpResponse, Service_T);
static void print_service_status_file_match(HttpResponse, Service_T);
static void print_service_status_file_checksum(HttpResponse, Service_T);
static void print_service_status_process_pid(HttpResponse, Service_T);
static void print_service_status_process_ppid(HttpResponse, Service_T);
static void print_service_status_process_euid(HttpResponse, Service_T);
static void print_service_status_process_uptime(HttpResponse, Service_T);
static void print_service_status_process_children(HttpResponse, Service_T);
static void print_service_status_process_cpu(HttpResponse, Service_T);
static void print_service_status_process_cputotal(HttpResponse, Service_T);
static void print_service_status_process_memory(HttpResponse, Service_T);
static void print_service_status_process_memorytotal(HttpResponse, Service_T);
static void print_service_status_system_loadavg(HttpResponse, Service_T);
static void print_service_status_system_cpu(HttpResponse, Service_T);
static void print_service_status_system_memory(HttpResponse, Service_T);
static void print_service_status_system_swap(HttpResponse, Service_T);
static void print_service_status_program_started(HttpResponse, Service_T);
static void print_service_status_program_status(HttpResponse, Service_T);
static void print_service_status_program_output(HttpResponse, Service_T);
static void print_service_status_link(HttpResponse, Service_T);
static void print_service_status_download(HttpResponse, Service_T);
static void print_service_status_upload(HttpResponse, Service_T);
static void print_status(HttpRequest, HttpResponse, int);
static void status_service_txt(Service_T, HttpResponse, Level_Type);
static char *get_monitoring_status(Service_T s, char *, int);
static char *get_service_status(Service_T, char *, int);


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


static void _printServiceStatus(StringBuffer_T sb, Service_T s) {
        ASSERT(sb);
        ASSERT(s);
        StringBuffer_append(sb, "<span class='%s-text'>", (s->monitor == Monitor_Not || s->monitor & Monitor_Init) ? "gray" : ((! s->error) ? "green" : "red"));
        char buf[STRLEN];
        get_service_status(s, buf, sizeof(buf));
        escapeHTML(sb, buf);
        StringBuffer_append(sb, "</span>");
}


/**
 * Called by the Processor (via the service method)
 * to handle a POST request.
 */
static void doPost(HttpRequest req, HttpResponse res) {
        set_content_type(res, "text/html");
        if (ACTION(RUN))
                handle_run(req, res);
        else if (ACTION(DOACTION))
                handle_do_action(req, res);
        else
                handle_action(req, res);
}


/**
 * Called by the Processor (via the service method)
 * to handle a GET request.
 */
static void doGet(HttpRequest req, HttpResponse res) {
        set_content_type(res, "text/html");
        if (ACTION(HOME)) {
                LOCK(Run.mutex)
                do_home(req, res);
                END_LOCK;
        } else if (ACTION(RUN)) {
                handle_run(req, res);
        } else if (ACTION(TEST)) {
                is_monit_running(req, res);
        } else if (ACTION(VIEWLOG)) {
                do_viewlog(req, res);
        } else if (ACTION(ABOUT)) {
                do_about(req, res);
        } else if (ACTION(FAVICON)) {
                printFavicon(res);
        } else if (ACTION(PING)) {
                do_ping(req, res);
        } else if (ACTION(GETID)) {
                do_getid(req, res);
        } else if (ACTION(STATUS)) {
                print_status(req, res, 1);
        } else if (ACTION(STATUS2)) {
                print_status(req, res, 2);
        } else if (ACTION(DOACTION)) {
                handle_do_action(req, res);
        } else {
                handle_action(req, res);
        }
}


/* ----------------------------------------------------------------- Helpers */


static void is_monit_running(HttpRequest req, HttpResponse res) {
        set_status(res, exist_daemon() ? SC_OK : SC_GONE);
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
                res->is_committed = true;
                Socket_print(S, "HTTP/1.0 200 OK\r\n");
                Socket_print(S, "Content-length: %lu\r\n", (unsigned long)l);
                Socket_print(S, "Content-Type: image/x-icon\r\n");
                Socket_print(S, "Connection: close\r\n\r\n");
                Socket_write(S, favicon, l);
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
                            " .rule {background:#ddd} "\
                            " .red-text {color:#ff0000;} "\
                            " .green-text {color:#00ff00;} "\
                            " .gray-text {color:#999999;} "\
                            " .blue-text {color:#0000ff;} "\
                            " .orange-text {color:#ff8800;} "\
                            " .short {overflow: hidden; text-overflow: ellipsis; white-space: nowrap; max-width: 350px;}"\
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
                            "Copyright &copy; 2001-2015 <a href=\"http://tildeslash.com/\">Tildeslash</a>. All rights reserved. "
                            "<span style='margin-left:5px;'></span>"
                            "<a href=\"http://mmonit.com/monit/\">Monit web site</a> | "
                            "<a href=\"http://mmonit.com/wiki/\">Monit Wiki</a> | "
                            "<a href=\"http://mmonit.com/\">M/Monit</a>"
                            "</div></body></html>");
}


static void do_home(HttpRequest req, HttpResponse res) {
        char *uptime = Util_getUptime(getProcessUptime(getpid(), ptree, ptreesize), "&nbsp;");

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
        do_home_net(req, res);
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
                            "<li style='padding-bottom:10px;'>Copyright &copy; 2001-2015 <a "
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
        if (Run.logfile)
                StringBuffer_append(res->outputbuffer,
                                    "<tr><td>Logfile</td><td>%s</td></tr>", Run.logfile);
        StringBuffer_append(res->outputbuffer,
                            "<tr><td>Pidfile</td><td>%s</td></tr>", Run.pidfile);
        StringBuffer_append(res->outputbuffer,
                            "<tr><td>State file</td><td>%s</td></tr>", Run.statefile);
        StringBuffer_append(res->outputbuffer,
                            "<tr><td>Debug</td><td>%s</td></tr>",
                            Run.debug ? "True" : "False");
        StringBuffer_append(res->outputbuffer,
                            "<tr><td>Log</td><td>%s</td></tr>", Run.dolog ? "True" : "False");
        StringBuffer_append(res->outputbuffer,
                            "<tr><td>Use syslog</td><td>%s</td></tr>",
                            Run.use_syslog ? "True" : "False");
        if (Run.eventlist_dir) {
                char slots[STRLEN];
                if (Run.eventlist_slots < 0)
                        snprintf(slots, STRLEN, "unlimited");
                else
                        snprintf(slots, STRLEN, "%d", Run.eventlist_slots);
                StringBuffer_append(res->outputbuffer,
                                    "<tr><td>Event queue</td>"
                                    "<td>base directory %s with %d slots</td></tr>",
                                    Run.eventlist_dir, Run.eventlist_slots);
        }
        if (Run.mmonits) {
                StringBuffer_append(res->outputbuffer, "<tr><td>M/Monit server(s)</td><td>");
                for (Mmonit_T c = Run.mmonits; c; c = c->next)
                {
                        StringBuffer_append(res->outputbuffer,
                                            "%s with timeout %d seconds%s%s%s%s</td></tr>%s",
                                            c->url->url,
                                            c->timeout / 1000,
                                            c->ssl.use_ssl ? " ssl version " : "",
                                            c->ssl.use_ssl ? sslnames[c->ssl.version] : "",
                                            c->ssl.certmd5 ? " server cert md5 sum " : "",
                                            c->ssl.certmd5 ? c->ssl.certmd5 : "",
                                            c->next ? "<tr><td>&nbsp;</td><td>" : "");
                }
                printf("\n");
        }
        if (Run.mailservers) {
                StringBuffer_append(res->outputbuffer, "<tr><td>Mail server(s)</td><td>");
                for (MailServer_T mta = Run.mailservers; mta; mta = mta->next)
                        StringBuffer_append(res->outputbuffer, "%s:%d%s&nbsp;",
                                            mta->host, mta->port, mta->ssl.use_ssl ? "(ssl)" : "");
                StringBuffer_append(res->outputbuffer, "</td></tr>");
        }
        if (Run.MailFormat.from)
                StringBuffer_append(res->outputbuffer,
                                    "<tr><td>Default mail from</td><td>%s</td></tr>",
                                    Run.MailFormat.from);
        if (Run.MailFormat.subject)
                StringBuffer_append(res->outputbuffer,
                                    "<tr><td>Default mail subject</td><td>%s</td></tr>",
                                    Run.MailFormat.subject);
        if (Run.MailFormat.message)
                StringBuffer_append(res->outputbuffer,
                                    "<tr><td>Default mail message</td><td>%s</td></tr>",
                                    Run.MailFormat.message);
        StringBuffer_append(res->outputbuffer,
                            "<tr><td>Poll time</td><td>%d seconds with start delay %d seconds</td></tr>",
                            Run.polltime, Run.startdelay);
        if (Run.httpd.flags & Httpd_Net) {
                StringBuffer_append(res->outputbuffer,
                                    "<tr><td>httpd bind address</td><td>%s</td></tr>",
                                    Run.httpd.socket.net.address ? Run.httpd.socket.net.address : "Any/All");
                StringBuffer_append(res->outputbuffer,
                                    "<tr><td>httpd portnumber</td><td>%d</td></tr>", Run.httpd.socket.net.port);
        } else if (Run.httpd.flags & Httpd_Unix) {
                StringBuffer_append(res->outputbuffer,
                                    "<tr><td>httpd unix socket</td><td>%s</td></tr>",
                                    Run.httpd.socket.unix.path);
        }
        StringBuffer_append(res->outputbuffer,
                            "<tr><td>httpd signature</td><td>%s</td></tr>",
                            Run.httpd.flags & Httpd_Signature ? "True" : "False");
        StringBuffer_append(res->outputbuffer,
                            "<tr><td>Use ssl encryption</td><td>%s</td></tr>",
                            Run.httpd.flags & Httpd_Ssl ? "True" : "False");
        if (Run.httpd.flags & Httpd_Ssl) {
                StringBuffer_append(res->outputbuffer,
                                    "<tr><td>PEM key/certificate file</td><td>%s</td></tr>",
                                    Run.httpd.socket.net.ssl.pem);
                if (Run.httpd.socket.net.ssl.clientpem != NULL) {
                        StringBuffer_append(res->outputbuffer,
                                            "<tr><td>Client PEM key/certification"
                                            "</td><td>%s</td></tr>", "Enabled");
                        StringBuffer_append(res->outputbuffer,
                                            "<tr><td>Client PEM key/certificate file"
                                            "</td><td>%s</td></tr>", Run.httpd.socket.net.ssl.clientpem);
                } else {
                        StringBuffer_append(res->outputbuffer,
                                            "<tr><td>Client PEM key/certification"
                                            "</td><td>%s</td></tr>", "Disabled");
                }
                StringBuffer_append(res->outputbuffer,
                                    "<tr><td>Allow self certified certificates "
                                    "</td><td>%s</td></tr>", Run.httpd.flags & Httpd_AllowSelfSignedCertificates ? "True" : "False");
        }
        StringBuffer_append(res->outputbuffer,
                            "<tr><td>httpd auth. style</td><td>%s</td></tr>",
                            Run.httpd.credentials && Engine_hasHostsAllow() ? "Basic Authentication and Host/Net allow list" : Run.httpd.credentials ? "Basic Authentication" : Engine_hasHostsAllow() ? "Host/Net allow list" : "No authentication");
        print_alerts(res, Run.maillist);
        StringBuffer_append(res->outputbuffer, "</table>");
        if (! is_readonly(req)) {
                StringBuffer_append(res->outputbuffer,
                                    "<table id='buttons'><tr>");
                StringBuffer_append(res->outputbuffer,
                                    "<td style='color:red;'><form method=POST action='_runtime'>Stop Monit http server? "
                                    "<input type=hidden name='action' value='stop'><input type=submit value='Go'></form></td>");
                StringBuffer_append(res->outputbuffer,
                                    "<td><form method=POST action='_runtime'>Force validate now? <input type=hidden name='action' value='validate'>"
                                    "<input type=submit value='Go'></form></td>");

                if (Run.dolog && ! Run.use_syslog) {
                        StringBuffer_append(res->outputbuffer,
                                            "<td><form method=GET action='_viewlog'>View Monit logfile? <input type=submit value='Go'></form></td>");
                }
                StringBuffer_append(res->outputbuffer,
                                    "</tr></table>");
        }
        do_foot(res);
}


static void do_viewlog(HttpRequest req, HttpResponse res) {
        if (is_readonly(req)) {
                send_error(res, SC_FORBIDDEN, "You do not have sufficent privileges to access this page");
                return;
        }
        do_head(res, "_viewlog", "View log", 100);
        if (Run.dolog && ! Run.use_syslog) {
                struct stat sb;
                if (! stat(Run.logfile, &sb)) {
                        FILE *f = fopen(Run.logfile, "r");
                        if (f) {
#define BUFSIZE 512
                                size_t n;
                                char buf[BUFSIZE+1];
                                StringBuffer_append(res->outputbuffer, "<br><p><form><textarea cols=120 rows=30 readonly>");
                                while ((n = fread(buf, sizeof(char), BUFSIZE, f)) > 0) {
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
                if (! Run.dolog)
                        StringBuffer_append(res->outputbuffer, "Monit was started without logging");
                else
                        StringBuffer_append(res->outputbuffer, "Monit uses syslog");
        }
        do_foot(res);
}


static void handle_action(HttpRequest req, HttpResponse res) {
        char *name = req->url;
        Service_T s = Util_getService(++name);
        if (! s) {
                send_error(res, SC_NOT_FOUND, "There is no service named \"%s\"", name ? name : "");
                return;
        }
        const char *action = get_parameter(req, "action");
        if (action) {
                if (is_readonly(req)) {
                        send_error(res, SC_FORBIDDEN, "You do not have sufficent privileges to access this page");
                        return;
                }
                Action_Type doaction = Util_getAction(action);
                if (doaction == Action_Ignored) {
                        send_error(res, SC_BAD_REQUEST, "Invalid action \"%s\"", action);
                        return;
                }
                if (s->doaction != Action_Ignored) {
                        send_error(res, SC_SERVICE_UNAVAILABLE, "Other action already in progress -- please try again later");
                        return;
                }
                s->doaction = doaction;
                const char *token = get_parameter(req, "token");
                if (token) {
                        FREE(s->token);
                        s->token = Str_dup(token);
                }
                LogInfo("'%s' %s on user request\n", s->name, action);
                Run.doaction = true; /* set the global flag */
                do_wakeupcall();
        }
        do_service(req, res, s);
}


static void handle_do_action(HttpRequest req, HttpResponse res) {
        Service_T s;
        Action_Type doaction = Action_Ignored;
        const char *action = get_parameter(req, "action");
        const char *token = get_parameter(req, "token");

        if (action) {
                if (is_readonly(req)) {
                        send_error(res, SC_FORBIDDEN, "You do not have sufficent privileges to access this page");
                        return;
                }
                if ((doaction = Util_getAction(action)) == Action_Ignored) {
                        send_error(res, SC_BAD_REQUEST, "Invalid action \"%s\"", action);
                        return;
                }
                for (HttpParameter p = req->params; p; p = p->next) {
                        if (IS(p->name, "service")) {
                                s  = Util_getService(p->value);
                                if (! s) {
                                        send_error(res, SC_BAD_REQUEST, "There is no service named \"%s\"", p->value ? p->value : "");
                                        return;
                                }
                                if (s->doaction != Action_Ignored) {
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
                Run.doaction = true;
                do_wakeupcall();
        }
}


static void handle_run(HttpRequest req, HttpResponse res) {
        const char *action = get_parameter(req, "action");
        if (action) {
                if (is_readonly(req)) {
                        send_error(res, SC_FORBIDDEN, "You do not have sufficent privileges to access this page");
                        return;
                }
                if (IS(action, "validate")) {
                        LogInfo("The Monit http server woke up on user request\n");
                        do_wakeupcall();
                } else if (IS(action, "stop")) {
                        LogInfo("The Monit http server stopped on user request\n");
                        send_error(res, SC_SERVICE_UNAVAILABLE, "The Monit http server is stopped");
                        Engine_stop();
                        return;
                }
        }
        LOCK(Run.mutex)
        do_runtime(req, res);
        END_LOCK;
}


static void do_service(HttpRequest req, HttpResponse res, Service_T s) {
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
        if (s->type == Service_Process)
                StringBuffer_append(res->outputbuffer, "<tr><td>%s</td><td>%s</td></tr>", s->matchlist ? "Match" : "Pid file", s->path);
        else if (s->type == Service_Host)
                StringBuffer_append(res->outputbuffer, "<tr><td>Address</td><td>%s</td></tr>", s->path);
        else if (s->type == Service_Net)
                StringBuffer_append(res->outputbuffer, "<tr><td>Interface</td><td>%s</td></tr>", s->path);
        else if (s->type != Service_System)
                StringBuffer_append(res->outputbuffer, "<tr><td>Path</td><td>%s</td></tr>", s->path);
        StringBuffer_append(res->outputbuffer, "<tr><td>Status</td><td>");
        _printServiceStatus(res->outputbuffer, s);
        StringBuffer_append(res->outputbuffer, "</td></tr>");
        for (ServiceGroup_T sg = servicegrouplist; sg; sg = sg->next)
                for (ServiceGroupMember_T sgm = sg->members; sgm; sgm = sgm->next)
                        if (IS(sgm->name, s->name))
                                StringBuffer_append(res->outputbuffer, "<tr><td>Group</td><td class='blue-text'>%s</td></tr>", sg->name);
        StringBuffer_append(res->outputbuffer,
                            "<tr><td>Monitoring mode</td><td>%s</td></tr>", modenames[s->mode]);
        StringBuffer_append(res->outputbuffer,
                            "<tr><td>Monitoring status</td><td>%s</td></tr>", get_monitoring_status(s, buf, sizeof(buf)));
        for (Dependant_T d = s->dependantlist; d; d = d->next) {
                if (d->dependant != NULL) {
                        StringBuffer_append(res->outputbuffer,
                                            "<tr><td>Depends on service </td><td> <a href=%s> %s </a></td></tr>",
                                            d->dependant, d->dependant);
                }
        }
        if (s->start) {
                int i = 0;
                StringBuffer_append(res->outputbuffer, "<tr><td>Start program</td><td>'");
                while (s->start->arg[i]) {
                        if (i)
                                StringBuffer_append(res->outputbuffer, " ");
                        StringBuffer_append(res->outputbuffer, "%s", s->start->arg[i++]);
                }
                StringBuffer_append(res->outputbuffer, "'");
                if (s->start->has_uid)
                        StringBuffer_append(res->outputbuffer, " as uid %d", s->start->uid);
                if (s->start->has_gid)
                        StringBuffer_append(res->outputbuffer, " as gid %d", s->start->gid);
                StringBuffer_append(res->outputbuffer, " timeout %d second(s)", s->start->timeout);
                StringBuffer_append(res->outputbuffer, "</td></tr>");
        }
        if (s->stop) {
                int i = 0;
                StringBuffer_append(res->outputbuffer, "<tr><td>Stop program</td><td>'");
                while (s->stop->arg[i]) {
                        if (i)
                                StringBuffer_append(res->outputbuffer, " ");
                        StringBuffer_append(res->outputbuffer, "%s", s->stop->arg[i++]);
                }
                StringBuffer_append(res->outputbuffer, "'");
                if (s->stop->has_uid)
                        StringBuffer_append(res->outputbuffer, " as uid %d", s->stop->uid);
                if (s->stop->has_gid)
                        StringBuffer_append(res->outputbuffer, " as gid %d", s->stop->gid);
                StringBuffer_append(res->outputbuffer, " timeout %d second(s)", s->stop->timeout);
                StringBuffer_append(res->outputbuffer, "</td></tr>");
        }
        if (s->restart) {
                int i = 0;
                StringBuffer_append(res->outputbuffer, "<tr><td>Restart program</td><td>'");
                while (s->restart->arg[i]) {
                        if (i) StringBuffer_append(res->outputbuffer, " ");
                        StringBuffer_append(res->outputbuffer, "%s", s->restart->arg[i++]);
                }
                StringBuffer_append(res->outputbuffer, "'");
                if (s->restart->has_uid)
                        StringBuffer_append(res->outputbuffer, " as uid %d", s->restart->uid);
                if (s->restart->has_gid)
                        StringBuffer_append(res->outputbuffer, " as gid %d", s->restart->gid);
                StringBuffer_append(res->outputbuffer, " timeout %d second(s)", s->restart->timeout);
                StringBuffer_append(res->outputbuffer, "</td></tr>");
        }
        if (s->every.type != Every_Cycle) {
                StringBuffer_append(res->outputbuffer, "<tr><td>Check service</td><td>");
                if (s->every.type == Every_SkipCycles)
                        StringBuffer_append(res->outputbuffer, "every %d cycle", s->every.spec.cycle.number);
                else if (s->every.type == Every_Cron)
                        StringBuffer_append(res->outputbuffer, "every <code>\"%s\"</code>", s->every.spec.cron);
                else if (s->every.type == Every_NotInCron)
                        StringBuffer_append(res->outputbuffer, "not every <code>\"%s\"</code>", s->every.spec.cron);
                StringBuffer_append(res->outputbuffer, "</td></tr>");
        }
        // Status
        switch (s->type) {
                case Service_Filesystem:
                        print_service_status_perm(res, s, s->inf->priv.filesystem.mode);
                        print_service_status_uid(res, s, s->inf->priv.filesystem.uid);
                        print_service_status_gid(res, s, s->inf->priv.filesystem.gid);
                        print_service_status_filesystem_flags(res, s);
                        print_service_status_filesystem_blockstotal(res, s);
                        print_service_status_filesystem_blocksfree(res, s);
                        print_service_status_filesystem_blocksfreetotal(res, s);
                        print_service_status_filesystem_blocksize(res, s);
                        print_service_status_filesystem_inodestotal(res, s);
                        print_service_status_filesystem_inodesfree(res, s);
                        break;
                case Service_Directory:
                        print_service_status_perm(res, s, s->inf->priv.directory.mode);
                        print_service_status_uid(res, s, s->inf->priv.directory.uid);
                        print_service_status_gid(res, s, s->inf->priv.directory.gid);
                        print_service_status_timestamp(res, s, s->inf->priv.directory.timestamp);
                        break;
                case Service_File:
                        print_service_status_perm(res, s, s->inf->priv.file.mode);
                        print_service_status_uid(res, s, s->inf->priv.file.uid);
                        print_service_status_gid(res, s, s->inf->priv.file.gid);
                        print_service_status_timestamp(res, s, s->inf->priv.file.timestamp);
                        print_service_status_file_size(res, s);
                        print_service_status_file_match(res, s);
                        print_service_status_file_checksum(res, s);
                        break;
                case Service_Process:
                        print_service_status_process_pid(res, s);
                        print_service_status_process_ppid(res, s);
                        print_service_status_uid(res, s, s->inf->priv.process.uid);
                        print_service_status_process_euid(res, s);
                        print_service_status_gid(res, s, s->inf->priv.process.gid);
                        print_service_status_process_uptime(res, s);
                        print_service_status_process_children(res, s);
                        print_service_status_process_cpu(res, s);
                        print_service_status_process_cputotal(res, s);
                        print_service_status_process_memory(res, s);
                        print_service_status_process_memorytotal(res, s);
                        print_service_status_port(res, s);
                        print_service_status_socket(res, s);
                        break;
                case Service_Host:
                        print_service_status_icmp(res, s);
                        print_service_status_port(res, s);
                        break;
                case Service_System:
                        print_service_status_system_loadavg(res, s);
                        print_service_status_system_cpu(res, s);
                        print_service_status_system_memory(res, s);
                        print_service_status_system_swap(res, s);
                        break;
                case Service_Fifo:
                        print_service_status_perm(res, s, s->inf->priv.fifo.mode);
                        print_service_status_uid(res, s, s->inf->priv.fifo.uid);
                        print_service_status_gid(res, s, s->inf->priv.fifo.gid);
                        print_service_status_timestamp(res, s, s->inf->priv.fifo.timestamp);
                        break;
                case Service_Program:
                        print_service_status_program_started(res, s);
                        print_service_status_program_status(res, s);
                        print_service_status_program_output(res, s);
                        break;
                case Service_Net:
                        print_service_status_link(res, s);
                        print_service_status_download(res, s);
                        print_service_status_upload(res, s);
                        break;
                default:
                        break;
        }
        StringBuffer_append(res->outputbuffer, "<tr><td>Data collected</td><td>%s</td></tr>", Time_string(s->collected.tv_sec, buf));
        // Rules
        print_service_rules_timeout(res, s);
        print_service_rules_existence(res, s);
        print_service_rules_icmp(res, s);
        print_service_rules_port(res, s);
        print_service_rules_socket(res, s);
        print_service_rules_perm(res, s);
        print_service_rules_uid(res, s);
        print_service_rules_euid(res, s);
        print_service_rules_gid(res, s);
        print_service_rules_timestamp(res, s);
        print_service_rules_fsflags(res, s);
        print_service_rules_filesystem(res, s);
        print_service_rules_size(res, s);
        print_service_rules_linkstatus(res, s);
        print_service_rules_linkspeed(res, s);
        print_service_rules_linksaturation(res, s);
        print_service_rules_uploadbytes(res, s);
        print_service_rules_uploadpackets(res, s);
        print_service_rules_downloadbytes(res, s);
        print_service_rules_downloadpackets(res, s);
        print_service_rules_uptime(res, s);
        print_service_rules_match(res, s);
        print_service_rules_checksum(res, s);
        print_service_rules_pid(res, s);
        print_service_rules_ppid(res, s);
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

        if (Run.doprocess) {
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
                            "<td align='left'>",
                            s->name, s->name);
        _printServiceStatus(res->outputbuffer, s);
        StringBuffer_append(res->outputbuffer,
                            "</td>");
        if (Run.doprocess) {
                StringBuffer_append(res->outputbuffer,
                                    "<td align='right'>[%.2f]&nbsp;[%.2f]&nbsp;[%.2f]</td>"
                                    "<td align='right'>"
                                    "%.1f%%us,&nbsp;%.1f%%sy"
#ifdef HAVE_CPU_WAIT
                                    ",&nbsp;%.1f%%wa"
#endif
                                    "</td>",
                                    systeminfo.loadavg[0], systeminfo.loadavg[1], systeminfo.loadavg[2],
                                    systeminfo.total_cpu_user_percent > 0 ? systeminfo.total_cpu_user_percent/10. : 0,
                                    systeminfo.total_cpu_syst_percent > 0 ? systeminfo.total_cpu_syst_percent/10. : 0
#ifdef HAVE_CPU_WAIT
                                    , systeminfo.total_cpu_wait_percent > 0 ? systeminfo.total_cpu_wait_percent/10. : 0
#endif
                                    );
                StringBuffer_append(res->outputbuffer,
                                    "<td align='right'>%.1f%% [%s]</td>",
                                    systeminfo.total_mem_percent/10., Str_bytesToSize(systeminfo.total_mem_kbyte * 1024., buf));
                StringBuffer_append(res->outputbuffer,
                                    "<td align='right'>%.1f%% [%s]</td>",
                                    systeminfo.total_swap_percent/10., Str_bytesToSize(systeminfo.total_swap_kbyte * 1024., buf));
        }
        StringBuffer_append(res->outputbuffer,
                            "</tr>"
                            "</table>");
}


static void do_home_process(HttpRequest req, HttpResponse res) {
        char      buf[STRLEN];
        boolean_t on = true;
        boolean_t header = true;

        for (Service_T s = servicelist_conf; s; s = s->next_conf) {
                if (s->type != Service_Process)
                        continue;
                if (header) {
                        StringBuffer_append(res->outputbuffer,
                                            "<table id='header-row'>"
                                            "<tr>"
                                            "<th align='left' class='first'>Process</th>"
                                            "<th align='left'>Status</th>"
                                            "<th align='right'>Uptime</th>");
                        if (Run.doprocess) {
                                StringBuffer_append(res->outputbuffer,
                                                    "<th align='right'>CPU Total</b></th>"
                                                    "<th align='right'>Memory Total</th>");
                        }
                        StringBuffer_append(res->outputbuffer, "</tr>");
                        header = false;
                }
                StringBuffer_append(res->outputbuffer,
                                    "<tr %s>"
                                    "<td align='left'><a href='%s'>%s</a></td>"
                                    "<td align='left'>",
                                    on ? "class='stripe'" : "",
                                    s->name, s->name);
                _printServiceStatus(res->outputbuffer, s);
                StringBuffer_append(res->outputbuffer,
                                    "</td>");
                if (! Util_hasServiceStatus(s)) {
                        StringBuffer_append(res->outputbuffer,
                                            "<td align='right'>-</td>");
                        if (Run.doprocess) {
                                StringBuffer_append(res->outputbuffer,
                                                    "<td align='right'>-</td>"
                                                    "<td align='right'>-</td>");
                        }
                } else {
                        char *uptime = Util_getUptime(s->inf->priv.process.uptime, "&nbsp;");
                        StringBuffer_append(res->outputbuffer,
                                            "<td align='right'>%s</td>", uptime);
                        FREE(uptime);
                        if (Run.doprocess) {
                                StringBuffer_append(res->outputbuffer,
                                                    "<td align='right' class='%s'>%.1f%%</td>",
                                                    (s->error & Event_Resource) ? "red-text" : "",
                                                    s->inf->priv.process.total_cpu_percent/10.0);
                                StringBuffer_append(res->outputbuffer,
                                                    "<td align='right' class='%s'>%.1f%% [%s]</td>",
                                                    (s->error & Event_Resource) ? "red-text" : "",
                                                    s->inf->priv.process.total_mem_percent/10.0, Str_bytesToSize(s->inf->priv.process.total_mem_kbyte * 1024., buf));
                        }
                }
                StringBuffer_append(res->outputbuffer, "</tr>");
                on = ! on;
        }
        if (! header)
                StringBuffer_append(res->outputbuffer, "</table>");
}


static void do_home_program(HttpRequest req, HttpResponse res) {
        boolean_t on = true;
        boolean_t header = true;

        for (Service_T s = servicelist_conf; s; s = s->next_conf) {
                if (s->type != Service_Program)
                        continue;
                if (header) {
                        StringBuffer_append(res->outputbuffer,
                                            "<table id='header-row'>"
                                            "<tr>"
                                            "<th align='left' class='first'>Program</th>"
                                            "<th align='left'>Status</th>"
                                            "<th align='left'>Output</th>"
                                            "<th align='right'>Last started</th>"
                                            "<th align='right'>Exit value</th>"
                                            "</tr>");
                        header = false;
                }
                StringBuffer_append(res->outputbuffer,
                                    "<tr %s>"
                                    "<td align='left'><a href='%s'>%s</a></td>"
                                    "<td align='left'>",
                                    on ? "class='stripe'" : "",
                                    s->name, s->name);
                _printServiceStatus(res->outputbuffer, s);
                StringBuffer_append(res->outputbuffer,
                                    "</td>");
                if (! Util_hasServiceStatus(s)) {
                        StringBuffer_append(res->outputbuffer, "<td align='left'>-</td>");
                        StringBuffer_append(res->outputbuffer, "<td align='right'>-</td>");
                        StringBuffer_append(res->outputbuffer, "<td align='right'>-</td>");
                } else {
                        if (s->program->started) {
                                StringBuffer_append(res->outputbuffer, "<td align='left' class='short'>");
                                if (StringBuffer_length(s->program->output)) {
                                        // Print first line only (escape HTML characters if any)
                                        const char *output = StringBuffer_toString(s->program->output);
                                        for (int i = 0; output[i]; i++) {
                                                if (output[i] == '<')
                                                        StringBuffer_append(res->outputbuffer, "&lt;");
                                                else if (output[i] == '>')
                                                        StringBuffer_append(res->outputbuffer, "&gt;");
                                                else if (output[i] == '&')
                                                        StringBuffer_append(res->outputbuffer, "&amp;");
                                                else if (output[i] == '\r' || output[i] == '\n')
                                                        break;
                                                else
                                                        StringBuffer_append(res->outputbuffer, "%c", output[i]);
                                        }
                                } else {
                                        StringBuffer_append(res->outputbuffer, "no output");
                                }
                                StringBuffer_append(res->outputbuffer, "</td>");
                                StringBuffer_append(res->outputbuffer, "<td align='right'>%s</td>", Time_fmt((char[32]){}, 32, "%d %b %Y %H:%M:%S", s->program->started));
                                StringBuffer_append(res->outputbuffer, "<td align='right'>%d</td>", s->program->exitStatus);
                        } else {
                                StringBuffer_append(res->outputbuffer, "<td align='right'>N/A</td>");
                                StringBuffer_append(res->outputbuffer, "<td align='right'>Not yet started</td>");
                                StringBuffer_append(res->outputbuffer, "<td align='right'>N/A</td>");
                        }
                }
                StringBuffer_append(res->outputbuffer, "</tr>");
                on = ! on;
        }
        if (! header)
                StringBuffer_append(res->outputbuffer, "</table>");

}


static void do_home_net(HttpRequest req, HttpResponse res) {
        char buf[STRLEN];
        boolean_t on = true;
        boolean_t header = true;

        for (Service_T s = servicelist_conf; s; s = s->next_conf) {
                if (s->type != Service_Net)
                        continue;
                if (header) {
                        StringBuffer_append(res->outputbuffer,
                                            "<table id='header-row'>"
                                            "<tr>"
                                            "<th align='left' class='first'>Net</th>"
                                            "<th align='left'>Status</th>"
                                            "<th align='right'>Upload</th>"
                                            "<th align='right'>Download</th>"
                                            "</tr>");
                        header = false;
                }
                StringBuffer_append(res->outputbuffer,
                                    "<tr %s>"
                                    "<td align='left'><a href='%s'>%s</a></td>"
                                    "<td align='left'>",
                                    on ? "class='stripe'" : "",
                                    s->name, s->name);
                _printServiceStatus(res->outputbuffer, s);
                StringBuffer_append(res->outputbuffer,
                                    "</td>");

                if (! Util_hasServiceStatus(s) || Link_getState(s->inf->priv.net.stats) != 1) {
                        StringBuffer_append(res->outputbuffer, "<td align='right'>-</td>");
                        StringBuffer_append(res->outputbuffer, "<td align='right'>-</td>");
                } else {
                        StringBuffer_append(res->outputbuffer, "<td align='right'>%s&#47;s</td>", Str_bytesToSize(Link_getBytesOutPerSecond(s->inf->priv.net.stats), buf));
                        StringBuffer_append(res->outputbuffer, "<td align='right'>%s&#47;s</td>", Str_bytesToSize(Link_getBytesInPerSecond(s->inf->priv.net.stats), buf));
                }
                StringBuffer_append(res->outputbuffer, "</tr>");
                on = ! on;
        }
        if (! header)
                StringBuffer_append(res->outputbuffer, "</table>");
}


static void do_home_filesystem(HttpRequest req, HttpResponse res) {
        char buf[STRLEN];
        boolean_t on = true;
        boolean_t header = true;

        for (Service_T s = servicelist_conf; s; s = s->next_conf) {
                if (s->type != Service_Filesystem)
                        continue;
                if (header) {
                        StringBuffer_append(res->outputbuffer,
                                            "<table id='header-row'>"
                                            "<tr>"
                                            "<th align='left' class='first'>Filesystem</th>"
                                            "<th align='left'>Status</th>"
                                            "<th align='right'>Space usage</th>"
                                            "<th align='right'>Inodes usage</th>"
                                            "</tr>");
                        header = false;
                }
                StringBuffer_append(res->outputbuffer,
                                    "<tr %s>"
                                    "<td align='left'><a href='%s'>%s</a></td>"
                                    "<td align='left'>",
                                    on ? "class='stripe'" : "",
                                    s->name, s->name);
                _printServiceStatus(res->outputbuffer, s);
                StringBuffer_append(res->outputbuffer,
                                    "</td>");
                if (! Util_hasServiceStatus(s)) {
                        StringBuffer_append(res->outputbuffer,
                                            "<td align='right'>- [-]</td>"
                                            "<td align='right'>- [-]</td>");
                } else {
                        StringBuffer_append(res->outputbuffer,
                                            "<td align='right'>%.1f%% [%s]</td>",
                                            s->inf->priv.filesystem.space_percent/10.,
                                            s->inf->priv.filesystem.f_bsize > 0 ? Str_bytesToSize(s->inf->priv.filesystem.space_total * s->inf->priv.filesystem.f_bsize, buf) : "0 MB");
                        if (s->inf->priv.filesystem.f_files > 0) {
                                StringBuffer_append(res->outputbuffer,
                                                    "<td align='right'>%.1f%% [%lld objects]</td>",
                                                    s->inf->priv.filesystem.inode_percent/10.,
                                                    s->inf->priv.filesystem.inode_total);
                        } else {
                                StringBuffer_append(res->outputbuffer,
                                                    "<td align='right'>not supported by filesystem</td>");
                        }
                }
                StringBuffer_append(res->outputbuffer, "</tr>");
                on = ! on;
        }
        if (! header)
                StringBuffer_append(res->outputbuffer, "</table>");
}


static void do_home_file(HttpRequest req, HttpResponse res) {
        boolean_t on = true;
        boolean_t header = true;

        for (Service_T s = servicelist_conf; s; s = s->next_conf) {
                if (s->type != Service_File)
                        continue;
                if (header) {
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

                        header = false;
                }
                StringBuffer_append(res->outputbuffer,
                                    "<tr %s>"
                                    "<td align='left'><a href='%s'>%s</a></td>"
                                    "<td align='left'>",
                                    on ? "class='stripe'" : "",
                                    s->name, s->name);
                _printServiceStatus(res->outputbuffer, s);
                StringBuffer_append(res->outputbuffer,
                                    "</td>");
                if (! Util_hasServiceStatus(s)) {
                        StringBuffer_append(res->outputbuffer,
                                            "<td align='right'>-</td>"
                                            "<td align='right'>-</td>"
                                            "<td align='right'>-</td>"
                                            "<td align='right'>-</td>");
                } else {
                        char buf[STRLEN];
                        StringBuffer_append(res->outputbuffer,
                                            "<td align='right'>%s</td>"
                                            "<td align='right'>%04o</td>"
                                            "<td align='right'>%d</td>"
                                            "<td align='right'>%d</td>",
                                            Str_bytesToSize(s->inf->priv.file.size, buf),
                                            s->inf->priv.file.mode & 07777,
                                            s->inf->priv.file.uid,
                                            s->inf->priv.file.gid);
                }
                StringBuffer_append(res->outputbuffer, "</tr>");
                on = ! on;
        }
        if (! header)
                StringBuffer_append(res->outputbuffer, "</table>");
}


static void do_home_fifo(HttpRequest req, HttpResponse res) {
        boolean_t on = true;
        boolean_t header = true;

        for (Service_T s = servicelist_conf; s; s = s->next_conf) {
                if (s->type != Service_Fifo)
                        continue;
                if (header) {
                        StringBuffer_append(res->outputbuffer,
                                            "<table id='header-row'>"
                                            "<tr>"
                                            "<th align='left' class='first'>Fifo</th>"
                                            "<th align='left'>Status</th>"
                                            "<th align='right'>Permission</th>"
                                            "<th align='right'>UID</th>"
                                            "<th align='right'>GID</th>"
                                            "</tr>");
                        header = false;
                }
                StringBuffer_append(res->outputbuffer,
                                    "<tr %s>"
                                    "<td align='left'><a href='%s'>%s</a></td>"
                                    "<td align='left'>",
                                    on ? "class='stripe'" : "",
                                    s->name, s->name);
                _printServiceStatus(res->outputbuffer, s);
                StringBuffer_append(res->outputbuffer,
                                    "</td>");
                if (! Util_hasServiceStatus(s)) {
                        StringBuffer_append(res->outputbuffer,
                                            "<td align='right'>-</td>"
                                            "<td align='right'>-</td>"
                                            "<td align='right'>-</td>");
                } else {
                        StringBuffer_append(res->outputbuffer,
                                            "<td align='right'>%o</td>"
                                            "<td align='right'>%d</td>"
                                            "<td align='right'>%d</td>",
                                            s->inf->priv.fifo.mode & 07777,
                                            s->inf->priv.fifo.uid,
                                            s->inf->priv.fifo.gid);
                }
                StringBuffer_append(res->outputbuffer, "</tr>");
                on = ! on;
        }
        if (! header)
                StringBuffer_append(res->outputbuffer, "</table>");
}


static void do_home_directory(HttpRequest req, HttpResponse res) {
        boolean_t on = true;
        boolean_t header = true;

        for (Service_T s = servicelist_conf; s; s = s->next_conf) {
                if (s->type != Service_Directory)
                        continue;
                if (header) {
                        StringBuffer_append(res->outputbuffer,
                                            "<table id='header-row'>"
                                            "<tr>"
                                            "<th align='left' class='first'>Directory</th>"
                                            "<th align='left'>Status</th>"
                                            "<th align='right'>Permission</th>"
                                            "<th align='right'>UID</th>"
                                            "<th align='right'>GID</th>"
                                            "</tr>");
                        header = false;
                }
                StringBuffer_append(res->outputbuffer,
                                    "<tr %s>"
                                    "<td align='left'><a href='%s'>%s</a></td>"
                                    "<td align='left'>",
                                    on ? "class='stripe'" : "",
                                    s->name, s->name);
                _printServiceStatus(res->outputbuffer, s);
                StringBuffer_append(res->outputbuffer,
                                    "</td>");
                if (! Util_hasServiceStatus(s)) {
                        StringBuffer_append(res->outputbuffer,
                                            "<td align='right'>-</td>"
                                            "<td align='right'>-</td>"
                                            "<td align='right'>-</td>");
                } else {
                        StringBuffer_append(res->outputbuffer,
                                            "<td align='right'>%o</td>"
                                            "<td align='right'>%d</td>"
                                            "<td align='right'>%d</td>",
                                            s->inf->priv.directory.mode & 07777,
                                            s->inf->priv.directory.uid,
                                            s->inf->priv.directory.gid);
                }
                StringBuffer_append(res->outputbuffer, "</tr>");
                on = ! on;
        }
        if (! header)
                StringBuffer_append(res->outputbuffer, "</table>");
}


static void do_home_host(HttpRequest req, HttpResponse res) {
        boolean_t on = true;
        boolean_t header = true;

        for (Service_T s = servicelist_conf; s; s = s->next_conf) {
                if (s->type != Service_Host)
                        continue;
                if (header) {
                        StringBuffer_append(res->outputbuffer,
                                            "<table id='header-row'>"
                                            "<tr>"
                                            "<th align='left' class='first'>Host</th>"
                                            "<th align='left'>Status</th>"
                                            "<th align='right'>Protocol(s)</th>"
                                            "</tr>");
                        header = false;
                }
                StringBuffer_append(res->outputbuffer,
                                    "<tr %s>"
                                    "<td align='left'><a href='%s'>%s</a></td>"
                                    "<td align='left'>",
                                    on ? "class='stripe'" : "",
                                    s->name, s->name);
                _printServiceStatus(res->outputbuffer, s);
                StringBuffer_append(res->outputbuffer,
                                    "</td>");
                if (! Util_hasServiceStatus(s)) {
                        StringBuffer_append(res->outputbuffer,
                                            "<td align='right'>-</td>");
                } else {
                        StringBuffer_append(res->outputbuffer,
                                            "<td align='right'>");
                        for (Icmp_T icmp = s->icmplist; icmp; icmp = icmp->next) {
                                if (icmp != s->icmplist)
                                        StringBuffer_append(res->outputbuffer, "&nbsp;&nbsp;<b>|</b>&nbsp;&nbsp;");
                                StringBuffer_append(res->outputbuffer, "<span class='%s'>[Ping]</span>",
                                                    (icmp->is_available) ? "" : "red-text");
                        }
                        if (s->icmplist && s->portlist)
                                StringBuffer_append(res->outputbuffer, "&nbsp;&nbsp;<b>|</b>&nbsp;&nbsp;");
                        for (Port_T port = s->portlist; port; port = port->next) {
                                if (port != s->portlist)
                                        StringBuffer_append(res->outputbuffer, "&nbsp;&nbsp;<b>|</b>&nbsp;&nbsp;");
                                StringBuffer_append(res->outputbuffer, "<span class='%s'>[%s] at port %d</span>",
                                                    (port->is_available) ? "" : "red-text",
                                                    port->protocol->name, port->port);
                        }
                        StringBuffer_append(res->outputbuffer, "</td>");
                }
                StringBuffer_append(res->outputbuffer, "</tr>");
                on = ! on;
        }
        if (! header)
                StringBuffer_append(res->outputbuffer, "</table>");
}


/* ------------------------------------------------------------------------- */


static void print_alerts(HttpResponse res, Mail_T s) {
        for (Mail_T r = s; r; r = r->next) {
                StringBuffer_append(res->outputbuffer,
                                    "<tr class='stripe'><td>Alert mail to</td>"
                                    "<td>%s</td></tr>", r->to ? r->to : "");
                StringBuffer_append(res->outputbuffer, "<tr><td>Alert on</td><td>");
                if (r->events == Event_Null) {
                        StringBuffer_append(res->outputbuffer, "No events");
                } else if (r->events == Event_All) {
                        StringBuffer_append(res->outputbuffer, "All events");
                } else {
                        if (IS_EVENT_SET(r->events, Event_Action))
                                StringBuffer_append(res->outputbuffer, "Action ");
                        if (IS_EVENT_SET(r->events, Event_ByteIn))
                                StringBuffer_append(res->outputbuffer, "ByteIn ");
                        if (IS_EVENT_SET(r->events, Event_ByteOut))
                                StringBuffer_append(res->outputbuffer, "ByteOut ");
                        if (IS_EVENT_SET(r->events, Event_Checksum))
                                StringBuffer_append(res->outputbuffer, "Checksum ");
                        if (IS_EVENT_SET(r->events, Event_Connection))
                                StringBuffer_append(res->outputbuffer, "Connection ");
                        if (IS_EVENT_SET(r->events, Event_Content))
                                StringBuffer_append(res->outputbuffer, "Content ");
                        if (IS_EVENT_SET(r->events, Event_Data))
                                StringBuffer_append(res->outputbuffer, "Data ");
                        if (IS_EVENT_SET(r->events, Event_Exec))
                                StringBuffer_append(res->outputbuffer, "Exec ");
                        if (IS_EVENT_SET(r->events, Event_Fsflag))
                                StringBuffer_append(res->outputbuffer, "Fsflags ");
                        if (IS_EVENT_SET(r->events, Event_Gid))
                                StringBuffer_append(res->outputbuffer, "Gid ");
                        if (IS_EVENT_SET(r->events, Event_Instance))
                                StringBuffer_append(res->outputbuffer, "Instance ");
                        if (IS_EVENT_SET(r->events, Event_Invalid))
                                StringBuffer_append(res->outputbuffer, "Invalid ");
                        if (IS_EVENT_SET(r->events, Event_Link))
                                StringBuffer_append(res->outputbuffer, "Link ");
                        if (IS_EVENT_SET(r->events, Event_Nonexist))
                                StringBuffer_append(res->outputbuffer, "Nonexist ");
                        if (IS_EVENT_SET(r->events, Event_Permission))
                                StringBuffer_append(res->outputbuffer, "Permission ");
                        if (IS_EVENT_SET(r->events, Event_PacketIn))
                                StringBuffer_append(res->outputbuffer, "PacketIn ");
                        if (IS_EVENT_SET(r->events, Event_PacketOut))
                                StringBuffer_append(res->outputbuffer, "PacketOut ");
                        if (IS_EVENT_SET(r->events, Event_Pid))
                                StringBuffer_append(res->outputbuffer, "PID ");
                        if (IS_EVENT_SET(r->events, Event_Icmp))
                                StringBuffer_append(res->outputbuffer, "Ping ");
                        if (IS_EVENT_SET(r->events, Event_PPid))
                                StringBuffer_append(res->outputbuffer, "PPID ");
                        if (IS_EVENT_SET(r->events, Event_Resource))
                                StringBuffer_append(res->outputbuffer, "Resource ");
                        if (IS_EVENT_SET(r->events, Event_Saturation))
                                StringBuffer_append(res->outputbuffer, "Saturation ");
                        if (IS_EVENT_SET(r->events, Event_Size))
                                StringBuffer_append(res->outputbuffer, "Size ");
                        if (IS_EVENT_SET(r->events, Event_Speed))
                                StringBuffer_append(res->outputbuffer, "Speed ");
                        if (IS_EVENT_SET(r->events, Event_Status))
                                StringBuffer_append(res->outputbuffer, "Status ");
                        if (IS_EVENT_SET(r->events, Event_Timeout))
                                StringBuffer_append(res->outputbuffer, "Timeout ");
                        if (IS_EVENT_SET(r->events, Event_Timestamp))
                                StringBuffer_append(res->outputbuffer, "Timestamp ");
                        if (IS_EVENT_SET(r->events, Event_Uid))
                                StringBuffer_append(res->outputbuffer, "Uid ");
                        if (IS_EVENT_SET(r->events, Event_Uptime))
                                StringBuffer_append(res->outputbuffer, "Uptime ");
                }
                StringBuffer_append(res->outputbuffer, "</td></tr>");
                if (r->reminder) {
                        StringBuffer_append(res->outputbuffer,
                                            "<tr><td>Alert reminder</td><td>%u cycles</td></tr>",
                                            r->reminder);
                }
        }
}


static void print_buttons(HttpRequest req, HttpResponse res, Service_T s) {
        if (is_readonly(req)) {
                 // A read-only REMOTE_USER does not get access to these buttons
                return;
        }
        StringBuffer_append(res->outputbuffer, "<table id='buttons'><tr>");
        /* Start program */
        if (s->start)
                StringBuffer_append(res->outputbuffer,
                                    "<td><form method=POST action=%s>"
                                    "<input type=hidden value='start' name=action>"
                                    "<input type=submit value='Start service'></form></td>", s->name);
        /* Stop program */
        if (s->stop)
                StringBuffer_append(res->outputbuffer,
                                    "<td><form method=POST action=%s>"
                                    "<input type=hidden value='stop' name=action>"
                                    "<input type=submit value='Stop service'></form></td>", s->name);
        /* Restart program */
        if ((s->start && s->stop) || s->restart)
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


static void print_service_rules_timeout(HttpResponse res, Service_T s) {
        for (ActionRate_T ar = s->actionratelist; ar; ar = ar->next) {
                StringBuffer_append(res->outputbuffer, "<tr class='rule'><td>Timeout</td><td>If restarted %d times within %d cycle(s) then ", ar->count, ar->cycle);
                Util_printAction(ar->action->failed, res->outputbuffer);
                StringBuffer_append(res->outputbuffer, "</td></tr>");
        }
}


static void print_service_rules_existence(HttpResponse res, Service_T s) {
        for (Nonexist_T l = s->nonexistlist; l; l = l->next) {
                StringBuffer_append(res->outputbuffer, "<tr class='rule'><td>Existence</td><td>");
                Util_printRule(res->outputbuffer, l->action, "If doesn't exist");
                StringBuffer_append(res->outputbuffer, "</td></tr>");
        }
}


static void print_service_rules_port(HttpResponse res, Service_T s) {
        for (Port_T p = s->portlist; p; p = p->next) {
                StringBuffer_append(res->outputbuffer, "<tr class='rule'><td>Port</td><td>");
                if (p->retry > 1)
                        Util_printRule(res->outputbuffer, p->action, "If failed [%s]:%d%s type %s/%s protocol %s with timeout %d seconds and retry %d times", p->hostname, p->port, p->request ? p->request : "", Util_portTypeDescription(p), Util_portIpDescription(p), p->protocol->name, p->timeout / 1000, p->retry);
                else
                        Util_printRule(res->outputbuffer, p->action, "If failed [%s]:%d%s type %s/%s protocol %s with timeout %d seconds", p->hostname, p->port, p->request ? p->request : "", Util_portTypeDescription(p), Util_portIpDescription(p), p->protocol->name, p->timeout / 1000);
                StringBuffer_append(res->outputbuffer, "</td></tr>");
                if (p->SSL.certmd5 != NULL)
                        StringBuffer_append(res->outputbuffer, "<tr class='rule'><td>Server certificate md5 sum</td><td>%s</td></tr>", p->SSL.certmd5);
        }
}


static void print_service_rules_socket(HttpResponse res, Service_T s) {
        for (Port_T p = s->socketlist; p; p = p->next) {
                StringBuffer_append(res->outputbuffer, "<tr class='rule'><td>Unix Socket</td><td>");
                if (p->retry > 1)
                        Util_printRule(res->outputbuffer, p->action, "If failed %s type %s protocol %s with timeout %d seconds and retry %d time(s)", p->pathname, Util_portTypeDescription(p), p->protocol->name, p->timeout / 1000, p->retry);
                else
                        Util_printRule(res->outputbuffer, p->action, "If failed %s type %s protocol %s with timeout %d seconds", p->pathname, Util_portTypeDescription(p), p->protocol->name, p->timeout / 1000);
                StringBuffer_append(res->outputbuffer, "</td></tr>");
        }
}


static void print_service_rules_icmp(HttpResponse res, Service_T s) {
        for (Icmp_T i = s->icmplist; i; i = i->next) {
                switch (i->family) {
                        case Socket_Ip4:
                                StringBuffer_append(res->outputbuffer, "<tr class='rule'><td>Ping4</td><td>");
                                break;
                        case Socket_Ip6:
                                StringBuffer_append(res->outputbuffer, "<tr class='rule'><td>Ping6</td><td>");
                                break;
                        default:
                                StringBuffer_append(res->outputbuffer, "<tr class='rule'><td>Ping</td><td>");
                                break;
                }
                Util_printRule(res->outputbuffer, i->action, "If failed [count %d with timeout %d seconds]", i->count, i->timeout / 1000);
                StringBuffer_append(res->outputbuffer, "</td></tr>");
        }
}


static void print_service_rules_perm(HttpResponse res, Service_T s) {
        if (s->perm) {
                StringBuffer_append(res->outputbuffer, "<tr class='rule'><td>Permissions</td><td>");
                if (s->perm->test_changes)
                        Util_printRule(res->outputbuffer, s->perm->action, "If changed");
                else
                        Util_printRule(res->outputbuffer, s->perm->action, "If failed %o", s->perm->perm);
                StringBuffer_append(res->outputbuffer, "</td></tr>");
        }
}


static void print_service_rules_uid(HttpResponse res, Service_T s) {
        if (s->uid) {
                StringBuffer_append(res->outputbuffer, "<tr class='rule'><td>UID</td><td>");
                Util_printRule(res->outputbuffer, s->uid->action, "If failed %d", s->uid->uid);
                StringBuffer_append(res->outputbuffer, "</td></tr>");
        }
}


static void print_service_rules_euid(HttpResponse res, Service_T s) {
        if (s->euid) {
                StringBuffer_append(res->outputbuffer, "<tr class='rule'><td>EUID</td><td>");
                Util_printRule(res->outputbuffer, s->euid->action, "If failed %d", s->euid->uid);
                StringBuffer_append(res->outputbuffer, "</td></tr>");
        }
}


static void print_service_rules_gid(HttpResponse res, Service_T s) {
        if (s->gid) {
                StringBuffer_append(res->outputbuffer, "<tr class='rule'><td>GID</td><td>");
                Util_printRule(res->outputbuffer, s->gid->action, "If failed %d", s->gid->gid);
                StringBuffer_append(res->outputbuffer, "</td></tr>");
        }
}


static void print_service_rules_timestamp(HttpResponse res, Service_T s) {
        for (Timestamp_T t = s->timestamplist; t; t = t->next) {
                StringBuffer_append(res->outputbuffer, "<tr class='rule'><td>Timestamp</td><td>");
                if (t->test_changes)
                        Util_printRule(res->outputbuffer, t->action, "If changed");
                else
                        Util_printRule(res->outputbuffer, t->action, "If %s %d second(s)", operatornames[t->operator], t->time);
                StringBuffer_append(res->outputbuffer, "</td></tr>");
        }
}


static void print_service_rules_fsflags(HttpResponse res, Service_T s) {
        for (Fsflag_T l = s->fsflaglist; l; l = l->next) {
                StringBuffer_append(res->outputbuffer, "<tr class='rule'><td>Filesystem flags</td><td>");
                Util_printRule(res->outputbuffer, l->action, "If changed");
                StringBuffer_append(res->outputbuffer, "</td></tr>");
        }
}


static void print_service_rules_filesystem(HttpResponse res, Service_T s) {
        for (Filesystem_T dl = s->filesystemlist; dl; dl = dl->next) {
                if (dl->resource == Resource_Inode) {
                        StringBuffer_append(res->outputbuffer, "<tr class='rule'><td>Inodes usage limit</td><td>");
                        if (dl->limit_absolute > -1)
                                Util_printRule(res->outputbuffer, dl->action, "If %s %lld", operatornames[dl->operator], dl->limit_absolute);
                        else
                                Util_printRule(res->outputbuffer, dl->action, "If %s %.1f%%", operatornames[dl->operator], dl->limit_percent / 10.);
                        StringBuffer_append(res->outputbuffer, "</td></tr>");
                } else if (dl->resource == Resource_InodeFree) {
                        StringBuffer_append(res->outputbuffer, "<tr class='rule'><td>Inodes free limit</td><td>");
                        if (dl->limit_absolute > -1)
                                Util_printRule(res->outputbuffer, dl->action, "If %s %lld", operatornames[dl->operator], dl->limit_absolute);
                        else
                                Util_printRule(res->outputbuffer, dl->action, "If %s %.1f%%", operatornames[dl->operator], dl->limit_percent / 10.);
                        StringBuffer_append(res->outputbuffer, "</td></tr>");
                } else if (dl->resource == Resource_Space) {
                        StringBuffer_append(res->outputbuffer, "<tr class='rule'><td>Space usage limit</td><td>");
                        if (dl->limit_absolute > -1) {
                                if (s->inf->priv.filesystem.f_bsize > 0) {
                                        char buf[STRLEN];
                                        Util_printRule(res->outputbuffer, dl->action, "If %s %s", operatornames[dl->operator], Str_bytesToSize(dl->limit_absolute * s->inf->priv.filesystem.f_bsize, buf));
                                } else {
                                        Util_printRule(res->outputbuffer, dl->action, "If %s %lld blocks", operatornames[dl->operator], dl->limit_absolute);
                                }
                        } else {
                                Util_printRule(res->outputbuffer, dl->action, "If %s %.1f%%", operatornames[dl->operator], dl->limit_percent / 10.);
                        }
                        StringBuffer_append(res->outputbuffer, "</td></tr>");
                } else if (dl->resource == Resource_SpaceFree) {
                        StringBuffer_append(res->outputbuffer, "<tr class='rule'><td>Space free limit</td><td>");
                        if (dl->limit_absolute > -1) {
                                if (s->inf->priv.filesystem.f_bsize > 0) {
                                        char buf[STRLEN];
                                        Util_printRule(res->outputbuffer, dl->action, "If %s %s", operatornames[dl->operator], Str_bytesToSize(dl->limit_absolute * s->inf->priv.filesystem.f_bsize, buf));
                                } else {
                                        Util_printRule(res->outputbuffer, dl->action, "If %s %lld blocks", operatornames[dl->operator], dl->limit_absolute);
                                }
                        } else {
                                Util_printRule(res->outputbuffer, dl->action, "If %s %.1f%%", operatornames[dl->operator], dl->limit_percent / 10.);
                        }
                        StringBuffer_append(res->outputbuffer, "</td></tr>");
                }
        }
}


static void print_service_rules_size(HttpResponse res, Service_T s) {
        for (Size_T sl = s->sizelist; sl; sl = sl->next) {
                StringBuffer_append(res->outputbuffer, "<tr class='rule'><td>Size</td><td>");
                if (sl->test_changes)
                        Util_printRule(res->outputbuffer, sl->action, "If changed");
                else
                        Util_printRule(res->outputbuffer, sl->action, "If %s %llu byte(s)", operatornames[sl->operator], sl->size);
                StringBuffer_append(res->outputbuffer, "</td></tr>");
        }
}


static void print_service_rules_linkstatus(HttpResponse res, Service_T s) {
        for (LinkStatus_T l = s->linkstatuslist; l; l = l->next) {
                StringBuffer_append(res->outputbuffer, "<tr class='rule'><td>Link status</td><td>");
                Util_printRule(res->outputbuffer, l->action, "If failed");
                StringBuffer_append(res->outputbuffer, "</td></tr>");
        }
}


static void print_service_rules_linkspeed(HttpResponse res, Service_T s) {
        for (LinkSpeed_T l = s->linkspeedlist; l; l = l->next) {
                StringBuffer_append(res->outputbuffer, "<tr class='rule'><td>Link capacity</td><td>");
                Util_printRule(res->outputbuffer, l->action, "If changed");
                StringBuffer_append(res->outputbuffer, "</td></tr>");
        }
}


static void print_service_rules_linksaturation(HttpResponse res, Service_T s) {
        for (LinkSaturation_T l = s->linksaturationlist; l; l = l->next) {
                StringBuffer_append(res->outputbuffer, "<tr class='rule'><td>Link saturation</td><td>");
                Util_printRule(res->outputbuffer, l->action, "If %s %.1f%%", operatornames[l->operator], l->limit);
                StringBuffer_append(res->outputbuffer, "</td></tr>");
        }
}


static void print_service_rules_uploadbytes(HttpResponse res, Service_T s) {
        char buf[STRLEN];
        for (Bandwidth_T bl = s->uploadbyteslist; bl; bl = bl->next) {
                if (bl->range == Time_Second) {
                        StringBuffer_append(res->outputbuffer, "<tr class='rule'><td>Upload bytes</td><td>");
                        Util_printRule(res->outputbuffer, bl->action, "If %s %s/s", operatornames[bl->operator], Str_bytesToSize(bl->limit, buf));
                } else {
                        StringBuffer_append(res->outputbuffer, "<tr class='rule'><td>Total upload bytes</td><td>");
                        Util_printRule(res->outputbuffer, bl->action, "If %s %s in last %d %s(s)", operatornames[bl->operator], Str_bytesToSize(bl->limit, buf), bl->rangecount, Util_timestr(bl->range));
                }
                StringBuffer_append(res->outputbuffer, "</td></tr>");
        }
}


static void print_service_rules_uploadpackets(HttpResponse res, Service_T s) {
        for (Bandwidth_T bl = s->uploadpacketslist; bl; bl = bl->next) {
                if (bl->range == Time_Second) {
                        StringBuffer_append(res->outputbuffer, "<tr class='rule'><td>Upload packets</td><td>");
                        Util_printRule(res->outputbuffer, bl->action, "If %s %lld packets/s", operatornames[bl->operator], bl->limit);
                } else {
                        StringBuffer_append(res->outputbuffer, "<tr class='rule'><td>Total upload packets</td><td>");
                        Util_printRule(res->outputbuffer, bl->action, "If %s %lld packets in last %d %s(s)", operatornames[bl->operator], bl->limit, bl->rangecount, Util_timestr(bl->range));
                }
                StringBuffer_append(res->outputbuffer, "</td></tr>");
        }
}


static void print_service_rules_downloadbytes(HttpResponse res, Service_T s) {
        char buf[STRLEN];
        for (Bandwidth_T bl = s->downloadbyteslist; bl; bl = bl->next) {
                if (bl->range == Time_Second) {
                        StringBuffer_append(res->outputbuffer, "<tr class='rule'><td>Download bytes</td><td>");
                        Util_printRule(res->outputbuffer, bl->action, "If %s %s/s", operatornames[bl->operator], Str_bytesToSize(bl->limit, buf));
                } else {
                        StringBuffer_append(res->outputbuffer, "<tr class='rule'><td>Total download bytes</td><td>");
                        Util_printRule(res->outputbuffer, bl->action, "If %s %s in last %d %s(s)", operatornames[bl->operator], Str_bytesToSize(bl->limit, buf), bl->rangecount, Util_timestr(bl->range));
                }
                StringBuffer_append(res->outputbuffer, "</td></tr>");
        }
}


static void print_service_rules_downloadpackets(HttpResponse res, Service_T s) {
        for (Bandwidth_T bl = s->downloadpacketslist; bl; bl = bl->next) {
                if (bl->range == Time_Second) {
                        StringBuffer_append(res->outputbuffer, "<tr class='rule'><td>Download packets</td><td>");
                        Util_printRule(res->outputbuffer, bl->action, "If %s %lld packets/s", operatornames[bl->operator], bl->limit);
                } else {
                        StringBuffer_append(res->outputbuffer, "<tr class='rule'><td>Total download packets</td><td>");
                        Util_printRule(res->outputbuffer, bl->action, "If %s %lld packets in last %d %s(s)", operatornames[bl->operator], bl->limit, bl->rangecount, Util_timestr(bl->range));
                }
                StringBuffer_append(res->outputbuffer, "</td></tr>");
        }
}


static void print_service_rules_uptime(HttpResponse res, Service_T s) {
        for (Uptime_T ul = s->uptimelist; ul; ul = ul->next) {
                StringBuffer_append(res->outputbuffer, "<tr class='rule'><td>Uptime</td><td>");
                Util_printRule(res->outputbuffer, ul->action, "If %s %llu second(s)", operatornames[ul->operator], ul->uptime);
                StringBuffer_append(res->outputbuffer, "</td></tr>");
        }
}

static void print_service_rules_match(HttpResponse res, Service_T s) {
        if (s->type != Service_Process) {
                for (Match_T ml = s->matchignorelist; ml; ml = ml->next) {
                        StringBuffer_append(res->outputbuffer, "<tr class='rule'><td>Ignore pattern</td><td>");
                        Util_printRule(res->outputbuffer, ml->action, "If %smatch \"%s\"", ml->not ? "not " : "", ml->match_string);
                        StringBuffer_append(res->outputbuffer, "</td></tr>");
                }
                for (Match_T ml = s->matchlist; ml; ml = ml->next) {
                        StringBuffer_append(res->outputbuffer, "<tr class='rule'><td>Pattern</td><td>");
                        Util_printRule(res->outputbuffer, ml->action, "If %smatch \"%s\"", ml->not ? "not " : "", ml->match_string);
                        StringBuffer_append(res->outputbuffer, "</td></tr>");
                }
        }
}


static void print_service_rules_checksum(HttpResponse res, Service_T s) {
        if (s->checksum) {
                StringBuffer_append(res->outputbuffer, "<tr class='rule'><td>Checksum</td><td>");
                if (s->checksum->test_changes)
                        Util_printRule(res->outputbuffer, s->checksum->action, "If changed %s", checksumnames[s->checksum->type]);
                else
                        Util_printRule(res->outputbuffer, s->checksum->action, "If failed %s(%s)", s->checksum->hash, checksumnames[s->checksum->type]);
                StringBuffer_append(res->outputbuffer, "</td></tr>");
        }
}


static void print_service_rules_pid(HttpResponse res, Service_T s) {
        for (Pid_T l = s->pidlist; l; l = l->next) {
                StringBuffer_append(res->outputbuffer, "<tr class='rule'><td>PID</td><td>");
                Util_printRule(res->outputbuffer, l->action, "If changed");
                StringBuffer_append(res->outputbuffer, "</td></tr>");
        }
}


static void print_service_rules_ppid(HttpResponse res, Service_T s) {
        for (Pid_T l = s->ppidlist; l; l = l->next) {
                StringBuffer_append(res->outputbuffer, "<tr class='rule'><td>PPID</td><td>");
                Util_printRule(res->outputbuffer, l->action, "If changed");
                StringBuffer_append(res->outputbuffer, "</td></tr>");
        }
}


static void print_service_rules_program(HttpResponse res, Service_T s) {
        if (s->type == Service_Program) {
                StringBuffer_append(res->outputbuffer, "<tr class='rule'><td>Program timeout</td><td>Terminate the program if not finished within %d seconds</td></tr>", s->program->timeout);
                for (Status_T status = s->statuslist; status; status = status->next) {
                        StringBuffer_append(res->outputbuffer, "<tr class='rule'><td>Test Exit value</td><td>");
                        if (status->operator == Operator_Changed)
                                Util_printRule(res->outputbuffer, status->action, "If exit value changed");
                        else
                                Util_printRule(res->outputbuffer, status->action, "If exit value %s %d", operatorshortnames[status->operator], status->return_value);
                        StringBuffer_append(res->outputbuffer, "</td></tr>");
                }
        }
}


static void print_service_rules_resource(HttpResponse res, Service_T s) {
        char buf[STRLEN];
        for (Resource_T q = s->resourcelist; q; q = q->next) {
                StringBuffer_append(res->outputbuffer, "<tr class='rule'><td>");
                switch (q->resource_id) {
                        case Resource_CpuPercent:
                                StringBuffer_append(res->outputbuffer, "CPU usage limit");
                                break;

                        case Resource_CpuPercentTotal:
                                StringBuffer_append(res->outputbuffer, "CPU usage limit (incl. children)");
                                break;

                        case Resource_CpuUser:
                                StringBuffer_append(res->outputbuffer, "CPU user limit");
                                break;

                        case Resource_CpuSystem:
                                StringBuffer_append(res->outputbuffer, "CPU system limit");
                                break;

                        case Resource_CpuWait:
                                StringBuffer_append(res->outputbuffer, "CPU wait limit");
                                break;

                        case Resource_MemoryPercent:
                                StringBuffer_append(res->outputbuffer, "Memory usage limit");
                                break;

                        case Resource_MemoryKbyte:
                                StringBuffer_append(res->outputbuffer, "Memory amount limit");
                                break;

                        case Resource_SwapPercent:
                                StringBuffer_append(res->outputbuffer, "Swap usage limit");
                                break;

                        case Resource_SwapKbyte:
                                StringBuffer_append(res->outputbuffer, "Swap amount limit");
                                break;

                        case Resource_LoadAverage1m:
                                StringBuffer_append(res->outputbuffer, "Load average (1min)");
                                break;

                        case Resource_LoadAverage5m:
                                StringBuffer_append(res->outputbuffer, "Load average (5min)");
                                break;

                        case Resource_LoadAverage15m:
                                StringBuffer_append(res->outputbuffer, "Load average (15min)");
                                break;

                        case Resource_Children:
                                StringBuffer_append(res->outputbuffer, "Children");
                                break;

                        case Resource_MemoryKbyteTotal:
                                StringBuffer_append(res->outputbuffer, "Memory amount limit (incl. children)");
                                break;

                        case Resource_MemoryPercentTotal:
                                StringBuffer_append(res->outputbuffer, "Memory usage limit (incl. children)");
                                break;
                        default:
                                break;
                }
                StringBuffer_append(res->outputbuffer, "</td><td>");
                switch (q->resource_id) {
                        case Resource_CpuPercent:
                        case Resource_CpuPercentTotal:
                        case Resource_MemoryPercentTotal:
                        case Resource_CpuUser:
                        case Resource_CpuSystem:
                        case Resource_CpuWait:
                        case Resource_MemoryPercent:
                        case Resource_SwapPercent:
                                Util_printRule(res->outputbuffer, q->action, "If %s %.1f%%", operatornames[q->operator], q->limit / 10.);
                                break;

                        case Resource_MemoryKbyte:
                        case Resource_SwapKbyte:
                        case Resource_MemoryKbyteTotal:
                                Util_printRule(res->outputbuffer, q->action, "If %s %s", operatornames[q->operator], Str_bytesToSize(q->limit * 1024., buf));
                                break;

                        case Resource_LoadAverage1m:
                        case Resource_LoadAverage5m:
                        case Resource_LoadAverage15m:
                                Util_printRule(res->outputbuffer, q->action, "If %s %.1f", operatornames[q->operator], q->limit / 10.);
                                break;

                        case Resource_Children:
                                Util_printRule(res->outputbuffer, q->action, "If %s %ld", operatornames[q->operator], q->limit);
                                break;
                        default:
                                break;
                }
                StringBuffer_append(res->outputbuffer, "</td></tr>");
        }
}


static void print_service_status_port(HttpResponse res, Service_T s) {
        int status = Util_hasServiceStatus(s);
        for (Port_T p = s->portlist; p; p = p->next) {
                StringBuffer_append(res->outputbuffer, "<tr><td>Port Response time</td>");
                if (! status)
                        StringBuffer_append(res->outputbuffer, "<td>-<td>");
                else if (! p->is_available)
                        StringBuffer_append(res->outputbuffer, "<td class='red-text'>failed to [%s]:%d%s type %s/%s protocol %s</td>", p->hostname, p->port, p->request ? p->request : "", Util_portTypeDescription(p), Util_portIpDescription(p), p->protocol->name);
                else
                        StringBuffer_append(res->outputbuffer, "<td>%.3fs to %s:%d%s type %s/%s protocol %s</td>", p->response, p->hostname, p->port, p->request ? p->request : "", Util_portTypeDescription(p), Util_portIpDescription(p), p->protocol->name);
                StringBuffer_append(res->outputbuffer, "</tr>");
        }
}


static void print_service_status_socket(HttpResponse res, Service_T s) {
        int status = Util_hasServiceStatus(s);
        for (Port_T p = s->socketlist; p; p = p->next) {
                StringBuffer_append(res->outputbuffer, "<tr><td>Unix Socket Response time</td>");
                if (! status)
                        StringBuffer_append(res->outputbuffer, "<td>-<td>");
                else if (! p->is_available)
                        StringBuffer_append(res->outputbuffer, "<td class='red-text'>failed to %s type %s protocol %s</td>", p->pathname, Util_portTypeDescription(p), p->protocol->name);
                else
                        StringBuffer_append(res->outputbuffer, "<td>%.3fs to %s type %s protocol %s</td>", p->response, p->pathname, Util_portTypeDescription(p), p->protocol->name);
                StringBuffer_append(res->outputbuffer, "</tr>");
        }
}


static void print_service_status_icmp(HttpResponse res, Service_T s) {
        int status = Util_hasServiceStatus(s);
        for (Icmp_T i = s->icmplist; i; i = i->next) {
                StringBuffer_append(res->outputbuffer, "<tr><td>Ping Response time</td>");
                if (! status)
                        StringBuffer_append(res->outputbuffer, "<td>-</td>");
                else if (! i->is_available)
                        StringBuffer_append(res->outputbuffer, "<td class='red-text'>connection failed</td>");
                else if (i->response < 0)
                        StringBuffer_append(res->outputbuffer, "<td class='gray-text'>N/A</td>");
                else
                        StringBuffer_append(res->outputbuffer, "<td>%.3fs</td>", i->response);
                StringBuffer_append(res->outputbuffer, "</tr>");
        }
}


static void print_service_status_perm(HttpResponse res, Service_T s, mode_t mode) {
        StringBuffer_append(res->outputbuffer, "<tr><td>Permission</td>");
        if (! Util_hasServiceStatus(s))
                StringBuffer_append(res->outputbuffer, "<td>-</td>");
        else
                StringBuffer_append(res->outputbuffer, "<td class='%s'>%o</td>", (s->error & Event_Permission) ? "red-text" : "", mode & 07777);
        StringBuffer_append(res->outputbuffer, "</tr>");
}


static void print_service_status_uid(HttpResponse res, Service_T s, uid_t uid) {
        StringBuffer_append(res->outputbuffer, "<tr><td>UID</td>");
        if (! Util_hasServiceStatus(s))
                StringBuffer_append(res->outputbuffer, "<td>-</td>");
        else
                StringBuffer_append(res->outputbuffer, "<td class='%s'>%d</td>", (s->error & Event_Uid) ? "red-text" : "", (int)uid);
        StringBuffer_append(res->outputbuffer, "</tr>");
}


static void print_service_status_gid(HttpResponse res, Service_T s, gid_t gid) {
        StringBuffer_append(res->outputbuffer, "<tr><td>GID</td>");
        if (! Util_hasServiceStatus(s))
                StringBuffer_append(res->outputbuffer, "<td>-</td>");
        else
                StringBuffer_append(res->outputbuffer, "<td class='%s'>%d</td>", (s->error & Event_Gid) ? "red-text" : "", (int)gid);
        StringBuffer_append(res->outputbuffer, "</tr>");
}


static void print_service_status_link(HttpResponse res, Service_T s) {
        StringBuffer_append(res->outputbuffer, "<tr><td>Link capacity</td>");
        if (! Util_hasServiceStatus(s) || Link_getState(s->inf->priv.net.stats) != 1) {
                StringBuffer_append(res->outputbuffer, "<td>-</td>");
        } else {
                long long speed = Link_getSpeed(s->inf->priv.net.stats);
                if (speed > 0)
                        StringBuffer_append(res->outputbuffer, "<td class='%s'>%.0lf Mb&#47;s %s-duplex</td>", s->error & Event_Speed ? "red-text" : "", (double)speed / 1000000., Link_getDuplex(s->inf->priv.net.stats) == 1 ? "full" : "half");
                else
                        StringBuffer_append(res->outputbuffer, "<td class='gray-text'>N/A for this link type</td>");
        }
        StringBuffer_append(res->outputbuffer, "</tr>");
}


static void print_service_status_download(HttpResponse res, Service_T s) {
        StringBuffer_append(res->outputbuffer, "<tr><td>Download</td>");
        if (! Util_hasServiceStatus(s) || Link_getState(s->inf->priv.net.stats) != 1) {
                StringBuffer_append(res->outputbuffer, "<td>-</td>");
        } else {
                char buf[STRLEN];
                long long speed = Link_getSpeed(s->inf->priv.net.stats);
                long long ibytes = Link_getBytesInPerSecond(s->inf->priv.net.stats);
                StringBuffer_append(res->outputbuffer, "<td class='%s'>%s/s [%lld packets/s] [%lld errors]",
                                    (s->error & Event_ByteIn || s->error & Event_PacketIn) ? "red-text" : "",
                                    Str_bytesToSize(ibytes, buf),
                                    Link_getPacketsInPerSecond(s->inf->priv.net.stats),
                                    Link_getErrorsInPerSecond(s->inf->priv.net.stats));
                if (speed > 0 && ibytes > 0)
                        StringBuffer_append(res->outputbuffer, " (%.1f%% link saturation)", 100. * ibytes * 8 / (double)speed);
                StringBuffer_append(res->outputbuffer, "</td>");
        }
        StringBuffer_append(res->outputbuffer, "</tr>");
}


static void print_service_status_upload(HttpResponse res, Service_T s) {
        StringBuffer_append(res->outputbuffer, "<tr><td>Upload</td>");
        if (! Util_hasServiceStatus(s) || Link_getState(s->inf->priv.net.stats) != 1) {
                StringBuffer_append(res->outputbuffer, "<td>-</td>");
        } else {
                char buf[STRLEN];
                long long speed = Link_getSpeed(s->inf->priv.net.stats);
                long long obytes = Link_getBytesOutPerSecond(s->inf->priv.net.stats);
                StringBuffer_append(res->outputbuffer, "<td class='%s'>%s/s [%lld packets/s] [%lld errors]",
                                    (s->error & Event_ByteOut || s->error & Event_PacketOut) ? "red-text" : "",
                                    Str_bytesToSize(obytes, buf),
                                    Link_getPacketsOutPerSecond(s->inf->priv.net.stats),
                                    Link_getErrorsOutPerSecond(s->inf->priv.net.stats));
                if (speed > 0 && obytes > 0)
                        StringBuffer_append(res->outputbuffer, " (%.1f%% link saturation)", 100. * obytes * 8 / (double)speed);
                StringBuffer_append(res->outputbuffer, "</td>");
        }
        StringBuffer_append(res->outputbuffer, "</tr>");
}


static void print_service_status_timestamp(HttpResponse res, Service_T s, time_t timestamp) {
        StringBuffer_append(res->outputbuffer, "<tr><td>Timestamp</td>");
        if (! Util_hasServiceStatus(s)) {
                StringBuffer_append(res->outputbuffer, "<td>-</td>");
        } else {
                char t[32];
                StringBuffer_append(res->outputbuffer, "<td class='%s'>%s</td>", (s->error & Event_Timestamp) ? "red-text" : "", Time_string(timestamp, t));
        }
        StringBuffer_append(res->outputbuffer, "</tr>");
}


static void print_service_status_filesystem_flags(HttpResponse res, Service_T s) {
        StringBuffer_append(res->outputbuffer, "<tr><td>Filesystem flags</td>");
        if (! Util_hasServiceStatus(s))
                StringBuffer_append(res->outputbuffer, "<td>-</td>");
        else
                StringBuffer_append(res->outputbuffer, "<td>0x%x</td>", s->inf->priv.filesystem.flags);
        StringBuffer_append(res->outputbuffer, "</tr>");
}


static void print_service_status_filesystem_blockstotal(HttpResponse res, Service_T s) {
        StringBuffer_append(res->outputbuffer, "<tr><td>Space total</td>");
        if (! Util_hasServiceStatus(s)) {
                StringBuffer_append(res->outputbuffer, "<td>-</td>");
        } else {
                char buf[STRLEN];
                StringBuffer_append(res->outputbuffer, "<td>%s (of which %.1f%% is reserved for root user)</td>",
                                    s->inf->priv.filesystem.f_bsize > 0 ? Str_bytesToSize(s->inf->priv.filesystem.f_blocks * s->inf->priv.filesystem.f_bsize, buf) : "0 MB",
                                    s->inf->priv.filesystem.f_blocks > 0 ? ((float)100 * (float)(s->inf->priv.filesystem.f_blocksfreetotal - s->inf->priv.filesystem.f_blocksfree) / (float)s->inf->priv.filesystem.f_blocks) : 0);
        }
        StringBuffer_append(res->outputbuffer, "</tr>");
}


static void print_service_status_filesystem_blocksfree(HttpResponse res, Service_T s) {
        StringBuffer_append(res->outputbuffer, "<tr><td>Space free for non superuser</td>");
        if (! Util_hasServiceStatus(s)) {
                StringBuffer_append(res->outputbuffer, "<td>-</td>");
        } else {
                char buf[STRLEN];
                StringBuffer_append(res->outputbuffer, "<td>%s [%.1f%%]</td>",
                                    s->inf->priv.filesystem.f_bsize > 0 ? Str_bytesToSize(s->inf->priv.filesystem.f_blocksfree * s->inf->priv.filesystem.f_bsize, buf) : "0 MB",
                                    s->inf->priv.filesystem.f_blocks > 0 ? ((float)100 * (float)s->inf->priv.filesystem.f_blocksfree / (float)s->inf->priv.filesystem.f_blocks) : 0);
        }
        StringBuffer_append(res->outputbuffer, "</tr>");
}


static void print_service_status_filesystem_blocksfreetotal(HttpResponse res, Service_T s) {
        StringBuffer_append(res->outputbuffer, "<tr><td>Space free total</td>");
        if (! Util_hasServiceStatus(s)) {
                StringBuffer_append(res->outputbuffer, "<td>-</td>");
        } else {
                char buf[STRLEN];
                StringBuffer_append(res->outputbuffer,
                                    "<td class='%s'>%s [%.1f%%]</td>", (s->error & Event_Resource) ? "red-text" : "",
                                    s->inf->priv.filesystem.f_bsize > 0 ? Str_bytesToSize(s->inf->priv.filesystem.f_blocksfreetotal * s->inf->priv.filesystem.f_bsize, buf) : "0 MB",
                                    s->inf->priv.filesystem.f_blocks > 0 ? ((float)100 * (float)s->inf->priv.filesystem.f_blocksfreetotal / (float)s->inf->priv.filesystem.f_blocks) : 0);
        }
        StringBuffer_append(res->outputbuffer, "</tr>");
}


static void print_service_status_filesystem_blocksize(HttpResponse res, Service_T s) {
        StringBuffer_append(res->outputbuffer, "<tr><td>Block size</td>");
        if (! Util_hasServiceStatus(s)) {
                StringBuffer_append(res->outputbuffer, "<td>-</td>");
        } else {
                char buf[STRLEN];
                StringBuffer_append(res->outputbuffer, "<td>%s</td>", Str_bytesToSize(s->inf->priv.filesystem.f_bsize, buf));
        }
        StringBuffer_append(res->outputbuffer, "</tr>");
}


static void print_service_status_filesystem_inodestotal(HttpResponse res, Service_T s) {
        StringBuffer_append(res->outputbuffer, "<tr><td>Inodes total</td>");
        if (! Util_hasServiceStatus(s)) {
                StringBuffer_append(res->outputbuffer, "<td>-</td>");
        } else {
                if (s->inf->priv.filesystem.f_files > 0)
                        StringBuffer_append(res->outputbuffer, "<td>%lld</td>", s->inf->priv.filesystem.f_files);
                else
                        StringBuffer_append(res->outputbuffer, "<td class='gray-text'>N/A</td>");
        }
        StringBuffer_append(res->outputbuffer, "</tr>");
}


static void print_service_status_filesystem_inodesfree(HttpResponse res, Service_T s) {
        StringBuffer_append(res->outputbuffer, "<tr><td>Inodes free</td>");
        if (! Util_hasServiceStatus(s)) {
                StringBuffer_append(res->outputbuffer, "<td>-</td>");
        } else {
                if (s->inf->priv.filesystem.f_files > 0)
                        StringBuffer_append(res->outputbuffer, "<td class='%s'>%lld [%.1f%%]</td>", (s->error & Event_Resource) ? "red-text" : "", s->inf->priv.filesystem.f_filesfree, (float)100 * (float)s->inf->priv.filesystem.f_filesfree / (float)s->inf->priv.filesystem.f_files);
                else
                        StringBuffer_append(res->outputbuffer, "<td class='gray-text'>N/A</td>");
        }
        StringBuffer_append(res->outputbuffer, "</tr>");
}


static void print_service_status_file_size(HttpResponse res, Service_T s) {
        StringBuffer_append(res->outputbuffer, "<tr><td>Size</td>");
        if (! Util_hasServiceStatus(s)) {
                StringBuffer_append(res->outputbuffer, "<td>-</td>");
        } else {
                char buf[STRLEN];
                StringBuffer_append(res->outputbuffer, "<td class='%s'>%s</td>", (s->error & Event_Size) ? "red-text" : "", Str_bytesToSize(s->inf->priv.file.size, buf));
        }
        StringBuffer_append(res->outputbuffer, "</tr>");
}

static void print_service_status_file_match(HttpResponse res, Service_T s) {
        StringBuffer_append(res->outputbuffer, "<tr><td>Match regex</td>");
        if (! Util_hasServiceStatus(s))
                StringBuffer_append(res->outputbuffer, "<td>-</td>");
        else
                StringBuffer_append(res->outputbuffer, "<td class='%s'>%s</td>", (s->error & Event_Content) ? "red-text" : "", (s->error & Event_Content) ? "yes" : "no");
        StringBuffer_append(res->outputbuffer, "</tr>");
}


static void print_service_status_file_checksum(HttpResponse res, Service_T s) {
        if (s->checksum) {
                StringBuffer_append(res->outputbuffer, "<tr><td>Checksum</td>");
                if (! Util_hasServiceStatus(s))
                        StringBuffer_append(res->outputbuffer, "<td>-</td>");
                else
                        StringBuffer_append(res->outputbuffer, "<td class='%s'>%s(%s)</td>", (s->error & Event_Checksum) ? "red-text" : "", s->inf->priv.file.cs_sum, checksumnames[s->checksum->type]);
                StringBuffer_append(res->outputbuffer, "</tr>");
        }
}


static void print_service_status_process_pid(HttpResponse res, Service_T s) {
        StringBuffer_append(res->outputbuffer, "<tr><td>Process id</td>");
        if (! Util_hasServiceStatus(s))
                StringBuffer_append(res->outputbuffer, "<td>-</td>");
        else
                StringBuffer_append(res->outputbuffer, "<td>%d</td>", s->inf->priv.process.pid > 0 ? s->inf->priv.process.pid : 0);
        StringBuffer_append(res->outputbuffer, "</tr>");
}


static void print_service_status_process_ppid(HttpResponse res, Service_T s) {
        StringBuffer_append(res->outputbuffer, "<tr><td>Parent process id</td>");
        if (! Util_hasServiceStatus(s))
                StringBuffer_append(res->outputbuffer, "<td>-</td>");
        else
                StringBuffer_append(res->outputbuffer, "<td>%d</td>", s->inf->priv.process.ppid > 0 ? s->inf->priv.process.ppid : 0);
        StringBuffer_append(res->outputbuffer, "</tr>");
}


static void print_service_status_process_euid(HttpResponse res, Service_T s) {
        StringBuffer_append(res->outputbuffer, "<tr><td>Effective UID</td>");
        if (! Util_hasServiceStatus(s))
                StringBuffer_append(res->outputbuffer, "<td>-</td>");
        else
                StringBuffer_append(res->outputbuffer, "<td>%d</td>", s->inf->priv.process.euid);
        StringBuffer_append(res->outputbuffer, "</tr>");
}


static void print_service_status_process_uptime(HttpResponse res, Service_T s) {
        StringBuffer_append(res->outputbuffer, "<tr><td>Process uptime</td>");
        if (! Util_hasServiceStatus(s)) {
                StringBuffer_append(res->outputbuffer, "<td>-</td>");
        } else {
                char *uptime = Util_getUptime(s->inf->priv.process.uptime, "&nbsp;");
                StringBuffer_append(res->outputbuffer, "<td>%s</td>", uptime);
                FREE(uptime);
        }
        StringBuffer_append(res->outputbuffer, "</tr>");
}


static void print_service_status_process_children(HttpResponse res, Service_T s) {
        if (Run.doprocess) {
                StringBuffer_append(res->outputbuffer, "<tr><td>Children</td>");
                if (! Util_hasServiceStatus(s))
                        StringBuffer_append(res->outputbuffer, "<td>-</td>");
                else
                        StringBuffer_append(res->outputbuffer, "<td class='%s'>%d</td>", (s->error & Event_Resource) ? "red-text" : "", s->inf->priv.process.children);
                StringBuffer_append(res->outputbuffer, "</tr>");
        }
}


static void print_service_status_process_cpu(HttpResponse res, Service_T s) {
        if (Run.doprocess) {
                StringBuffer_append(res->outputbuffer, "<tr><td>CPU usage</td>");
                if (! Util_hasServiceStatus(s))
                        StringBuffer_append(res->outputbuffer, "<td>-</td>");
                else
                        StringBuffer_append(res->outputbuffer, "<td class='%s'>%.1f%% (Usage / Number of CPUs)</td>", (s->error & Event_Resource) ? "red-text" : "", s->inf->priv.process.cpu_percent/10.0);
                StringBuffer_append(res->outputbuffer, "</tr>");
        }
}


static void print_service_status_process_cputotal(HttpResponse res, Service_T s) {
        if (Run.doprocess) {
                StringBuffer_append(res->outputbuffer, "<tr><td>Total CPU usage (incl. children)</td>");
                if (! Util_hasServiceStatus(s))
                        StringBuffer_append(res->outputbuffer, "<td>-</td>");
                else
                        StringBuffer_append(res->outputbuffer, "<td class='%s'>%.1f%%</td>", (s->error & Event_Resource) ? "red-text"  :"", s->inf->priv.process.total_cpu_percent/10.0);
                StringBuffer_append(res->outputbuffer, "</tr>");
        }
}


static void print_service_status_process_memory(HttpResponse res, Service_T s) {
        if (Run.doprocess) {
                StringBuffer_append(res->outputbuffer, "<tr><td>Memory usage</td>");
                if (! Util_hasServiceStatus(s)) {
                        StringBuffer_append(res->outputbuffer, "<td>-</td>");
                } else {
                        char buf[STRLEN];
                        StringBuffer_append(res->outputbuffer, "<td class='%s'>%.1f%% [%s]</td>", (s->error & Event_Resource) ? "red-text" : "", s->inf->priv.process.mem_percent/10.0, Str_bytesToSize(s->inf->priv.process.mem_kbyte * 1024., buf));
                }
                StringBuffer_append(res->outputbuffer, "</tr>");
        }
}


static void print_service_status_process_memorytotal(HttpResponse res, Service_T s) {
        if (Run.doprocess) {
                StringBuffer_append(res->outputbuffer, "<tr><td>Total memory usage (incl. children)</td>");
                if (! Util_hasServiceStatus(s)) {
                        StringBuffer_append(res->outputbuffer, "<td>-</td>");
                } else {
                        char buf[STRLEN];
                        StringBuffer_append(res->outputbuffer, "<td class='%s'>%.1f%% [%s]</td>", (s->error & Event_Resource) ? "red-text" : "", s->inf->priv.process.total_mem_percent/10.0, Str_bytesToSize(s->inf->priv.process.total_mem_kbyte * 1024., buf));
                }
                StringBuffer_append(res->outputbuffer, "</tr>");
        }
}


static void print_service_status_system_loadavg(HttpResponse res, Service_T s) {
        StringBuffer_append(res->outputbuffer, "<tr><td>Load average</td>");
        if (! Util_hasServiceStatus(s))
                StringBuffer_append(res->outputbuffer, "<td>-</td>");
        else
                StringBuffer_append(res->outputbuffer, "<td class='%s'>[%.2f] [%.2f] [%.2f]</td>", (s->error & Event_Resource) ? "red-text" : "", systeminfo.loadavg[0], systeminfo.loadavg[1], systeminfo.loadavg[2]);
        StringBuffer_append(res->outputbuffer, "</tr>");
}


static void print_service_status_system_cpu(HttpResponse res, Service_T s) {
        StringBuffer_append(res->outputbuffer, "<tr><td>CPU usage</td>");
        if (! Util_hasServiceStatus(s)) {
                StringBuffer_append(res->outputbuffer, "<td>-</td>");
        } else {
                StringBuffer_append(res->outputbuffer,
                                    "<td class='%s'>%.1f%%us %.1f%%sy"
#ifdef HAVE_CPU_WAIT
                                    " %.1f%%wa"
#endif
                                    "%s",
                                    (s->error & Event_Resource) ? "red-text" : "",
                                    systeminfo.total_cpu_user_percent > 0 ? systeminfo.total_cpu_user_percent / 10. : 0,
                                    systeminfo.total_cpu_syst_percent > 0 ? systeminfo.total_cpu_syst_percent / 10. : 0,
#ifdef HAVE_CPU_WAIT
                                    systeminfo.total_cpu_wait_percent > 0 ? systeminfo.total_cpu_wait_percent / 10. : 0,
#endif
                                    "</td>");
        }
        StringBuffer_append(res->outputbuffer, "</tr>");
}


static void print_service_status_system_memory(HttpResponse res, Service_T s) {
        StringBuffer_append(res->outputbuffer, "<tr><td>Memory usage</td>");
        if (! Util_hasServiceStatus(s)) {
                StringBuffer_append(res->outputbuffer, "<td>-</td>");
        } else {
                char buf[STRLEN];
                StringBuffer_append(res->outputbuffer, "<td class='%s'>%s [%.1f%%]</td>", (s->error & Event_Resource) ? "red-text" : "", Str_bytesToSize(systeminfo.total_mem_kbyte * 1024., buf), systeminfo.total_mem_percent / 10.);
        }
        StringBuffer_append(res->outputbuffer, "</tr>");
}


static void print_service_status_system_swap(HttpResponse res, Service_T s) {
        StringBuffer_append(res->outputbuffer, "<tr><td>Swap usage</td>");
        if (! Util_hasServiceStatus(s)) {
                StringBuffer_append(res->outputbuffer, "<td>-</td>");
        } else {
                char buf[STRLEN];
                StringBuffer_append(res->outputbuffer, "<td class='%s'>%s [%.1f%%]</td>", (s->error & Event_Resource) ? "red-text" : "", Str_bytesToSize(systeminfo.total_swap_kbyte * 1024., buf), systeminfo.total_swap_percent/10.);
        }
        StringBuffer_append(res->outputbuffer, "</tr>");
}


static void print_service_status_program_started(HttpResponse res, Service_T s) {
        StringBuffer_append(res->outputbuffer, "<tr><td>Last started</td>");
        if (! Util_hasServiceStatus(s)) {
                StringBuffer_append(res->outputbuffer, "<td>-</td>");
        } else {
                if (s->program->started) {
                        char t[32];
                        StringBuffer_append(res->outputbuffer, "<td>%s</td>", Time_string(s->program->started, t));
                } else {
                        StringBuffer_append(res->outputbuffer, "<td>Not yet started</td>");
                }
        }
        StringBuffer_append(res->outputbuffer, "</tr>");
}


static void print_service_status_program_status(HttpResponse res, Service_T s) {
        StringBuffer_append(res->outputbuffer, "<tr><td>Last exit value</td>");
        if (! Util_hasServiceStatus(s)) {
                StringBuffer_append(res->outputbuffer, "<td>-</td>");
        } else {
                if (s->program->started)
                        StringBuffer_append(res->outputbuffer, "<td>%d</td>", s->program->exitStatus);
                else
                        StringBuffer_append(res->outputbuffer, "<td class='gray-text'>N/A</td>");
        }
        StringBuffer_append(res->outputbuffer, "</tr>");
}


static void print_service_status_program_output(HttpResponse res, Service_T s) {
        StringBuffer_append(res->outputbuffer, "<tr><td>Last output</td>");
        if (! Util_hasServiceStatus(s)) {
                StringBuffer_append(res->outputbuffer, "<td>-</td>");
        } else {
                if (s->program->started) {
                        StringBuffer_append(res->outputbuffer, "<td>");
                        if (StringBuffer_length(s->program->output)) {
                                // If the output contains multiple line, wrap use <pre>, otherwise keep as is
                                int multiline = StringBuffer_lastIndexOf(s->program->output, "\n") > 0;
                                if (multiline)
                                        StringBuffer_append(res->outputbuffer, "<pre>");
                                escapeHTML(res->outputbuffer, StringBuffer_toString(s->program->output));
                                if (multiline)
                                        StringBuffer_append(res->outputbuffer, "</pre>");
                        } else {
                                StringBuffer_append(res->outputbuffer, "no output");
                        }
                        StringBuffer_append(res->outputbuffer, "</td>");
                } else {
                        StringBuffer_append(res->outputbuffer, "<td class='gray-text'>N/A</td>");
                }
        }
        StringBuffer_append(res->outputbuffer, "</tr>");
}


static boolean_t is_readonly(HttpRequest req) {
        if (req->remote_user) {
                Auth_T user_creds = Util_getUserCredentials(req->remote_user);
                return (user_creds ? user_creds->is_readonly : true);
        }
        return false;
}


/* ----------------------------------------------------------- Status output */


/* Print status in the given format. Text status is default. */
static void print_status(HttpRequest req, HttpResponse res, int version) {
        Level_Type level = Level_Full;
        const char *stringFormat = get_parameter(req, "format");
        const char *stringLevel = get_parameter(req, "level");

        if (stringLevel && Str_startsWith(stringLevel, LEVEL_NAME_SUMMARY))
                level = Level_Summary;

        if (stringFormat && Str_startsWith(stringFormat, "xml")) {
                char buf[STRLEN];
                StringBuffer_T sb = StringBuffer_create(256);
                status_xml(sb, NULL, level, version, Socket_getLocalHost(req->S, buf, sizeof(buf)));
                StringBuffer_append(res->outputbuffer, "%s", StringBuffer_toString(sb));
                StringBuffer_free(&sb);
                set_content_type(res, "text/xml");
        } else {
                char *uptime = Util_getUptime(getProcessUptime(getpid(), ptree, ptreesize), " ");
                StringBuffer_append(res->outputbuffer, "The Monit daemon %s uptime: %s\n\n", VERSION, uptime);
                FREE(uptime);

                for (Service_T s = servicelist_conf; s; s = s->next_conf)
                        status_service_txt(s, res, level);
                set_content_type(res, "text/plain");
        }
}


static void status_service_txt(Service_T s, HttpResponse res, Level_Type level) {
        char buf[STRLEN];
        if (level == Level_Summary) {
                char prefix[STRLEN];
                snprintf(prefix, STRLEN, "%s '%s'", servicetypes[s->type], s->name);
                StringBuffer_append(res->outputbuffer, "%-35s %s\n", prefix, get_service_status(s, buf, sizeof(buf)));
        } else {
                StringBuffer_append(res->outputbuffer,
                                    "%s '%s'\n"
                                    "  %-33s %s\n",
                                    servicetypes[s->type], s->name,
                                    "status", get_service_status(s, buf, sizeof(buf)));
                StringBuffer_append(res->outputbuffer,
                                    "  %-33s %s\n",
                                    "monitoring status", get_monitoring_status(s, buf, sizeof(buf)));

                char *uptime = NULL;
                if (Util_hasServiceStatus(s)) {
                        switch (s->type) {
                                case Service_File:
                                        StringBuffer_append(res->outputbuffer,
                                                    "  %-33s %o\n"
                                                    "  %-33s %d\n"
                                                    "  %-33s %d\n"
                                                    "  %-33s %s\n"
                                                    "  %-33s %s\n",
                                                    "permission", s->inf->priv.file.mode & 07777,
                                                    "uid", (int)s->inf->priv.file.uid,
                                                    "gid", (int)s->inf->priv.file.gid,
                                                    "size", Str_bytesToSize(s->inf->priv.file.size, buf),
                                                    "timestamp", Time_string(s->inf->priv.file.timestamp, buf));
                                        if (s->checksum) {
                                                StringBuffer_append(res->outputbuffer,
                                                                    "  %-33s %s (%s)\n",
                                                                    "checksum", s->inf->priv.file.cs_sum,
                                                                    checksumnames[s->checksum->type]);
                                        }
                                        break;

                                case Service_Directory:
                                        StringBuffer_append(res->outputbuffer,
                                                    "  %-33s %o\n"
                                                    "  %-33s %d\n"
                                                    "  %-33s %d\n"
                                                    "  %-33s %s\n",
                                                    "permission", s->inf->priv.directory.mode & 07777,
                                                    "uid", (int)s->inf->priv.directory.uid,
                                                    "gid", (int)s->inf->priv.directory.gid,
                                                    "timestamp", Time_string(s->inf->priv.directory.timestamp, buf));
                                        break;

                                case Service_Fifo:
                                        StringBuffer_append(res->outputbuffer,
                                                    "  %-33s %o\n"
                                                    "  %-33s %d\n"
                                                    "  %-33s %d\n"
                                                    "  %-33s %s\n",
                                                    "permission", s->inf->priv.fifo.mode & 07777,
                                                    "uid", (int)s->inf->priv.fifo.uid,
                                                    "gid", (int)s->inf->priv.fifo.gid,
                                                    "timestamp", Time_string(s->inf->priv.fifo.timestamp, buf));
                                        break;

                                case Service_Net:
                                        if (Link_getState(s->inf->priv.net.stats) == 1) {
                                                long long speed = Link_getSpeed(s->inf->priv.net.stats);
                                                if (speed > 0)
                                                        StringBuffer_append(res->outputbuffer,
                                                                            "  %-33s %.0lf Mb/s %s-duplex\n",
                                                                            "link capacity", (double)speed / 1000000., Link_getDuplex(s->inf->priv.net.stats) == 1 ? "full" : "half");
                                                else
                                                        StringBuffer_append(res->outputbuffer,
                                                                            "  %-33s N/A for this link type\n",
                                                                            "link capacity");

                                                long long ibytes = Link_getBytesInPerSecond(s->inf->priv.net.stats);
                                                StringBuffer_append(res->outputbuffer, "  %-33s %s/s [%lld packets/s] [%lld errors]",
                                                                    "download",
                                                                    Str_bytesToSize(ibytes, buf),
                                                                    Link_getPacketsInPerSecond(s->inf->priv.net.stats),
                                                                    Link_getErrorsInPerSecond(s->inf->priv.net.stats));
                                                if (speed > 0 && ibytes > 0)
                                                        StringBuffer_append(res->outputbuffer, " (%.1f%% link saturation)", 100. * ibytes * 8 / (double)speed);
                                                StringBuffer_append(res->outputbuffer, "\n");

                                                long long obytes = Link_getBytesOutPerSecond(s->inf->priv.net.stats);
                                                StringBuffer_append(res->outputbuffer, "  %-33s %s/s [%lld packets/s] [%lld errors]",
                                                                    "upload",
                                                                    Str_bytesToSize(obytes, buf),
                                                                    Link_getPacketsOutPerSecond(s->inf->priv.net.stats),
                                                                    Link_getErrorsOutPerSecond(s->inf->priv.net.stats));
                                                if (speed > 0 && obytes > 0)
                                                        StringBuffer_append(res->outputbuffer, " (%.1f%% link saturation)", 100. * obytes * 8 / (double)speed);
                                                StringBuffer_append(res->outputbuffer, "\n");
                                        }
                                        break;

                                case Service_Filesystem:
                                        StringBuffer_append(res->outputbuffer,
                                                    "  %-33s %o\n"
                                                    "  %-33s %d\n"
                                                    "  %-33s %d\n",
                                                    "permission", s->inf->priv.filesystem.mode & 07777,
                                                    "uid", (int)s->inf->priv.filesystem.uid,
                                                    "gid", (int)s->inf->priv.filesystem.gid);
                                        StringBuffer_append(res->outputbuffer,
                                                            "  %-33s 0x%x\n"
                                                            "  %-33s %s\n",
                                                            "filesystem flags",
                                                            s->inf->priv.filesystem.flags,
                                                            "block size",
                                                            Str_bytesToSize(s->inf->priv.filesystem.f_bsize, buf));
                                        StringBuffer_append(res->outputbuffer,
                                                            "  %-33s %s (of which %.1f%% is reserved for root user)\n",
                                                            "space total",
                                                            s->inf->priv.filesystem.f_bsize > 0 ? Str_bytesToSize((long long)(s->inf->priv.filesystem.f_blocks * s->inf->priv.filesystem.f_bsize), buf) : "0 MB",
                                                            s->inf->priv.filesystem.f_blocks > 0 ? ((float)100 * (float)(s->inf->priv.filesystem.f_blocksfreetotal - s->inf->priv.filesystem.f_blocksfree) / (float)s->inf->priv.filesystem.f_blocks) : 0);
                                        StringBuffer_append(res->outputbuffer,
                                                            "  %-33s %s [%.1f%%]\n",
                                                            "space free for non superuser",
                                                            s->inf->priv.filesystem.f_bsize > 0 ? Str_bytesToSize(s->inf->priv.filesystem.f_blocksfree * s->inf->priv.filesystem.f_bsize, buf) : "0 MB",
                                                            s->inf->priv.filesystem.f_blocks > 0 ? ((float)100 * (float)s->inf->priv.filesystem.f_blocksfree / (float)s->inf->priv.filesystem.f_blocks) : 0);
                                        StringBuffer_append(res->outputbuffer,
                                                            "  %-33s %s [%.1f%%]\n",
                                                            "space free total",
                                                            s->inf->priv.filesystem.f_bsize > 0 ? Str_bytesToSize(s->inf->priv.filesystem.f_blocksfreetotal * s->inf->priv.filesystem.f_bsize, buf) : "0 MB",
                                                            s->inf->priv.filesystem.f_blocks > 0 ? ((float)100 * (float)s->inf->priv.filesystem.f_blocksfreetotal / (float)s->inf->priv.filesystem.f_blocks) : 0);
                                        if (s->inf->priv.filesystem.f_files > 0) {
                                                StringBuffer_append(res->outputbuffer,
                                                                    "  %-33s %lld\n"
                                                                    "  %-33s %lld [%.1f%%]\n",
                                                                    "inodes total",
                                                                    s->inf->priv.filesystem.f_files,
                                                                    "inodes free",
                                                                    s->inf->priv.filesystem.f_filesfree,
                                                                    ((float)100*(float)s->inf->priv.filesystem.f_filesfree/ (float)s->inf->priv.filesystem.f_files));
                                        }
                                        break;

                                case Service_Process:
                                        uptime = Util_getUptime(s->inf->priv.process.uptime, " ");
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
                                        if (Run.doprocess) {
                                                StringBuffer_append(res->outputbuffer,
                                                                    "  %-33s %d\n",
                                                                    "children", s->inf->priv.process.children);
                                                StringBuffer_append(res->outputbuffer,
                                                                    "  %-33s %s\n",
                                                                    "memory", Str_bytesToSize(s->inf->priv.process.mem_kbyte * 1024., buf));
                                                StringBuffer_append(res->outputbuffer,
                                                                    "  %-33s %s\n",
                                                                    "memory total", Str_bytesToSize(s->inf->priv.process.total_mem_kbyte * 1024., buf));
                                                StringBuffer_append(res->outputbuffer,
                                                                    "  %-33s %.1f%%\n"
                                                                    "  %-33s %.1f%%\n"
                                                                    "  %-33s %.1f%%\n"
                                                                    "  %-33s %.1f%%\n",
                                                                    "memory percent", s->inf->priv.process.mem_percent/10.0,
                                                                    "memory percent total", s->inf->priv.process.total_mem_percent/10.0,
                                                                    "cpu percent", s->inf->priv.process.cpu_percent/10.0,
                                                                    "cpu percent total", s->inf->priv.process.total_cpu_percent/10.0);
                                        }
                                        break;

                                default:
                                        break;
                        }
                        for (Icmp_T i = s->icmplist; i; i = i->next) {
                                if (! i->is_available)
                                        StringBuffer_append(res->outputbuffer,
                                                            "  %-33s connection failed\n",
                                                            "ping response time");
                                else if (i->response < 0)
                                        StringBuffer_append(res->outputbuffer,
                                                            "  %-33s N/A\n",
                                                            "ping response time");
                                else
                                        StringBuffer_append(res->outputbuffer,
                                                            "  %-33s %.3fs\n",
                                                            "ping response time", i->response);
                        }
                        for (Port_T p = s->portlist; p; p = p->next) {
                                if (p->is_available)
                                        StringBuffer_append(res->outputbuffer,
                                                    "  %-33s %.3fs to [%s]:%d%s type %s/%s protocol %s\n",
                                                    "port response time", p->response, p->hostname, p->port, p->request ? p->request : "", Util_portTypeDescription(p), Util_portIpDescription(p), p->protocol->name);
                                else
                                        StringBuffer_append(res->outputbuffer,
                                                    "  %-33s FAILED to [%s]:%d%s type %s/%s protocol %s\n",
                                                    "port response time", p->hostname, p->port, p->request ? p->request : "", Util_portTypeDescription(p), Util_portIpDescription(p), p->protocol->name);
                        }
                        for (Port_T p = s->socketlist; p; p = p->next) {
                                if (p->is_available)
                                        StringBuffer_append(res->outputbuffer,
                                                    "  %-33s %.3fs to %s type %s protocol %s\n",
                                                    "unix socket response time", p->response, p->pathname, Util_portTypeDescription(p), p->protocol->name);
                                else
                                        StringBuffer_append(res->outputbuffer,
                                                    "  %-33s FAILED to %s type %s protocol %s\n",
                                                    "unix socket response time", p->pathname, Util_portTypeDescription(p), p->protocol->name);
                        }
                        if (s->type == Service_System && Run.doprocess) {
                                StringBuffer_append(res->outputbuffer,
                                                    "  %-33s [%.2f] [%.2f] [%.2f]\n"
                                                    "  %-33s %.1f%%us %.1f%%sy"
#ifdef HAVE_CPU_WAIT
                                                    " %.1f%%wa"
#endif
                                                    "\n",
                                                    "load average", systeminfo.loadavg[0], systeminfo.loadavg[1], systeminfo.loadavg[2],
                                                    "cpu", systeminfo.total_cpu_user_percent > 0 ? systeminfo.total_cpu_user_percent/10. : 0, systeminfo.total_cpu_syst_percent > 0 ? systeminfo.total_cpu_syst_percent/10. : 0
#ifdef HAVE_CPU_WAIT
                                                    , systeminfo.total_cpu_wait_percent > 0 ? systeminfo.total_cpu_wait_percent/10. : 0
#endif
                                                    );
                                StringBuffer_append(res->outputbuffer,
                                                    "  %-33s %s [%.1f%%]\n",
                                                    "memory usage", Str_bytesToSize(systeminfo.total_mem_kbyte * 1024., buf), systeminfo.total_mem_percent/10.);
                                StringBuffer_append(res->outputbuffer,
                                                    "  %-33s %s [%.1f%%]\n",
                                                    "swap usage", Str_bytesToSize(systeminfo.total_swap_kbyte * 1024., buf), systeminfo.total_swap_percent/10.);
                        }
                        if (s->type == Service_Program) {
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
        if (s->monitor == Monitor_Not)
                snprintf(buf, buflen, "Not monitored");
        else if (s->monitor & Monitor_Waiting)
                snprintf(buf, buflen, "Waiting");
        else if (s->monitor & Monitor_Init)
                snprintf(buf, buflen, "Initializing");
        else if (s->monitor & Monitor_Yes)
                snprintf(buf, buflen, "Monitored");
        return buf;
}


static char *get_service_status(Service_T s, char *buf, int buflen) {
        EventTable_T *et = Event_Table;
        ASSERT(s);
        ASSERT(buf);
        if (s->monitor == Monitor_Not || s->monitor & Monitor_Init) {
                get_monitoring_status(s, buf, buflen);
        } else if (s->error == 0) {
                snprintf(buf, buflen, "%s", statusnames[s->type]);
        } else {
                // In the case that the service has actualy some failure, error will be non zero. We will check the bitmap and print the description of the first error found
                while ((*et).id) {
                        if (s->error & (*et).id) {
                                snprintf(buf, buflen, "%s", (s->error_hint & (*et).id) ? (*et).description_changed : (*et).description_failed);
                                break;
                        }
                        et++;
                }
        }
        if (s->doaction)
                snprintf(buf + strlen(buf), buflen - strlen(buf), " - %s pending", actionnames[s->doaction]);

        return buf;
}

