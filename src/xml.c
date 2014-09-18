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

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif

#ifdef HAVE_ERRNO_H
#include <errno.h>
#endif

#include "monit.h"
#include "event.h"
#include "process.h"


/**
 *  XML routines for status and event notification message handling.
 *
 *  @file
 */


/* ----------------------------------------------------------------- Private */


/**
 * Escape the CDATA "]]>" stop sequence in string
 * @param B Output StringBuffer object
 * @param buf String to escape
 */
static void _escapeCDATA(StringBuffer_T B, const char *buf) {
        for (int i = 0; buf[i]; i++) {
                if (buf[i] == '>' && i > 1 && (buf[i - 1] == ']' && buf[i - 2] == ']'))
                        StringBuffer_append(B, "&gt;");
                else
                        StringBuffer_append(B, "%c", buf[i]);
        }
}


/**
 * Prints a document header into the given buffer.
 * @param B StringBuffer object
 * @param V Format version
 * @param myip The client-side IP address
 */
static void document_head(StringBuffer_T B, int V, const char *myip) {
        StringBuffer_append(B, "<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?>");
        if (V == 2)
                StringBuffer_append(B, "<monit id=\"%s\" incarnation=\"%lld\" version=\"%s\"><server>", Run.id, (long long)Run.incarnation, VERSION);
        else
                StringBuffer_append(B,
                        "<monit>"
                        "<server>"
                        "<id>%s</id>"
                        "<incarnation>%lld</incarnation>"
                        "<version>%s</version>",
                        Run.id,
                        (long long)Run.incarnation,
                        VERSION);
        StringBuffer_append(B,
                "<uptime>%ld</uptime>"
                "<poll>%d</poll>"
                "<startdelay>%d</startdelay>"
                "<localhostname>%s</localhostname>"
                "<controlfile>%s</controlfile>",
                (long)Util_getProcessUptime(Run.pidfile),
                Run.polltime,
                Run.startdelay,
                Run.system->name ? Run.system->name : "",
                Run.controlfile ? Run.controlfile : "");

        if (Run.dohttpd) {
                StringBuffer_append(B, "<httpd><address>%s</address><port>%d</port><ssl>%d</ssl></httpd>", Run.bind_addr ? Run.bind_addr : myip, Run.httpdport, Run.httpdssl);

                if (Run.mmonitcredentials)
                        StringBuffer_append(B, "<credentials><username>%s</username><password>%s</password></credentials>", Run.mmonitcredentials->uname, Run.mmonitcredentials->passwd);
        }

        StringBuffer_append(B,
                "</server>"
                "<platform>"
                "<name>%s</name>"
                "<release>%s</release>"
                "<version>%s</version>"
                "<machine>%s</machine>"
                "<cpu>%d</cpu>"
                "<memory>%lu</memory>"
                "<swap>%lu</swap>"
                "</platform>",
                systeminfo.uname.sysname,
                systeminfo.uname.release,
                systeminfo.uname.version,
                systeminfo.uname.machine,
                systeminfo.cpus,
                systeminfo.mem_kbyte_max,
                systeminfo.swap_kbyte_max);
}


/**
 * Prints a document footer into the given buffer.
 * @param B StringBuffer object
 */
static void document_foot(StringBuffer_T B) {
        StringBuffer_append(B, "</monit>");
}


/**
 * Prints a service status into the given buffer.
 * @param S Service object
 * @param B StringBuffer object
 * @param L Status information level
 * @param V Format version
 */
static void status_service(Service_T S, StringBuffer_T B, short L, int V) {
        if (V == 2)
                StringBuffer_append(B, "<service name=\"%s\"><type>%d</type>", S->name ? S->name : "", S->type);
        else
                StringBuffer_append(B, "<service type=\"%d\"><name>%s</name>", S->type, S->name ? S->name : "");
        StringBuffer_append(B,
                "<collected_sec>%ld</collected_sec>"
                "<collected_usec>%ld</collected_usec>"
                "<status>%d</status>"
                "<status_hint>%d</status_hint>"
                "<monitor>%d</monitor>"
                "<monitormode>%d</monitormode>"
                "<pendingaction>%d</pendingaction>",
                (long)S->collected.tv_sec,
                (long)S->collected.tv_usec,
                S->error,
                S->error_hint,
                S->monitor,
                S->mode,
                S->doaction);
        if (S->every.type != EVERY_CYCLE) {
                StringBuffer_append(B, "<every><type>%d</type>", S->every.type);
                if (S->every.type == 1)
                        StringBuffer_append(B, "<counter>%d</counter><number>%d</number>", S->every.spec.cycle.counter, S->every.spec.cycle.number);
                else
                        StringBuffer_append(B, "<cron>%s</cron>", S->every.spec.cron);
                StringBuffer_append(B, "</every>");
        }

        if (L == LEVEL_FULL) {
                if (Util_hasServiceStatus(S)) {
                        if (S->type == TYPE_FILE || S->type == TYPE_DIRECTORY || S->type == TYPE_FIFO || S->type == TYPE_FILESYSTEM)
                                StringBuffer_append(B, "<mode>%o</mode><uid>%d</uid><gid>%d</gid>", S->inf->st_mode & 07777, (int)S->inf->st_uid, (int)S->inf->st_gid);
                        if (S->type == TYPE_FILE || S->type == TYPE_FIFO || S->type == TYPE_DIRECTORY)
                                StringBuffer_append(B, "<timestamp>%ld</timestamp>", (long)S->inf->timestamp);
                        if (S->type == TYPE_FILE) {
                                StringBuffer_append(B, "<size>%llu</size>", (unsigned long long) S->inf->priv.file.st_size);
                                if (S->checksum)
                                        StringBuffer_append(B, "<checksum type=\"%s\">%s</checksum>", checksumnames[S->checksum->type], S->inf->priv.file.cs_sum);
                        }
                        if (S->type == TYPE_FILESYSTEM) {
                                StringBuffer_append(B,
                                        "<flags>%d</flags>"
                                        "<block>"
                                        "<percent>%.1f</percent>"
                                        "<usage>%.1f</usage>"
                                        "<total>%.1f</total>"
                                        "</block>",
                                        S->inf->priv.filesystem.flags,
                                        S->inf->priv.filesystem.space_percent/10.,
                                        S->inf->priv.filesystem.f_bsize > 0 ? (double)S->inf->priv.filesystem.space_total / 1048576. * (double)S->inf->priv.filesystem.f_bsize : 0.,
                                        S->inf->priv.filesystem.f_bsize > 0 ? (double)S->inf->priv.filesystem.f_blocks / 1048576. * (double)S->inf->priv.filesystem.f_bsize : 0.);
                                if (S->inf->priv.filesystem.f_files > 0) {
                                        StringBuffer_append(B,
                                                "<inode>"
                                                "<percent>%.1f</percent>"
                                                "<usage>%lld</usage>"
                                                "<total>%lld</total>"
                                                "</inode>",
                                                S->inf->priv.filesystem.inode_percent/10.,
                                                S->inf->priv.filesystem.inode_total,
                                                S->inf->priv.filesystem.f_files);
                                }
                        }
                        if (S->type == TYPE_PROCESS) {
                                StringBuffer_append(B,
                                        "<pid>%d</pid>"
                                        "<ppid>%d</ppid>"
                                        "<uid>%d</uid>"
                                        "<euid>%d</euid>"
                                        "<gid>%d</gid>"
                                        "<uptime>%ld</uptime>",
                                        S->inf->priv.process.pid,
                                        S->inf->priv.process.ppid,
                                        S->inf->priv.process.uid,
                                        S->inf->priv.process.euid,
                                        S->inf->priv.process.gid,
                                        (long)S->inf->priv.process.uptime);
                                if (Run.doprocess) {
                                        StringBuffer_append(B,
                                                "<children>%d</children>"
                                                "<memory>"
                                                "<percent>%.1f</percent>"
                                                "<percenttotal>%.1f</percenttotal>"
                                                "<kilobyte>%ld</kilobyte>"
                                                "<kilobytetotal>%ld</kilobytetotal>"
                                                "</memory>"
                                                "<cpu>"
                                                "<percent>%.1f</percent>"
                                                "<percenttotal>%.1f</percenttotal>"
                                                "</cpu>",
                                                S->inf->priv.process.children,
                                                S->inf->priv.process.mem_percent/10.0,
                                                S->inf->priv.process.total_mem_percent/10.0,
                                                S->inf->priv.process.mem_kbyte,
                                                S->inf->priv.process.total_mem_kbyte,
                                                S->inf->priv.process.cpu_percent/10.0,
                                                S->inf->priv.process.total_cpu_percent/10.0);
                                }
                        }
                        if (S->type == TYPE_HOST && S->icmplist) {
                                for (Icmp_T i = S->icmplist; i; i = i->next) {
                                        StringBuffer_append(B,
                                                "<icmp>"
                                                "<type>%s</type>"
                                                "<responsetime>%.3f</responsetime>"
                                                "</icmp>",
                                                icmpnames[i->type],
                                                i->is_available ? i->response : -1.);
                                }
                        }
                        if ((S->type == TYPE_HOST || S->type == TYPE_PROCESS) && S-> portlist) {
                                Port_T p;
                                for (p = S->portlist; p; p = p->next) {
                                        if (p->family == AF_INET)
                                                StringBuffer_append(B,
                                                          "<port>"
                                                          "<hostname>%s</hostname>"
                                                          "<portnumber>%d</portnumber>"
                                                          "<request><![CDATA[%s]]></request>"
                                                          "<protocol>%s</protocol>"
                                                          "<type>%s</type>"
                                                          "<responsetime>%.3f</responsetime>"
                                                          "</port>",
                                                          p->hostname?p->hostname:"",
                                                          p->port,
                                                          p->request?p->request:"",
                                                          p->protocol->name?p->protocol->name:"",
                                                          Util_portTypeDescription(p),
                                                          p->is_available?p->response:-1.);
                                        else if (p->family == AF_UNIX)
                                                StringBuffer_append(B,
                                                        "<unix>"
                                                        "<path>%s</path>"
                                                        "<protocol>%s</protocol>"
                                                        "<responsetime>%.3f</responsetime>"
                                                        "</unix>",
                                                        p->pathname?p->pathname:"",
                                                        p->protocol->name?p->protocol->name:"",
                                                        p->is_available?p->response:-1.);
                                }
                        }
                        if (S->type == TYPE_SYSTEM && Run.doprocess) {
                                StringBuffer_append(B,
                                        "<system>"
                                        "<load>"
                                        "<avg01>%.2f</avg01>"
                                        "<avg05>%.2f</avg05>"
                                        "<avg15>%.2f</avg15>"
                                        "</load>"
                                        "<cpu>"
                                        "<user>%.1f</user>"
                                        "<system>%.1f</system>"
#ifdef HAVE_CPU_WAIT
                                        "<wait>%.1f</wait>"
#endif
                                        "</cpu>"
                                        "<memory>"
                                        "<percent>%.1f</percent>"
                                        "<kilobyte>%ld</kilobyte>"
                                        "</memory>"
                                        "<swap>"
                                        "<percent>%.1f</percent>"
                                        "<kilobyte>%ld</kilobyte>"
                                        "</swap>"
                                        "</system>",
                                        systeminfo.loadavg[0],
                                        systeminfo.loadavg[1],
                                        systeminfo.loadavg[2],
                                        systeminfo.total_cpu_user_percent > 0 ? systeminfo.total_cpu_user_percent/10. : 0,
                                        systeminfo.total_cpu_syst_percent > 0 ? systeminfo.total_cpu_syst_percent/10. : 0,
#ifdef HAVE_CPU_WAIT
                                        systeminfo.total_cpu_wait_percent > 0 ? systeminfo.total_cpu_wait_percent/10. : 0,
#endif
                                        systeminfo.total_mem_percent/10.,
                                        systeminfo.total_mem_kbyte,
                                        systeminfo.total_swap_percent/10.,
                                        systeminfo.total_swap_kbyte);
                        }
                        if (S->type == TYPE_PROGRAM && S->program->started) {
                                StringBuffer_append(B,
                                        "<program>"
                                        "<started>%lu</started>"
                                        "<status>%d</status>"
                                        "<output><![CDATA[",
                                        (unsigned long)S->program->started,
                                        S->program->exitStatus);
                                _escapeCDATA(B, StringBuffer_toString(S->program->output));
                                StringBuffer_append(B,
                                        "]]></output>"
                                        "</program>");
                        }
                }
        }
        StringBuffer_append(B, "</service>");
}


/**
 * Prints a servicegroups into the given buffer.
 * @param SG ServiceGroup object
 * @param B StringBuffer object
 * @param L Status information level
 */
static void status_servicegroup(ServiceGroup_T SG, StringBuffer_T B, short L) {
        StringBuffer_append(B, "<servicegroup name=\"%s\">", SG->name);
        for (ServiceGroupMember_T SGM = SG->members; SGM; SGM = SGM->next)
                StringBuffer_append(B, "<service>%s</service>", SGM->name);
        StringBuffer_append(B, "</servicegroup>");
}


/**
 * Prints a event description into the given buffer.
 * @param E Event object
 * @param B StringBuffer object
 */
static void status_event(Event_T E, StringBuffer_T B) {
        struct timeval *tv = Event_get_collected(E);
        StringBuffer_append(B,
                "<event>"
                "<collected_sec>%ld</collected_sec>"
                "<collected_usec>%ld</collected_usec>"
                "<service>%s</service>"
                "<type>%d</type>"
                "<id>%ld</id>"
                "<state>%d</state>"
                "<action>%d</action>"
                "<message><![CDATA[",
                (long)tv->tv_sec,
                (long)tv->tv_usec,
                Event_get_id(E) == Event_Instance ? "Monit" : Event_get_source_name(E),
                Event_get_source_type(E),
                Event_get_id(E),
                Event_get_state(E),
                Event_get_action(E));
        _escapeCDATA(B, Event_get_message(E));
        StringBuffer_append(B, "]]></message>");
        Service_T s = Event_get_source(E);
        if (s && s->token)
                StringBuffer_append(B, "<token>%s</token>", s->token);
        StringBuffer_append(B, "</event>");
}


/* ------------------------------------------------------------------ Public */


/**
 * Get a XML formated message for event notification or general status
 * of monitored services and resources.
 * @param E An event object or NULL for general status
 * @param L Status information level
 * @param V Format version
 * @param myip The client-side IP address
 */
void status_xml(StringBuffer_T B, Event_T E, short L, int V, const char *myip) {
        Service_T S;
        ServiceGroup_T SG;

        document_head(B, V, myip);
        if (V == 2)
                StringBuffer_append(B, "<services>");
        for (S = servicelist_conf; S; S = S->next_conf)
                status_service(S, B, L, V);
        if (V == 2) {
                StringBuffer_append(B, "</services><servicegroups>");
                for (SG = servicegrouplist; SG; SG = SG->next)
                        status_servicegroup(SG, B, L);
                StringBuffer_append(B, "</servicegroups>");
        }
        if (E)
                status_event(E, B);
        document_foot(B);
}

