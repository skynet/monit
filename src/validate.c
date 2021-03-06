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

#ifdef HAVE_STDARG_H
#include <stdarg.h>
#endif

#ifdef HAVE_ERRNO_H
#include <errno.h>
#endif

#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif

#ifdef HAVE_SIGNAL_H
#include <signal.h>
#endif

#ifdef HAVE_SETJMP_H
#include <setjmp.h>
#endif

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif

#ifdef HAVE_IFADDRS_H
#include <ifaddrs.h>
#endif

#ifdef HAVE_STRING_H
#include <string.h>
#endif

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif

#ifdef HAVE_TIME_H
#include <time.h>
#endif

#ifdef HAVE_NETINET_IN_SYSTM_H
#include <netinet/in_systm.h>
#endif

#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif

#ifdef HAVE_NETINET_IP_H
#include <netinet/ip.h>
#endif

#ifdef HAVE_NETINET_IP_ICMP_H
#include <netinet/ip_icmp.h>
#endif

#include "monit.h"
#include "alert.h"
#include "event.h"
#include "socket.h"
#include "net.h"
#include "device.h"
#include "process.h"
#include "protocol.h"

// libmonit
#include "system/Time.h"
#include "io/File.h"
#include "io/InputStream.h"
#include "exceptions/AssertException.h"

/**
 *  Implementation of validation engine
 *
 *  @file
 */


/* ------------------------------------------------------------- Definitions */


#define MATCH_LINE_LENGTH 512


/* ----------------------------------------------------------------- Private */


/**
 * Read program output into stringbuffer. Limit the output to 1kB
 */
static void _programOutput(InputStream_T I, StringBuffer_T S) {
        int n;
        char buf[STRLEN];
        InputStream_setTimeout(I, 0);
        do {
                n = InputStream_readBytes(I, buf, sizeof(buf) - 1);
                if (n) {
                        buf[n] = 0;
                        StringBuffer_append(S, "%s", buf);
                }
        } while (n > 0 && StringBuffer_length(S) < 1024);
}


/**
 * Test the connection and protocol
 */
static void check_connection(Service_T s, Port_T p) {
        ASSERT(s && p);
        volatile int retry_count = p->retry;
        volatile boolean_t rv = true;
        char buf[STRLEN];
        char report[STRLEN] = {};
retry:
        TRY
        {
                Socket_test(p);
                DEBUG("'%s' succeeded testing protocol [%s] at %s\n", s->name, p->protocol->name, Util_portDescription(p, buf, sizeof(buf)));
        }
        ELSE
        {
                snprintf(report, STRLEN, "failed protocol test [%s] at %s -- %s", p->protocol->name, Util_portDescription(p, buf, sizeof(buf)), Exception_frame.message);
                rv = false;
        }
        END_TRY;
        if (! rv) {
                if (retry_count-- > 1) {
                        DEBUG("'%s' %s (attempt %d/%d)\n", s->name, report, p->retry - retry_count, p->retry);
                        goto retry;
                }
                Event_post(s, Event_Connection, State_Failed, p->action, "%s", report);
        } else {
                Event_post(s, Event_Connection, State_Succeeded, p->action, "connection succeeded to %s", Util_portDescription(p, buf, sizeof(buf)));
        }
}


/**
 * Test process state (e.g. Zombie)
 */
static void check_process_state(Service_T s) {
        ASSERT(s);
        if (s->inf->priv.process.zombie)
                Event_post(s, Event_Data, State_Failed, s->action_DATA, "process with pid %d is a zombie", s->inf->priv.process.pid);
        else
                Event_post(s, Event_Data, State_Succeeded, s->action_DATA, "zombie check succeeded");
}


/**
 * Test process pid for possible change since last cycle
 */
static void check_process_pid(Service_T s) {

        ASSERT(s && s->inf);

        /* process pid was not initialized yet */
        if (s->inf->priv.process._pid < 0 || s->inf->priv.process.pid < 0)
                return;

        for (Pid_T l = s->pidlist; l; l = l->next) {
                if (s->inf->priv.process._pid != s->inf->priv.process.pid)
                        Event_post(s, Event_Pid, State_Changed, l->action, "process PID changed from %d to %d", s->inf->priv.process._pid, s->inf->priv.process.pid);
                else
                        Event_post(s, Event_Pid, State_ChangedNot, l->action, "process PID has not changed since last cycle");
        }
}


/**
 * Test process ppid for possible change since last cycle
 */
static void check_process_ppid(Service_T s) {

        ASSERT(s && s->inf);

        /* process ppid was not initialized yet */
        if (s->inf->priv.process._ppid < 0 || s->inf->priv.process.ppid < 0)
                return;

        for (Pid_T l = s->ppidlist; l; l = l->next) {
                if (s->inf->priv.process._ppid != s->inf->priv.process.ppid)
                        Event_post(s, Event_PPid, State_Changed, l->action, "process PPID changed from %d to %d", s->inf->priv.process._ppid, s->inf->priv.process.ppid);
                else
                        Event_post(s, Event_PPid, State_ChangedNot, l->action, "process PPID has not changed since last cycle");
        }
}


/**
 * Check process resources
 */
static void check_process_resources(Service_T s, Resource_T r) {
        ASSERT(s && r);

        boolean_t okay = true;
        char report[STRLEN]={0}, buf1[STRLEN], buf2[STRLEN];
        switch (r->resource_id) {

                case Resource_CpuPercent:
                        {
                                short cpu;
                                if (s->type == Service_System) {
                                        cpu =
#ifdef HAVE_CPU_WAIT
                                                (systeminfo.total_cpu_wait_percent > 0 ? systeminfo.total_cpu_wait_percent : 0) +
#endif
                                                (systeminfo.total_cpu_syst_percent > 0 ? systeminfo.total_cpu_syst_percent : 0) +
                                                (systeminfo.total_cpu_user_percent > 0 ? systeminfo.total_cpu_user_percent : 0);
                                } else {
                                        cpu = s->inf->priv.process.cpu_percent;
                                }
                                if (s->monitor & Monitor_Init || cpu < 0) {
                                        DEBUG("'%s' cpu usage check skipped (initializing)\n", s->name);
                                        return;
                                } else if (Util_evalQExpression(r->operator, cpu, r->limit)) {
                                        snprintf(report, STRLEN, "cpu usage of %.1f%% matches resource limit [cpu usage%s%.1f%%]", cpu / 10., operatorshortnames[r->operator], r->limit / 10.);
                                        okay = false;
                                } else {
                                        snprintf(report, STRLEN, "cpu usage check succeeded [current cpu usage=%.1f%%]", cpu / 10.);
                                }
                        }
                        break;

                case Resource_CpuPercentTotal:
                        if (s->monitor & Monitor_Init || s->inf->priv.process.total_cpu_percent < 0) {
                                DEBUG("'%s' total cpu usage check skipped (initializing)\n", s->name);
                                return;
                        } else if (Util_evalQExpression(r->operator, s->inf->priv.process.total_cpu_percent, r->limit)) {
                                snprintf(report, STRLEN, "total cpu usage of %.1f%% matches resource limit [cpu usage%s%.1f%%]", s->inf->priv.process.total_cpu_percent / 10., operatorshortnames[r->operator], r->limit / 10.);
                                okay = false;
                        } else
                                snprintf(report, STRLEN, "total cpu usage check succeeded [current cpu usage=%.1f%%]", s->inf->priv.process.total_cpu_percent / 10.);
                        break;

                case Resource_CpuUser:
                        if (s->monitor & Monitor_Init || systeminfo.total_cpu_user_percent < 0) {
                                DEBUG("'%s' cpu user usage check skipped (initializing)\n", s->name);
                                return;
                        } else if (Util_evalQExpression(r->operator, systeminfo.total_cpu_user_percent, r->limit)) {
                                snprintf(report, STRLEN, "cpu user usage of %.1f%% matches resource limit [cpu user usage%s%.1f%%]", systeminfo.total_cpu_user_percent / 10., operatorshortnames[r->operator], r->limit / 10.);
                                okay = false;
                        } else
                                snprintf(report, STRLEN, "cpu user usage check succeeded [current cpu user usage=%.1f%%]", systeminfo.total_cpu_user_percent / 10.);
                        break;

                case Resource_CpuSystem:
                        if (s->monitor & Monitor_Init || systeminfo.total_cpu_syst_percent < 0) {
                                DEBUG("'%s' cpu system usage check skipped (initializing)\n", s->name);
                                return;
                        } else if (Util_evalQExpression(r->operator, systeminfo.total_cpu_syst_percent, r->limit)) {
                                snprintf(report, STRLEN, "cpu system usage of %.1f%% matches resource limit [cpu system usage%s%.1f%%]", systeminfo.total_cpu_syst_percent / 10., operatorshortnames[r->operator], r->limit / 10.);
                                okay = false;
                        } else
                                snprintf(report, STRLEN, "cpu system usage check succeeded [current cpu system usage=%.1f%%]", systeminfo.total_cpu_syst_percent / 10.);
                        break;

                case Resource_CpuWait:
                        if (s->monitor & Monitor_Init || systeminfo.total_cpu_wait_percent < 0) {
                                DEBUG("'%s' cpu wait usage check skipped (initializing)\n", s->name);
                                return;
                        } else if (Util_evalQExpression(r->operator, systeminfo.total_cpu_wait_percent, r->limit)) {
                                snprintf(report, STRLEN, "cpu wait usage of %.1f%% matches resource limit [cpu wait usage%s%.1f%%]", systeminfo.total_cpu_wait_percent / 10., operatorshortnames[r->operator], r->limit / 10.);
                                okay = false;
                        } else
                                snprintf(report, STRLEN, "cpu wait usage check succeeded [current cpu wait usage=%.1f%%]", systeminfo.total_cpu_wait_percent / 10.);
                        break;

                case Resource_MemoryPercent:
                        if (s->type == Service_System) {
                                if (Util_evalQExpression(r->operator, systeminfo.total_mem_percent, r->limit)) {
                                        snprintf(report, STRLEN, "mem usage of %.1f%% matches resource limit [mem usage%s%.1f%%]", systeminfo.total_mem_percent / 10., operatorshortnames[r->operator], r->limit / 10.);
                                        okay = false;
                                } else
                                        snprintf(report, STRLEN, "mem usage check succeeded [current mem usage=%.1f%%]", systeminfo.total_mem_percent / 10.);
                        } else {
                                if (Util_evalQExpression(r->operator, s->inf->priv.process.mem_percent, r->limit)) {
                                        snprintf(report, STRLEN, "mem usage of %.1f%% matches resource limit [mem usage%s%.1f%%]", s->inf->priv.process.mem_percent / 10., operatorshortnames[r->operator], r->limit / 10.);
                                        okay = false;
                                } else
                                        snprintf(report, STRLEN, "mem usage check succeeded [current mem usage=%.1f%%]", s->inf->priv.process.mem_percent / 10.);
                        }
                        break;

                case Resource_MemoryKbyte:
                        if (s->type == Service_System) {
                                if (Util_evalQExpression(r->operator, systeminfo.total_mem_kbyte, r->limit)) {
                                        snprintf(report, STRLEN, "mem amount of %s matches resource limit [mem amount%s%s]", Str_bytesToSize(systeminfo.total_mem_kbyte * 1024., buf1), operatorshortnames[r->operator], Str_bytesToSize(r->limit * 1024., buf2));
                                        okay = false;
                                } else
                                        snprintf(report, STRLEN, "mem amount check succeeded [current mem amount=%s]", Str_bytesToSize(systeminfo.total_mem_kbyte * 1024., buf1));
                        } else {
                                if (Util_evalQExpression(r->operator, s->inf->priv.process.mem_kbyte, r->limit)) {
                                        snprintf(report, STRLEN, "mem amount of %s matches resource limit [mem amount%s%s]", Str_bytesToSize(s->inf->priv.process.mem_kbyte * 1024., buf1), operatorshortnames[r->operator], Str_bytesToSize(r->limit * 1024., buf2));
                                        okay = false;
                                } else
                                        snprintf(report, STRLEN, "mem amount check succeeded [current mem amount=%s]", Str_bytesToSize(s->inf->priv.process.mem_kbyte * 1024., buf1));
                        }
                        break;

                case Resource_SwapPercent:
                        if (s->type == Service_System) {
                                if (Util_evalQExpression(r->operator, systeminfo.total_swap_percent, r->limit)) {
                                        snprintf(report, STRLEN, "swap usage of %.1f%% matches resource limit [swap usage%s%.1f%%]", systeminfo.total_swap_percent / 10., operatorshortnames[r->operator], r->limit / 10.);
                                        okay = false;
                                } else
                                        snprintf(report, STRLEN, "swap usage check succeeded [current swap usage=%.1f%%]", systeminfo.total_swap_percent / 10.);
                        }
                        break;

                case Resource_SwapKbyte:
                        if (s->type == Service_System) {
                                if (Util_evalQExpression(r->operator, systeminfo.total_swap_kbyte, r->limit)) {
                                        snprintf(report, STRLEN, "swap amount of %s matches resource limit [swap amount%s%s]", Str_bytesToSize(systeminfo.total_swap_kbyte * 1024., buf1), operatorshortnames[r->operator], Str_bytesToSize(r->limit * 1024., buf2));
                                        okay = false;
                                } else
                                        snprintf(report, STRLEN, "swap amount check succeeded [current swap amount=%s]", Str_bytesToSize(systeminfo.total_swap_kbyte * 1024., buf1));
                        }
                        break;

                case Resource_LoadAverage1m:
                        if (Util_evalQExpression(r->operator, (int)(systeminfo.loadavg[0] * 10.), r->limit)) {
                                snprintf(report, STRLEN, "loadavg(1min) of %.1f matches resource limit [loadavg(1min)%s%.1f]", systeminfo.loadavg[0], operatorshortnames[r->operator], r->limit / 10.);
                                okay = false;
                        } else
                                snprintf(report, STRLEN, "loadavg(1min) check succeeded [current loadavg(1min)=%.1f]", systeminfo.loadavg[0]);
                        break;

                case Resource_LoadAverage5m:
                        if (Util_evalQExpression(r->operator, (int)(systeminfo.loadavg[1] * 10.), r->limit)) {
                                snprintf(report, STRLEN, "loadavg(5min) of %.1f matches resource limit [loadavg(5min)%s%.1f]", systeminfo.loadavg[1], operatorshortnames[r->operator], r->limit / 10.);
                                okay = false;
                        } else
                                snprintf(report, STRLEN, "loadavg(5min) check succeeded [current loadavg(5min)=%.1f]", systeminfo.loadavg[1]);
                        break;

                case Resource_LoadAverage15m:
                        if (Util_evalQExpression(r->operator, (int)(systeminfo.loadavg[2] * 10.), r->limit)) {
                                snprintf(report, STRLEN, "loadavg(15min) of %.1f matches resource limit [loadavg(15min)%s%.1f]", systeminfo.loadavg[2], operatorshortnames[r->operator], r->limit / 10.);
                                okay = false;
                        } else
                                snprintf(report, STRLEN, "loadavg(15min) check succeeded [current loadavg(15min)=%.1f]", systeminfo.loadavg[2]);
                        break;

                case Resource_Children:
                        if (Util_evalQExpression(r->operator, s->inf->priv.process.children, r->limit)) {
                                snprintf(report, STRLEN, "children of %i matches resource limit [children%s%ld]", s->inf->priv.process.children, operatorshortnames[r->operator], r->limit);
                                okay = false;
                        } else
                                snprintf(report, STRLEN, "children check succeeded [current children=%i]", s->inf->priv.process.children);
                        break;

                case Resource_MemoryKbyteTotal:
                        if (Util_evalQExpression(r->operator, s->inf->priv.process.total_mem_kbyte, r->limit)) {
                                snprintf(report, STRLEN, "total mem amount of %s matches resource limit [total mem amount%s%s]", Str_bytesToSize(s->inf->priv.process.total_mem_kbyte * 1024., buf1), operatorshortnames[r->operator], Str_bytesToSize(r->limit * 1024., buf2));
                                okay = false;
                        } else
                                snprintf(report, STRLEN, "total mem amount check succeeded [current total mem amount=%s]", Str_bytesToSize(s->inf->priv.process.total_mem_kbyte * 1024., buf1));
                        break;

                case Resource_MemoryPercentTotal:
                        if (Util_evalQExpression(r->operator, s->inf->priv.process.total_mem_percent, r->limit)) {
                                snprintf(report, STRLEN, "total mem amount of %.1f%% matches resource limit [total mem amount%s%.1f%%]", (float)s->inf->priv.process.total_mem_percent / 10., operatorshortnames[r->operator], (float)r->limit / 10.);
                                okay = false;
                        } else
                                snprintf(report, STRLEN, "total mem amount check succeeded [current total mem amount=%.1f%%]", s->inf->priv.process.total_mem_percent / 10.);
                        break;

                default:
                        LogError("'%s' error -- unknown resource ID: [%d]\n", s->name, r->resource_id);
                        return;
        }
        Event_post(s, Event_Resource, okay ? State_Succeeded : State_Failed, r->action, "%s", report);
}


/**
 * Test for associated path checksum change
 */
static void check_checksum(Service_T s) {
        int         changed;
        Checksum_T  cs;

        ASSERT(s && s->path && s->checksum);

        cs = s->checksum;

        if (Util_getChecksum(s->path, cs->type, s->inf->priv.file.cs_sum, sizeof(s->inf->priv.file.cs_sum))) {

                Event_post(s, Event_Data, State_Succeeded, s->action_DATA, "checksum computed for %s", s->path);

                if (! cs->initialized) {
                        cs->initialized = true;
                        snprintf(cs->hash, sizeof(cs->hash), "%s", s->inf->priv.file.cs_sum);
                }

                switch (cs->type) {
                        case Hash_Md5:
                                changed = strncmp(cs->hash, s->inf->priv.file.cs_sum, 32);
                                break;
                        case Hash_Sha1:
                                changed = strncmp(cs->hash, s->inf->priv.file.cs_sum, 40);
                                break;
                        default:
                                LogError("'%s' unknown hash type\n", s->name);
                                *s->inf->priv.file.cs_sum = 0;
                                return;
                }

                if (changed) {

                        if (cs->test_changes) {
                                /* if we are testing for changes only, the value is variable */
                                Event_post(s, Event_Checksum, State_Changed, cs->action, "checksum was changed for %s", s->path);
                                /* reset expected value for next cycle */
                                snprintf(cs->hash, sizeof(cs->hash), "%s", s->inf->priv.file.cs_sum);
                        } else {
                                /* we are testing constant value for failed or succeeded state */
                                Event_post(s, Event_Checksum, State_Failed, cs->action, "checksum test failed for %s", s->path);
                        }

                } else if (cs->test_changes) {
                        Event_post(s, Event_Checksum, State_ChangedNot, cs->action, "checksum has not changed");
                } else {
                        Event_post(s, Event_Checksum, State_Succeeded, cs->action, "checksum is valid");
                }
                return;
        }

        Event_post(s, Event_Data, State_Failed, s->action_DATA, "cannot compute checksum for %s", s->path);

}


/**
 * Test for associated path permission change
 */
static void check_perm(Service_T s, mode_t mode) {
        ASSERT(s && s->perm);
        mode_t m = mode & 07777;
        if (m != s->perm->perm) {
                if (s->perm->test_changes) {
                        Event_post(s, Event_Permission, State_Changed, s->perm->action, "permission for %s changed from %04o to %04o", s->path, s->perm->perm, m);
                        s->perm->perm = m;
                } else {
                        Event_post(s, Event_Permission, State_Failed, s->perm->action, "permission test failed for %s [current permission %04o]", s->path, m);
                }
        } else {
                if (s->perm->test_changes)
                        Event_post(s, Event_Permission, State_ChangedNot, s->perm->action, "permission not changed for %s", s->path);
                else
                        Event_post(s, Event_Permission, State_Succeeded, s->perm->action, "permission test succeeded [current permission %04o]", m);
        }
}


/**
 * Test UID of file or process
 */
static void check_uid(Service_T s, int uid) {
        ASSERT(s && s->uid);

        if (uid >= 0) {
                if (uid != s->uid->uid)
                        Event_post(s, Event_Uid, State_Failed, s->uid->action, "uid test failed for %s -- current uid is %d", s->name, uid);
                else
                        Event_post(s, Event_Uid, State_Succeeded, s->uid->action, "uid test succeeded [current uid=%d]", uid);
        }
}


/**
 * Test effective UID of process
 */
static void check_euid(Service_T s, int euid) {
        ASSERT(s && s->euid);

        if (euid >= 0) {
                if (euid != s->euid->uid)
                        Event_post(s, Event_Uid, State_Failed, s->euid->action, "euid test failed for %s -- current euid is %d", s->name, euid);
                else
                        Event_post(s, Event_Uid, State_Succeeded, s->euid->action, "euid test succeeded [current euid=%d]", euid);
        }
}


/**
 * Test GID of file or process
 */
static void check_gid(Service_T s, int gid) {
        ASSERT(s && s->gid);

        if (gid >= 0) {
                if (gid != s->gid->gid)
                        Event_post(s, Event_Gid, State_Failed, s->gid->action, "gid test failed for %s -- current gid is %d", s->name, gid);
                else
                        Event_post(s, Event_Gid, State_Succeeded, s->gid->action, "gid test succeeded [current gid=%d]", gid);
        }
}


/**
 * Validate timestamps of a service s
 */
static void check_timestamp(Service_T s, time_t timestamp) {
        time_t now;

        ASSERT(s && s->timestamplist);

        if ((int)time(&now) == -1) {
                Event_post(s, Event_Data, State_Failed, s->action_DATA, "can't obtain actual system time");
                return;
        } else {
                Event_post(s, Event_Data, State_Succeeded, s->action_DATA, "actual system time obtained");
        }

        for (Timestamp_T t = s->timestamplist; t; t = t->next) {
                if (t->test_changes) {
                        /* if we are testing for changes only, the value is variable */
                        if (t->timestamp != timestamp) {
                                /* reset expected value for next cycle */
                                t->timestamp = timestamp;
                                Event_post(s, Event_Timestamp, State_Changed, t->action, "timestamp was changed for %s", s->path);
                        } else {
                                Event_post(s, Event_Timestamp, State_ChangedNot, t->action, "timestamp was not changed for %s", s->path);
                        }
                } else {
                        /* we are testing constant value for failed or succeeded state */
                        if (Util_evalQExpression(t->operator, (int)(now - timestamp), t->time))
                                Event_post(s, Event_Timestamp, State_Failed, t->action, "timestamp test failed for %s", s->path);
                        else
                                Event_post(s, Event_Timestamp, State_Succeeded, t->action, "timestamp test succeeded for %s", s->path);
                }
        }
}


/**
 * Test size
 */
static void check_size(Service_T s) {
        ASSERT(s && s->sizelist);
        char buf[10];
        for (Size_T sl = s->sizelist; sl; sl = sl->next) {
                /* if we are testing for changes only, the value is variable */
                if (sl->test_changes) {
                        if (! sl->initialized) {
                                /* the size was not initialized during monit start, so set the size now
                                 * and allow further size change testing */
                                sl->initialized = true;
                                sl->size = s->inf->priv.file.size;
                        } else {
                                if (sl->size != s->inf->priv.file.size) {
                                        Event_post(s, Event_Size, State_Changed, sl->action, "size was changed for %s", s->path);
                                        /* reset expected value for next cycle */
                                        sl->size = s->inf->priv.file.size;
                                } else {
                                        Event_post(s, Event_Size, State_ChangedNot, sl->action, "size has not changed [current size=%s]", Str_bytesToSize(s->inf->priv.file.size, buf));
                                }
                        }
                } else {
                        /* we are testing constant value for failed or succeeded state */
                        if (Util_evalQExpression(sl->operator, s->inf->priv.file.size, sl->size))
                                Event_post(s, Event_Size, State_Failed, sl->action, "size test failed for %s -- current size is %s", s->path, Str_bytesToSize(s->inf->priv.file.size, buf));
                        else
                                Event_post(s, Event_Size, State_Succeeded, sl->action, "size check succeeded [current size=%s]", Str_bytesToSize(s->inf->priv.file.size, buf));
                }
        }
}


/**
 * Test uptime
 */
static void check_uptime(Service_T s) {
        ASSERT(s);

        for (Uptime_T ul = s->uptimelist; ul; ul = ul->next) {
                if (Util_evalQExpression(ul->operator, s->inf->priv.process.uptime, ul->uptime))
                        Event_post(s, Event_Uptime, State_Failed, ul->action, "uptime test failed for %s -- current uptime is %llu seconds", s->path, (unsigned long long)s->inf->priv.process.uptime);
                else
                        Event_post(s, Event_Uptime, State_Succeeded, ul->action, "uptime test succeeded [current uptime=%llu seconds]", (unsigned long long)s->inf->priv.process.uptime);
        }
}


static int check_pattern(Match_T pattern, const char *line) {
#ifdef HAVE_REGEX_H
        return regexec(pattern->regex_comp, line, 0, NULL, 0);
#else
        if (strstr(line, pattern->match_string) == NULL)
                return -1;
        else
                return 0;
#endif
}


/**
 * Match content.
 *
 * The test compares only the lines terminated with \n.
 *
 * In the case that line with missing \n is read, the test stops, as we suppose that the file contains only partial line and the rest of it is yet stored in the buffer of the application which writes to the file.
 * The test will resume at the beginning of the incomplete line during the next cycle, allowing the writer to finish the write.
 *
 * We test only MATCH_LINE_LENGTH at maximum (512 bytes) - in the case that the line is bigger, we read the rest of the line (till '\n') but ignore the characters past the maximum (512+).
 */
static void check_match(Service_T s) {
        Match_T ml;
        FILE *file;
        char line[MATCH_LINE_LENGTH];

        ASSERT(s && s->matchlist);

        /* Open the file */
        if (! (file = fopen(s->path, "r"))) {
                LogError("'%s' cannot open file %s: %s\n", s->name, s->path, STRERROR);
                return;
        }

        /* FIXME: Refactor: Initialize the filesystems table ahead of file and filesystems test and index it by device id + replace the Str_startsWith() with lookup to the table by device id (obtained via file's stat()).
         The central filesystems initialization will allow to reduce the statfs() calls in the case that there will be multiple file and/or filesystems tests for the same fs. Temporarily we go with
         dummy Str_startsWith() as quick fix which will cover 99.9% of use cases without rising the statfs overhead if statfs call would be inlined here.
         */
        if (Str_startsWith(s->path, "/proc")) {
                s->inf->priv.file.readpos = 0;
        } else {
                /* If inode changed or size shrinked -> set read position = 0 */
                if (s->inf->priv.file.inode != s->inf->priv.file.inode_prev || s->inf->priv.file.readpos > s->inf->priv.file.size)
                        s->inf->priv.file.readpos = 0;

                /* Do we need to match? Even if not, go to final, so we can reset the content match error flags in this cycle */
                if (s->inf->priv.file.readpos == s->inf->priv.file.size) {
                        DEBUG("'%s' content match skipped - file size nor inode has not changed since last test\n", s->name);
                        goto final;
                }
        }

        while (true) {
        next:
                /* Seek to the read position */
                if (fseek(file, (long)s->inf->priv.file.readpos, SEEK_SET)) {
                        LogError("'%s' cannot seek file %s: %s\n", s->name, s->path, STRERROR);
                        goto final;
                }

                if (! fgets(line, MATCH_LINE_LENGTH, file)) {
                        if (! feof(file))
                                LogError("'%s' cannot read file %s: %s\n", s->name, s->path, STRERROR);
                        goto final;
                }

                size_t length = strlen(line);
                if (length == 0) {
                        /* No content: shouldn't happen - empty line will contain at least '\n' */
                        goto final;
                } else if (line[length-1] != '\n') {
                        if (length < MATCH_LINE_LENGTH-1) {
                                /* Incomplete line: we gonna read it next time again, allowing the writer to complete the write */
                                DEBUG("'%s' content match: incomplete line read - no new line at end. (retrying next cycle)\n", s->name);
                                goto final;
                        } else if (length == MATCH_LINE_LENGTH-1) {
                                /* Our read buffer is full: ignore the content past the MATCH_LINE_LENGTH */
                                int rv;
                                do {
                                        if ((rv = fgetc(file)) == EOF)
                                                goto final;
                                        length++;
                                } while (rv != '\n');
                        }
                } else {
                        /* Remove appending newline */
                        line[length - 1] = 0;
                }
                /* Set read position to the end of last read */
                s->inf->priv.file.readpos += length;

                /* Check ignores */
                for (ml = s->matchignorelist; ml; ml = ml->next) {
                        if ((check_pattern(ml, line) == 0)  ^ (ml->not)) {
                                /* We match! -> line is ignored! */
                                DEBUG("'%s' Ignore pattern %s'%s' match on content line\n", s->name, ml->not ? "not " : "", ml->match_string);
                                goto next;
                        }
                }

                /* Check non ignores */
                for (ml = s->matchlist; ml; ml = ml->next) {
                        if ((check_pattern(ml, line) == 0) ^ (ml->not)) {
                                DEBUG("'%s' Pattern %s'%s' match on content line [%s]\n", s->name, ml->not ? "not " : "", ml->match_string, line);
                                /* Save the line: we limit the content showed in the event roughly to MATCH_LINE_LENGTH (we allow exceed to not break the line) */
                                if (! ml->log)
                                        ml->log = StringBuffer_create(MATCH_LINE_LENGTH);
                                if (StringBuffer_length(ml->log) < MATCH_LINE_LENGTH) {
                                        StringBuffer_append(ml->log, "%s\n", line);
                                        if (StringBuffer_length(ml->log) >= MATCH_LINE_LENGTH)
                                                StringBuffer_append(ml->log, "...\n");
                                }
                        } else {
                                DEBUG("'%s' Pattern %s'%s' doesn't match on content line [%s]\n", s->name, ml->not ? "not " : "", ml->match_string, line);
                        }
                }
        }
final:
        if (fclose(file))
                LogError("'%s' cannot close file %s: %s\n", s->name, s->path, STRERROR);

        /* Post process the matches: generate events for particular patterns */
        for (ml = s->matchlist; ml; ml = ml->next) {
                if (ml->log) {
                        Event_post(s, Event_Content, State_Changed, ml->action, "content match:\n%s", StringBuffer_toString(ml->log));
                        StringBuffer_free(&ml->log);
                } else {
                        Event_post(s, Event_Content, State_ChangedNot, ml->action, "content doesn't match");
                }
        }
}


/**
 * Test filesystem flags for possible change since last cycle
 */
static void check_filesystem_flags(Service_T s) {
        ASSERT(s && s->inf);

        /* filesystem flags were not initialized yet */
        if (s->inf->priv.filesystem._flags == -1)
                return;

        for (Fsflag_T l = s->fsflaglist; l; l = l->next)
                if (s->inf->priv.filesystem._flags != s->inf->priv.filesystem.flags)
                        Event_post(s, Event_Fsflag, State_Changed, l->action, "filesytem flags changed to %#x", s->inf->priv.filesystem.flags);
}

/**
 * Filesystem test
 */
static void check_filesystem_resources(Service_T s, Filesystem_T td) {
        ASSERT(s && td);

        if ( (td->limit_percent < 0) && (td->limit_absolute < 0) ) {
                LogError("'%s' error: filesystem limit not set\n", s->name);
                return;
        }

        switch (td->resource) {

                case Resource_Inode:
                        if (s->inf->priv.filesystem.f_files <= 0) {
                                DEBUG("'%s' filesystem doesn't support inodes\n", s->name);
                                return;
                        }

                        if (td->limit_percent >= 0) {
                                if (Util_evalQExpression(td->operator, s->inf->priv.filesystem.inode_percent, td->limit_percent)) {
                                        Event_post(s, Event_Resource, State_Failed, td->action, "inode usage %.1f%% matches resource limit [inode usage%s%.1f%%]", s->inf->priv.filesystem.inode_percent / 10., operatorshortnames[td->operator], td->limit_percent / 10.);
                                        return;
                                }
                        } else {
                                if (Util_evalQExpression(td->operator, s->inf->priv.filesystem.inode_total, td->limit_absolute)) {
                                        Event_post(s, Event_Resource, State_Failed, td->action, "inode usage %lld matches resource limit [inode usage%s%lld]", s->inf->priv.filesystem.inode_total, operatorshortnames[td->operator], td->limit_absolute);
                                        return;
                                }
                        }
                        Event_post(s, Event_Resource, State_Succeeded, td->action, "inode usage test succeeded [current inode usage=%.1f%%]", s->inf->priv.filesystem.inode_percent / 10.);
                        return;

                case Resource_InodeFree:
                        if (s->inf->priv.filesystem.f_files <= 0) {
                                DEBUG("'%s' filesystem doesn't support inodes\n", s->name);
                                return;
                        }

                        if (td->limit_percent >= 0) {
                                if (Util_evalQExpression(td->operator, 1000 - s->inf->priv.filesystem.inode_percent, td->limit_percent)) {
                                        Event_post(s, Event_Resource, State_Failed, td->action, "inode free %.1f%% matches resource limit [inode free%s%.1f%%]", (1000. - s->inf->priv.filesystem.inode_percent) / 10., operatorshortnames[td->operator], td->limit_percent / 10.);
                                        return;
                                }
                        } else {
                                if (Util_evalQExpression(td->operator, s->inf->priv.filesystem.f_filesfree, td->limit_absolute)) {
                                        Event_post(s, Event_Resource, State_Failed, td->action, "inode free %lld matches resource limit [inode free%s%lld]", s->inf->priv.filesystem.f_filesfree, operatorshortnames[td->operator], td->limit_absolute);
                                        return;
                                }
                        }
                        Event_post(s, Event_Resource, State_Succeeded, td->action, "inode free test succeeded [current inode free=%.1f%%]", (1000. - s->inf->priv.filesystem.inode_percent) / 10.);
                        return;

                case Resource_Space:
                        if (td->limit_percent >= 0) {
                                if (Util_evalQExpression(td->operator, s->inf->priv.filesystem.space_percent, td->limit_percent)) {
                                        Event_post(s, Event_Resource, State_Failed, td->action, "space usage %.1f%% matches resource limit [space usage%s%.1f%%]", s->inf->priv.filesystem.space_percent / 10., operatorshortnames[td->operator], td->limit_percent / 10.);
                                        return;
                                }
                        } else {
                                if (Util_evalQExpression(td->operator, s->inf->priv.filesystem.space_total, td->limit_absolute)) {
                                        if (s->inf->priv.filesystem.f_bsize > 0) {
                                                char buf1[STRLEN];
                                                char buf2[STRLEN];
                                                Str_bytesToSize(s->inf->priv.filesystem.space_total * s->inf->priv.filesystem.f_bsize, buf1);
                                                Str_bytesToSize(td->limit_absolute * s->inf->priv.filesystem.f_bsize, buf2);
                                                Event_post(s, Event_Resource, State_Failed, td->action, "space usage %s matches resource limit [space usage%s%s]", buf1, operatorshortnames[td->operator], buf2);
                                        } else {
                                                Event_post(s, Event_Resource, State_Failed, td->action, "space usage %lld blocks matches resource limit [space usage%s%lld blocks]", s->inf->priv.filesystem.space_total, operatorshortnames[td->operator], td->limit_absolute);
                                        }
                                        return;
                                }
                        }
                        Event_post(s, Event_Resource, State_Succeeded, td->action, "space usage test succeeded [current space usage=%.1f%%]", s->inf->priv.filesystem.space_percent / 10.);
                        return;

                case Resource_SpaceFree:
                        if (td->limit_percent >= 0) {
                                if (Util_evalQExpression(td->operator, 1000 - s->inf->priv.filesystem.space_percent, td->limit_percent)) {
                                        Event_post(s, Event_Resource, State_Failed, td->action, "space free %.1f%% matches resource limit [space free%s%.1f%%]", (1000. - s->inf->priv.filesystem.space_percent) / 10., operatorshortnames[td->operator], td->limit_percent / 10.);
                                        return;
                                }
                        } else {
                                if (Util_evalQExpression(td->operator, s->inf->priv.filesystem.f_blocksfreetotal, td->limit_absolute)) {
                                        if (s->inf->priv.filesystem.f_bsize > 0) {
                                                char buf1[STRLEN];
                                                char buf2[STRLEN];
                                                Str_bytesToSize(s->inf->priv.filesystem.f_blocksfreetotal * s->inf->priv.filesystem.f_bsize, buf1);
                                                Str_bytesToSize(td->limit_absolute * s->inf->priv.filesystem.f_bsize, buf2);
                                                Event_post(s, Event_Resource, State_Failed, td->action, "space free %s matches resource limit [space free%s%s]", buf1, operatorshortnames[td->operator], buf2);
                                        } else {
                                                Event_post(s, Event_Resource, State_Failed, td->action, "space free %lld blocks matches resource limit [space free%s%lld blocks]", s->inf->priv.filesystem.f_blocksfreetotal, operatorshortnames[td->operator], td->limit_absolute);
                                        }
                                        return;
                                }
                        }
                        Event_post(s, Event_Resource, State_Succeeded, td->action, "space free test succeeded [current space free=%.1f%%]", (1000. - s->inf->priv.filesystem.space_percent) / 10.);
                        return;

                default:
                        LogError("'%s' error -- unknown resource type: [%d]\n", s->name, td->resource);
                        return;
        }

}


static void check_timeout(Service_T s) {
        ASSERT(s);

        if (! s->actionratelist)
                return;

        /* Start counting cycles */
        if (s->nstart > 0)
                s->ncycle++;

        int max = 0;
        for (ActionRate_T ar = s->actionratelist; ar; ar = ar->next) {
                if (max < ar->cycle)
                        max = ar->cycle;
                if (s->nstart >= ar->count && s->ncycle <= ar->cycle)
                        Event_post(s, Event_Timeout, State_Failed, ar->action, "service restarted %d times within %d cycles(s) - %s", s->nstart, s->ncycle, actionnames[ar->action->failed->id]);
        }

        /* Stop counting and reset if the cycle interval is succeeded */
        if (s->ncycle > max) {
                s->ncycle = 0;
                s->nstart = 0;
        }
}


static boolean_t _incron(Service_T s, time_t now) {
        if ((now - s->every.last_run) > 59) { // Minute is the lowest resolution, so only run once per minute
                if (Time_incron(s->every.spec.cron, now)) {
                        s->every.last_run = now;
                        return true;
                }
        }
        return false;
}


/**
 * Returns true if validation should be skiped for
 * this service in this cycle, otherwise false. Handle
 * every statement
 */
static boolean_t check_skip(Service_T s) {
        ASSERT(s);
        if (s->visited) {
                DEBUG("'%s' check skipped -- service already handled in a dependency chain\n", s->name);
                return true;
        }
        time_t now = Time_now();
        if (s->every.type == Every_SkipCycles) {
                s->every.spec.cycle.counter++;
                if (s->every.spec.cycle.counter < s->every.spec.cycle.number) {
                        s->monitor |= Monitor_Waiting;
                        DEBUG("'%s' test skipped as current cycle (%d) < every cycle (%d) \n", s->name, s->every.spec.cycle.counter, s->every.spec.cycle.number);
                        return true;
                }
                s->every.spec.cycle.counter = 0;
        } else if (s->every.type == Every_Cron && ! _incron(s, now)) {
                s->monitor |= Monitor_Waiting;
                DEBUG("'%s' test skipped as current time (%lld) does not match every's cron spec \"%s\"\n", s->name, (long long)now, s->every.spec.cron);
                return true;
        } else if (s->every.type == Every_NotInCron && Time_incron(s->every.spec.cron, now)) {
                s->monitor |= Monitor_Waiting;
                DEBUG("'%s' test skipped as current time (%lld) matches every's cron spec \"not %s\"\n", s->name, (long long)now, s->every.spec.cron);
                return true;
        }
        s->monitor &= ~Monitor_Waiting;
        return false;
}


/**
 * Returns true if scheduled action was performed
 */
static boolean_t do_scheduled_action(Service_T s) {
        int rv = false;
        if (s->doaction != Action_Ignored) {
                // FIXME: let the event engine do the action directly? (just replace s->action_ACTION with s->doaction and drop control_service call)
                rv = control_service(s->name, s->doaction);
                Event_post(s, Event_Action, State_Changed, s->action_ACTION, "%s action %s", actionnames[s->doaction], rv ? "done" : "failed");
                s->doaction = Action_Ignored;
                FREE(s->token);
        }
        return rv;
}


/* ---------------------------------------------------------------- Public */


/**
 *  This function contains the main check machinery for  monit. The
 *  validate function check services in the service list to see if
 *  they will pass all defined tests.
 */
int validate() {
        int errors = 0;
        Service_T s;

        Run.handler_flag = Handler_Succeeded;
        Event_queue_process();

        update_system_load();
        initprocesstree(&ptree, &ptreesize, &oldptree, &oldptreesize);
        gettimeofday(&systeminfo.collected, NULL);

        /* In the case that at least one action is pending, perform quick loop to handle the actions ASAP */
        if (Run.flags & Run_ActionPending) {
                Run.flags &= ~Run_ActionPending;
                for (s = servicelist; s; s = s->next)
                        do_scheduled_action(s);
        }

        /* Check the services */
        for (s = servicelist; s; s = s->next) {
                if (Run.flags & Run_Stopped)
                        break;
                if (! do_scheduled_action(s) && s->monitor && ! check_skip(s)) {
                        check_timeout(s); // Can disable monitoring => need to check s->monitor again
                        if (s->monitor) {
                                if (! s->check(s))
                                        errors++;
                                /* The monitoring may be disabled by some matching rule in s->check
                                 * so we have to check again before setting to Monitor_Yes */
                                if (s->monitor != Monitor_Not)
                                        s->monitor = Monitor_Yes;
                        }
                        gettimeofday(&s->collected, NULL);
                }
        }

        reset_depend();

        return errors;
}


/**
 * Validate a given process service s. Events are posted according to
 * its configuration. In case of a fatal event false is returned.
 */
boolean_t check_process(Service_T s) {
        ASSERT(s);
        pid_t pid = Util_isProcessRunning(s, false);
        if (! pid) {
                for (Nonexist_T l = s->nonexistlist; l; l = l->next)
                        Event_post(s, Event_Nonexist, State_Failed, l->action, "process is not running");
                return false;
        } else {
                for (Nonexist_T l = s->nonexistlist; l; l = l->next)
                        Event_post(s, Event_Nonexist, State_Succeeded, l->action, "process is running with pid %d", (int)pid);
        }
        /* Reset the exec and timeout errors if active ... the process is running (most probably after manual intervention) */
        if (IS_EVENT_SET(s->error, Event_Exec))
                Event_post(s, Event_Exec, State_Succeeded, s->action_EXEC, "process is running after previous exec error (slow starting or manually recovered?)");
        if (IS_EVENT_SET(s->error, Event_Timeout))
                for (ActionRate_T ar = s->actionratelist; ar; ar = ar->next)
                        Event_post(s, Event_Timeout, State_Succeeded, ar->action, "process is running after previous restart timeout (manually recovered?)");
        if (Run.flags & Run_ProcessEngineEnabled) {
                if (update_process_data(s, ptree, ptreesize, pid)) {
                        check_process_state(s);
                        check_process_pid(s);
                        check_process_ppid(s);
                        if (s->uid)
                                check_uid(s, s->inf->priv.process.uid);
                        if (s->euid)
                                check_euid(s, s->inf->priv.process.euid);
                        if (s->gid)
                                check_gid(s, s->inf->priv.process.gid);
                        if (s->uptimelist)
                                check_uptime(s);
                        for (Resource_T pr = s->resourcelist; pr; pr = pr->next)
                                check_process_resources(s, pr);
                } else {
                        LogError("'%s' failed to get service data\n", s->name);
                }
        }
        if (s->portlist) {
                /* pause port tests in the start timeout timeframe while the process is starting (it may take some time to the process before it starts accepting connections) */
                if (! s->start || s->inf->priv.process.uptime > s->start->timeout)
                        for (Port_T pp = s->portlist; pp; pp = pp->next)
                                check_connection(s, pp);
        }
        if (s->socketlist) {
                /* pause socket tests in the start timeout timeframe while the process is starting (it may take some time to the process before it starts accepting connections) */
                if (! s->start || s->inf->priv.process.uptime > s->start->timeout)
                        for (Port_T pp = s->socketlist; pp; pp = pp->next)
                                check_connection(s, pp);
        }
        return true;
}


/**
 * Validate a given filesystem service s. Events are posted according to
 * its configuration. In case of a fatal event false is returned.
 */
boolean_t check_filesystem(Service_T s) {
        ASSERT(s);

        if (! filesystem_usage(s)) {
                Event_post(s, Event_Data, State_Failed, s->action_DATA, "unable to read filesystem '%s' state", s->path);
                return false;
        }
        Event_post(s, Event_Data, State_Succeeded, s->action_DATA, "succeeded getting filesystem statistics for '%s'", s->path);

        if (s->perm)
                check_perm(s, s->inf->priv.filesystem.mode);

        if (s->uid)
                check_uid(s, s->inf->priv.filesystem.uid);

        if (s->gid)
                check_gid(s, s->inf->priv.filesystem.gid);

        check_filesystem_flags(s);

        for (Filesystem_T td = s->filesystemlist; td; td = td->next)
                check_filesystem_resources(s, td);

        return true;
}


/**
 * Validate a given file service s. Events are posted according to
 * its configuration. In case of a fatal event false is returned.
 */
boolean_t check_file(Service_T s) {
        struct stat stat_buf;

        ASSERT(s);

        if (stat(s->path, &stat_buf) != 0) {
                for (Nonexist_T l = s->nonexistlist; l; l = l->next)
                        Event_post(s, Event_Nonexist, State_Failed, l->action, "file doesn't exist");
                return false;
        } else {
                s->inf->priv.file.mode = stat_buf.st_mode;
                if (s->inf->priv.file.inode) {
                        s->inf->priv.file.inode_prev = s->inf->priv.file.inode;
                } else {
                        // Seek to the end of the file the first time we see it => skip existing content (files which passed the test at least once have inode always set via state file)
                        DEBUG("'%s' seeking to the end of the file\n", s->name);
                        s->inf->priv.file.readpos = stat_buf.st_size;
                        s->inf->priv.file.inode_prev = stat_buf.st_ino;
                }
                s->inf->priv.file.inode = stat_buf.st_ino;
                s->inf->priv.file.uid = stat_buf.st_uid;
                s->inf->priv.file.gid = stat_buf.st_gid;
                s->inf->priv.file.size = stat_buf.st_size;
                s->inf->priv.file.timestamp = MAX(stat_buf.st_mtime, stat_buf.st_ctime);
                for (Nonexist_T l = s->nonexistlist; l; l = l->next)
                        Event_post(s, Event_Nonexist, State_Succeeded, l->action, "file exists");
        }

        if (! S_ISREG(s->inf->priv.file.mode) && ! S_ISSOCK(s->inf->priv.file.mode)) {
                Event_post(s, Event_Invalid, State_Failed, s->action_INVALID, "is neither a regular file nor a socket");
                return false;
        } else {
                Event_post(s, Event_Invalid, State_Succeeded, s->action_INVALID, "is a regular file or socket");
        }

        if (s->checksum)
                check_checksum(s);

        if (s->perm)
                check_perm(s, s->inf->priv.file.mode);

        if (s->uid)
                check_uid(s, s->inf->priv.file.uid);

        if (s->gid)
                check_gid(s, s->inf->priv.file.gid);

        if (s->sizelist)
                check_size(s);

        if (s->timestamplist)
                check_timestamp(s, s->inf->priv.file.timestamp);

        if (s->matchlist)
                check_match(s);

        return true;

}


/**
 * Validate a given directory service s. Events are posted according to
 * its configuration. In case of a fatal event false is returned.
 */
boolean_t check_directory(Service_T s) {

        struct stat stat_buf;

        ASSERT(s);

        if (stat(s->path, &stat_buf) != 0) {
                for (Nonexist_T l = s->nonexistlist; l; l = l->next)
                        Event_post(s, Event_Nonexist, State_Failed, l->action, "directory doesn't exist");
                return false;
        } else {
                s->inf->priv.directory.mode = stat_buf.st_mode;
                s->inf->priv.directory.uid = stat_buf.st_uid;
                s->inf->priv.directory.gid = stat_buf.st_gid;
                s->inf->priv.directory.timestamp = MAX(stat_buf.st_mtime, stat_buf.st_ctime);
                for (Nonexist_T l = s->nonexistlist; l; l = l->next)
                        Event_post(s, Event_Nonexist, State_Succeeded, l->action, "directory exists");
        }

        if (! S_ISDIR(s->inf->priv.directory.mode)) {
                Event_post(s, Event_Invalid, State_Failed, s->action_INVALID, "is not directory");
                return false;
        } else {
                Event_post(s, Event_Invalid, State_Succeeded, s->action_INVALID, "is directory");
        }

        if (s->perm)
                check_perm(s, s->inf->priv.directory.mode);

        if (s->uid)
                check_uid(s, s->inf->priv.directory.uid);

        if (s->gid)
                check_gid(s, s->inf->priv.directory.gid);

        if (s->timestamplist)
                check_timestamp(s, s->inf->priv.directory.timestamp);

        return true;

}


/**
 * Validate a given fifo service s. Events are posted according to
 * its configuration. In case of a fatal event false is returned.
 */
boolean_t check_fifo(Service_T s) {

        struct stat stat_buf;

        ASSERT(s);

        if (stat(s->path, &stat_buf) != 0) {
                for (Nonexist_T l = s->nonexistlist; l; l = l->next)
                        Event_post(s, Event_Nonexist, State_Failed, l->action, "fifo doesn't exist");
                return false;
        } else {
                s->inf->priv.fifo.mode = stat_buf.st_mode;
                s->inf->priv.fifo.uid = stat_buf.st_uid;
                s->inf->priv.fifo.gid = stat_buf.st_gid;
                s->inf->priv.fifo.timestamp = MAX(stat_buf.st_mtime, stat_buf.st_ctime);
                for (Nonexist_T l = s->nonexistlist; l; l = l->next)
                        Event_post(s, Event_Nonexist, State_Succeeded, l->action, "fifo exists");
        }

        if (! S_ISFIFO(s->inf->priv.fifo.mode)) {
                Event_post(s, Event_Invalid, State_Failed, s->action_INVALID, "is not fifo");
                return false;
        } else {
                Event_post(s, Event_Invalid, State_Succeeded, s->action_INVALID, "is fifo");
        }

        if (s->perm)
                check_perm(s, s->inf->priv.fifo.mode);

        if (s->uid)
                check_uid(s, s->inf->priv.fifo.uid);

        if (s->gid)
                check_gid(s, s->inf->priv.fifo.gid);

        if (s->timestamplist)
                check_timestamp(s, s->inf->priv.fifo.timestamp);

        return true;

}


/**
 * Validate a program status. Events are posted according to
 * its configuration. In case of a fatal event false is returned.
 */
boolean_t check_program(Service_T s) {
        ASSERT(s);
        ASSERT(s->program);
        boolean_t rv = true;
        time_t now = Time_now();
        Process_T P = s->program->P;
        if (P) {
                if (Process_exitStatus(P) < 0) { // Program is still running
                        time_t execution_time = (now - s->program->started);
                        if (execution_time > s->program->timeout) { // Program timed out
                                LogError("'%s' program timed out after %lld seconds. Killing program with pid %ld\n", s->name, (long long)execution_time, (long)Process_getPid(P));
                                Process_kill(P);
                                Process_waitFor(P); // Wait for child to exit to get correct exit value
                                // Fall-through with P and evaluate exit value below.
                        } else {
                                // Defer test of exit value until program exit or timeout
                                DEBUG("'%s' status check defered - waiting on program to exit\n", s->name);
                                return true;
                        }
                }
                s->program->exitStatus = Process_exitStatus(P); // Save exit status for web-view display
                // Save program output
                StringBuffer_clear(s->program->output);
                _programOutput(Process_getErrorStream(P), s->program->output);
                _programOutput(Process_getInputStream(P), s->program->output);
                StringBuffer_trim(s->program->output);
                // Evaluate program's exit status against our status checks.
                /* TODO: Multiple checks we have now should be deprecated and removed - not useful because it
                 will alert on everything if != is used other than the match or if = is used, might report nothing on error. */
                for (Status_T status = s->statuslist; status; status = status->next) {
                        if (status->operator == Operator_Changed) {
                                if (status->initialized) {
                                        if (Util_evalQExpression(status->operator, s->program->exitStatus, status->return_value)) {
                                                Event_post(s, Event_Status, State_Changed, status->action, "program status changed (%d -> %d) -- %s", status->return_value, s->program->exitStatus, StringBuffer_length(s->program->output) ? StringBuffer_toString(s->program->output) : "no output");
                                                status->return_value = s->program->exitStatus;
                                        } else {
                                                Event_post(s, Event_Status, State_ChangedNot, status->action, "program status didn't change [status=%d] -- %s", s->program->exitStatus, StringBuffer_length(s->program->output) ? StringBuffer_toString(s->program->output) : "no output");
                                        }
                                } else {
                                        status->initialized = true;
                                        status->return_value = s->program->exitStatus;
                                }
                        } else {
                                if (Util_evalQExpression(status->operator, s->program->exitStatus, status->return_value)) {
                                        rv = false;
                                        Event_post(s, Event_Status, State_Failed, status->action, "'%s' failed with exit status (%d) -- %s", s->path, s->program->exitStatus, StringBuffer_length(s->program->output) ? StringBuffer_toString(s->program->output) : "no output");
                                } else {
                                        Event_post(s, Event_Status, State_Succeeded, status->action, "status succeeded [status=%d] -- %s", s->program->exitStatus, StringBuffer_length(s->program->output) ? StringBuffer_toString(s->program->output) : "no output");
                                }
                        }
                }
                Process_free(&s->program->P);
        }
        // Start program
        s->program->P = Command_execute(s->program->C);
        if (! s->program->P) {
                Event_post(s, Event_Status, State_Failed, s->action_EXEC, "failed to execute '%s' -- %s", s->path, STRERROR);
        } else {
                Event_post(s, Event_Status, State_Succeeded, s->action_EXEC, "'%s' program started", s->name);
                s->program->started = now;
        }
        return rv;
}


/**
 * Validate a remote service.
 * @param s The remote service to validate
 * @return false if there was an error otherwise true
 */
boolean_t check_remote_host(Service_T s) {
        ASSERT(s);

        Icmp_T last_ping = NULL;

        /* Test each icmp type in the service's icmplist */
        for (Icmp_T icmp = s->icmplist; icmp; icmp = icmp->next) {

                switch (icmp->type) {
                        case ICMP_ECHO:

                                icmp->response = icmp_echo(s->path, icmp->family, icmp->timeout, icmp->count);

                                if (icmp->response == -2) {
                                        icmp->is_available = true;
#ifdef SOLARIS
                                        DEBUG("'%s' ping test skipped -- the monit user has no permission to create raw socket, please add net_icmpaccess privilege\n", s->name);
#else
                                        DEBUG("'%s' ping test skipped -- the monit user has no permission to create raw socket, please run monit as root\n", s->name);
#endif
                                } else if (icmp->response == -1) {
                                        icmp->is_available = false;
                                        Event_post(s, Event_Icmp, State_Failed, icmp->action, "ping test failed");
                                } else {
                                        icmp->is_available = true;
                                        Event_post(s, Event_Icmp, State_Succeeded, icmp->action, "ping test succeeded [response time %.3fs]", icmp->response);
                                }
                                last_ping = icmp;
                                break;

                        default:
                                LogError("'%s' error -- unknown ICMP type: [%d]\n", s->name, icmp->type);
                                return false;

                }
        }

        /* If we could not ping the host we assume it's down and do not
         * continue to check any port connections  */
        if (last_ping && ! last_ping->is_available) {
                DEBUG("'%s' icmp ping failed, skipping any port connection tests\n", s->name);
                return false;
        }

        /* Test each host:port and protocol in the service's portlist */
        for (Port_T p = s->portlist; p; p = p->next)
                check_connection(s, p);

        return true;

}


/**
 * Validate the general system indicators. In case of a fatal event
 * false is returned.
 */
boolean_t check_system(Service_T s) {
        ASSERT(s);
        for (Resource_T r = s->resourcelist; r; r = r->next)
                check_process_resources(s, r);
        return true;
}


boolean_t check_net(Service_T s) {
        boolean_t havedata = true;
        TRY
        {
                Link_update(s->inf->priv.net.stats);
        }
        ELSE
        {
                havedata = false;
                for (LinkStatus_T link = s->linkstatuslist; link; link = link->next)
                        Event_post(s, Event_Link, State_Failed, link->action, "link data gathering failed -- %s", Exception_frame.message);
        }
        END_TRY;
        if (! havedata)
                return false; // Terminate test if no data are available
        for (LinkStatus_T link = s->linkstatuslist; link; link = link->next) {
                Event_post(s, Event_Size, State_Succeeded, link->action, "link data gathering succeeded");
        }
        // State
        if (! Link_getState(s->inf->priv.net.stats)) {
                for (LinkStatus_T link = s->linkstatuslist; link; link = link->next)
                        Event_post(s, Event_Link, State_Failed, link->action, "link down");
                return false; // Terminate test if the link is down
        } else {
                for (LinkStatus_T link = s->linkstatuslist; link; link = link->next)
                        Event_post(s, Event_Link, State_Succeeded, link->action, "link up");
        }
        // Link errors
        long long oerrors = Link_getErrorsOutPerSecond(s->inf->priv.net.stats);
        for (LinkStatus_T link = s->linkstatuslist; link; link = link->next) {
                if (oerrors)
                        Event_post(s, Event_Link, State_Failed, link->action, "%lld upload errors detected", oerrors);
                else
                        Event_post(s, Event_Link, State_Succeeded, link->action, "upload errors check succeeded");
        }
        long long ierrors = Link_getErrorsInPerSecond(s->inf->priv.net.stats);
        for (LinkStatus_T link = s->linkstatuslist; link; link = link->next) {
                if (ierrors)
                        Event_post(s, Event_Link, State_Failed, link->action, "%lld download errors detected", ierrors);
                else
                        Event_post(s, Event_Link, State_Succeeded, link->action, "download errors check succeeded");
        }
        // Link speed
        int duplex = Link_getDuplex(s->inf->priv.net.stats);
        long long speed = Link_getSpeed(s->inf->priv.net.stats);
        for (LinkSpeed_T link = s->linkspeedlist; link; link = link->next) {
                if (speed > 0 && link->speed) {
                        if (duplex > -1 && duplex != link->duplex)
                                Event_post(s, Event_Speed, State_Changed, link->action, "link mode is now %s-duplex", duplex ? "full" : "half");
                        else
                                Event_post(s, Event_Speed, State_ChangedNot, link->action, "link mode has not changed since last cycle [current mode is %s-duplex]", duplex ? "full" : "half");
                        if (speed != link->speed)
                                Event_post(s, Event_Speed, State_Changed, link->action, "link speed changed to %.0lf Mb/s", (double)speed / 1000000.);
                        else
                                Event_post(s, Event_Speed, State_ChangedNot, link->action, "link speed has not changed since last cycle [current speed = %.0lf Mb/s]", (double)speed / 1000000.);
                }
                link->duplex = duplex;
                link->speed = speed;
        }
        // Link saturation
        double osaturation = Link_getSaturationOutPerSecond(s->inf->priv.net.stats);
        double isaturation = Link_getSaturationInPerSecond(s->inf->priv.net.stats);
        if (osaturation >= 0. && isaturation >= 0.) {
                for (LinkSaturation_T link = s->linksaturationlist; link; link = link->next) {
                        if (duplex) {
                                if (Util_evalDoubleQExpression(link->operator, osaturation, link->limit))
                                        Event_post(s, Event_Saturation, State_Failed, link->action, "link upload saturation of %.1f%% matches limit [saturation %s %.1f%%]", osaturation, operatorshortnames[link->operator], link->limit);
                                else
                                        Event_post(s, Event_Saturation, State_Succeeded, link->action, "link upload saturation check succeeded [current upload saturation %.1f%%]", osaturation);
                                if (Util_evalDoubleQExpression(link->operator, isaturation, link->limit))
                                        Event_post(s, Event_Saturation, State_Failed, link->action, "link download saturation of %.1f%% matches limit [saturation %s %.1f%%]", isaturation, operatorshortnames[link->operator], link->limit);
                                else
                                        Event_post(s, Event_Saturation, State_Succeeded, link->action, "link download saturation check succeeded [current download saturation %.1f%%]", isaturation);
                        } else {
                                double iosaturation = osaturation + isaturation;
                                if (Util_evalDoubleQExpression(link->operator, iosaturation, link->limit))
                                        Event_post(s, Event_Saturation, State_Failed, link->action, "link saturation of %.1f%% matches limit [saturation %s %.1f%%]", iosaturation, operatorshortnames[link->operator], link->limit);
                                else
                                        Event_post(s, Event_Saturation, State_Succeeded, link->action, "link saturation check succeeded [current saturation %.1f%%]", iosaturation);
                        }
                }
        }
        // Upload
        char buf1[STRLEN], buf2[STRLEN];
        for (Bandwidth_T upload = s->uploadbyteslist; upload; upload = upload->next) {
                long long obytes;
                switch (upload->range) {
                        case Time_Minute:
                                obytes = Link_getBytesOutPerMinute(s->inf->priv.net.stats, upload->rangecount);
                                break;
                        case Time_Hour:
                                if (upload->rangecount == 1) // Use precise minutes range for "last hour"
                                        obytes = Link_getBytesOutPerMinute(s->inf->priv.net.stats, 60);
                                else
                                        obytes = Link_getBytesOutPerHour(s->inf->priv.net.stats, upload->rangecount);
                                break;
                        default:
                                obytes = Link_getBytesOutPerSecond(s->inf->priv.net.stats);
                                break;
                }
                if (Util_evalQExpression(upload->operator, obytes, upload->limit))
                        Event_post(s, Event_ByteOut, State_Failed, upload->action, "%supload %s matches limit [upload rate %s %s in last %d %s]", upload->range != Time_Second ? "total " : "", Str_bytesToSize(obytes, buf1), operatorshortnames[upload->operator], Str_bytesToSize(upload->limit, buf2), upload->rangecount, Util_timestr(upload->range));
                else
                        Event_post(s, Event_ByteOut, State_Succeeded, upload->action, "%supload check succeeded [current upload rate %s in last %d %s]", upload->range != Time_Second ? "total " : "", Str_bytesToSize(obytes, buf1), upload->rangecount, Util_timestr(upload->range));
        }
        for (Bandwidth_T upload = s->uploadpacketslist; upload; upload = upload->next) {
                long long opackets;
                switch (upload->range) {
                        case Time_Minute:
                                opackets = Link_getPacketsOutPerMinute(s->inf->priv.net.stats, upload->rangecount);
                                break;
                        case Time_Hour:
                                if (upload->rangecount == 1) // Use precise minutes range for "last hour"
                                        opackets = Link_getPacketsOutPerMinute(s->inf->priv.net.stats, 60);
                                else
                                        opackets = Link_getPacketsOutPerHour(s->inf->priv.net.stats, upload->rangecount);
                                break;
                        default:
                                opackets = Link_getPacketsOutPerSecond(s->inf->priv.net.stats);
                                break;
                }
                if (Util_evalQExpression(upload->operator, opackets, upload->limit))
                        Event_post(s, Event_PacketOut, State_Failed, upload->action, "%supload packets %lld matches limit [upload packets %s %lld in last %d %s]", upload->range != Time_Second ? "total " : "", opackets, operatorshortnames[upload->operator], upload->limit, upload->rangecount, Util_timestr(upload->range));
                else
                        Event_post(s, Event_PacketOut, State_Succeeded, upload->action, "%supload packets check succeeded [current upload packets %lld in last %d %s]", upload->range != Time_Second ? "total " : "", opackets, upload->rangecount, Util_timestr(upload->range));
        }
        // Download
        for (Bandwidth_T download = s->downloadbyteslist; download; download = download->next) {
                long long ibytes;
                switch (download->range) {
                        case Time_Minute:
                                ibytes = Link_getBytesInPerMinute(s->inf->priv.net.stats, download->rangecount);
                                break;
                        case Time_Hour:
                                if (download->rangecount == 1) // Use precise minutes range for "last hour"
                                        ibytes = Link_getBytesInPerMinute(s->inf->priv.net.stats, 60);
                                else
                                        ibytes = Link_getBytesInPerHour(s->inf->priv.net.stats, download->rangecount);
                                break;
                        default:
                                ibytes = Link_getBytesInPerSecond(s->inf->priv.net.stats);
                                break;
                }
                if (Util_evalQExpression(download->operator, ibytes, download->limit))
                        Event_post(s, Event_ByteIn, State_Failed, download->action, "%sdownload %s matches limit [download rate %s %s in last %d %s]", download->range != Time_Second ? "total " : "", Str_bytesToSize(ibytes, buf1), operatorshortnames[download->operator], Str_bytesToSize(download->limit, buf2), download->rangecount, Util_timestr(download->range));
                else
                        Event_post(s, Event_ByteIn, State_Succeeded, download->action, "%sdownload check succeeded [current download rate %s in last %d %s]", download->range != Time_Second ? "total " : "", Str_bytesToSize(ibytes, buf1), download->rangecount, Util_timestr(download->range));
        }
        for (Bandwidth_T download = s->downloadpacketslist; download; download = download->next) {
                long long ipackets;
                switch (download->range) {
                        case Time_Minute:
                                ipackets = Link_getPacketsInPerMinute(s->inf->priv.net.stats, download->rangecount);
                                break;
                        case Time_Hour:
                                if (download->rangecount == 1) // Use precise minutes range for "last hour"
                                        ipackets = Link_getPacketsInPerMinute(s->inf->priv.net.stats, 60);
                                else
                                        ipackets = Link_getPacketsInPerHour(s->inf->priv.net.stats, download->rangecount);
                                break;
                        default:
                                ipackets = Link_getPacketsInPerSecond(s->inf->priv.net.stats);
                                break;
                }
                if (Util_evalQExpression(download->operator, ipackets, download->limit))
                        Event_post(s, Event_PacketIn, State_Failed, download->action, "%sdownload packets %lld matches limit [download packets %s %lld in last %d %s]", download->range != Time_Second ? "total " : "", ipackets, operatorshortnames[download->operator], download->limit, download->rangecount, Util_timestr(download->range));
                else
                        Event_post(s, Event_PacketIn, State_Succeeded, download->action, "%sdownload packets check succeeded [current download packets %lld in last %d %s]", download->range != Time_Second ? "total " : "", ipackets, download->rangecount, Util_timestr(download->range));
        }
        return true;
}

