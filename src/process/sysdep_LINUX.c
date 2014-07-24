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

#ifdef HAVE_ERRNO_H
#include <errno.h>
#endif

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#ifdef HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif

#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif

#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#ifdef TIME_WITH_SYS_TIME
#include <time.h>

#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif
#else
#include <time.h>
#endif

#ifdef HAVE_STRING_H
#include <string.h>
#endif

#ifdef HAVE_ASM_PARAM_H
#include <asm/param.h>
#endif

#ifdef HAVE_GLOB_H
#include <glob.h>
#endif

#ifndef HZ
# define HZ sysconf(_SC_CLK_TCK)
#endif

#include "monit.h"
#include "process.h"
#include "process_sysdep.h"


/**
 *  System dependent resource gathering code for Linux.
 *
 *  @file
 */


/* ----------------------------------------------------------------- Private */


#define UID             "Uid:"
#define GID             "Gid:"
#define MEMTOTAL        "MemTotal:"
#define MEMFREE         "MemFree:"
#define MEMBUF          "Buffers:"
#define MEMCACHE        "Cached:"
#define SLABRECLAIMABLE "SReclaimable:"
#define SWAPTOTAL       "SwapTotal:"
#define SWAPFREE        "SwapFree:"

#define NSEC_PER_SEC    1000000000L

static unsigned long long old_cpu_user     = 0;
static unsigned long long old_cpu_syst     = 0;
static unsigned long long old_cpu_wait     = 0;
static unsigned long long old_cpu_total    = 0;
static int                page_shift_to_kb = 0;


/**
 * Get system start time
 * @return seconds since unix epoch
 */
static time_t get_starttime() {
  char   buf[1024];
  double up = 0;

  if (! read_proc_file(buf, 1024, "uptime", -1, NULL)) {
    LogError("system statistic error -- cannot get system uptime\n");
    return 0;
  }

  if (sscanf(buf, "%lf", &up) != 1) {
    LogError("system statistic error -- invalid uptime\n");
    return 0;
  }

  return time(NULL) - (time_t)up;
}


/* ------------------------------------------------------------------ Public */


int init_process_info_sysdep(void) {
  char *ptr;
  char  buf[1024];
  long  page_size;
  int   page_shift;

  if (! read_proc_file(buf, sizeof(buf), "meminfo", -1, NULL)) {
    DEBUG("system statistic error -- cannot read /proc/meminfo\n");
    return FALSE;
  }
  if (! (ptr = strstr(buf, MEMTOTAL))) {
    DEBUG("system statistic error -- cannot get real memory amount\n");
    return FALSE;
  }
  if (sscanf(ptr+strlen(MEMTOTAL), "%ld", &systeminfo.mem_kbyte_max) != 1) {
    DEBUG("system statistic error -- cannot get real memory amount\n");
    return FALSE;
  }

  if ((systeminfo.cpus = sysconf(_SC_NPROCESSORS_CONF)) < 0) {
    DEBUG("system statistic error -- cannot get cpu count: %s\n", STRERROR);
    return FALSE;
  } else if (systeminfo.cpus == 0) {
    DEBUG("system reports cpu count 0, setting dummy cpu count 1\n");
    systeminfo.cpus = 1;
  }

  if ((page_size = sysconf(_SC_PAGESIZE)) <= 0) {
    DEBUG("system statistic error -- cannot get page size: %s\n", STRERROR);
    return FALSE;
  }

  for (page_shift = 0; page_size != 1; page_size >>= 1, page_shift++)
        ;
  page_shift_to_kb = page_shift - 10;

  return TRUE;
}


/**
 * Read all processes of the proc files system to initialize
 * the process tree (sysdep version... but should work for
 * all procfs based unices)
 * @param reference  reference of ProcessTree
 * @return treesize>0 if succeeded otherwise =0.
 */
int initprocesstree_sysdep(ProcessTree_T ** reference) {
  int                 i = 0, j;
  int                 rv, bytes = 0;
  int                 treesize = 0;
  int                 stat_pid = 0;
  int                 stat_ppid = 0;
  int                 stat_uid = 0;
  int                 stat_euid = 0;
  int                 stat_gid = 0;
  char               *tmp = NULL;
  char                procname[STRLEN];
  char                buf[1024];
  char                stat_item_state;
  long                stat_item_cutime = 0;
  long                stat_item_cstime = 0;
  long                stat_item_rss = 0;
  glob_t              globbuf;
  unsigned long       stat_item_utime = 0;
  unsigned long       stat_item_stime = 0;
  unsigned long long  stat_item_starttime = 0ULL;
  ProcessTree_T      *pt = NULL;

  ASSERT(reference);

  /* Find all processes in the /proc directory */
  if ((rv = glob("/proc/[0-9]*", GLOB_ONLYDIR, NULL, &globbuf))) {
    LogError("system statistic error -- glob failed: %d (%s)\n", rv, STRERROR);
    return FALSE;
  }

  treesize = globbuf.gl_pathc;

  pt = CALLOC(sizeof(ProcessTree_T), treesize);

  /* Insert data from /proc directory */
  for (i = 0; i < treesize; i++) {
    stat_pid = atoi(globbuf.gl_pathv[i] + strlen("/proc/"));

    /********** /proc/PID/stat **********/
    if (!read_proc_file(buf, sizeof(buf), "stat", stat_pid, NULL)) {
      DEBUG("system statistic error -- cannot read /proc/%d/stat\n", stat_pid);
      continue;
    }
    if (!(tmp = strrchr(buf, ')'))) {
      DEBUG("system statistic error -- file /proc/%d/stat parse error\n", stat_pid);
      continue;
    }
    *tmp = 0;
    if (sscanf(buf, "%*d (%256s", procname) != 1) {
      DEBUG("system statistic error -- file /proc/%d/stat process name parse error\n", stat_pid);
      continue;
    }
    tmp += 2;
    if (sscanf(tmp,
         "%c %d %*d %*d %*d %*d %*u %*u"
         "%*u %*u %*u %lu %lu %ld %ld %*d %*d %*d "
         "%*u %llu %*u %ld %*u %*u %*u %*u %*u "
         "%*u %*u %*u %*u %*u %*u %*u %*u %*d %*d\n",
         &stat_item_state,
         &stat_ppid,
         &stat_item_utime,
         &stat_item_stime,
         &stat_item_cutime,
         &stat_item_cstime,
         &stat_item_starttime,
         &stat_item_rss) != 8) {
      DEBUG("system statistic error -- file /proc/%d/stat parse error\n", stat_pid);
      continue;
    }

    /********** /proc/PID/status **********/
    if (! read_proc_file(buf, sizeof(buf), "status", stat_pid, NULL)) {
      DEBUG("system statistic error -- cannot read /proc/%d/status\n", stat_pid);
      continue;
    }
    if (! (tmp = strstr(buf, UID))) {
      DEBUG("system statistic error -- cannot find process uid\n");
      continue;
    }
    if (sscanf(tmp+strlen(UID), "\t%d\t%d", &stat_uid, &stat_euid) != 2) {
      DEBUG("system statistic error -- cannot read process uid\n");
      continue;
    }
    if (! (tmp = strstr(buf, GID))) {
      DEBUG("system statistic error -- cannot find process gid\n");
      continue;
    }
    if (sscanf(tmp+strlen(GID), "\t%d", &stat_gid) != 1) {
      DEBUG("system statistic error -- cannot read process gid\n");
      continue;
    }

    /********** /proc/PID/cmdline **********/
    if (! read_proc_file(buf, sizeof(buf), "cmdline", stat_pid, &bytes)) {
      DEBUG("system statistic error -- cannot read /proc/%d/cmdline\n", stat_pid);
      continue;
    }
    for (j = 0; j < (bytes - 1); j++) // The cmdline file contains argv elements/strings terminated separated by '\0' => join the string
      if (buf[j] == 0)
        buf[j] = ' ';

    /* Set the data in ptree only if all process related reads succeeded (prevent partial data in the case that continue was called during data gathering) */
    pt[i].time = get_float_time();
    pt[i].pid = stat_pid;
    pt[i].ppid = stat_ppid;
    pt[i].uid = stat_uid;
    pt[i].euid = stat_euid;
    pt[i].gid = stat_gid;
    pt[i].starttime = get_starttime() + (time_t)(stat_item_starttime / HZ);
    pt[i].cmdline = Str_dup(*buf ? buf : procname);
    pt[i].cputime = ((float)(stat_item_utime + stat_item_stime) * 10.0) / HZ; // jiffies -> seconds = 1 / HZ. HZ is defined in "asm/param.h"  and it is usually 1/100s but on alpha system it is 1/1024s
    pt[i].cpu_percent = 0;
    pt[i].mem_kbyte = (page_shift_to_kb < 0) ? (stat_item_rss >> abs(page_shift_to_kb)) : (stat_item_rss << abs(page_shift_to_kb));
    if (stat_item_state == 'Z') // State is Zombie -> then we are a Zombie ... clear or? (-:
      pt[i].status_flag |= PROCESS_ZOMBIE;
  }

  *reference = pt;
  globfree(&globbuf);

  return treesize;
}


/**
 * This routine returns 'nelem' double precision floats containing
 * the load averages in 'loadv'; at most 3 values will be returned.
 * @param loadv destination of the load averages
 * @param nelem number of averages
 * @return: 0 if successful, -1 if failed (and all load averages are 0).
 */
int getloadavg_sysdep(double *loadv, int nelem) {
#ifdef HAVE_GETLOADAVG
        return getloadavg(loadv, nelem);
#else
        char buf[STRLEN];
        double load[3];
        if (! read_proc_file(buf, sizeof(buf), "loadavg", -1, NULL))
                return -1;
        if (sscanf(buf, "%lf %lf %lf", &load[0], &load[1], &load[2]) != 3) {
                DEBUG("system statistic error -- cannot get load average\n");
                return -1;
        }
        for (int i = 0; i < nelem; i++)
                loadv[i] = load[i];
        return 0;
#endif
}


/**
 * This routine returns kbyte of real memory in use.
 * @return: TRUE if successful, FALSE if failed
 */
int used_system_memory_sysdep(SystemInfo_T *si) {
  char          *ptr;
  char           buf[1024];
  unsigned long  mem_free = 0UL;
  unsigned long  buffers = 0UL;
  unsigned long  cached = 0UL;
  unsigned long  slabreclaimable = 0UL;
  unsigned long  swap_total = 0UL;
  unsigned long  swap_free = 0UL;

  if (! read_proc_file(buf, 1024, "meminfo", -1, NULL)) {
    LogError("system statistic error -- cannot get real memory free amount\n");
    goto error;
  }

  /* Memory */
  if (! (ptr = strstr(buf, MEMFREE)) || sscanf(ptr + strlen(MEMFREE), "%ld", &mem_free) != 1) {
    LogError("system statistic error -- cannot get real memory free amount\n");
    goto error;
  }
  if (! (ptr = strstr(buf, MEMBUF)) || sscanf(ptr + strlen(MEMBUF), "%ld", &buffers) != 1)
    DEBUG("system statistic error -- cannot get real memory buffers amount\n");
  if (! (ptr = strstr(buf, MEMCACHE)) || sscanf(ptr + strlen(MEMCACHE), "%ld", &cached) != 1)
    DEBUG("system statistic error -- cannot get real memory cache amount\n");
  if (! (ptr = strstr(buf, SLABRECLAIMABLE)) || sscanf(ptr + strlen(SLABRECLAIMABLE), "%ld", &slabreclaimable) != 1)
    DEBUG("system statistic error -- cannot get slab reclaimable memory amount\n");
  si->total_mem_kbyte = systeminfo.mem_kbyte_max - mem_free - buffers - cached - slabreclaimable;

  /* Swap */
  if (! (ptr = strstr(buf, SWAPTOTAL)) || sscanf(ptr + strlen(SWAPTOTAL), "%ld", &swap_total) != 1) {
    LogError("system statistic error -- cannot get swap total amount\n");
    goto error;
  }
  if (! (ptr = strstr(buf, SWAPFREE)) || sscanf(ptr + strlen(SWAPFREE), "%ld", &swap_free) != 1) {
    LogError("system statistic error -- cannot get swap free amount\n");
    goto error;
  }
  si->swap_kbyte_max   = swap_total;
  si->total_swap_kbyte = swap_total - swap_free;

  return TRUE;

  error:
  si->total_mem_kbyte = 0;
  si->swap_kbyte_max = 0;
  return FALSE;
}


/**
 * This routine returns system/user CPU time in use.
 * @return: TRUE if successful, FALSE if failed (or not available)
 */
int used_system_cpu_sysdep(SystemInfo_T *si) {
  int                rv;
  unsigned long long cpu_total;
  unsigned long long cpu_user;
  unsigned long long cpu_nice;
  unsigned long long cpu_syst;
  unsigned long long cpu_idle;
  unsigned long long cpu_wait;
  unsigned long long cpu_irq;
  unsigned long long cpu_softirq;
  char               buf[1024];

  if (!read_proc_file(buf, 1024, "stat", -1, NULL)) {
    LogError("system statistic error -- cannot read /proc/stat\n");
    goto error;
  }

  rv = sscanf(buf, "cpu %llu %llu %llu %llu %llu %llu %llu",
         &cpu_user,
         &cpu_nice,
         &cpu_syst,
         &cpu_idle,
         &cpu_wait,
         &cpu_irq,
         &cpu_softirq);
  if (rv < 4) {
    LogError("system statistic error -- cannot read cpu usage\n");
    goto error;
  } else if (rv == 4) {
    /* linux 2.4.x doesn't support these values */
    cpu_wait    = 0;
    cpu_irq     = 0;
    cpu_softirq = 0;
  }

  cpu_total = cpu_user + cpu_nice + cpu_syst + cpu_idle + cpu_wait + cpu_irq + cpu_softirq;
  cpu_user  = cpu_user + cpu_nice;

  if (old_cpu_total == 0) {
    si->total_cpu_user_percent = -10;
    si->total_cpu_syst_percent = -10;
    si->total_cpu_wait_percent = -10;
  } else {
    unsigned long long delta = cpu_total - old_cpu_total;

    si->total_cpu_user_percent = (int)(1000 * (double)(cpu_user - old_cpu_user) / delta);
    si->total_cpu_syst_percent = (int)(1000 * (double)(cpu_syst - old_cpu_syst) / delta);
    si->total_cpu_wait_percent = (int)(1000 * (double)(cpu_wait - old_cpu_wait) / delta);
  }

  old_cpu_user  = cpu_user;
  old_cpu_syst  = cpu_syst;
  old_cpu_wait  = cpu_wait;
  old_cpu_total = cpu_total;
  return TRUE;

  error:
  si->total_cpu_user_percent = 0;
  si->total_cpu_syst_percent = 0;
  si->total_cpu_wait_percent = 0;
  return FALSE;
}


