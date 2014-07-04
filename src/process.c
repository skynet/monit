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

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
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

#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif

#ifdef HAVE_TIME_H
#include <time.h>
#endif

#ifdef HAVE_STRING_H
#include <string.h>
#endif

#include <stdio.h>

#include "monit.h"
#include "process.h"
#include "process_sysdep.h"

/**
 *  General purpose /proc methods.
 *
 *  @file
 */


/* ------------------------------------------------------------------ Public */


/**
 * Initialize the proc information code
 * @return TRUE if succeeded otherwise FALSE.
 */
int init_process_info(void) {
        memset(&systeminfo, 0, sizeof(SystemInfo_T));
        gettimeofday(&systeminfo.collected, NULL);
        if(uname(&systeminfo.uname) < 0) {
                LogError("'%s' resource monitoring initialization error -- uname failed: %s\n", Run.system->name, STRERROR);
                return FALSE;
        }

        systeminfo.total_cpu_user_percent = -10;
        systeminfo.total_cpu_syst_percent = -10;
        systeminfo.total_cpu_wait_percent = -10;

        return (init_process_info_sysdep());
}


/**
 * Get the proc infomation (CPU percentage, MEM in MByte and percent,
 * status), enduser version.
 * @param p A Service object
 * @param pid The process id
 * @return TRUE if succeeded otherwise FALSE.
 */
int update_process_data(Service_T s, ProcessTree_T *pt, int treesize, pid_t pid) {
        ASSERT(s);
        ASSERT(systeminfo.mem_kbyte_max > 0);

        /* save the previous pid and set actual one */
        s->inf->priv.process._pid = s->inf->priv.process.pid;
        s->inf->priv.process.pid  = pid;

        int leaf;
        if ((leaf = findprocess(pid, pt, treesize)) != -1) {
                /* save the previous ppid and set actual one */
                s->inf->priv.process._ppid             = s->inf->priv.process.ppid;
                s->inf->priv.process.ppid              = pt[leaf].ppid;
                s->inf->priv.process.uid               = pt[leaf].uid;
                s->inf->priv.process.euid              = pt[leaf].euid;
                s->inf->priv.process.gid               = pt[leaf].gid;
                s->inf->priv.process.uptime            = time(NULL) - pt[leaf].starttime;
                s->inf->priv.process.children          = pt[leaf].children_sum;
                s->inf->priv.process.mem_kbyte         = pt[leaf].mem_kbyte;
                s->inf->priv.process.status_flag       = pt[leaf].status_flag;
                s->inf->priv.process.total_mem_kbyte   = pt[leaf].mem_kbyte_sum;
                s->inf->priv.process.cpu_percent       = pt[leaf].cpu_percent;
                s->inf->priv.process.total_cpu_percent = pt[leaf].cpu_percent_sum;
                if (systeminfo.mem_kbyte_max == 0) {
                        s->inf->priv.process.total_mem_percent = 0;
                        s->inf->priv.process.mem_percent       = 0;
                } else {
                        s->inf->priv.process.total_mem_percent = (int)((double)pt[leaf].mem_kbyte_sum * 1000.0 / systeminfo.mem_kbyte_max);
                        s->inf->priv.process.mem_percent       = (int)((double)pt[leaf].mem_kbyte * 1000.0 / systeminfo.mem_kbyte_max);
                }
        } else {
                s->inf->priv.process.ppid              = -1;
                s->inf->priv.process.uid               = -1;
                s->inf->priv.process.euid              = -1;
                s->inf->priv.process.gid               = -1;
                s->inf->priv.process.uptime            = 0;
                s->inf->priv.process.children          = 0;
                s->inf->priv.process.total_mem_kbyte   = 0;
                s->inf->priv.process.total_mem_percent = 0;
                s->inf->priv.process.mem_kbyte         = 0;
                s->inf->priv.process.mem_percent       = 0;
                s->inf->priv.process.cpu_percent       = 0;
                s->inf->priv.process.total_cpu_percent = 0;
        }
        return TRUE;
}


/**
 * Updates the system wide statistic
 * @return TRUE if successful, otherwise FALSE
 */
int update_system_load() {
        if (Run.doprocess) {
                ASSERT(systeminfo.mem_kbyte_max > 0);

                /** Get load average triplet */
                if (-1 == getloadavg_sysdep(systeminfo.loadavg, 3)) {
                        LogError("'%s' statistic error -- load average gathering failed\n", Run.system->name);
                        goto error1;
                }

                /** Get memory usage statistic */
                if (! used_system_memory_sysdep(&systeminfo)) {
                        LogError("'%s' statistic error -- memory usage gathering failed\n", Run.system->name);
                        goto error2;
                }
                systeminfo.total_mem_percent  = (int)(1000 * (double)systeminfo.total_mem_kbyte / (double)systeminfo.mem_kbyte_max);
                systeminfo.total_swap_percent = systeminfo.swap_kbyte_max ? (int)(1000 * (double)systeminfo.total_swap_kbyte / (double)systeminfo.swap_kbyte_max) : 0;

                /** Get CPU usage statistic */
                if (! used_system_cpu_sysdep(&systeminfo)) {
                        LogError("'%s' statistic error -- cpu usage gathering failed\n", Run.system->name);
                        goto error3;
                }

                return TRUE;
        }

error1:
        systeminfo.loadavg[0] = 0;
        systeminfo.loadavg[1] = 0;
        systeminfo.loadavg[2] = 0;
error2:
        systeminfo.total_mem_kbyte   = 0;
        systeminfo.total_mem_percent = 0;
error3:
        systeminfo.total_cpu_user_percent = 0;
        systeminfo.total_cpu_syst_percent = 0;
        systeminfo.total_cpu_wait_percent = 0;

        return FALSE;
}


/**
 * Initialize the process tree
 * @return treesize >= 0 if succeeded otherwise < 0
 */
int initprocesstree(ProcessTree_T **pt_r, int *size_r, ProcessTree_T **oldpt_r, int *oldsize_r) {
        ASSERT(pt_r);
        ASSERT(size_r);
        ASSERT(oldpt_r);
        ASSERT(oldsize_r);

        if (*pt_r) {
                if (*oldpt_r)
                        delprocesstree(oldpt_r, oldsize_r);
                *oldpt_r = *pt_r;
                *oldsize_r = *size_r;
                *pt_r = NULL;
                *size_r = 0;
        }

        if ((*size_r = initprocesstree_sysdep(pt_r)) <= 0 || ! *pt_r) {
                DEBUG("System statistic error -- cannot initialize the process tree -- process resource monitoring disabled\n");
                Run.doprocess = FALSE;
                if (*oldpt_r)
                        delprocesstree(oldpt_r, oldsize_r);
                return -1;
        } else if (Run.doprocess == FALSE) {
                DEBUG("System statistic -- initialization of the process tree succeeded -- process resource monitoring enabled\n");
                Run.doprocess = TRUE;
        }

        int oldentry;
        ProcessTree_T *pt = *pt_r;
        ProcessTree_T *oldpt = *oldpt_r;
        for (int i = 0; i < (volatile int)*size_r; i ++) {
                if (oldpt && ((oldentry = findprocess(pt[i].pid, oldpt, *oldsize_r)) != -1)) {
                        pt[i].cputime_prev = oldpt[oldentry].cputime;
                        pt[i].time_prev    = oldpt[oldentry].time;

                        /* The cpu_percent may be set already (for example by HPUX module) */
                        if (pt[i].cpu_percent  == 0 && pt[i].cputime_prev != 0 && pt[i].cputime != 0 && pt[i].cputime > pt[i].cputime_prev) {
                                pt[i].cpu_percent = (int)((1000 * (double)(pt[i].cputime - pt[i].cputime_prev) / (pt[i].time - pt[i].time_prev)) / systeminfo.cpus);
                                if (pt[i].cpu_percent > 1000)
                                        pt[i].cpu_percent = 1000;
                        }
                } else {
                        pt[i].cputime_prev = 0;
                        pt[i].time_prev    = 0.0;
                        pt[i].cpu_percent  = 0;
                }

                if (pt[i].pid == pt[i].ppid) {
                        pt[i].parent = i;
                        continue;
                }

                if ((pt[i].parent = findprocess(pt[i].ppid, pt, *size_r)) == -1) {
                        /* Parent process wasn't found - on Linux this is normal: main process with PID 0 is not listed, similarly in FreeBSD jail.
                         * We create virtual process entry for missing parent so we can have full tree-like structure with root. */
                        int j = (*size_r)++;

                        pt = RESIZE(*pt_r, *size_r * sizeof(ProcessTree_T));
                        memset(&pt[j], 0, sizeof(ProcessTree_T));
                        pt[j].ppid = pt[j].pid  = pt[i].ppid;
                        pt[i].parent = j;
                }

                if (! connectchild(pt, pt[i].parent, i)) {
                        /* connection to parent process has failed, this is usually caused in the part above */
                        DEBUG("System statistic error -- cannot connect process id %d to its parent %d\n", pt[i].pid, pt[i].ppid);
                        pt[i].pid = 0;
                        continue;
                }
        }

        /* The main process in Solaris zones and FreeBSD host doesn't have pid 1, so try to find process which is parent of itself */
        int root = -1;
        for (int i = 0; i < *size_r; i++) {
                if (pt[i].pid == pt[i].ppid) {
                        root = i;
                        break;
                }
        }

        if (root == -1) {
                DEBUG("System statistic error -- cannot find root process id\n");
                if (*oldpt_r)
                        delprocesstree(oldpt_r, oldsize_r);
                if (*pt_r)
                        delprocesstree(pt_r, size_r);
                return -1;
        }

        fillprocesstree(pt, root);

        return *size_r;
}


/**
 * Search a leaf in the processtree
 * @param pid  pid of the process
 * @param pt  processtree
 * @param treesize  size of the processtree
 * @return process index if succeeded otherwise -1
 */
int findprocess(int pid, ProcessTree_T *pt, int size) {
        ASSERT(pt);

        if (size <= 0)
                return -1;

        for (int i = 0; i < size; i++)
                if (pid == pt[i].pid)
                        return i;

        return -1;
}

/**
 * Delete the process tree
 */
void delprocesstree(ProcessTree_T **reference, int *size) {
        ProcessTree_T *pt = *reference;
        if (pt) {
                for (int i = 0; i < *size; i++) {
                        FREE(pt[i].cmdline);
                        FREE(pt[i].children);
                }
                FREE(pt);
                *reference = NULL;
                *size = 0;
        }
}


void process_testmatch(char *pattern) {
#ifdef HAVE_REGEX_H
        regex_t *regex_comp;
        int reg_return;

        NEW(regex_comp);
        if ((reg_return = regcomp(regex_comp, pattern, REG_NOSUB|REG_EXTENDED))) {
                char errbuf[STRLEN];
                regerror(reg_return, regex_comp, errbuf, STRLEN);
                regfree(regex_comp);
                FREE(regex_comp);
                printf("Regex %s parsing error: %s\n", pattern, errbuf);
                exit(1);
        }
#endif
        initprocesstree(&ptree, &ptreesize, &oldptree, &oldptreesize);
        if (Run.doprocess) {
                int count = 0;
                printf("List of processes matching pattern \"%s\":\n", pattern);
                printf("------------------------------------------\n");
                for (int i = 0; i < ptreesize; i++) {
                        int match = FALSE;
                        if (ptree[i].cmdline && ! strstr(ptree[i].cmdline, "procmatch")) {
#ifdef HAVE_REGEX_H
                                match = regexec(regex_comp, ptree[i].cmdline, 0, NULL, 0) ? FALSE : TRUE;
#else
                                match = strstr(ptree[i].cmdline, pattern) ? TRUE : FALSE;
#endif
                                if (match) {
                                        printf("\t%s\n", ptree[i].cmdline);
                                        count++;
                                }
                        }
                }
                printf("------------------------------------------\n");
                printf("Total matches: %d\n", count);
                if (count > 1)
                        printf("WARNING: multiple processes matched the pattern. The check is FIRST-MATCH based, please refine the pattern\n");
        }
}


