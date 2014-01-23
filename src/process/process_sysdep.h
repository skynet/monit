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

#ifndef MONIT_PROCESS_SYSDEP_H
#define MONIT_PROCESS_SYSDEP_H

int init_process_info_sysdep(void);
int init_proc_info_sysdep(void);

int read_proc_file(char *, int, char *, int, int *);
int getloadavg_sysdep (double *, int);
int used_system_memory_sysdep(SystemInfo_T *);
int used_system_cpu_sysdep(SystemInfo_T *);

double get_float_time(void);

int    initprocesstree_sysdep(ProcessTree_T **);
void   fillprocesstree(ProcessTree_T *, int);

int    connectchild(ProcessTree_T *, int, int);


#endif
