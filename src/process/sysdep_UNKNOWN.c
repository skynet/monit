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

#include "monit.h"
#include "process.h"
#include "process_sysdep.h"


/**
 *  System dependent resource gathering code for UNKNOWN systems
 *
 *  @file
 */


int init_process_info_sysdep(void) {
  systeminfo.mem_kbyte_max = 0;

  return FALSE;
}


/**
 * THIS IS JUST A DUMMY!!!
 *
 * Read all processes of the proc files system to initialize
 * the process tree (sysdep version... but should work for
 * all procfs based unices)
 * @param reference  reference of ProcessTree
 * @return treesize>0 if succeeded otherwise =0.
 */
int initprocesstree_sysdep(ProcessTree_T ** reference) {
  return 0;
}

/**
 * THIS IS JUST A DUMMY!!!
 *
 * This routine returns 'nelem' double precision floats containing
 * the load averages in 'loadv'; at most 3 values will be returned.
 * @param loadv destination of the load averages
 * @param nelem number of averages
 * @return: 0 if successful, -1 if failed (and all load averages are 0).
 */
int getloadavg_sysdep (double *loadv, int nelem) {
  int i;

  for (i = 0; i < nelem; i++)
    loadv[i] = 0.0;

  return -1;
}


/**
 * This routine returns kbyte of real memory in use.
 * @return: TRUE if successful, FALSE if failed (or not available)
 */
int used_system_memory_sysdep(SystemInfo_T *si) {
  return FALSE;
}


/**
 * This routine returns system/user CPU time in use.
 * @return: TRUE if successful, FALSE if failed (or not available)
 */
int used_system_cpu_sysdep(SystemInfo_T *si) {
  return FALSE;
}

