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

#ifndef MONIT_PROCESS_H
#define MONIT_PROCESS_H

#include "config.h"

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#define PROCESS_ZOMBIE        1

int update_process_data(Service_T s, ProcessTree_T *, int treesize, pid_t pid);
int init_process_info(void);
int update_system_load();
int  findprocess(int, ProcessTree_T *, int);
int  initprocesstree(ProcessTree_T **, int *, ProcessTree_T **, int *);
void delprocesstree(ProcessTree_T **, int *);
void process_testmatch(char *);

#endif

