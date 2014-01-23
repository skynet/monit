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


#ifndef ENGINE_H
#define ENGINE_H

#include "config.h"

#include "net.h"
#include "processor.h"
#include "cervlet.h"

/*
 * The maximum queue length for incoming connection
 * indications (a request to connect)
 */
#define DEFAULT_QUEUE_LEN  10

typedef struct host_allow {
  unsigned long network;
  unsigned long mask;
  /* For internal use */
  struct host_allow *next;
} *HostsAllow;

/* Public prototypes */
void start_httpd(int port, int backlog, char *bindAddr);
void stop_httpd();
int add_host_allow(char *);
int add_net_allow(char *);
int has_hosts_allow();
void destroy_hosts_allow();


#endif
