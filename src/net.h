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


#ifndef NET_H
#define NET_H

#include "config.h"
#include "monit.h"


/**
 *  General purpose Network and Socket methods.
 *
 *  @file
 */


/**
 * Standard milliseconds to wait for a socket connection or for socket read
 * i/o before aborting
 */
#define NET_TIMEOUT 5000


/**
 * Check if the hostname resolves
 * @param hostname The host to check
 * @return true if hostname resolves, otherwise false
 */
boolean_t check_host(const char *hostname);


/**
 * Create a non-blocking server socket and bind it to the specified local
 * port number, with the specified backlog. Set a socket option to
 * make the port reusable again. If a bind address is given the socket
 * will only accept connect requests to this addresses. If the bind
 * address is NULL it will accept connections on any/all local
 * addresses
 * @param address the local address the server will bind to
 * @param port The localhost port number to open
 * @param backlog The maximum queue length for incomming connections
 * @return The socket ready for accept, or -1 if an error occured.
 */
int create_server_socket(const char *address, int port, int backlog);


/**
 * Create a non-blocking server socket and bind it to the specified unix
 * socket path, with the specified backlog.
 * @param address the path to the unix socket
 * @param backlog The maximum queue length for incomming connections
 * @return The socket ready for accept, or -1 if an error occured.
 */
int create_server_socket_unix(const char *path, int backlog);


/**
 * Create a ICMP socket against hostname, send echo and wait for response.
 * The 'count' echo requests  is send and we expect at least one reply.
 * @param hostname The host to open a socket at
 * @param family The socket family to use
 * @param timeout If response will not come within timeout milliseconds abort
 * @param count How many pings to send
 * @return response time on succes, -1 on error
 */
double icmp_echo(const char *hostname, Socket_Family family, int timeout, int count);

#endif
