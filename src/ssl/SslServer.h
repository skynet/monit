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

#ifndef SSLSERVER_H
#define SSLSERVER_H


#include "config.h"


#define T SslServer_T
typedef struct T *T;


/**
 * Initialize an SSL server connection
 * @param pemfile A server PEM file
 * @param clientpemfile A PEM file for certificate based authentication or NULL if not used
 * @param socket A socket
 * @return a new SSL server object or NULL if failed
 */
T SslServer_new(char *pemfile, char *clientpemfile, int socket);


/**
 * Delete an SSL server connection
 * @param S An SSL server object 
 */
void SslServer_free(T *S);


/**
 * Insert an SSL connection to the server connection list
 * @param S An SSL server object
 * @return a new SSL connection object or NULL if failed
 */
Ssl_T SslServer_newConnection(T S);


/**
 * Close and free an accepted SSL server connection and remove it from the connection list
 * @param S An SSL server object 
 * @param C An SSL connection object reference
 */
void SslServer_freeConnection(T S, Ssl_T *C);


/**
 * Embed an accepted socket in an existing SSL connection
 * @param C An SSL connection object 
 * @param socket An accepted socket
 * @param timeout Milliseconds to wait for connection to be established
 * @return true if succeeded or false if failed
 */
boolean_t SslServer_accept(Ssl_T C, int socket, int timeout);


#undef T
#endif

