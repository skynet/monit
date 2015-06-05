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

#ifndef SSL_H
#define SSL_H


#include "config.h"


typedef enum {
        SSL_Disabled = 0,
        SSL_Auto,
        SSL_V2,
        SSL_V3,
        SSL_TLSV1,
        SSL_TLSV11,
        SSL_TLSV12
} __attribute__((__packed__)) Ssl_Version;


#define T Ssl_T
typedef struct T *T;


/*
 * The list of all ciphers suites in order of strength except those containing anonymous DH ciphers, low bit-size ciphers, export-crippled ciphersm the MD5 hash algorithm and weak DES and RC4 ciphers.
 */
#define CIPHER_LIST "ALL:!DES:!RC4:!aNULL:!LOW:!EXP:!IDEA:!MD5:@STRENGTH"


/**
 * Prepare for the beginning of active use of the OpenSSL library
 */
void Ssl_start();


/**
 * Gracefully terminate the active use of the OpenSSL library
 */
void Ssl_stop();


/**
 * Cleanup thread's error queue.
 */
void Ssl_threadCleanup();


/**
 * Enable or disable FIPS-140 mode
 * @param enabled true to enable FIPS-140 mode
 */
void Ssl_setFipsMode(boolean_t enabled);


/**
 * Create a new SSL connection object
 * @return a new SSL connection object or NULL if failed
 */
T Ssl_new(char *clientpemfile, Ssl_Version version);


/**
 * Free an SSL connection object
 * @param C A reference to SSL connection object
 */
void Ssl_free(T *C);


/**
 * Connect a socket using SSL. If name is set and TLS is used,
 * the Server Name Indication (SNI) TLS extension is enabled.
 * @param C An SSL connection object
 * @param socket A socket
 * @param name A server name string (optional)
 * @return true if succeeded or false if failed
 */
boolean_t Ssl_connect(T C, int socket, const char *name);


/**
 * Close an SSL connection
 * @param C An SSL connection object
 */
void Ssl_close(T C);


/**
 * Write <code>size</code> bytes from <code>b</code> to an encrypted channel
 * @param C An SSL connection object
 * @param b The data to be written
 * @param size Number of bytes in b
 * @param timeout Milliseconds to wait for data to be written
 * @return Number of bytes written or -1 if failed
 */
int Ssl_write(T C, void *b, int size, int timeout);


/**
 * Read <code>size</code> bytes to <code>b</code> from an encrypted channel
 * @param C An SSL connection object
 * @param b A byte buffer
 * @param size The size of the buffer b
 * @param timeout Milliseconds to wait for data to be read
 * @return Number of bytes read or -1 if failed
 */
int Ssl_read(T C, void *b, int size, int timeout);


/**
 * Compare a peer certificate with a given MD5 checksum
 * @param C An SSL connection object
 * @param md5sum Expected MD5 checksum in string format
 * @return true if succeeded or false if failed
 */
boolean_t Ssl_checkCertificate(T C, char *md5sum);


#undef T
#endif

