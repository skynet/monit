/*
 * Copyright (C) Tildeslash Ltd. All rights reserved.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License version 3.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
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


#ifndef NET_INCLUDED
#define NET_INCLUDED
#include <sys/types.h>
#include <sys/socket.h>


/**
 * Facade for system specific network and socket operation.
 *
 * @author http://www.tildeslash.com/
 * @see http://www.mmonit.com/
 * @file
 */


/**
 * Number of milli seconds before a socket write timeout
 */
#define NET_WRITE_TIMEOUT       3000

/**
 * Number of milli seconds before a socket read timeout
 */
#define NET_READ_TIMEOUT        3000


/**
 * Enable nonblocking i|o on the given socket.
 * @param socket A socket
 * @return true if success, otherwise false
 */
int Net_setNonBlocking(int socket);


/**
 * Disable nonblocking i|o on the given socket
 * @param socket A socket
 * @return true if success, otherwise false
 */
int Net_setBlocking(int socket);


/**
 * Check if data is available, if not, wait timeout milliseconds for data
 * to be present.
 * @param socket A socket
 * @param milliseconds How long to wait before timeout
 * @return true if the event occured, otherwise false.
 */
int Net_canRead(int socket, time_t milliseconds);


/**
 * Check if data can be sent to the socket, if not, wait timeout
 * milliseconds for the socket to be ready.
 * @param socket A socket
 * @param milliseconds How long to wait before timeout
 * @return true if the event occured, otherwise false.
 */
int Net_canWrite(int socket, time_t milliseconds);


/**
 * Read up to size bytes from the <code>socket</code> into the
 * <code>buffer</code>. If data is not available wait for
 * <code>timeout</code> milliseconds.
 * @param socket the Socket to read data from
 * @param buffer The buffer to write the data to
 * @param size Number of bytes to read from the socket
 * @param timeout Milliseconds to wait for data to be available
 * @return The number of bytes read or -1 if an error occured.
 */
ssize_t Net_read(int socket, void *buffer, size_t size, time_t timeout);


/**
 * Write <code>size</code> bytes from the <code>buffer</code> to the
 * <code>socket</code> 
 * @param socket the Socket to write to
 * @param buffer The buffer to write
 * @param size Number of bytes to send
 * @param timeout Milliseconds to wait for data to be sent
 * @return The number of bytes sent or -1 if an error occured. 
 */
ssize_t Net_write(int socket, const void *buffer, size_t size, time_t timeout);


/**
 * Aborts a TCP a connection. That is, TCP discards any data still remaining
 * in the socket send buffer and sends an RST to the peer, not the normal 
 * four-packet connection termination sequence. See "UNIX Network Programming" 
 * third edition ch 7.5. Generic Socket Options
 * @param socket The socket connection to abort and close
 * @return true if success otherwise false
 */
int Net_abort(int socket);



/**
 * Shutdown a full-duplex socket connection.
 * @param socket The socket connection to shutdown
 * @param how If how is SHUT_RD, further receives will be disallowed. If how
 * is SHUT_WR, further sends will be disallowed. If how is SHUT_RDWR, further
 * sends and receives will be disallowed
 * @return true if success otherwise false
 */
int Net_shutdown(int socket, int how);


/**
 * Close a socket connection
 * @param socket The socket connection to close
 * @return true if success otherwise false
 */
int Net_close(int socket);


#endif
