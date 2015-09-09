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


#ifndef MONIT_SOCKET_H
#define MONIT_SOCKET_H


typedef enum {
        Socket_Tcp = SOCK_STREAM,
        Socket_Udp = SOCK_DGRAM
} __attribute__((__packed__)) Socket_Type;


typedef enum {
        Socket_Unix = 0,
        Socket_Ip,      // IP, version not specified (IPv4 or IPv6)
        Socket_Ip4,     // IPv4 only
        Socket_Ip6      // IPv6 only
} __attribute__((__packed__)) Socket_Family;


/**
 * This class implements a <b>Socket</b>. A socket is an endpoint for
 * communication between two machines.
 *
 * @file
 */


#define T Socket_T
typedef struct T *T;


/**
 * Create a new Socket opened against host:port. The returned Socket
 * is a connected socket. This method can be used to create either TCP
 * or UDP sockets and the type parameter is used to select the socket
 * type. If the use_ssl parameter is true the socket is created using
 * SSL. Only TCP sockets may use SSL.
 * @param host The remote host to open the Socket against. The host
 * may be a hostname found in the DNS or an IP address string.
 * @param port The port number to connect to
 * @param type The socket type to use
 * @param family The socket family to use
 * @param use_ssl if true the socket is created supporting SSL
 * @param timeout The timeout value in milliseconds
 * @return The connected Socket or NULL if an error occurred
 */
T Socket_new(const char *host, int port, Socket_Type type, Socket_Family family, boolean_t use_ssl, int timeout);


/**
 * Create a new Socket opened against host:port with an explicit
 * ssl value for connect and read. Otherwise, same as socket_new()
 * @param host The remote host to open the Socket against. The host
 * may be a hostname found in the DNS or an IP address string.
 * @param port The port number to connect to
 * @param type The socket type to use
 * @param family The socket family to use
 * @param ssl Options for SSL
 * @param timeout The timeout value in milliseconds
 * @return The connected Socket or NULL if an error occurred
 */
T Socket_create(const char *host, int port, Socket_Type type, Socket_Family family, SslOptions_T ssl, int timeout);


/**
 * Create a new unix Socket for given path for connect and read.
 * Otherwise, same as socket_new().
 * @param path The path to unix socket
 * @param type The socket type to use
 * @param timeout The timeout value in milliseconds
 * @return The connected Socket or NULL if an error occurred
 */
T Socket_createUnix(const char *path, Socket_Type type, int timeout);


/**
 * Factory method for creating a Socket object from an accepted
 * socket. The given socket must be a socket created from accept(2).
 * If the sslserver context is non-null the socket will support
 * ssl. This method does only support TCP sockets.
 * @param socket The accepted socket
 * @param addr The socket address
 * @param addrlen The socket address length
 * @param sslserver A ssl server connection context, may be NULL
 * @return A Socket or NULL if an error occurred
 */
T Socket_createAccepted(int socket, struct sockaddr *addr, socklen_t addrlen, void *sslserver);


/**
 * Destroy a Socket object. Close the socket and release allocated
 * resources.
 * @param S A Socket_T object reference
 */
void Socket_free(T *S);


/**
 * Set a read/write <code>timeout</code> in milliseconds. During a read
 * operation the socket will wait up to <code>timeout</code>
 * milliseconds for data to become available if not already present.
 * @param S A Socket_T object
 * @param timeout The timeout value in milliseconds
 */
void Socket_setTimeout(T S, int timeout);


/**
 * Returns the socket's read/write <code>timeout</code> in milliseconds.
 * @param S A Socket_T object
 * @return The timeout value in milliseconds
 */
int Socket_getTimeout(T S);


/**
 * Return true if the connection is encrypted with SSL
 * @param S A Socket_T object
 * @return true if SSL is used otherwise false
 */
boolean_t Socket_isSecure(T S);


/**
 * Get the underlying socket descriptor
 * @param S A Socket_T object
 * @return The socket descriptor
 */
int Socket_getSocket(T S);


/**
 * Get the type of this socket.
 * @param S A Socket_T object
 * @return The socket type
 */
Socket_Type Socket_getType(T S);


/**
 * Get the Port object used to create this socket. If no Port object
 * was used this method returns NULL.
 * @param S A Socket_T object
 * @return The Port object or NULL
 */
void *Socket_getPort(T S);


/**
 * Get the remote port number the socket is connected to
 * @param S A Socket_T object
 * @return The remote host's port number
 */
int Socket_getRemotePort(T S);


/**
 * Get the remote host this socket is connected to. The host is either
 * a host name in DNS or an IP address string.
 * @param S A Socket_T object
 * @return The remote host
 */
const char *Socket_getRemoteHost(T S);


/**
 * Get the local (ephemeral) port number this socket is using.
 * @param S A Socket_T object
 * @return The port number on success otherwise -1
 */
int Socket_getLocalPort(T S);


/**
 * Get the local interface IP address
 * @param S A Socket_T object
 * @param host A buffer for the hostname
 * @param hostlen A buffer length
 * @return The local host interface address or NULL if an error occurred
 */
const char *Socket_getLocalHost(T S, char *host, int hostlen);


/**
 * Test a Port_T object
 * @param P A port object to test
 * @exception IOException if test failed
 */
void Socket_test(void *P);


/**
 * Enables SSL on a connected socket.
 * @param S A connected Socket_T object
 * @param ssl Options for ssl
 * @param name An optional server name for SNI TLS extension
 * @exception IOException or AssertException if failed
 */
void Socket_enableSsl(T S, SslOptions_T ssl, const char *name);


/**
 * Writes a character string. Use this function to send text based
 * messages to a client.
 * @param S A Socket_T object
 * @param m A String to send to the client
 * @return The bytes sent or -1 if an error occured
 */
int Socket_print(T S, const char *m, ...) __attribute__((format (printf, 2, 3)));


/**
 * Write size bytes from the buffer b.
 * @param S A Socket_T object
 * @param b The data to be written
 * @param size The size of the data in b
 * @return The bytes sent or -1 if an error occured
 */
int Socket_write(T S, void *b, size_t size);


/**
 * Read a single byte. The byte is returned as an int in the range 0
 * to 255.
 * @param S A Socket_T object
 * @return The byte read, or -1 if the end of the stream has been reached
 */
int Socket_readByte(T S);


/**
 * Reads size bytes and stores them into the byte buffer pointed to by b.
 * @param S A Socket_T object
 * @param b A Byte buffer
 * @param size The size of the buffer b
 * @return The bytes read or -1 if an error occured
 */
int Socket_read(T S, void *b, int size);


/**
 * Reads in at most one less than size <code>characters</code> and
 * stores them into the buffer pointed to by s. Reading stops after
 * an EOF or a newline.  If a newline is read, it is stored into the
 * buffer.  A '\0' is stored after the last character in the buffer.
 * @param S A Socket_T object
 * @param s A character buffer to store the string in
 * @param size The size of the string buffer, s
 * @return s on success, and NULL on error or when end of file occurs
 * while no characters have been read.
 */
char *Socket_readLine(T S, char *s, int size);


#undef T
#endif

