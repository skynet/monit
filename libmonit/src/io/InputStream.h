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


#ifndef INPUTSTREAM_INCLUDED
#define INPUTSTREAM_INCLUDED
#include <sys/types.h>


/**
 * An <b>InputStream</b> can be used for reading text or binary
 * data (8 bits) from a descriptor. 
 *
 * The method InputStream_isClosed() can be used to test the
 * underlying descriptor for an error, a read timeout or for EOF.
 * 
 * Clients can use this stream in a non-blocking manner by setting 
 * InputStream_setTimeout() to 0.
 * 
 * @author http://www.tildeslash.com/
 * @see http://www.mmonit.com/
 * @file
 */


#define T InputStream_T
typedef struct T *T;


/**
 * Create a new InputStream object.
 * @param descriptor The descriptor for this inputstream
 * @return An InputStream object
 */
T InputStream_new(int descriptor);


/**
 * Destroy an InputStream object and release allocated resources. 
 * Call this method to release an InputStream object allocated with
 * InputStream_new()
 * @param S An InputStream object reference
 */
void InputStream_free(T *S);


/** @name Properties */
//@{


/**
 * Returns the underlying descriptor for this stream
 * @param S An InputStream object
 * @return The descriptor for this stream 
 */
int InputStream_getDescriptor(T S);


/**
 * Set a read <code>timeout</code> in milliseconds. During a read
 * operation the stream will wait up to <code>timeout</code>
 * milliseconds for data to become available if not already present.
 * @param S An InputStream object
 * @param timeout The timeout value in milliseconds
 * @exception AssertException if timeout is < 0
 */
void InputStream_setTimeout(T S, time_t timeout);


/**
 * Get the read timeout in milliseconds. 
 * @param S An InputStream object
 * @return The timeout value in milliseconds
 */
time_t InputStream_getTimeout(T S);


/**
 * Returns true if the underlying descriptor was closed. The stream is
 * closed if an I/O error occurs.
 * @param S An InputStream object
 * @return true if the descriptor was closed, otherwise false
 */
int InputStream_isClosed(T S);


/**
 * Returns the number of bytes in the InputStream's cache buffer. 
 * I.e. bytes that are cached in the stream's internal buffer
 * @param S An InputStream object
 * @return Number of input bytes cached
 */
int InputStream_buffered(T S);

//@}

/**
 * Read a single byte. The byte is returned as an int in the range 0-255.
 * @param S An InputStream object
 * @return The byte read, or -1 if the end of the stream has been reached
 * If the stream uses non-blocking I/O, i.e. timeout is 0, then -1 is also
 * returned if a read would block, indicating that the caller should try again
 * later.
 */
int InputStream_read(T S);


/**
 * Reads in at most one less than <code>size</code> characters and stores
 * them into the buffer pointed to by <code>s</code>. Reading stops after
 * an EOF, a newline or '\\0'. If a newline is read, it is stored into the buffer.
 * A '\\0' is stored after the last character in the buffer.
 * @param S An InputStream object
 * @param s A character buffer to store the string in
 * @param size The size of the string buffer s
 * @return s on success or NULL when end of file or an error occurs.
 * If the stream uses non-blocking I/O, i.e. timeout is 0, then NULL is also
 * returned if a read would block, indicating that the caller should try again
 * later.
 */
char *InputStream_readLine(T S, char *s, int size);


/**
 * Reads size <code>bytes</code> and stores them into the byte buffer
 * pointed to by <code>b</code>. Reading stops when size bytes are read
 * or if no more data is available. The buffer is <b>not</b> NUL terminated. 
 * @param S An InputStream object
 * @param b A Byte buffer
 * @param size The size of the buffer b
 * @return Number of bytes read, 0 when end of file or -1 if an error occurs.
 * If the stream uses non-blocking I/O, i.e. timeout is 0, then 0 is also
 * returned if a read would block, indicating that the caller should try again
 * later.
 */
int InputStream_readBytes(T S, void *b, int size);


/**
 * Clears any data that exist in the buffer
 * @param S An InputStream object
 */
void InputStream_clear(T S);


#undef T
#endif
