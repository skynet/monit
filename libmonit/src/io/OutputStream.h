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


#ifndef OUTPUTSTREAM_INCLUDED
#define OUTPUTSTREAM_INCLUDED
#include <sys/types.h>


/**
 * An <b>OutputStream</b> can be used for writing text or binary
 * data (8 bits) to a descriptor. 
 *
 * The method OutputStream_isClosed() can be used to test the
 * underlying descriptor for an error, a write timeout or for EOF.
 * 
 * Clients can use this stream in a non-blocking manner by setting 
 * OutputStream_setTimeout() to 0.
 * 
 * @author http://www.tildeslash.com/
 * @see http://www.mmonit.com/
 * @file
 */


#define T OutputStream_T
typedef struct T *T;


/**
 * Create a new OutputStream object.
 * @param descriptor The descriptor for this OutputStream
 * @return An OutputStream object
 */
T OutputStream_new(int descriptor);


/**
 * Destroy an OutputStream object, release allocated resources and flush
 * any remaining buffered data in the stream. Call this method to release
 * an OutputStream object allocated with OutputStream_new()
 * @param S An OutputStream object reference
 */
void OutputStream_free(T *S);


/** @name Properties */
//@{


/**
 * Returns the underlying descriptor for this stream
 * @param S An OutputStream object
 * @return The descriptor for this stream 
 */
int OutputStream_getDescriptor(T S);


/**
 * Returns the number of bytes in the OutputStream's cache buffer.
 * I.e. bytes that are cached in stream's internal buffer
 * @param S An OutputStream object
 * @return Number of output bytes cached
 */
int OutputStream_buffered(T S);


/**
 * Set a write <code>timeout</code> in milliseconds. During a write
 * operation the stream will wait up to <code>timeout</code>
 * milliseconds for write to be performed.
 * @param S An OutputStream object
 * @param timeout The timeout value in milliseconds
 * @exception AssertException if timeout isd < 0
 */
void OutputStream_setTimeout(T S, time_t timeout);


/**
 * Get the write timeout in milliseconds. 
 * @param S An OutputStream object
 * @return The timeout value in milliseconds
 */
time_t OutputStream_getTimeout(T S);


/**
 * Returns true if the stream was closed. The stream is closed
 * if an I/O error occurs
 * @param S An OutputStream object
 * @return true if the stream is closed, otherwise false
 */
int OutputStream_isClosed(T S);


/**
 * Get the total number of bytes written by the stream to the
 * underlying descriptor
 * @param S An OutputStream object
 * @return The total number of bytes written
 */
long long int OutputStream_getBytesWritten(T S);

//@}

/**
 * Writes a character string. Use this function to send text
 * based data to the underlying descriptor.
 * @param S An OutputStream object
 * @param s A String to send to the client. The string may contain 
 * format specifiers similar to the ones used by printf(3). The format
 * specifiers supported are:
 * <ul>
 * <li><b>%s, %c</b> - Prints a string (s) or a single char (c)
 * <li><b>%d, %i, %u, %o, %x</b> - The int argument is printed as a 
 * signed decimal (d or i), unsigned decimal (u), unsigned octal (o) or 
 * unsigned hexadecimal (x), respectively. An optional length modifier,
 * 'l' can be used to prefix d, i, n, o, u or x to specify a long argument
 * instead of an int argument. 
 * <li><b>%e, %f, %g</b> - Prints a real number (see printf(3) for details)
 * <li><b>%p</b> - The void * pointer argument is printed in hexadecimal
 * </ul>
 * @return The number of bytes written or -1 if an error occurred. If the 
 * stream uses non-blocking I/O, i.e. timeout is 0, then 0 is also returned
 * if a write would block, indicating that the caller should try again later.
 * @exception AssertException if an unknown format specifier is used in s.
 */
int OutputStream_print(T S, const char *s, ...) __attribute__((format (printf, 2, 3)));


/**
 * Writes a character string with a variable argument list. 
 * @param S An OutputStream object
 * @param s A String to send to the client. The string may contain 
 * format specifiers similar to the ones used by printf(3).
 * @param ap A variable argument lists
 * @return The number of bytes written or -1 if an error occurred. If the 
 * stream uses non-blocking I/O, i.e. timeout is 0, then 0 is also returned
 * if a write would block, indicating that the caller should try again later.
 * @exception AssertException if an unknown format specifier is used in s.
 */
int OutputStream_vprint(T S, const char *s, va_list ap);


/**
 * Write <code>size</code> bytes from the buffer <code>b</code>.
 * @param S An OutputStream object
 * @param b The data to be written
 * @param size The size of the data in b
 * @return The number of bytes written or -1 if an error occurred. If the 
 * stream uses non-blocking I/O, i.e. timeout is 0, then 0 is also returned
 * if a write would block, indicating that the caller should try again later.
*/
int OutputStream_write(T S, const void *b, int size);


/**
 * Flushes this output stream and write any buffered output bytes. 
 * @param S An OutputStream object
 * @return The number of bytes written or -1 if an error occurred. If the 
 * stream uses non-blocking I/O, i.e. timeout is 0, then 0 is also returned
 * if a write would block, indicating that the caller should try again later.
 */
int OutputStream_flush(T S);


/**
 * Clears any data that exists in the output buffer
 * @param S An OutputStream object
 */
void OutputStream_clear(T S);


#undef T
#endif
