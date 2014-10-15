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


#include "Config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <errno.h>
#include <stdarg.h>

#include "Str.h"
#include "system/Net.h"
#include "InputStream.h"


/**
 * Implementation of the InputStream interface. 
 *
 * @author http://www.tildeslash.com/
 * @see http://www.mmonit.com/
 * @file
 */


/* ----------------------------------------------------------- Definitions */


// One TCP frame data size
#define BUFFER_SIZE 1500

#define T InputStream_T
struct T {
        int fd;
        int offset;
        int length;
        time_t timeout;
        boolean_t isclosed;
        uchar_t buffer[BUFFER_SIZE];
};


/* --------------------------------------------------------------- Private */


/* Fill the internal buffer. Only read once, since we may have read all and an
extra read would just be an extra system call. Returns true (the length of
data read), -1 if an error occured or if the connection was closed by the
client. 0 is returned if a read returned 0 (eof) and read should be retried
because it would block. If an error occured the stream is also set in closed
mode. */
static inline int fill(T S) {
        if (S->isclosed)
                return -1;
        S->length = 0;
        S->offset = 0;
        errno = 0;
        int n = (int)Net_read(S->fd, S->buffer, BUFFER_SIZE, S->timeout);
        if (n > 0)
                S->length = n;
        else if (n < 0) {
                n = -1;
                S->isclosed = true;
                S->offset = S->length = 0;
        } else if (! (errno == EAGAIN || errno == EWOULDBLOCK)) // peer closed connection
                n = -1;
        return n;
}


/* Read a single byte. The byte is returned as an int in the range 0 to 255.
Returns the byte read, or -1 if the end of the stream has been reached or if a
read error occurred */
static inline int read_byte(T S) {
        if (S->offset >= S->length) {
                if (fill(S) <= 0) {
                        return -1;
                }
        }
        return S->buffer[S->offset++];
}


/* ---------------------------------------------------------------- Public */


T InputStream_new(int descriptor) {
        T S;
        NEW(S);
        S->fd = descriptor;
        S->timeout = NET_READ_TIMEOUT;
        return S;
}


void InputStream_free(T *S) {
        assert(S && *S);
        FREE(*S);
}


/* ------------------------------------------------------------ Properties */


int InputStream_getDescriptor(T S) {
        assert(S);
        return S->fd;
}


void InputStream_setTimeout(T S, time_t timeout) {
        assert(S);
        assert(timeout >= 0);
        S->timeout = timeout;
}


time_t InputStream_getTimeout(T S) {
        assert(S);
        return S->timeout;
}


int InputStream_isClosed(T S) {
        assert(S);
        return S->isclosed;
}


int InputStream_buffered(T S) {
        assert(S);
        return S->length - S->offset;
}


/* ---------------------------------------------------------------- Public */


int InputStream_read(T S) {
        assert(S);
        return read_byte(S);
}


char *InputStream_readLine(T S, char *s, int size) { 
        assert(S);
        assert(s);
        uchar_t *p = (uchar_t *)s; 
        for (int c = 0; (--size > 0) && ((c = read_byte(S)) > 0);) { // Stop if \0 is read or no more data
                *p++ = c;
                if (c == '\n')
                        break;
        }
        *p = 0;
        return *s ? s : NULL;
}


int InputStream_readBytes(T S, void *b, int size) {
        assert(S);
        assert(b);
        uchar_t *p = (uchar_t*)b;
        for (int c = 0; (size-- > 0) && ((c = read_byte(S)) != -1);)
                *p++ = c;
        return  S->isclosed ? -1 : (int)(p - (uchar_t*)b);
}


void InputStream_clear(T S) {
        assert(S);
        S->offset = S->length = 0;
}
