/*
 * Copyright (C) Tildeslash Ltd. All rights reserved.
 * Copyright (c) 1994,1995,1996,1997 by David R. Hanson.
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
#include <errno.h>
#include <stdarg.h>
#include <float.h>
#include <limits.h>
#include <ctype.h>
#ifdef OPENBSD
#include <sys/uio.h>
#endif

#include "system/Net.h"
#include "OutputStream.h"


/**
 * Implementation of the OutputStream interface. The printf implementation is
 * based on "Fmt" from David Hanson's excellent CII library.
 *
 * @author http://www.tildeslash.com/
 * @see http://www.mmonit.com/
 * @file
 */


/* ----------------------------------------------------------- Definitions */


// One TCP frame data size
#define BUFFER_SIZE 1500

#define T OutputStream_T
struct T {
        int fd;
        time_t timeout;
        uchar_t *limit;
        uchar_t *length;
        boolean_t isclosed;
        int sessionWritten;
        long long int bytesWritten;
        uchar_t buffer[BUFFER_SIZE + 1];
};
typedef struct va_list_box {va_list ap;} va_list_box;
typedef void (*fmt_t)(T S, int code, va_list_box *box, unsigned char flags[256], int width, int precision);


/* --------------------------------------------------------------- Private */


/* Write the output buffer to the underlying file descriptor */
static int flush(T S) {
        if (S->isclosed)
                return -1;
        errno = 0;
        int n = (int)Net_write(S->fd, S->buffer, S->length - S->buffer, S->timeout);
        if (n > 0) {
                S->bytesWritten += n;
                if ((S->buffer + n) < S->length) { // Did not write all, shift remaining to the front of buffer
                        // TODO: Instead of shifting, use buffer as a circular buffer
                        memmove(S->buffer, S->buffer + n, S->length - (S->buffer + n));
                }
                S->length -= n;
        } else if (n < 0) {
                n = -1; 
                S->isclosed = true; 
        } else if (! (errno == EAGAIN || errno == EWOULDBLOCK)) // peer closed connection
                n = -1;
        return n;
}


/* Write a single byte. The byte is written as an int in the range 0 to 255.
 Returns the byte written, or -1 if a write error occurred */
static inline int write_byte(T S, uchar_t byte) {
        if (S->length == S->limit) {
                if (flush(S) <= 0)
                        return -1;
        }
        *S->length++ = byte;
        S->sessionWritten++;
        return byte;
}


/* ------------------------------------------------------- Format handlers */


#define pad(n,c) do { int nn = (n); while (nn-- > 0) write_byte(S, (c)); } while (0)
static void putd(T S, const char *str, int len, unsigned char flags[], int width, int precision) {
        int sign;
        assert(str);
        assert(len >= 0);
        assert(flags);
        if (width == INT_MIN)
                width = 0;
        if (width < 0) {
                flags['-'] = 1;
                width = -width;
        }
        if (precision >= 0)
                flags['0'] = 0;
        if (len > 0 && (*str == '-' || *str == '+')) {
                sign = *str++;
                len--;
        } else if (flags['+'])
                sign = '+';
        else if (flags[' '])
                sign = ' ';
        else
                sign = 0;
        { int n;
                if (precision < 0)
                        precision = 1;
                if (len < precision)
                        n = precision;
                else if (precision == 0 && len == 1 && str[0] == '0')
                        n = 0;
                else
                        n = len;
                if (sign)
                        n++;
                if (flags['-']) {
                        if (sign)
                                write_byte(S, sign);
                } else if (flags['0']) {
                        if (sign)
                                write_byte(S, sign);
                        pad(width - n, '0');
                } else {
                        pad(width - n, ' ');
                        if (sign)
                                write_byte(S, sign);
                }
                pad(precision - len, '0');
                for (int i = 0; i < len; i++)
                        write_byte(S, (uchar_t)*str++);
                if (flags['-'])
                        pad(width - n, ' '); 
        }
}


static void cvt_s(T S, int code, va_list_box *box, unsigned char flags[], int width, int precision) {
        uchar_t *str = va_arg(box->ap, uchar_t *);
        assert(str);
        int len = (int)strlen((char*)str);
        assert(len >= 0);
        assert(flags);
        if (width == INT_MIN)
                width = 0;
        if (width < 0) {
                flags['-'] = 1;
                width = -width;
        }
        if (precision >= 0)
                flags['0'] = 0;
        if (precision >= 0 && precision < len)
                len = precision;
        if (!flags['-'])
                pad(width - len, ' ');
        for (int i = 0; i < len; i++)
                write_byte(S, *str++);
        if (flags['-'])
                pad(width - len, ' ');
}


static void cvt_d(T S, int code, va_list_box *box, unsigned char flags[], int width, int precision) {
        int val = va_arg(box->ap, int);
        unsigned int m;
        char buf[43];
        char *p = buf + sizeof buf;
        if (val == INT_MIN)
                m = INT_MAX + 1UL;
        else if (val < 0)
                m = -val;
        else
                m = val;
        do
                *--p = m%10 + '0';
        while ((m /= 10) > 0);
        if (val < 0)
                *--p = '-';
        putd(S, p, (int)((buf + sizeof buf) - p), flags, width, precision);
}


static void cvt_l(T S, int code, va_list_box *box, unsigned char flags[], int width, int precision) {
        long val = va_arg(box->ap, long);
        unsigned long m;
        char buf[43];
        char *p = buf + sizeof buf;
        if (val == LONG_MIN)
                m = LONG_MAX + 1UL;
        else if (val < 0)
                m = -val;
        else
                m = val;
        do
                *--p = m%10 + '0';
        while ((m /= 10) > 0);
        if (val < 0)
                *--p = '-';
        putd(S, p, (int)((buf + sizeof buf) - p), flags, width, precision);
}


static void cvt_u(T S, int code, va_list_box *box, unsigned char flags[], int width, int precision) {
        unsigned long m = va_arg(box->ap, unsigned long);
        char buf[43];
        char *p = buf + sizeof buf;
        do
                *--p = m%10 + '0';
        while ((m /= 10) > 0);
        putd(S, p, (int)((buf + sizeof buf) - p), flags, width, precision);
}


static void cvt_o(T S, int code, va_list_box *box, unsigned char flags[], int width, int precision) {
        unsigned long m = va_arg(box->ap, unsigned long);
        char buf[43];
        char *p = buf + sizeof buf;
        do
                *--p = (m&0x7) + '0';
        while ((m>>= 3) != 0);
        putd(S, p, (int)((buf + sizeof buf) - p), flags, width, precision);
}


static void cvt_x(T S, int code, va_list_box *box, unsigned char flags[], int width, int precision) {
        unsigned long m = va_arg(box->ap, unsigned long);
        char buf[43];
        char *p = buf + sizeof buf;
        do
                *--p = "0123456789abcdef"[m&0xf];
        while ((m>>= 4) != 0);
        putd(S, p, (int)((buf + sizeof buf) - p), flags, width, precision);
}


static void cvt_p(T S, int code, va_list_box *box, unsigned char flags[], int width, int precision) {
        unsigned long m = (unsigned long)va_arg(box->ap, void*);
        char buf[43];
        char *p = buf + sizeof buf;
        precision = INT_MIN;
        do
                *--p = "0123456789abcdef"[m&0xf];
        while ((m>>= 4) != 0);
        putd(S, p, (int)((buf + sizeof buf) - p), flags, width, precision);
}


static void cvt_c(T S, int code, va_list_box *box, unsigned char flags[], int width, int precision) {
        if (width == INT_MIN)
                width = 0;
        if (width < 0) {
                flags['-'] = 1;
                width = -width;
        }
        if (!flags['-'])
                pad(width - 1, ' ');
        write_byte(S, va_arg(box->ap, int));
        if (flags['-'])
                pad(width - 1, ' ');
}


static void cvt_f(T S, int code, va_list_box *box, unsigned char flags[], int width, int precision) {
        char buf[DBL_MAX_10_EXP+1+1+99+1];
        if (precision < 0)
                precision = 6;
        if (code == 'g' && precision == 0)
                precision = 1;
        {
                char fmt[] = "%.dd?";
                assert(precision <= 99);
                fmt[4] = code;
                fmt[3] = precision%10 + '0';
                fmt[2] = (precision/10)%10 + '0';
                snprintf(buf, sizeof(buf), fmt, va_arg(box->ap, double));
        }
        putd(S, buf, (int)strlen(buf), flags, width, precision);
}


static char *Fmt_flags = "-+ 0";
static fmt_t cvt[256] = {
        /*   0-  7 */     0,     0,     0,     0,     0,     0,     0,     0,
        /*   8- 15 */     0,     0,     0,     0,     0,     0,     0,     0,
        /*  16- 23 */     0,     0,     0,     0,     0,     0,     0,     0,
        /*  24- 31 */     0,     0,     0,     0,     0,     0,     0,     0,
        /*  32- 39 */     0,     0,     0,     0,     0,     0,     0,     0,
        /*  40- 47 */     0,     0,     0,     0,     0,     0,     0,     0,
        /*  48- 55 */     0,     0,     0,     0,     0,     0,     0,     0,
        /*  56- 63 */     0,     0,     0,     0,     0,     0,     0,     0,
        /*  64- 71 */     0,     0,     0,     0,     0,     0,     0,     0,
        /*  72- 79 */     0,     0,     0,     0,     0,     0,     0,     0,
        /*  80- 87 */     0,     0,     0,     0,     0,     0,     0,     0,
        /*  88- 95 */     0,     0,     0,     0,     0,     0,     0,     0,
        /*  96-103 */     0,     0,     0, cvt_c, cvt_d, cvt_f, cvt_f, cvt_f,
        /* 104-111 */     0, cvt_d,     0,     0, cvt_l,     0,     0, cvt_o,
        /* 112-119 */ cvt_p,     0,     0, cvt_s,     0, cvt_u,     0,     0,
        /* 120-127 */ cvt_x,     0,     0,     0,     0,     0,     0,     0
};


/* ---------------------------------------------------------------- Public */


T OutputStream_new(int descriptor) {
        T S;
        NEW(S);
        S->fd = descriptor;
        S->timeout = NET_WRITE_TIMEOUT;
        S->length = S->buffer;
        S->limit = S->buffer + BUFFER_SIZE;
        return S;
}


void OutputStream_free(T *S) {
        assert(S && *S);
        OutputStream_flush(*S);
        FREE(*S);
}


/* ------------------------------------------------------------ Properties */


int OutputStream_getDescriptor(T S) {
        assert(S);
        return S->fd;
}


int OutputStream_buffered(T S) {
        assert(S);
        return (int)(S->length - S->buffer);
}


void OutputStream_setTimeout(T S, time_t timeout) {
        assert(S);
        assert(timeout >= 0);
        S->timeout = timeout;
}


time_t OutputStream_getTimeout(T S) {
        assert(S);
        return S->timeout;
}


int OutputStream_isClosed(T S) {
        assert(S);
        return S->isclosed;
}


long long int OutputStream_getBytesWritten(T S) {
        assert(S);
        return S->bytesWritten;
}


/* ---------------------------------------------------------------- Public */


int OutputStream_print(T S, const char *s, ...) {
        assert(S);
        assert(s);
        va_list ap;
        va_start(ap, s);
        int n = OutputStream_vprint(S, s, ap);
        va_end(ap);
        return n;
}


int OutputStream_vprint(T S, const char *fmt, va_list ap) {
        assert(S);
        assert(fmt);
        va_list_box box;
        va_copy(box.ap, ap);
        S->sessionWritten = 0;
        while (*fmt) {
                if (*fmt != '%' || *++fmt == '%')
                        write_byte(S, *fmt++);
                else {
                        uchar_t c, flags[256] = {0};
                        int width = INT_MIN, precision = INT_MIN;
                        for (c = *fmt; c && strchr(Fmt_flags, c); c = *++fmt) {
                                assert(flags[c] < 255);
                                flags[c]++;
                        }
                        if (*fmt == '*' || isdigit(*fmt)) {
                                int n;
                                if (*fmt == '*') {
                                        n = va_arg(box.ap, int);
                                        assert(n != INT_MIN);
                                        fmt++;
                                } else
                                        for (n = 0; isdigit(*fmt); fmt++) {
                                                int d = *fmt - '0';
                                                assert(n <= (INT_MAX - d)/10);
                                                n = 10*n + d;
                                        }
                                width = n;
                        }
                        if (*fmt == '.' && (*++fmt == '*' || isdigit(*fmt))) {
                                int n;
                                if (*fmt == '*') {
                                        n = va_arg(box.ap, int);
                                        assert(n != INT_MIN);
                                        fmt++;
                                } else
                                        for (n = 0; isdigit(*fmt); fmt++) {
                                                int d = *fmt - '0';
                                                assert(n <= (INT_MAX - d)/10);
                                                n = 10*n + d;
                                        }
                                precision = n;
                        }
                        c = *fmt++;
                        if (c == 'l')  {
                                c = *fmt++;
                                if (c == 'd' || c == 'i')
                                        c = 'l';
                        }
                        assert(cvt[c]);
                        cvt[c](S, c, &box, flags, width, precision);
                }
        }
        va_end(box.ap);
        return S->isclosed ? -1 : S->sessionWritten;
}


int OutputStream_write(T S, const void *b, int size) {
        assert(S);
        assert(b);
        S->sessionWritten = 0;
        for (uchar_t *t = (uchar_t*)b; (size-- > 0); t++)
                if (write_byte(S, *t) < 0)
                        break;
        return S->isclosed ? -1 : S->sessionWritten;
}


int OutputStream_flush(T S) {
        assert(S);
        if (S->length > S->buffer)
                return flush(S);
        return 0;
}


void OutputStream_clear(T S) {
        assert(S);
        S->length = S->buffer;
}

