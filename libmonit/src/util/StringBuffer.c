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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <ctype.h>

#include "Str.h"
#include "StringBuffer.h"


/**
 * Implementation of the StringBuffer interface. 
 *
 * @author http://www.tildeslash.com/
 * @see http://www.mmonit.com/
 * @file
 */


/* ------------------------------------------------------------ Definitions */


#define T StringBuffer_T
struct T {
        int used;
        int length;
	uchar_t *buffer;
};


/* ---------------------------------------------------------------- Private */


static inline void append(T S, const char *s, va_list ap) {
        va_list ap_copy;
        while (true) {
                va_copy(ap_copy, ap);
                int n = vsnprintf((char*)(S->buffer + S->used), S->length - S->used, s, ap_copy);
                va_end(ap_copy);
                if ((S->used + n) < S->length) {
                        S->used += n;
                        break;
                }
                S->length += STRLEN + n;
                RESIZE(S->buffer, S->length);
        }
}


static inline T ctor(int hint) {
        T S;
        NEW(S);
        S->used = 0;
        S->length = hint;
        S->buffer = ALLOC(hint);
        *S->buffer = 0;
        return S;
}


/* ----------------------------------------------------------------- Public */


T StringBuffer_new(const char *s) {
        return StringBuffer_append(ctor(STRLEN), "%s", s);
}


T StringBuffer_create(int hint) {
        if (hint <= 0)
                THROW(AssertException, "Illegal hint value");
        return ctor(hint);
}


void StringBuffer_free(T *S) {
        assert(S && *S);
        FREE((*S)->buffer);
        FREE(*S);
}


T StringBuffer_append(T S, const char *s, ...) {
        assert(S);
        if (STR_DEF(s)) {
                va_list ap;
                va_start(ap, s);
                append(S, s, ap);
                va_end(ap);
        }
        return S;
}


T StringBuffer_vappend(T S, const char *s, va_list ap) {
        assert(S);
        if (STR_DEF(s)) {
                va_list ap_copy;
                va_copy(ap_copy, ap);
                append(S, s, ap_copy);
                va_end(ap_copy);
        }
        return S;
}


int StringBuffer_replace(T S, const char *a, const char *b) {
        int n = 0;
        assert(S);
        if (a && b && *a) {
                int i, j;
                for (i = 0; S->buffer[i]; i++) {
                        if (S->buffer[i] == *a) {
                                j = 0;
                                do
                                        if (! a[++j]) {n++; break;}
                                while (S->buffer[i + j] == a[j]);
                        }
                }
                if (n) {
                        int m = n;
                        size_t bl = strlen(b);
                        size_t diff = bl - strlen(a);
                        if (diff > 0) {
                                size_t required = (diff * n) + S->used + 1;
                                if (required >= S->length) {
                                        S->length = (int)required;
                                        RESIZE(S->buffer, S->length);
                                }
                        }
                        for (i = 0; m; i++) {
                                if (S->buffer[i] == *a) {
                                        j = 0;
                                        do
                                                if (! a[++j]) {
                                                        memmove(S->buffer + i + bl, S->buffer + i + j, (S->used - (i + j)));
                                                        memcpy(S->buffer + i, b, bl); 
                                                        S->used += diff;
                                                        i += bl - 1;
                                                        m--;
                                                        break;
                                                }
                                        while (S->buffer[i + j] == a[j]);
                                }
                        }
                        S->buffer[S->used] = 0;
                }
        }
        return n;
}


T StringBuffer_trim(T S) {
        assert(S);
        // Right trim
        while (S->used && isspace(S->buffer[S->used - 1])) 
                S->buffer[--S->used] = 0;
        // Left trim
        if (isspace(*S->buffer)) {
                int i;
                for (i = 0; isspace(S->buffer[i]); i++) ;
                memmove(S->buffer, S->buffer + i, S->used - i);
                S->used -= i;
                S->buffer[S->used] = 0;
        }
        return S;
}


T StringBuffer_delete(T S, int index) {
        assert(S);
        if (index < 0 || index > S->used)
                THROW(AssertException, "Index out of bounds");
        S->used = index;
        S->buffer[S->used] = 0;
        return S;
}


int StringBuffer_indexOf(T S, const char *s) {
        assert(S);
        if (STR_DEF(s)) {
                int i, j;
                for (i = 0; i < S->used; i++) {
                        if (S->buffer[i] == *s) {
                                j = 0;
                                do
                                        if (! s[++j])
                                                return i;
                                while (S->buffer[i + j] == s[j]);
                        }
                }
        }
        return -1;
}


int StringBuffer_lastIndexOf(T S, const char *s) {
        assert(S);
        if (STR_DEF(s)) {
                int i, j;
                for (i = S->used - 1; i >= 0; i--) {
                        if (S->buffer[i] == *s) {
                                j = 0;
                                do
                                        if (! s[++j])
                                                return i;
                                while (S->buffer[i + j] == s[j]);
                        }
                }
        }
        return -1;
}


const char *StringBuffer_substring(T S, int index) {
        assert(S);
        if (index < 0 || index > S->used)
                THROW(AssertException, "Index out of bounds");
        return (const char*)(S->buffer + index);
}


int StringBuffer_length(T S) {
        assert(S);
        return S->used;
}


T StringBuffer_clear(T S) {
        assert(S);
        S->used = 0;
        *S->buffer = 0;
        return S;
}


const char *StringBuffer_toString(T S) {
        assert(S);
        return (const char*)S->buffer;
}

