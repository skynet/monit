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

#include "config.h"

#ifdef HAVE_STRING_H
#include <string.h>
#endif

#ifdef HAVE_REGEX_H
#include <regex.h>
#endif

#include "protocol.h"


/*
 Escape zero i.e. '\0' in expect buffer with "\0" so zero can be tested in expect strings
 as "\0". If there are no '\0' in the buffer it is returned as it is
 */
static char *_escapeZeroInExpectBuffer(char *s, int n) {
        assert(n < EXPECT_BUFFER_MAX);
        char t[n]; // VLA
        memcpy(t, s, n);
        for (int i = 0, j = 0; j <= n; i++, j++) {
                if ((t[j] = s[i]) == '\0') {
                        if (j + 2 < n) {
                                t[j] = '\\';
                                t[j + 1] = '0';
                                j++;
                        }
                }
        }
        memcpy(s, t, n);
        s[n] = 0;
        return s;
}


/**
 *  Generic service test.
 *
 *  @file
 */
int check_generic(Socket_T socket) {
        Generic_T g = NULL;
        char *buf;
#ifdef HAVE_REGEX_H
        int regex_return;
#endif
        
        ASSERT(socket);
        
        if(socket_get_Port(socket))
                g = ((Port_T)(socket_get_Port(socket)))->generic;
        
        buf = CALLOC(sizeof(char), Run.expectbuffer + 1);
        
        while (g != NULL) {
                
                if (g->send != NULL) {
                        
                        /* Unescape any \0x00 escaped chars in g's send string
                         to allow sending a string containing \0 bytes also */
                        char *X = Str_dup(g->send);
                        int l = Util_handle0Escapes(X);
                        
                        if(socket_write(socket, X, l) < 0) {
                                socket_setError(socket, "GENERIC: error sending data -- %s", STRERROR);
                                FREE(X);
                                FREE(buf);
                                return FALSE;
                        } else
                                DEBUG("GENERIC: successfully sent: '%s'\n", g->send);
                        
                        FREE(X);
                        
                } else if (g->expect != NULL) {
                        /* Since the protocol is unknown we need to wait on EOF. To avoid waiting
                         timeout seconds on EOF we first read one byte to fill the socket's read 
                         buffer and then set a low timeout on next read which reads remaining bytes 
                         as well as waiting on EOF */
                        *buf = socket_read_byte(socket);
                        if (*buf < 0) {
                                socket_setError(socket, "GENERIC: error receiving data -- %s", STRERROR);
                                FREE(buf);
                                return FALSE;
                        }
                        int timeout = socket_getTimeout(socket);
                        socket_setTimeout(socket, 200);
                        int n = socket_read(socket, buf + 1, Run.expectbuffer - 1) + 1;
                        buf[n] = 0;
                        if (n > 0)
                                _escapeZeroInExpectBuffer(buf, n);
                        socket_setTimeout(socket, timeout); // Reset original timeout
#ifdef HAVE_REGEX_H
                        regex_return = regexec(g->expect, buf, 0, NULL, 0);
                        if (regex_return != 0) {
                                char e[STRLEN];
                                regerror(regex_return, g->expect, e, STRLEN);
                                socket_setError(socket, "GENERIC: receiving unexpected data [%s] -- %s", Str_trunc(buf, STRLEN - 4), e);
                                FREE(buf);
                                return FALSE;
                        } else
                                DEBUG("GENERIC: successfully received: '%s'\n", Str_trunc(buf, STRLEN - 4));
                        
#else
                        /* w/o regex support */
                        
                        if (strncmp(buf, g->expect, strlen(g->expect)) != 0) {
                                socket_setError(socket, "GENERIC: receiving unexpected data [%s]", Str_trunc(buf, STRLEN - 4));
                                FREE(buf);
                                return FALSE;
                        } else
                                DEBUG("GENERIC: successfully received: '%s'\n", Str_trunc(buf, STRLEN - 4));
                        
#endif
                        
                } else {
                        /* This should not happen */
                        socket_setError(socket, "GENERIC: unexpected strangeness");
                        FREE(buf);
                        return FALSE;
                }
                g = g->next;
        }
        
        FREE(buf);
        return TRUE;
        
}

