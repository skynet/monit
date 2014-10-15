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

#include "md5.h"
#include "sha1.h"
#include "base64.h"
#include "protocol.h"
#include "httpstatus.h"
#include "util/Str.h"


/**
 *  A HTTP test.
 *
 *  We send the following request to the server:
 *  'GET / HTTP/1.1'             ... if request statement isn't defined
 *  'GET /custom/page  HTTP/1.1' ... if request statement is defined
 *  and check the server's status code.
 *
 *  If the statement defines hostname, it's used in the 'Host:' header
 * otherwise a default (empty) Host header is set.
 *
 *  If the status code is >= 400, an error has occurred.
 *  Return TRUE if the status code is OK, otherwise FALSE.
 *  @file
 */



/* ------------------------------------------------------------- Definitions */


#undef   READ_SIZE
#define  READ_SIZE  8192
#define  LINE_SIZE  512


/* ----------------------------------------------------------------- Private */


static const char *_findHostHeaderIn(List_T list) {
        if (list) {
                for (list_t h = list->head; h; h = h->next) {
                        char *header = h->e;
                        if (Str_startsWith(header, "Host")) {
                                return strchr(header, ':') + 1;
                        }
                }
        }
        return NULL;
}


static int do_regex(Socket_T socket, int content_length, Request_T R) {
        int n, size = 0, length = 0, rv = FALSE, regex_return;
        char *buf = NULL;

        if (content_length == 0) {
                socket_setError(socket, "HTTP error: No content returned from server");
                return FALSE;
        } else if (content_length < 0) { /* Not defined in response */
                content_length = HTTP_CONTENT_MAX;
        } else if (content_length > HTTP_CONTENT_MAX) {
                content_length = HTTP_CONTENT_MAX;
        }

        length = content_length;
        buf = ALLOC(content_length + 1);

        do {
                n = socket_read(socket, &buf[size], length);
                if (n <= 0)
                        break;
                size += n;
                length -= n;
        } while (length > 0);

        if (size == 0) {
                socket_setError(socket, "HTTP error: receiving data -- %s", STRERROR);
                goto error;
        }
        buf[size] = 0;

#ifdef HAVE_REGEX_H
        regex_return = regexec(R->regex, buf, 0, NULL, 0);
#else
        regex_return = strstr(buf, R->regex) ? 0 : 1;
#endif
        switch (R->operator) {
                case Operator_Equal:
                        if (regex_return == 0) {
                                rv = TRUE;
                                DEBUG("HTTP: Regular expression matches\n");
                        } else {
#ifdef HAVE_REGEX_H
                                char errbuf[STRLEN];
                                regerror(regex_return, NULL, errbuf, sizeof(errbuf));
                                socket_setError(socket, "HTTP error: Regular expression doesn't match: %s", errbuf);
#else
                                socket_setError(socket, "HTTP error: Regular expression doesn't match");
#endif
                        }
                        break;
                case Operator_NotEqual:
                        if (regex_return == 0) {
                                socket_setError(socket, "HTTP error: Regular expression matches");
                        } else {
                                rv = TRUE;
                                DEBUG("HTTP: Regular expression doesn't match\n");
                        }
                        break;
                default:
                        socket_setError(socket, "HTTP error: Invalid content operator");
        }

error:
        FREE(buf);
        return rv;
}


static int check_request_checksum(Socket_T socket, int content_length, char *checksum, int hashtype) {
        int n, keylength = 0;
        MD_T result, hash;
        md5_context_t ctx_md5;
        sha1_context_t ctx_sha1;
        char buf[READ_SIZE];

        if (content_length <= 0) {
                DEBUG("HTTP warning: Response does not contain a valid Content-Length -- cannot compute checksum\n");
                return TRUE;
        }

        switch (hashtype) {
                case HASH_MD5:
                        md5_init(&ctx_md5);
                        while (content_length > 0) {
                                if ((n = socket_read(socket, buf, content_length > sizeof(buf) ? sizeof(buf) : content_length)) < 0)
                                        break;
                                md5_append(&ctx_md5, (const md5_byte_t *)buf, n);
                                content_length -= n;
                        }
                        md5_finish(&ctx_md5, (md5_byte_t *)hash);
                        keylength = 16; /* Raw key bytes not string chars! */
                        break;
                case HASH_SHA1:
                        sha1_init(&ctx_sha1);
                        while (content_length > 0) {
                                if ((n = socket_read(socket, buf, content_length > sizeof(buf) ? sizeof(buf) : content_length)) < 0)
                                        break;
                                sha1_append(&ctx_sha1, (md5_byte_t *)buf, n);
                                content_length -= n;
                        }
                        sha1_finish(&ctx_sha1, (md5_byte_t *)hash);
                        keylength = 20; /* Raw key bytes not string chars! */
                        break;
                default:
                        socket_setError(socket, "HTTP checksum error: Unknown hash type");
                        return FALSE;
        }

        if (strncasecmp(Util_digest2Bytes((unsigned char *)hash, keylength, result), checksum, keylength * 2) != 0) {
                socket_setError(socket, "HTTP checksum error: Document checksum mismatch");
                return FALSE;
        } else {
                DEBUG("HTTP: Succeeded testing document checksum\n");
        }
        return TRUE;
}


/**
 * Check that the server returns a valid HTTP response as well as checksum
 * or content regex if required
 * @param s A socket
 * @return TRUE if the response is valid otherwise FALSE
 */
static int check_request(Socket_T socket, Port_T P) {
        int status, content_length = -1;
        char buf[LINE_SIZE];
        if (! socket_readln(socket, buf, LINE_SIZE)) {
                socket_setError(socket, "HTTP: Error receiving data -- %s", STRERROR);
                return FALSE;
        }
        Str_chomp(buf);
        if (! sscanf(buf, "%*s %d", &status)) {
                socket_setError(socket, "HTTP error: Cannot parse HTTP status in response: %s", buf);
                return FALSE;
        }
        if (! Util_evalQExpression(P->operator, status, P->status)) {
                socket_setError(socket, "HTTP error: Server returned status %d", status);
                return FALSE;
        }
        /* Get Content-Length header value */
        while (socket_readln(socket, buf, LINE_SIZE)) {
                if ((buf[0] == '\r' && buf[1] == '\n') || (buf[0] == '\n'))
                        break;
                Str_chomp(buf);
                if (Str_startsWith(buf, "Content-Length")) {
                        if (! sscanf(buf, "%*s%*[: ]%d", &content_length)) {
                                socket_setError(socket, "HTTP error: Parsing Content-Length response header '%s'", buf);
                                return FALSE;
                        }
                        if (content_length < 0) {
                                socket_setError(socket, "HTTP error: Illegal Content-Length response header '%s'", buf);
                                return FALSE;
                        }
                }
        }
        if (P->url_request && P->url_request->regex && ! do_regex(socket, content_length, P->url_request))
                return FALSE;
        if (P->request_checksum)
                return check_request_checksum(socket, content_length, P->request_checksum, P->request_hashtype);
        return TRUE;
}


static char *get_auth_header(Port_T P, char *auth, int l) {
        char *b64;
        char buf[STRLEN];
        char *username = NULL;
        char *password = NULL;

        if (P->url_request) {
                URL_T U = P->url_request->url;
                if (U) {
                        username = U->user;
                        password = U->password;
                }
        }

        if (! (username && password))
                return auth;

        snprintf(buf, STRLEN, "%s:%s", username, password);
        if (! (b64 = encode_base64(strlen(buf), (unsigned char *)buf)) )
                return auth;

        snprintf(auth, l, "Authorization: Basic %s\r\n", b64);
        FREE(b64);

        return auth;
}


/* ------------------------------------------------------------------ Public */


int check_http(Socket_T socket) {
        Port_T P;
        char host[STRLEN];
        char auth[STRLEN] = {};
        const char *request = NULL;
        const char *hostheader = NULL;

        ASSERT(socket);

        P = socket_get_Port(socket);

        ASSERT(P);

        request = P->request ? P->request : "/";

        hostheader = _findHostHeaderIn(P->http_headers);
        hostheader = hostheader ? hostheader : P->request_hostheader
                                ? P->request_hostheader : Util_getHTTPHostHeader(socket, host, STRLEN); // Otherwise use deprecated request_hostheader or default host
        StringBuffer_T sb = StringBuffer_create(168);
        StringBuffer_append(sb,
                            "GET %s HTTP/1.1\r\n"
                            "Host: %s\r\n"
                            "Accept: */*\r\n"
                            "User-Agent: Monit/%s\r\n"
                            "%s",
                            request, hostheader, VERSION,
                            get_auth_header(P, auth, STRLEN));
        // Add headers if we have them
        if (P->http_headers) {
                for (list_t p = P->http_headers->head; p; p = p->next) {
			char *header = p->e;
                        if (Str_startsWith(header, "Host")) // Already set contrived above
                                continue;
                        StringBuffer_append(sb, "%s\r\n", header);
                }
        }
        StringBuffer_append(sb, "\r\n");
        int send_status = socket_write(socket, (void*)StringBuffer_toString(sb), StringBuffer_length(sb));
        StringBuffer_free(&sb);
        if (send_status < 0) {
                socket_setError(socket, "HTTP: error sending data -- %s", STRERROR);
                return FALSE;
        }

        return check_request(socket, P);
}

