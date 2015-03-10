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

// libmonit
#include "exceptions/IOException.h"

/**
 *  A HTTP test.
 *
 *  We send the following request to the server:
 *  'GET / HTTP/1.1'             ... if request statement isn't defined
 *  'GET /custom/page  HTTP/1.1' ... if request statement is defined
 *  and check the server's status code.
 *
 *  If the statement defines hostname, it's used in the 'Host:' header otherwise a default (empty) Host header is set.
 *
 *  If the status code is >= 400, an error has occurred.
 *
 *  @file
 */



/* ------------------------------------------------------------- Definitions */


#define HTTP_CONTENT_MAX 1048576


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


static void do_regex(Socket_T socket, int content_length, Request_T R) {
        boolean_t rv = false;

        if (content_length == 0)
                THROW(IOException, "HTTP error: No content returned from server");
        else if (content_length < 0 || content_length > HTTP_CONTENT_MAX) /* content_length < 0 if no Content-Length header was found */
                content_length = HTTP_CONTENT_MAX;

        char error[STRLEN];
        int size = 0, length = content_length, buflen = content_length + 1;
        char *buf = ALLOC(buflen);
        do {
                int n = Socket_read(socket, &buf[size], length);
                if (n <= 0)
                        break;
                size += n;
                length -= n;
        } while (length > 0);

        if (size == 0) {
                snprintf(error, sizeof(error), "Receiving data -- %s", STRERROR);
                goto error;
        }
        buf[size] = 0;

#ifdef HAVE_REGEX_H
        int regex_return = regexec(R->regex, buf, 0, NULL, 0);
#else
        int regex_return = strstr(buf, R->regex) ? 0 : 1;
#endif
        FREE(buf);
        switch (R->operator) {
                case Operator_Equal:
                        if (regex_return == 0) {
                                rv = true;
                                DEBUG("HTTP: Regular expression matches\n");
                        } else {
#ifdef HAVE_REGEX_H
                                char errbuf[STRLEN];
                                regerror(regex_return, NULL, errbuf, sizeof(errbuf));
                                snprintf(error, sizeof(error), "Regular expression doesn't match: %s", errbuf);
#else
                                snprintf(error, sizeof(error), "Regular expression doesn't match");
#endif
                        }
                        break;
                case Operator_NotEqual:
                        if (regex_return == 0) {
                                snprintf(error, sizeof(error), "Regular expression matches");
                        } else {
                                rv = true;
                                DEBUG("HTTP: Regular expression doesn't match\n");
                        }
                        break;
                default:
                        snprintf(error, sizeof(error), "Invalid content operator");
                        break;
        }

error:
        if (! rv)
                THROW(IOException, "HTTP error: %s", error);
}


static void check_request_checksum(Socket_T socket, int content_length, char *checksum, Hash_Type hashtype) {
        int n, keylength = 0;
        MD_T result, hash;
        md5_context_t ctx_md5;
        sha1_context_t ctx_sha1;
        char buf[8192];

        if (content_length <= 0) {
                DEBUG("HTTP warning: Response does not contain a valid Content-Length -- cannot compute checksum\n");
                return;
        }

        switch (hashtype) {
                case Hash_Md5:
                        md5_init(&ctx_md5);
                        while (content_length > 0) {
                                if ((n = Socket_read(socket, buf, content_length > sizeof(buf) ? sizeof(buf) : content_length)) < 0)
                                        break;
                                md5_append(&ctx_md5, (const md5_byte_t *)buf, n);
                                content_length -= n;
                        }
                        md5_finish(&ctx_md5, (md5_byte_t *)hash);
                        keylength = 16; /* Raw key bytes not string chars! */
                        break;
                case Hash_Sha1:
                        sha1_init(&ctx_sha1);
                        while (content_length > 0) {
                                if ((n = Socket_read(socket, buf, content_length > sizeof(buf) ? sizeof(buf) : content_length)) < 0)
                                        break;
                                sha1_append(&ctx_sha1, (md5_byte_t *)buf, n);
                                content_length -= n;
                        }
                        sha1_finish(&ctx_sha1, (md5_byte_t *)hash);
                        keylength = 20; /* Raw key bytes not string chars! */
                        break;
                default:
                        THROW(IOException, "HTTP checksum error: Unknown hash type");
        }
        if (strncasecmp(Util_digest2Bytes((unsigned char *)hash, keylength, result), checksum, keylength * 2) != 0)
                THROW(IOException, "HTTP checksum error: Document checksum mismatch");
        DEBUG("HTTP: Succeeded testing document checksum\n");
}


/**
 * Check that the server returns a valid HTTP response as well as checksum
 * or content regex if required
 * @param s A socket
 */
static void check_request(Socket_T socket, Port_T P) {
        int status, content_length = -1;
        char buf[512];
        if (! Socket_readLine(socket, buf, sizeof(buf)))
                THROW(IOException, "HTTP: Error receiving data -- %s", STRERROR);
        Str_chomp(buf);
        if (! sscanf(buf, "%*s %d", &status))
                THROW(IOException, "HTTP error: Cannot parse HTTP status in response: %s", buf);
        if (! Util_evalQExpression(P->operator, status, P->status))
                THROW(IOException, "HTTP error: Server returned status %d", status);
        /* Get Content-Length header value */
        while (Socket_readLine(socket, buf, sizeof(buf))) {
                if ((buf[0] == '\r' && buf[1] == '\n') || (buf[0] == '\n'))
                        break;
                Str_chomp(buf);
                if (Str_startsWith(buf, "Content-Length")) {
                        if (! sscanf(buf, "%*s%*[: ]%d", &content_length))
                                THROW(IOException, "HTTP error: Parsing Content-Length response header '%s'", buf);
                        if (content_length < 0)
                                THROW(IOException, "HTTP error: Illegal Content-Length response header '%s'", buf);
                }
        }
        if (P->url_request && P->url_request->regex)
                do_regex(socket, content_length, P->url_request);
        if (P->request_checksum)
                check_request_checksum(socket, content_length, P->request_checksum, P->request_hashtype);
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


void check_http(Socket_T socket) {
        Port_T P;
        char host[STRLEN];
        char auth[STRLEN] = {};
        const char *request = NULL;
        const char *hostheader = NULL;

        ASSERT(socket);

        P = Socket_getPort(socket);

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
        int send_status = Socket_write(socket, (void*)StringBuffer_toString(sb), StringBuffer_length(sb));
        StringBuffer_free(&sb);
        if (send_status < 0)
                THROW(IOException, "HTTP: error sending data -- %s", STRERROR);
        check_request(socket, P);
}

