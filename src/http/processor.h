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


#ifndef PROCESSOR_H
#define PROCESSOR_H

#include "config.h"
#include <stdio.h>

#include "monit.h"
#include "net.h"
#include "socket.h"
#include "httpstatus.h"

/* Server masquerade */
#define SERVER_NAME        "monit"
#define SERVER_VERSION     VERSION
#define SERVER_URL         "http://mmonit.com/monit/"
#define SERVER_PROTOCOL    "HTTP/1.0"
#define DATEFMT             "%a, %d %b %Y %H:%M:%S GMT"

/* Protocol methods supported */
#define METHOD_GET         "GET"
#define METHOD_POST        "POST"


/* Initial buffer sizes */
#define STRLEN             256
#define REQ_STRLEN         1024
#define RES_STRLEN         2048
#define MAX_URL_LENGTH     512

/* Request timeout in seconds */
#define REQUEST_TIMEOUT    30

struct entry {
        char *name;
        char *value;
        /* For internal use */
        struct entry *next;
};


typedef struct entry *HttpHeader;

typedef struct entry *HttpParameter;


typedef struct request {
        char *url;
        Socket_T S;
        char *method;
        char *protocol;
        char *pathinfo;
        char *remote_user;
        HttpHeader headers;
        HttpParameter params;
        Ssl_T ssl;
} *HttpRequest;


typedef struct response {
        int status;
        Socket_T S;
        const char *protocol;
        boolean_t is_committed;
        HttpHeader headers;
        const char *status_msg;
        StringBuffer_T outputbuffer;
        Ssl_T ssl;
} *HttpResponse;


/* Public prototypes */
void *http_processor(Socket_T);
char *get_headers(HttpResponse res);
void set_status(HttpResponse res, int status);
const char *get_status_string(int status_code);
void add_Impl(void(*doGet)(HttpRequest, HttpResponse), void(*doPost)(HttpRequest, HttpResponse));
void set_content_type(HttpResponse res, const char *mime);
const char *get_header(HttpRequest req, const char *header_name);
void escapeHTML(StringBuffer_T sb, const char *s);
void send_error(HttpRequest, HttpResponse, int status, const char *message, ...);
const char *get_parameter(HttpRequest req, const char *parameter_name);
void set_header(HttpResponse res, const char *name, const char *value);

#endif
