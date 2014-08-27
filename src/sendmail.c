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

#ifdef HAVE_STDIO_H
#include <stdio.h>
#endif

#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif

#ifdef HAVE_STDARG_H
#include <stdarg.h>
#endif

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif

#ifdef HAVE_ERRNO_H
#include <errno.h>
#endif

#ifdef HAVE_SETJMP_H
#include <setjmp.h>
#endif

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#ifdef HAVE_STRING_H
#include <string.h>
#endif

#include "monit.h"
#include "net.h"
#include "socket.h"
#include "base64.h"

// libmonit
#include "system/Time.h"
#include "exceptions/IOException.h"


/**
 *  Connect to a SMTP server and send mail.
 *
 *  @file
 */


/* ------------------------------------------------------------- Definitions */



typedef struct {
        Socket_T socket;
        StringBuffer_T status_message;
        int quit;
        const char *server;
        int port;
        const char *username;
        const char *password;
        Ssl_T ssl;
        char localhost[STRLEN];
} SendMail_T;


/* ----------------------------------------------------------------- Private */


void do_send(SendMail_T *S, const char *s, ...) {
        va_list ap;
        va_start(ap,s);
        char *msg = Str_vcat(s, ap);
        va_end(ap);
        int rv = socket_write(S->socket, msg, strlen(msg));
        FREE(msg);
        if (rv <= 0)
                THROW(IOException, "Error sending data to the server '%s' -- %s", S->server, STRERROR);
}


static void do_status(SendMail_T *S) {
        int status = 0;
        StringBuffer_clear(S->status_message);
        char buf[STRLEN];
        do {
                if (! socket_readln(S->socket, buf, sizeof(buf)))
                        THROW(IOException, "Error receiving data from the mailserver '%s' -- %s", S->server, STRERROR);
                StringBuffer_append(S->status_message, "%s", buf);
        } while (buf[3] == '-'); // multi-line response
        Str_chomp(buf);
        if (sscanf(buf, "%d", &status) != 1 || status < 200 || status >= 400)
                THROW(IOException, "%s", buf);
}


static void open_server(SendMail_T *S) {
        MailServer_T mta = Run.mailservers;
        if (mta) {
                S->server   = mta->host;
                S->port     = mta->port;
                S->username = mta->username;
                S->password = mta->password;
                S->ssl      = mta->ssl;
        } else {
                THROW(IOException, "No mail servers are defined -- see manual for 'set mailserver' statement");
        }
        do {
                /* wait with ssl-connect if SSL_VERSION_TLSV1 is set (rfc2487) */
                if (! S->ssl.use_ssl || S->ssl.version == SSL_VERSION_TLSV1 || S->ssl.version == SSL_VERSION_TLSV11 || S->ssl.version == SSL_VERSION_TLSV12)
                        S->socket = socket_new(S->server, S->port, SOCKET_TCP, FALSE, Run.mailserver_timeout);
                else
                        S->socket = socket_create_t(S->server, S->port, SOCKET_TCP, S->ssl, Run.mailserver_timeout);
                if (S->socket)
                        break;
                LogError("Cannot open a connection to the mailserver '%s:%i' -- %s\n", S->server, S->port, STRERROR);
                if (mta && (mta = mta->next)) {
                        S->server   = mta->host;
                        S->port     = mta->port;
                        S->username = mta->username;
                        S->password = mta->password;
                        S->ssl      = mta->ssl;
                        LogInfo("Trying the next mail server '%s:%i'\n", S->server, S->port);
                        continue;
                } else {
                        THROW(IOException, "No mail servers are available");
                }
        } while (TRUE);
        S->quit = TRUE;
}


static void close_server(SendMail_T *S) {
        TRY
        {
                if (S->quit) {
                        S->quit = FALSE;
                        do_send(S, "QUIT\r\n");
                        do_status(S);
                }
        }
        ELSE
        {
                LogError("Sendmail: %s\n", Exception_frame.message);
        }
        FINALLY
        {
                if (S->socket)
                        socket_free(&(S->socket));
        }
        END_TRY;
}


/* ------------------------------------------------------------------ Public */


/**
 * Send mail messages via SMTP
 * @param mail A Mail object
 * @return FALSE if failed, TRUE if succeeded
 */
int sendmail(Mail_T mail) {
        Mail_T m;
        SendMail_T S;
        int failed = FALSE;
        char now[STRLEN];

        ASSERT(mail);

        memset(&S, 0, sizeof(S));
        S.status_message = StringBuffer_create(STRLEN);

        TRY
        {
                open_server(&S);
                Time_gmtstring(Time_now(), now);
                snprintf(S.localhost, sizeof(S.localhost), "%s", Run.mail_hostname ? Run.mail_hostname : Run.system->name);
                do_status(&S);
                do_send(&S, "%s %s\r\n", ((S.ssl.use_ssl && (S.ssl.version == SSL_VERSION_TLSV1 || S.ssl.version == SSL_VERSION_TLSV11 || S.ssl.version == SSL_VERSION_TLSV12)) || S.username) ? "EHLO" : "HELO", S.localhost); // Use EHLO if TLS or Authentication is requested
                do_status(&S);
                /* Switch to TLS now if configured */
                if (S.ssl.use_ssl && (S.ssl.version == SSL_VERSION_TLSV1 || S.ssl.version == SSL_VERSION_TLSV11 || S.ssl.version == SSL_VERSION_TLSV12)) {
                        do_send(&S, "STARTTLS\r\n");
                        do_status(&S);
                        if (! socket_switch2ssl(S.socket, S.ssl)) {
                                S.quit = FALSE;
                                THROW(IOException, "Cannot switch to SSL");
                        }
                        /* After starttls, send ehlo again: RFC 3207: 4.2 Result of the STARTTLS Command */
                        do_send(&S, "EHLO %s\r\n", S.localhost);
                        do_status(&S);
                }
                /* Authenticate if possible */
                if (S.username) {
                        char buffer[STRLEN];
                        // PLAIN takes precedence
                        if (StringBuffer_indexOf(S.status_message, " PLAIN") > 0) {
                                int len = snprintf(buffer, STRLEN, "%c%s%c%s", '\0', S.username, '\0', S.password ? S.password : "");
                                char *b64 = encode_base64(len, (unsigned char *)buffer);
                                TRY
                                {
                                        do_send(&S, "AUTH PLAIN %s\r\n", b64);
                                        do_status(&S);
                                }
                                FINALLY
                                {
                                        FREE(b64);
                                }
                                END_TRY;
                        } else if (StringBuffer_indexOf(S.status_message, " LOGIN") > 0) {
                                do_send(&S, "AUTH LOGIN\r\n");
                                do_status(&S);
                                snprintf(buffer, STRLEN, "%s", S.username);
                                char *b64 = encode_base64(strlen(buffer), (unsigned char *)buffer);
                                TRY
                                {
                                        do_send(&S, "%s\r\n", b64);
                                        do_status(&S);
                                }
                                FINALLY
                                {
                                        FREE(b64);
                                }
                                END_TRY;
                                snprintf(buffer, STRLEN, "%s", S.password ? S.password : "");
                                b64 = encode_base64(strlen(buffer), (unsigned char *)buffer);
                                TRY
                                {
                                        do_send(&S, "%s\r\n", b64);
                                        do_status(&S);
                                }
                                FINALLY
                                {
                                        FREE(b64);
                                }
                                END_TRY;
                        } else {
                                THROW(IOException, "Authentication failed -- no supported authentication methods found");
                        }
                }
                for (m = mail; m; m = m->next) {
                        do_send(&S, "MAIL FROM: <%s>\r\n", m->from);
                        do_status(&S);
                        do_send(&S, "RCPT TO: <%s>\r\n", m->to);
                        do_status(&S);
                        do_send(&S, "DATA\r\n");
                        do_status(&S);
                        do_send(&S, "From: %s\r\n", m->from);
                        if (m->replyto)
                                do_send(&S, "Reply-To: %s\r\n", m->replyto);
                        do_send(&S, "To: %s\r\n", m->to);
                        do_send(&S, "Subject: %s\r\n", m->subject);
                        do_send(&S, "Date: %s\r\n", now);
                        do_send(&S, "X-Mailer: Monit %s\r\n", VERSION);
                        do_send(&S, "MIME-Version: 1.0\r\n");
                        do_send(&S, "Content-Type: text/plain; charset=\"iso-8859-1\"\r\n");
                        do_send(&S, "Content-Transfer-Encoding: 8bit\r\n");
                        do_send(&S, "Message-Id: <%ld.%lu@%s>\r\n", (long)time(NULL), random(), S.localhost);
                        do_send(&S, "\r\n");
                        do_send(&S, "%s\r\n", m->message);
                        do_send(&S, ".\r\n");
                        do_status(&S);
                }
        }
        ELSE
        {
                failed = TRUE;
                LogError("Sendmail: %s\n", Exception_frame.message);
        }
        FINALLY
        {
                close_server(&S);
                StringBuffer_free(&(S.status_message));
        }
        END_TRY;
        return failed;
}

