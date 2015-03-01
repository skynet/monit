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

#include "protocol.h"

// libmonit
#include "exceptions/IOException.h"


/**
 *  A simple Postfix SMTP access policy delegation protocol test
 *
 *  To not affect real traffic, we send the following request with
 *  fixed virtual triplet values to the server:
 *   request=smtpd_access_policy
 *   protocol_state=RCPT
 *   protocol_name=SMTP
 *   sender=monit@foo.tld
 *   recipient=monit@foo.tld
 *   client_address=1.2.3.4
 *   client_name=mx.foo.tld
 *  and check that the server replies with some action.
 *
 *  @file
 */
void check_postfix_policy(Socket_T socket) {

        char buf[STRLEN];

        ASSERT(socket);

        if (Socket_print(socket,
                         "request=smtpd_access_policy\n"
                         "protocol_state=RCPT\n"
                         "protocol_name=SMTP\n"
                         "sender=monit@foo.tld\n"
                         "recipient=monit@foo.tld\n"
                         "client_address=1.2.3.4\n"
                         "client_name=mx.foo.tld\n"
                         "\n") < 0) {
                THROW(IOException, "POSTFIX-POLICY: error sending data -- %s", STRERROR);
        }

        if (! Socket_readLine(socket, buf, sizeof(buf)))
                THROW(IOException, "POSTFIX-POLICY: error receiving data -- %s", STRERROR);

        Str_chomp(buf);

        if ((strlen(buf) <= 7) || strncasecmp(buf, "action=", 7))
                THROW(IOException, "POSTFIX-POLICY error: %s", *buf ? buf : "no action returned");
}

