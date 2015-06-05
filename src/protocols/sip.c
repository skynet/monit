/*
 * Copyright (C) Tildeslash Ltd. All rights reserved.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
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

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif

#include "protocol.h"

// libmonit
#include "exceptions/IOException.h"


/**
 *
 *  A SIP test.
 *
 *  This test has been created in order to construct valid SIP message,
 *  even with a low poll cycle. (In case of low poll cycle, chance are
 *  high for a  misinterpretation of the generic test by the SIP AS. It
 *  will considered it for a retransmission, not for a new message)
 *
 *  The test sends an OPTIONS request and check the server's status code.
 *
 *  The status code must be between 200 and 300.
 *
 *  In this current version, redirection is not supported. This code is
 * a rewrite of a patch we recieved from Pierrick Grasland and Bret McDanel
 * to check the SIP protocol.
 *
 *  @file
 */


/* -------------------------------------------------------------- Public*/

void check_sip(Socket_T socket) {
        ASSERT(socket);

        Port_T P = Socket_getPort(socket);
        ASSERT(P);
        const char *target = P->parameters.sip.target ? P->parameters.sip.target : "monit@foo.bar";

        int port = Socket_getLocalPort(socket);
        char *proto = Socket_isSecure(socket) ? "sips" : "sip";

        char *transport = "";
        char *rport = "";
        switch (Socket_getType(socket)) {
                case Socket_Udp:
                        transport = "UDP";
                        rport = ";rport";
                        break;
                case Socket_Tcp:
                        transport = "TCP";
                        break;
                default:
                        THROW(IOException, "Unsupported socket type, only TCP and UDP are supported");
                        break;
        }

        char buf[STRLEN];
        const char *myip = Socket_getLocalHost(socket, buf, sizeof(buf));

        if (Socket_print(socket,
                         "OPTIONS %s:%s SIP/2.0\r\n"
                         "Via: SIP/2.0/%s %s:%d;branch=z9hG4bKh%ld%s\r\n"
                         "Max-Forwards: %d\r\n"
                         "To: <%s:%s>\r\n"
                         "From: monit <%s:monit@%s>;tag=%ld\r\n"
                         "Call-ID: %ld\r\n"
                         "CSeq: 63104 OPTIONS\r\n"
                         "Contact: <%s:%s:%d>\r\n"
                         "Accept: application/sdp\r\n"
                         "Content-Length: 0\r\n"
                         "User-Agent: Monit/%s\r\n\r\n",
                         proto,                        // protocol
                         target,                       // to
                         transport,                    // via transport udp|tcp
                         myip,                         // who its from
                         port,                         // our port
                         random(),                     // branch
                         rport,                        // rport option
                         P->parameters.sip.maxforward ? P->parameters.sip.maxforward : 70, // maximum forwards
                         proto,                        // protocol
                         target,                       // to
                         proto,                        // protocol
                         myip,                         // from host
                         random(),                     // tag
                         random(),                     // call id
                         proto,                        // protocol
                         myip,                         // contact host
                         port,                         // contact port
                         VERSION                       // user agent
                         ) < 0) {
                THROW(IOException, "SIP: error sending data -- %s", STRERROR);
        }

        if (! Socket_readLine(socket, buf, sizeof(buf)))
                THROW(IOException, "SIP: error receiving data -- %s", STRERROR);

        Str_chomp(buf);

        DEBUG("Response from SIP server: %s\n", buf);

        int status;
        if (! sscanf(buf, "%*s %d", &status))
                THROW(IOException, "SIP error: cannot parse SIP status in response: %s", buf);

        if (status >= 400)
                THROW(IOException, "SIP error: Server returned status %d", status);

        if (status >= 300 && status < 400)
                THROW(IOException, "SIP info: Server redirection. Returned status %d", status);

        if (status > 100 && status < 200)
                THROW(IOException, "SIP error: Provisional response . Returned status %d", status);
}
