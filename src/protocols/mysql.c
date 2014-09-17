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

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif

#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif

#ifdef HAVE_STRING_H
#include <string.h>
#endif

#include "protocol.h"


/* ----------------------------------------------------------- Definitions */


#define MYSQL_ERROR 0xff
typedef struct {unsigned int len:24, seq:8; unsigned char *msg; unsigned char buf[STRLEN + 1];} mysql_packet_t;


/* --------------------------------------------------------------- Private */


static unsigned short B2(unsigned char *b) {
        unsigned short x;
        *(((char *)&x) + 0) = b[1];
        *(((char *)&x) + 1) = b[0];
        return ntohs(x);
}


static unsigned int B3(unsigned char *b) {
        unsigned int x;
        *(((char *)&x) + 0) = 0;
        *(((char *)&x) + 1) = b[2];
        *(((char *)&x) + 2) = b[1];
        *(((char *)&x) + 3) = b[0];
        return ntohl(x);
}


static int _response(Socket_T socket, mysql_packet_t *pkt) {
        memset(pkt, 0, sizeof *pkt);
        if (socket_read(socket, pkt->buf, 4) < 4) {
                socket_setError(socket, "Error receiving server response -- %s", STRERROR);
                return FALSE;
        }
        pkt->len = B3(pkt->buf);
        pkt->len = pkt->len > STRLEN ? STRLEN : pkt->len; // Adjust packet length for this buffer
        pkt->seq = pkt->buf[3];
        pkt->msg = pkt->buf + 4;
        if (socket_read(socket, pkt->msg, pkt->len) != pkt->len) {
                socket_setError(socket, "Error receiving server response -- %s", STRERROR);
                return FALSE;
        }
        if (*pkt->msg == MYSQL_ERROR) {
                unsigned short code = B2(pkt->msg + 1);
                unsigned char *err = pkt->msg + 9;
                socket_setError(socket, "Server returned error code %d -- %s", code, err);
                return FALSE;
        }
        return TRUE;
}


/* ---------------------------------------------------------------- Public */


/**
 * Simple MySQL test. Connect to MySQL and read Server Handshake Packet.
 * If we can read the packet and it is not an error packet we assume the 
 * server is up and working.
 *
 *  @see http://dev.mysql.com/doc/internals/en/client-server-protocol.html
 */
int check_mysql(Socket_T socket) {
        ASSERT(socket);
        mysql_packet_t pkt;
        if (_response(socket, &pkt)) {
                short protocol_version = pkt.msg[0];
                unsigned char *server_version = pkt.msg + 1;
                // Protocol is 10 for MySQL 5.x
                if ((protocol_version > 12) || (protocol_version < 9))
                        socket_setError(socket, "Invalid protocol version %d", protocol_version);
                // Handshake packet should have sequence id 0
                else if (pkt.seq != 0)
                        socket_setError(socket, "Invalid packet sequence id %d", pkt.seq);
                else {
                        DEBUG("MySQL: Protocol: %d, Server Version: %s\n", protocol_version, server_version);
                        return TRUE;
                }
        }
        return FALSE;
}

