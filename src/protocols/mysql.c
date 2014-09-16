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
        unsigned char x[3] = {0, b[1], b[0]};
        return ntohs(*(unsigned short*)x);
}


static unsigned int B3(unsigned char *b) {
        unsigned char x[4] = {0, b[2], b[1], b[0]};
        return ntohl(*(unsigned int*)x);
}


static int _response(Socket_T socket, mysql_packet_t *pkt) {
        memset(pkt, 0, sizeof *pkt);
        if (socket_read(socket, pkt->buf, STRLEN) < 4) {
                socket_setError(socket, "MYSQL: error receiving server response -- %s", STRERROR);
                return FALSE;
        }
        pkt->len = B3(pkt->buf);
        pkt->seq = pkt->buf[3];
        pkt->msg = pkt->buf + 4;
        if (*pkt->msg == MYSQL_ERROR) {
                unsigned short code = B2(pkt->msg + 1);
                unsigned char *err = pkt->msg + 9;
                socket_setError(socket, "MYSQL: server returned error code %d -- %s", code, err);
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
                unsigned short protocol_version = pkt.msg[0];
                unsigned char *server_version = pkt.msg + 1;
                DEBUG("MySQL: Protocol: %d, Server Version: %s\n", protocol_version, server_version);
                return TRUE;
        }
        return FALSE;
}

