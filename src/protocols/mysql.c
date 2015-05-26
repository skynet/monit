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

// libmonit
#include "exceptions/IOException.h"


/* ----------------------------------------------------------- Definitions */


#define MYSQL_ERROR 0xff


// Capability flags (see http://dev.mysql.com/doc/internals/en/capability-flags.html#packet-Protocol::CapabilityFlags)
#define CLIENT_LONG_PASSWORD                  0x00000001
#define CLIENT_FOUND_ROWS                     0x00000002
#define CLIENT_LONG_FLAG                      0x00000004
#define CLIENT_CONNECT_WITH_DB                0x00000008
#define CLIENT_NO_SCHEMA                      0x00000010
#define CLIENT_COMPRESS                       0x00000020
#define CLIENT_ODBC                           0x00000040
#define CLIENT_LOCAL_FILES                    0x00000080
#define CLIENT_IGNORE_SPACE                   0x00000100
#define CLIENT_PROTOCOL_41                    0x00000200
#define CLIENT_INTERACTIVE                    0x00000400
#define CLIENT_SSL                            0x00000800
#define CLIENT_IGNORE_SIGPIPE                 0x00001000
#define CLIENT_TRANSACTIONS                   0x00002000
#define CLIENT_RESERVED                       0x00004000
#define CLIENT_SECURE_CONNECTION              0x00008000
#define CLIENT_MULTI_STATEMENTS               0x00010000
#define CLIENT_MULTI_RESULTS                  0x00020000
#define CLIENT_PS_MULTI_RESULTS               0x00040000
#define CLIENT_PLUGIN_AUTH                    0x00080000
#define CLIENT_CONNECT_ATTRS                  0x00100000
#define CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA 0x00200000
#define CLIENT_CAN_HANDLE_EXPIRED_PASSWORDS   0x00400000
#define CLIENT_SESSION_TRACK                  0x00800000
#define CLIENT_DEPRECATE_EOF                  0x01000000
#define CLIENT_SSL_VERIFY_SERVER_CERT         0x40000000
#define CLIENT_REMEMBER_OPTIONS               0x80000000


// Status flags (see http://dev.mysql.com/doc/internals/en/status-flags.html#packet-Protocol::StatusFlags)
#define SERVER_STATUS_IN_TRANS                0x0001
#define SERVER_STATUS_AUTOCOMMIT              0x0002
#define SERVER_MORE_RESULTS_EXISTS            0x0008
#define SERVER_STATUS_NO_GOOD_INDEX_USED      0x0010
#define SERVER_STATUS_NO_INDEX_USED           0x0020
#define SERVER_STATUS_CURSOR_EXISTS           0x0040
#define SERVER_STATUS_LAST_ROW_SENT           0x0080
#define SERVER_STATUS_DB_DROPPED              0x0100
#define SERVER_STATUS_NO_BACKSLASH_ESCAPES    0x0200
#define SERVER_STATUS_METADATA_CHANGED        0x0400
#define SERVER_QUERY_WAS_SLOW                 0x0800
#define SERVER_PS_OUT_PARAMS                  0x1000
#define SERVER_STATUS_IN_TRANS_READONLY       0x2000
#define SERVER_SESSION_STATE_CHANGED          0x4000


typedef struct {
        uint32_t       len : 24;
        uint32_t       seq : 8;
        uint8_t        protocol;
        unsigned char *serverversion;
        uint32_t       connectionid;
        uint8_t        characterset;
        uint16_t       status;
        uint32_t       capabilities;
        uint8_t        authdatalen;
        unsigned char  authdata[21];
        // Data buffer
        unsigned char buf[STRLEN + 1];
} mysql_handshake_init_t;


typedef struct {
        uint32_t       len : 24;
        uint32_t       seq : 8;
        uint32_t       capabilities;
        uint32_t       maxpacketsize;
        uint8_t        characterset;
        // Data buffer
        unsigned char buf[STRLEN + 1];
        // Pointers to data hosted in buffer
        unsigned char *username;
        uint8_t       *authdatalen;
        unsigned char *authdata;
} mysql_handshake_response_t;


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


static unsigned int B4(unsigned char *b) {
        unsigned int x;
        *(((char *)&x) + 0) = b[3];
        *(((char *)&x) + 1) = b[2];
        *(((char *)&x) + 2) = b[1];
        *(((char *)&x) + 3) = b[0];
        return ntohl(x);
}


static void _handshakeInit(Socket_T socket, mysql_handshake_init_t *pkt) {
        memset(pkt, 0, sizeof(*pkt));
        // Read the packet length
        if (Socket_read(socket, pkt->buf, 4) < 4)
                THROW(IOException, "Error receiving server response -- %s", STRERROR);
        pkt->len = B3(pkt->buf);
        pkt->len = pkt->len > STRLEN ? STRLEN : pkt->len; // Adjust packet length for this buffer
        // sequence id (handshake packet should have sequence id 0)
        pkt->seq = pkt->buf[3];
        if (pkt->seq != 0)
                THROW(IOException, "Invalid packet sequence id %d", pkt->seq);
        // read payload
        if (Socket_read(socket, pkt->buf, pkt->len) != pkt->len)
                THROW(IOException, "Error receiving server response -- %s", STRERROR);
        if (*pkt->buf == MYSQL_ERROR) {
                unsigned short code = B2(pkt->buf + 1);
                unsigned char *err = pkt->buf + 9;
                THROW(IOException, "Server returned error code %d -- %s", code, err);
        }
        unsigned char *cursor = pkt->buf;
        unsigned char *limit = pkt->buf + sizeof(pkt->buf);
        // protocol version
        if (cursor + 1 > limit)
                return;
        pkt->protocol = pkt->buf[0];
        if ((pkt->protocol > 12) || (pkt->protocol < 9)) // Protocol is 10 for MySQL 5.x
                THROW(IOException, "Invalid protocol version %d", pkt->protocol);
        cursor += 1;
        // server version
        pkt->serverversion = cursor;
        cursor += strlen(pkt->serverversion) + 1;
        // connection id
        if (cursor + 4 > limit)
                return;
        pkt->connectionid = B4(cursor);
        cursor += 4;
        // auth_plugin_data_part_1
        if (cursor + 9 > limit)
                return;
        snprintf(pkt->authdata, 9, "%s", cursor);
        cursor += 9;
        // capability flags (lower 2 bytes)
        if (cursor + 2 > limit)
                return;
        pkt->capabilities = B2(cursor);
        cursor += 2;
        // character set
        if (cursor + 1 > limit)
                return;
        pkt->characterset = cursor[0];
        cursor += 1;
        // status flags
        if (cursor + 2 > limit)
                return;
        pkt->status = B2(cursor);
        cursor += 2;
        // capability flags (upper 2 bytes)
        if (cursor + 2 > limit)
                return;
        pkt->capabilities |= B2(cursor) << 16; // merge capability flags (lower 2 bytes + upper 2 bytes)
        cursor += 2;
        // byte reserved for length of auth-plugin-data
        if (cursor + 1 > limit)
                return;
        if (pkt->capabilities & CLIENT_PLUGIN_AUTH)
                pkt->authdatalen = cursor[0];
        cursor += 1;
        // reserved bytes
        if (cursor + 10 > limit)
                return;
        cursor += 10;
        // auth_plugin_data_part_2
        if (cursor + 13 > limit)
                return;
        if (pkt->capabilities & CLIENT_SECURE_CONNECTION)
                snprintf(pkt->authdata + 8, 13, "%s", cursor);
        // auth-plugin name ... ignored (not needed)
}


//FIXME: convert numeric values to network order
static void _handshakeResponse(Socket_T socket, mysql_handshake_response_t *pkt) {
        memset(pkt, 0, sizeof(*pkt));
        pkt->seq = 1;
        pkt->capabilities = CLIENT_LONG_PASSWORD | CLIENT_PROTOCOL_41 | CLIENT_SECURE_CONNECTION;
        pkt->maxpacketsize = 8192;
        pkt->characterset = 8;
        pkt->username = pkt->buf + 23; // skip reserved bytes
        //snprintf(pkt->username, xxx, "%s", yyy); //FIXME: use username if set in monit configuration, otherwise "" (anonymous)
        pkt->authdatalen = pkt->username + strlen(pkt->username + 1);
        *pkt->authdatalen = 0; //FIXME: compute authdata if password is set in monit configuration file + set authdatalen 
        pkt->authdata = pkt->authdatalen + 1;
        pkt->len = sizeof(pkt->capabilities) + sizeof(pkt->maxpacketsize) + sizeof(pkt->characterset) + 23 + strlen(pkt->username) + 1 + 1 + strlen(pkt->authdata);
        if (Socket_write(socket, pkt, pkt->len + 4) < 0) // Note: pkt->len value is just payload size + need to add 4 bytes for the header itself (len + seq)
                THROW(IOException, "Cannot send handshake response -- %s\n", STRERROR);
}


/* ---------------------------------------------------------------- Public */


/**
 * Simple MySQL test. Connect to MySQL and read Server Handshake Packet. If we can read the packet and it is not an error packet we assume the server is up and working.
 *
 *  @see http://dev.mysql.com/doc/internals/en/client-server-protocol.html
 */
void check_mysql(Socket_T socket) {
        ASSERT(socket);

        mysql_handshake_init_t hi;
        _handshakeInit(socket, &hi);
        DEBUG("MySQL Server: Protocol: %d, Version: %s, Connection ID: %d, Character Set: 0x%x, Status: 0x%x, Capabilities: 0x%x\n", hi.protocol, hi.serverversion, hi.connectionid, hi.characterset, hi.status, hi.capabilities);

        mysql_handshake_response_t hr;
        _handshakeResponse(socket, &hr);
}

