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
#include "sha1.h"

// libmonit
#include "exceptions/IOException.h"


/* ----------------------------------------------------------- Definitions */


#define MYSQL_OK    0x00
#define MYSQL_EOF   0xfe
#define MYSQL_ERROR 0xff


#define COM_QUIT  0x1
#define COM_QUERY 0x3
#define COM_PING  0xe


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
        uint32_t len : 24;
        uint32_t seq : 8;
        // Data buffer
        char buf[STRLEN + 1];
        // State
        char *cursor;
        char *limit;
} mysql_request_t;


typedef struct {
        // Data buffer
        char buf[STRLEN + 4 + 1]; // reserve 4 bytes for header
        // Parser state
        char *cursor;
        char *limit;
        // Header
        uint32_t len;
        uint8_t seq;
        uint8_t header;
        // Packet specific data
        union {
                struct {
                        uint16_t  code;
                        char      sql_state_marker;
                        char      sql_state[5];
                        char     *message;
                } error;
                struct {
                        char     *version;
                        uint32_t  connectionid;
                        uint8_t   characterset;
                        uint16_t  status;
                        uint32_t  capabilities;
                        uint8_t   authdatalen;
                        char      authdata[21];
                } handshake;
        } data;
} mysql_response_t;


typedef enum {
        MySQL_Init = 0,
        MySQL_Handshake,
        MySQL_Ok,
        MySQL_Eof,
        MySQL_Error
} __attribute__((__packed__)) mysql_state_t;


typedef struct mysql_t {
        mysql_state_t state;
        mysql_response_t response;
        mysql_request_t request;
        Socket_T socket;
        Port_T port;
        uint32_t capabilities;
} mysql_t;


/* ----------------------------------------------------------- Data parser */


static uint8_t _getUInt1(mysql_response_t *response) {
        if (response->cursor + 1 > response->limit)
                THROW(IOException, "Data not available -- EOF");
        uint8_t value = response->cursor[0];
        response->cursor += 1;
        return value;
}


static uint16_t _getUInt2(mysql_response_t *response) {
        if (response->cursor + 2 > response->limit)
                THROW(IOException, "Data not available -- EOF");
        uint16_t value;
        *(((char *)&value) + 0) = response->cursor[1];
        *(((char *)&value) + 1) = response->cursor[0];
        response->cursor += 2;
        return ntohs(value);
}


static uint32_t _getUInt3(mysql_response_t *response) {
        if (response->cursor + 3 > response->limit)
                THROW(IOException, "Data not available -- EOF");
        uint32_t value;
        *(((char *)&value) + 0) = 0;
        *(((char *)&value) + 1) = response->cursor[2];
        *(((char *)&value) + 2) = response->cursor[1];
        *(((char *)&value) + 3) = response->cursor[0];
        response->cursor += 3;
        return ntohl(value);
}


static uint32_t _getUInt4(mysql_response_t *response) {
        if (response->cursor + 4 > response->limit)
                THROW(IOException, "Data not available -- EOF");
        uint32_t value;
        *(((char *)&value) + 0) = response->cursor[3];
        *(((char *)&value) + 1) = response->cursor[2];
        *(((char *)&value) + 2) = response->cursor[1];
        *(((char *)&value) + 3) = response->cursor[0];
        response->cursor += 4;
        return ntohl(value);
}


static char *_getString(mysql_response_t *response) {
        int i;
        char *value;
        for (i = 0; response->cursor[i]; i++) // Check limits (cannot use strlen here as no terminating '\0' is guaranteed in the buffer)
                if (response->cursor + i >= response->limit) // If we reached the limit and didn't found '\0', throw error
                        THROW(IOException, "Data not available -- EOF");
        value = response->cursor;
        response->cursor += i + 1;
        return value;
}


static void _getPadding(mysql_response_t *response, int count) {
        if (response->cursor + count > response->limit)
                THROW(IOException, "Data not available -- EOF");
        response->cursor += count;
}


/* ----------------------------------------------------------- Data setter */


static void _setUInt1(mysql_request_t *request, uint8_t value) {
        if (request->cursor + 1 > request->limit)
                THROW(IOException, "Maximum packet size exceeded");
        request->cursor[0] = value;
        request->cursor += 1;
}


static void _setUInt4(mysql_request_t *request, uint32_t value) {
        if (request->cursor + 4 > request->limit)
                THROW(IOException, "Maximum packet size exceeded");
        uint32_t v = htonl(value);
        request->cursor[0] = *(((char *)&v) + 3);
        request->cursor[1] = *(((char *)&v) + 2);
        request->cursor[2] = *(((char *)&v) + 1);
        request->cursor[3] = *(((char *)&v) + 0);
        request->cursor += 4;
}


static void _setData(mysql_request_t *request, const char *data, unsigned long length) {
        if (request->cursor + length > request->limit)
                THROW(IOException, "Maximum packet size exceeded");
        memcpy(request->cursor, data, length);
        request->cursor += length;
}


static void _setPadding(mysql_request_t *request, int count) {
        if (request->cursor + count > request->limit)
                THROW(IOException, "Maximum packet size exceeded");
        request->cursor += count;
}


/* ----------------------------------------------------- Response handlers */


// OK packet (see http://dev.mysql.com/doc/internals/en/packet-OK_Packet.html)
static void _responseOk(mysql_t *mysql) {
        mysql->state = MySQL_Ok;
}


// EOF packet (see http://dev.mysql.com/doc/internals/en/packet-EOF_Packet.html)
static void _responseEof(mysql_t *mysql) {
        mysql->state = MySQL_Eof;
}


// ERR packet (see http://dev.mysql.com/doc/internals/en/packet-ERR_Packet.html)
static void _responseError(mysql_t *mysql) {
        mysql->state = MySQL_Error;
        mysql->response.data.error.code = _getUInt2(&mysql->response);
        if (mysql->capabilities & CLIENT_PROTOCOL_41)
                _getPadding(&mysql->response, 6); // skip sql_state_marker and sql_state which we don't use
        mysql->response.data.error.message = _getString(&mysql->response);
        THROW(IOException, "Server returned error code %d -- %s", mysql->response.data.error.code, mysql->response.data.error.message);
}


// Initial handshake packet (see http://dev.mysql.com/doc/internals/en/connection-phase-packets.html#packet-Protocol::Handshake)
static void _responseHandshake(mysql_t *mysql) {
        mysql->state = MySQL_Handshake;
        // Protocol is 10 for MySQL 5.x
        if (mysql->response.header != 10)
                THROW(IOException, "Invalid protocol version %d", mysql->response.header);
        mysql->response.data.handshake.version = _getString(&mysql->response);
        mysql->response.data.handshake.connectionid = _getUInt4(&mysql->response);
        snprintf(mysql->response.data.handshake.authdata, 9, "%s", _getString(&mysql->response)); // auth_plugin_data_part_1
        mysql->response.data.handshake.capabilities = _getUInt2(&mysql->response); // capability flags (lower 2 bytes)
        mysql->response.data.handshake.characterset = _getUInt1(&mysql->response);
        mysql->response.data.handshake.status = _getUInt2(&mysql->response);
        mysql->response.data.handshake.capabilities |= _getUInt2(&mysql->response) << 16; // merge capability flags (lower 2 bytes + upper 2 bytes)
        mysql->response.data.handshake.authdatalen = _getUInt1(&mysql->response);
        _getPadding(&mysql->response, 10); // reserved bytes
        if (mysql->response.data.handshake.capabilities & CLIENT_SECURE_CONNECTION)
                snprintf(mysql->response.data.handshake.authdata + 8, 13, "%s", _getString(&mysql->response)); // auth_plugin_data_part_2
        mysql->capabilities = mysql->response.data.handshake.capabilities; // Save capabilities
        DEBUG("MySQL Server: Protocol: %d, Version: %s, Connection ID: %d\n", mysql->response.header, mysql->response.data.handshake.version, mysql->response.data.handshake.connectionid);
}


// Response handler
static void _response(mysql_t *mysql) {
        memset(&mysql->response, 0, sizeof(mysql_response_t));
        mysql->response.cursor = mysql->response.buf;
        mysql->response.limit = mysql->response.buf + sizeof(mysql->response.buf);
        // Read the packet length
        if (Socket_read(mysql->socket, mysql->response.cursor, 4) < 4)
                THROW(IOException, "Error receiving server response -- %s", STRERROR);
        mysql->response.len = _getUInt3(&mysql->response);
        mysql->response.seq = _getUInt1(&mysql->response);
        if (mysql->state == MySQL_Init) {
                if (! mysql->response.len || mysql->response.len > STRLEN)
                        THROW(IOException, "Invalid handshake packet length -- not MySQL protocol");
                if (mysql->response.seq != 0)
                        THROW(IOException, "Invalid handshake packet sequence id -- not MySQL protocol");
        }
        mysql->response.len = mysql->response.len > STRLEN ? STRLEN : mysql->response.len; // Adjust packet length for this buffer
        // Read payload
        if (Socket_read(mysql->socket, mysql->response.cursor, mysql->response.len) != mysql->response.len)
                THROW(IOException, "Error receiving server response -- %s", STRERROR);
        // Packet type router
        mysql->response.header = _getUInt1(&mysql->response);
        switch (mysql->response.header) {
                case MYSQL_OK:
                        _responseOk(mysql);
                        break;
                case MYSQL_EOF:
                        _responseEof(mysql);
                        break;
                case MYSQL_ERROR:
                        _responseError(mysql);
                        break;
                default:
                        _responseHandshake(mysql);
                        break;
        }
}


/* ------------------------------------------------------ Request handlers */


// Set the password (see http://dev.mysql.com/doc/internals/en/secure-password-authentication.html):
static char *_password(char result[SHA1_DIGEST_SIZE], const char *password, const char *salt) {
        sha1_context_t ctx;
        // SHA1(password)
        uint8_t stage1[SHA1_DIGEST_SIZE];
        sha1_init(&ctx);
        sha1_append(&ctx, (const unsigned char *)password, strlen(password));
        sha1_finish(&ctx, stage1);
        // SHA1(SHA1(password))
        uint8_t stage2[SHA1_DIGEST_SIZE];
        sha1_init(&ctx);
        sha1_append(&ctx, (const unsigned char *)stage1, SHA1_DIGEST_SIZE);
        sha1_finish(&ctx, stage2);
        // SHA1("20-bytes random data from server" <concat> SHA1(SHA1(password)))
        uint8_t stage3[SHA1_DIGEST_SIZE];
        sha1_init(&ctx);
        sha1_append(&ctx, (const unsigned char *)salt, strlen(salt));
        sha1_append(&ctx, (const unsigned char *)stage2, SHA1_DIGEST_SIZE);
        sha1_finish(&ctx, stage3);
        // XOR
        for (int i = 0; i < SHA1_DIGEST_SIZE; i++)
                result[i] = stage1[i] ^ stage3[i];
        return result;
}


// Initiate the request
static void _initRequest(mysql_t *mysql, uint8_t sequence) {
        memset(&mysql->request, 0, sizeof(mysql_request_t));
        mysql->request.seq = sequence;
        mysql->request.cursor = mysql->request.buf;
        mysql->request.limit = mysql->request.buf + sizeof(mysql->request.buf);
}


// Set payload length and send the request to the server
static void _sendRequest(mysql_t *mysql) {
        mysql->request.len = (uint32_t)(mysql->request.cursor - mysql->request.buf);
        // Send request
        if (Socket_write(mysql->socket, &mysql->request, mysql->request.len + 4) < 0) // Note: mysql->request.len value is just payload size + need to add 4 bytes for the header itself (len + seq)
                THROW(IOException, "Cannot send handshake response -- %s\n", STRERROR);
}


// Hadshake response packet (see http://dev.mysql.com/doc/internals/en/connection-phase-packets.html#packet-Protocol::HandshakeResponse)
static void _requestHandshake(mysql_t *mysql) {
        ASSERT(mysql->state == MySQL_Handshake);
        _initRequest(mysql, 1);
        _setUInt4(&mysql->request, CLIENT_LONG_PASSWORD | CLIENT_PROTOCOL_41 | CLIENT_SECURE_CONNECTION);                                                                             // capabilities
        _setUInt4(&mysql->request, 8192);                                                                                                                                             // maxpacketsize
        _setUInt1(&mysql->request, 8);                                                                                                                                                // characterset
        _setPadding(&mysql->request, 23);                                                                                                                                             // reserved bytes
        if (mysql->port->parameters.mysql.username)
                _setData(&mysql->request, mysql->port->parameters.mysql.username, strlen(mysql->port->parameters.mysql.username));                                                    // username
        _setPadding(&mysql->request, 1);                                                                                                                                              // NUL
        if (mysql->port->parameters.mysql.password) {
                _setUInt1(&mysql->request, SHA1_DIGEST_SIZE);                                                                                                                         // authdatalen
                _setData(&mysql->request, _password((char[SHA1_DIGEST_SIZE]){0}, mysql->port->parameters.mysql.password, mysql->response.data.handshake.authdata), SHA1_DIGEST_SIZE); // password
        } else {
                _setUInt1(&mysql->request, 0);                                                                                                                                        // no password
        }
        _sendRequest(mysql);
}


// COM_QUIT packet (see http://dev.mysql.com/doc/internals/en/com-quit.html)
static void _requestQuit(mysql_t *mysql) {
        ASSERT(mysql->state == MySQL_Ok);
        _initRequest(mysql, 0);
        _setUInt1(&mysql->request, COM_QUIT);
        _sendRequest(mysql);
}


// COM_PING packet (see http://dev.mysql.com/doc/internals/en/com-ping.html)
static void _requestPing(mysql_t *mysql) {
        ASSERT(mysql->state == MySQL_Ok);
        _initRequest(mysql, 0);
        _setUInt1(&mysql->request, COM_PING);
        _sendRequest(mysql);
}


/*
// Note: we currently don't implement COM_QUERY *response* handler (OK/EOF packet with payload), if it'll be added and COM_QUERY used, uncomment the following COM_QUERY request implementation.
//
//   Usage (for example):
//      _requestQuery(&mysql, "show global status");
//

// COM_QUERY packet (see http://dev.mysql.com/doc/internals/en/com-query.html)
static void _requestQuery(mysql_t *mysql, const unsigned char *query) {
        ASSERT(mysql->state == MySQL_Ok);
        _initRequest(mysql, 0);
        _setUInt1(&mysql->request, COM_QUERY);
        _setData(&mysql->request, query, strlen(query));
        _sendRequest(mysql);
}
*/


/* ---------------------------------------------------------------- Public */


/**
 * Simple MySQL test. Connect to MySQL and read Server Handshake Packet. If we can read the packet and it is not an error packet we assume the server is up and working.
 *
 *  @see http://dev.mysql.com/doc/internals/en/client-server-protocol.html
 */
void check_mysql(Socket_T socket) {
        ASSERT(socket);
        mysql_t mysql = {.state = MySQL_Init, .socket = socket, .port = Socket_getPort(socket)};
        _response(&mysql);
        if (mysql.state != MySQL_Handshake)
                THROW(IOException, "Invalid server greeting, the server didn't sent a handshake packet -- not MySQL protocol\n");
        _requestHandshake(&mysql);
        // Check handshake response: if no credentials are set, we allow both Ok/Error as we've sent an anonymous login which may fail, but if credentials are set, we expect Ok only
        TRY
        {
                _response(&mysql);
        }
        ELSE
        {
                if (mysql.port->parameters.mysql.username)
                        RETHROW;
        }
        END_TRY;
        // If we're logged in, ping and quit
        if (mysql.state == MySQL_Ok) {
                _requestPing(&mysql);
                _response(&mysql);
                _requestQuit(&mysql);
        }
}

