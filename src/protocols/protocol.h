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


#ifndef MONIT_PROTOCOL_H
#define MONIT_PROTOCOL_H

#include "config.h"

#include "monit.h"
#include "socket.h"


/* Protocols supported */
typedef enum {
        Protocol_DEFAULT = 0,
        Protocol_HTTP,
        Protocol_FTP,
        Protocol_SMTP,
        Protocol_POP,
        Protocol_IMAP,
        Protocol_NNTP,
        Protocol_SSH,
        Protocol_DWP,
        Protocol_LDAP2,
        Protocol_LDAP3,
        Protocol_RDATE,
        Protocol_RSYNC,
        Protocol_GENERIC,
        Protocol_APACHESTATUS,
        Protocol_NTP3,
        Protocol_MYSQL,
        Protocol_DNS,
        Protocol_POSTFIXPOLICY,
        Protocol_TNS,
        Protocol_PGSQL,
        Protocol_CLAMAV,
        Protocol_SIP,
        Protocol_LMTP,
        Protocol_GPS,
        Protocol_RADIUS,
        Protocol_MEMCACHE,
        Protocol_WEBSOCKET,
        Protocol_REDIS,
        Protocol_MONGODB,
        Protocol_SIEVE
} Protocol_Type;


boolean_t check_apache_status(Socket_T);
boolean_t check_default(Socket_T);
boolean_t check_dns(Socket_T);
boolean_t check_dwp(Socket_T);
boolean_t check_ftp(Socket_T);
boolean_t check_generic(Socket_T);
boolean_t check_http(Socket_T);
boolean_t check_imap(Socket_T);
boolean_t check_clamav(Socket_T);
boolean_t check_ldap2(Socket_T);
boolean_t check_ldap3(Socket_T);
boolean_t check_mongodb(Socket_T);
boolean_t check_mysql(Socket_T);
boolean_t check_nntp(Socket_T);
boolean_t check_ntp3(Socket_T);
boolean_t check_postfix_policy(Socket_T);
boolean_t check_pop(Socket_T);
boolean_t check_sieve(Socket_T);
boolean_t check_smtp(Socket_T);
boolean_t check_ssh(Socket_T);
boolean_t check_redis(Socket_T);
boolean_t check_rdate(Socket_T);
boolean_t check_rsync(Socket_T);
boolean_t check_tns(Socket_T);
boolean_t check_pgsql(Socket_T);
boolean_t check_sip(Socket_T);
boolean_t check_lmtp(Socket_T);
boolean_t check_gps(Socket_T);
boolean_t check_radius(Socket_T);
boolean_t check_memcache(Socket_T);
boolean_t check_websocket(Socket_T);


/*
 * Returns a protocol object for the given protocol type
 */
Protocol_T Protocol_get(Protocol_Type type);


#endif
