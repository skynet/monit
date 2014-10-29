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

#ifdef HAVE_ERRNO_H
#include <errno.h>
#endif

#ifdef HAVE_STRING_H
#include <string.h>
#endif

#include "protocol.h"

static Protocol_T protocols[] = {
        &(struct Protocol_T){"DEFAULT",         check_default},
        &(struct Protocol_T){"HTTP",            check_http},
        &(struct Protocol_T){"FTP",             check_ftp},
        &(struct Protocol_T){"SMTP",            check_smtp},
        &(struct Protocol_T){"POP",             check_pop},
        &(struct Protocol_T){"IMAP",            check_imap},
        &(struct Protocol_T){"NNTP",            check_nntp},
        &(struct Protocol_T){"SSH",             check_ssh},
        &(struct Protocol_T){"DWP",             check_dwp},
        &(struct Protocol_T){"LDAP2",           check_ldap2},
        &(struct Protocol_T){"LDAP3",           check_ldap3},
        &(struct Protocol_T){"RDATE",           check_rdate},
        &(struct Protocol_T){"RSYNC",           check_rsync},
        &(struct Protocol_T){"generic",         check_generic},
        &(struct Protocol_T){"APACHESTATUS",    check_apache_status},
        &(struct Protocol_T){"NTP3",            check_ntp3},
        &(struct Protocol_T){"MYSQL",           check_mysql},
        &(struct Protocol_T){"DNS",             check_dns},
        &(struct Protocol_T){"POSTFIX-POLICY",  check_postfix_policy},
        &(struct Protocol_T){"TNS",             check_tns},
        &(struct Protocol_T){"PGSQL",           check_pgsql},
        &(struct Protocol_T){"CLAMAV",          check_clamav},
        &(struct Protocol_T){"SIP",             check_sip},
        &(struct Protocol_T){"LMTP",            check_lmtp},
        &(struct Protocol_T){"GPS",             check_gps},
        &(struct Protocol_T){"RADIUS",          check_radius},
        &(struct Protocol_T){"MEMCACHE",        check_memcache},
        &(struct Protocol_T){"WEBSOCKET",       check_websocket},
        &(struct Protocol_T){"REDIS",           check_redis},
        &(struct Protocol_T){"MONGODB",         check_mongodb}
};


/* ------------------------------------------------------------------ Public */


Protocol_T Protocol_get(Protocol_Type type) {
        if (type >= sizeof(protocols)/sizeof(protocols[0]))
                return protocols[0];
        return protocols[type];
}


