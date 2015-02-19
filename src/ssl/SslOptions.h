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

#ifndef SSLOPTIONS_H
#define SSLOPTIONS_H


#include "config.h"


#define T SslOptions_T
typedef struct T {
        boolean_t use_ssl;             /**< true if SSL is required for connection */ //FIXME: drop this (can use version -> SSL_Disabled)
        Ssl_Version version;            /**< The SSL version to use for connection */
        char *certmd5;       /**< The expected md5 sum of the server's certificate */
        char *clientpemfile;                      /**< Optional client certificate */
} T;


#undef T
#endif

