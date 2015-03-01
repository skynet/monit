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

#include "protocol.h"

// libmonit
#include "exceptions/IOException.h"
#include "system/Net.h"

/**
 * Default service test with no protocol. TCP socket is connection-oriented so we know if it is reachable after the TCP handshake already - the UDP is connection-less so we have to send something to see
 * if the UDP server is down/unreachable. In such case the remote host should send an ICMP error, we then need to call read to get the ICMP error as a ECONNREFUSED errno.
 *
 *  @file
 */
void check_default(Socket_T socket) {
        ASSERT(socket);
        if (Socket_getType(socket) == Socket_Udp) {
                char token[1] = {};
                int s = Socket_getSocket(socket);
                Net_write(s, token, 1, 0);
                if (Net_read(s, token, 1, 1200) < 0) {
                        switch (errno) {
                                case ECONNREFUSED:
                                        THROW(IOException, "%s", STRERROR);
                                        break;
                                default:
                                        break;
                        }
                }
        }
}

