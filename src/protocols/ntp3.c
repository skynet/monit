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
 *  NTP (Network time procol) version 3 test
 *
 *  Synchronization request based on RFC1305.
 *
 *
 */


/* ------------------------------------------------------------- Definitions */


#define NTPLEN           48
#define NTP_LEAP_NOWARN   0 /** Leap Indicator: No warning             */
#define NTP_LEAP_NOTSYNC  3 /** Leap Indicator: Clock not synchronized */
#define NTP_VERSION       3 /** Version Number: 3                      */
#define NTP_MODE_CLIENT   3 /** Mode:           Client                 */
#define NTP_MODE_SERVER   4 /** Mode:           Server                 */


/* ------------------------------------------------------------------ Public */


void check_ntp3(Socket_T socket) {
        int  br;
        char ntpRequest[NTPLEN] = {};
        char ntpResponse[NTPLEN] = {};

        ASSERT(socket);

        /*
         Prepare NTP request. The first octet consists of:
         bits 0-1 ... Leap Indicator
         bits 2-4 ... Version Number
         bits 5-7 ... Mode
         */
        ntpRequest[0]= (NTP_LEAP_NOTSYNC << 6) | (NTP_VERSION << 3) | (NTP_MODE_CLIENT);

        /* Send request to NTP server */
        if (Socket_write(socket, ntpRequest, NTPLEN) <= 0)
                THROW(IOException, "NTP: error sending NTP request -- %s", STRERROR);

        /* Receive and validate response */
        if ((br = Socket_read(socket, ntpResponse, NTPLEN)) <= 0)
                THROW(IOException, "NTP: did not receive answer from server -- %s", STRERROR);

        if (br != NTPLEN)
                THROW(IOException, "NTP: Received %d bytes from server, expected %d bytes", br, NTPLEN);

        /*
         Compare NTP response. The first octet consists of:
         bits 0-1 ... Leap Indicator
         bits 2-4 ... Version Number
         bits 5-7 ... Mode
         */
        if ((ntpResponse[0] & 0x07) != NTP_MODE_SERVER)
                THROW(IOException, "NTP: Server mode error");
        if ((ntpResponse[0] & 0x38) != NTP_VERSION << 3)
                THROW(IOException, "NTP: Server protocol version error");
        if ((ntpResponse[0] & 0xc0) == NTP_LEAP_NOTSYNC << 6)
                THROW(IOException, "NTP: Server not synchronized");
}

