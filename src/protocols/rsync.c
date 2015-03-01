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
 *  Check the server for greeting "@RSYNCD: XX, then send this greeting back to server, send command '#list' to get a listing of modules.
 *
 *  @file
 */
void check_rsync(Socket_T socket) {
        char  buf[64];
        char  header[11];
        int   rc, version_major, version_minor;
        char  *rsyncd = "@RSYNCD:";
        char  *rsyncd_exit = "@RSYNCD: EXIT";

        ASSERT(socket);

        /* Read and check the greeting */
        if (! Socket_readLine(socket, buf, sizeof(buf)))
                THROW(IOException, "RSYNC: did not see server greeting  -- %s", STRERROR);
        Str_chomp(buf);
        rc = sscanf(buf, "%10s %d.%d", header, &version_major, &version_minor);
        if ((rc == EOF) || (rc != 3))
                THROW(IOException, "RSYNC: server greeting parse error %s", buf);
        if (strncasecmp(header, rsyncd, strlen(rsyncd)) != 0)
                THROW(IOException, "RSYNC: server sent unexpected greeting -- %s", buf);

        /* Send back the greeting */
        if (Socket_print(socket, "%s\n", buf) <= 0)
                THROW(IOException, "RSYNC: identification string send failed -- %s", STRERROR);

        /* Send #list command */
        if (Socket_print(socket, "#list\n") < 0)
                THROW(IOException, "RSYNC: #list command failed -- %s", STRERROR);

        /* Read response: discard list output and check that we've received successful exit */
        do {
                if (! Socket_readLine(socket, buf, sizeof(buf)))
                        THROW(IOException, "RSYNC: error receiving data -- %s", STRERROR);
                Str_chomp(buf);
        } while (strncasecmp(buf, rsyncd, strlen(rsyncd)));
        if (strncasecmp(buf, rsyncd_exit, strlen(rsyncd_exit)) != 0)
                THROW(IOException, "RSYNC: server sent unexpected response -- %s", buf);
}

