/*
 * Copyright (C) Tildeslash Ltd. All rights reserved.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License version 3.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
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


/**
 * Implementation of the Network Statistics for AIX.
 *
 * @author http://www.tildeslash.com/
 * @see http://www.mmonit.com/
 * @file
 */


static boolean_t _update(T S, const char *interface) {
        perfstat_id_t id;
        perfstat_netinterface_t buf;
        snprintf(id.name, sizeof(id.name), interface);
        if (perfstat_netinterface(&id, &buf, sizeof(buf), 1) != 1)
                THROW(AssertException, "Cannot get perfstat data for %s -- %s", interface, System_getError(errno));
        S->ipackets.last = S->ipackets.now;
        S->ibytes.last = S->ibytes.now;
        S->ierrors.last = S->ierrors.now;
        S->opackets.last = S->opackets.now;
        S->obytes.last = S->obytes.now;
        S->oerrors.last = S->oerrors.now;
        S->speed = buf.bitrate;
        S->ipackets.now = buf.ipackets;
        S->ibytes.now = buf.ibytes;
        S->ierrors.now = buf.ierrors;
        S->opackets.now = buf.opackets;
        S->obytes.now = buf.obytes;
        S->oerrors.now = buf.oerrors;
        S->timestamp.last = S->timestamp.now;
        S->timestamp.now = Time_milli();
        //FIXME: S->state and S->duplex are not implemented
        return true;
}

