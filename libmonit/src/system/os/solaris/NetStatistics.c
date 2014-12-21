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
 * Implementation of the Network Statistics for Solaris.
 *
 * @author http://www.tildeslash.com/
 * @see http://www.mmonit.com/
 * @file
 */


static long long _getKstatValue(kstat_t *ksp, char *value) {
        const kstat_named_t *kdata = kstat_data_lookup(ksp, value);
        if (kdata) {
                switch (kdata->data_type) {
                        case KSTAT_DATA_INT32:
                                return (long long)kdata->value.i32;
                        case KSTAT_DATA_UINT32:
                                return (long long)kdata->value.ui32;
                        case KSTAT_DATA_INT64:
                                return (long long)kdata->value.i64;
                        case KSTAT_DATA_UINT64:
                                return (long long)kdata->value.ui64;
                }
                THROW(AssertException, "Unsupported kstat data type 0x%x", kdata->data_type);
        }
        THROW(AssertException, "Cannot read %s statistics -- %s", value, System_getError(errno));
        return -1LL;
}


static boolean_t _update(T S, const char *interface) {
        kstat_ctl_t *kc = kstat_open();
        if (kc) {
                kstat_t *ksp;
                if (Str_isEqual(interface, "lo0")) {
                        /*
                         * Loopback interface has special module on Solaris and provides packets statistics only.
                         *
                         * $ kstat -p -m lo
                         * lo:0:lo0:ipackets       878
                         * lo:0:lo0:opackets       878
                         */
                        if ((ksp = kstat_lookup(kc, "lo", -1, (char *)interface)) && kstat_read(kc, ksp, NULL) != -1) {
                                S->ipackets.last = S->ipackets.now;
                                S->opackets.last = S->opackets.now;
                                S->ipackets.now = _getKstatValue(ksp, "ipackets");
                                S->opackets.now = _getKstatValue(ksp, "opackets");
                                S->timestamp.last = S->timestamp.now;
                                S->timestamp.now = Time_milli();
                                kstat_close(kc);
                                return true;
                        } else {
                                kstat_close(kc);
                                THROW(AssertException, "Cannot get kstat data -- %s\n", System_getError(errno));
                        }
                } else {
                        /*
                         * Use link module for all other interface types.
                         *
                         * $ kstat -p -m link -n net0
                         * link:0:net0:ifspeed     1000000000
                         * link:0:net0:link_duplex 2
                         * link:0:net0:link_state  1
                         * ...
                         * link:0:net0:ierrors     0
                         * link:0:net0:ipackets    8748
                         * link:0:net0:ipackets64  8748
                         * link:0:net0:rbytes      1331127
                         * link:0:net0:rbytes64    1331127
                         * ...
                         * link:0:net0:oerrors     0
                         * link:0:net0:opackets    7560
                         * link:0:net0:opackets64  7560
                         * link:0:net0:obytes      3227785
                         * link:0:net0:obytes64    3227785
                         */
                        if ((ksp = kstat_lookup(kc, "link", -1, (char *)interface)) && kstat_read(kc, ksp, NULL) != -1) {
                                S->ipackets.last = S->ipackets.now;
                                S->ibytes.last = S->ibytes.now;
                                S->ierrors.last = S->ierrors.now;
                                S->opackets.last = S->opackets.now;
                                S->obytes.last = S->obytes.now;
                                S->oerrors.last = S->oerrors.now;
                                S->state = _getKstatValue(ksp, "link_state") ? 1LL : 0LL;
                                S->speed = _getKstatValue(ksp, "ifspeed");
                                S->duplex = _getKstatValue(ksp, "link_duplex") == 2 ? 1LL : 0LL;
                                S->ipackets.now = _getKstatValue(ksp, "ipackets64");
                                S->ibytes.now = _getKstatValue(ksp, "rbytes64");
                                S->ierrors.now = _getKstatValue(ksp, "ierrors");
                                S->opackets.now = _getKstatValue(ksp, "opackets64");
                                S->obytes.now = _getKstatValue(ksp, "obytes64");
                                S->oerrors.now = _getKstatValue(ksp, "oerrors");
                                S->timestamp.last = S->timestamp.now;
                                S->timestamp.now = Time_milli();
                                kstat_close(kc);
                                return true;
                        } else {
                                kstat_close(kc);
                                THROW(AssertException, "Cannot get kstat data -- %s", System_getError(errno));
                        }
                }
        }
        return false;
}

