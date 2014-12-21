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
 * Implementation of the Network Statistics for Linux.
 *
 * @author http://www.tildeslash.com/
 * @see http://www.mmonit.com/
 * @file
 */


static boolean_t _update(T S, const char *interface) {
        char buf[STRLEN];
        char path[PATH_MAX];
        /*
         * Get interface operation state (Optional: may not be present on older kernels).
         * $ cat /sys/class/net/eth0/operstate
         * up
         */
        snprintf(path, sizeof(path), "/sys/class/net/%s/operstate", interface);
        FILE *f = fopen(path, "r");
        if (f) {
                if (fscanf(f, "%256s\n", buf) == 1) {
                        S->state = Str_isEqual(buf, "down") ? 0LL : 1LL;
                }
                fclose(f);
        }
        /*
         * Get interface speed (Optional: may not be present on older kernels).
         * $ cat /sys/class/net/eth0/speed
         * 1000
         */
        snprintf(path, sizeof(path), "/sys/class/net/%s/speed", interface);
        f = fopen(path, "r");
        if (f) {
                int speed;
                if (fscanf(f, "%d\n", &speed) == 1) {
                        S->speed = speed * 1000000; // mbps -> bps
                }
                fclose(f);
        }
        /*
         * Get interface full/half duplex status (Optional: may not be present on older kernels).
         * $ cat /sys/class/net/eth0/duplex
         * full
         */
        snprintf(path, sizeof(path), "/sys/class/net/%s/duplex", interface);
        f = fopen(path, "r");
        if (f) {
                if (fscanf(f, "%256s\n", buf) == 1) {
                        S->duplex = Str_isEqual(buf, "full") ? 1LL : 0LL;
                }
                fclose(f);
        }
        /*
         * $ cat /proc/net/dev
         * Inter-|   Receive                                                |  Transmit
         *  face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
         *   eth0: 1841444   11557    0    0    0     0          0         0  1335636    7725    0    0    0     0       0          0
         *     lo:   28760     200    0    0    0     0          0         0    28760     200    0    0    0     0       0          0
         */
        f = fopen("/proc/net/dev", "r");
        if (f) {
                long long ibytes, ipackets, ierrors, obytes, opackets, oerrors;
                while (fgets(buf, sizeof(buf), f) != NULL) {
                        char iface[STRLEN];
                        if (sscanf(buf, "%256[^:]: %lld %lld %lld %*s %*s %*s %*s %*s %lld %lld %lld %*s %*s %*s %*s %*s", iface, &ibytes, &ipackets, &ierrors, &obytes, &opackets, &oerrors) == 7 && Str_isEqual(Str_trim(iface), interface)) {
                                S->timestamp.last = S->timestamp.now;
                                S->timestamp.now = Time_milli();
                                S->ipackets.last = S->ipackets.now;
                                S->ipackets.now = ipackets;
                                S->ibytes.last = S->ibytes.now;
                                S->ibytes.now = ibytes;
                                S->ierrors.last = S->ierrors.now;
                                S->ierrors.now = ierrors;
                                S->opackets.last = S->opackets.now;
                                S->opackets.now = opackets;
                                S->obytes.last = S->obytes.now;
                                S->obytes.now = obytes;
                                S->oerrors.last = S->oerrors.now;
                                S->oerrors.now = oerrors;
                                fclose(f);
                                return true;
                        }
                }
                fclose(f);
        } else {
                THROW(AssertException, "Cannot read /proc/net/dev -- %s", System_getError(errno));
        }
        return false;
}

