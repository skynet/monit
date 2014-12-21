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
 * Implementation of the Network Statistics for NetBSD.
 *
 * @author http://www.tildeslash.com/
 * @see http://www.mmonit.com/
 * @file
 */


static boolean_t _update(T S, const char *interface) {
        for (struct ifaddrs *a = _stats.addrs; a != NULL; a = a->ifa_next) {
                if (a->ifa_addr == NULL)
                        continue;
                if (Str_isEqual(interface, a->ifa_name) && a->ifa_addr->sa_family == AF_LINK) {
                        int s = socket(AF_INET, SOCK_DGRAM, 0);
                        if (s > 0) {
                                struct ifmediareq ifmr;
                                memset(&ifmr, 0, sizeof(ifmr));
                                strncpy(ifmr.ifm_name, interface, sizeof(ifmr.ifm_name));
                                // try SIOCGIFMEDIA - if not supported, assume the interface is UP (loopback or other virtual interface)
                                if (ioctl(s, SIOCGIFMEDIA, (caddr_t)&ifmr) >= 0) {
                                        if (ifmr.ifm_status & IFM_AVALID && ifmr.ifm_status & IFM_ACTIVE) {
                                                S->state = 1LL;
                                                S->duplex = ifmr.ifm_active & 0x00100000 ? 1LL : 0LL;
                                        } else {
                                                S->state = 0LL;
                                                S->duplex = -1LL;
                                        }
                                } else {
                                        S->state = 1LL;
                                }
                                close(s);
                        } else {
                                S->state = -1LL;
                                S->duplex = -1LL;
                        }
                        struct if_data *data = (struct if_data *)a->ifa_data;
                        S->timestamp.last = S->timestamp.now;
                        S->timestamp.now = Time_milli();
                        S->speed = data->ifi_baudrate;
                        S->ipackets.last = S->ipackets.now;
                        S->ipackets.now = data->ifi_ipackets;
                        S->ibytes.last = S->ibytes.now;
                        S->ibytes.now = data->ifi_ibytes;
                        S->ierrors.last = S->ierrors.now;
                        S->ierrors.now = data->ifi_ierrors;
                        S->opackets.last = S->opackets.now;
                        S->opackets.now = data->ifi_opackets;
                        S->obytes.last = S->obytes.now;
                        S->obytes.now = data->ifi_obytes;
                        S->oerrors.last = S->oerrors.now;
                        S->oerrors.now = data->ifi_oerrors;
                        return true;
                }
        }
        return false;
}

