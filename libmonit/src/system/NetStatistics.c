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


#include "Config.h"

#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <sys/ioctl.h>
#ifdef HAVE_IFADDRS_H
#include <ifaddrs.h>
#endif
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#ifdef HAVE_NET_IF_H
#include <net/if.h>
#endif
#ifdef HAVE_NET_IF_MEDIA_H
#include <net/if_media.h>
#endif
#ifdef HAVE_KSTAT_H
#include <kstat.h>
#endif

#include "system/NetStatistics.h"
#include "system/Time.h"
#include "system/System.h"
#include "Str.h"


/**
 * Implementation of the Statistics Facade for Unix Systems.
 *
 * @author http://www.tildeslash.com/
 * @see http://www.mmonit.com/
 * @file
 */


/* ------------------------------------------------------------- Definitions */


static struct {
        struct ifaddrs *addrs;
        time_t timestamp;
} _stats = {};


/* --------------------------------------- Static destructor */


static void __attribute__ ((destructor)) _Destructor() {
#ifdef HAVE_IFADDRS_H
        if (_stats.addrs)
                freeifaddrs(_stats.addrs);
#endif
}


/* --------------------------------------------------------------- Private */


#ifdef SOLARIS
long long _getKstatValue(kstat_t *ksp, char *value) {
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
        return -1LL; // Will be never reached
}
#endif

static void _refreshStats() {
#ifdef HAVE_IFADDRS_H
        time_t now = Time_now();
        if ((_stats.timestamp != now) || ! _stats.addrs) {
                _stats.timestamp = now;
                if (_stats.addrs) {
                        freeifaddrs(_stats.addrs);
                        _stats.addrs = NULL;
                }
                if (getifaddrs(&(_stats.addrs)) == -1) {
                        _stats.timestamp = 0;
                        THROW(AssertException, "Cannot get network statistics -- %s", System_getError(errno));
                }
        }
#else
        THROW(AssertException, "Cannot get network statistics -- getifaddrs not supported");
#endif
}


static void _updateStats(const char *interface, NetStatistics_T *stats) {
#if defined DARWIN || defined FREEBSD || defined OPENBSD || defined NETBSD
        for (struct ifaddrs *a = _stats.addrs; a != NULL; a = a->ifa_next) {
                if (a->ifa_addr == NULL)
                        continue;
                if (Str_isEqual(interface, a->ifa_name) && a->ifa_addr->sa_family == AF_LINK) {
                        stats->state.last = stats->state.now;
                        stats->duplex.last = stats->duplex.now;
                        int s = socket(AF_INET, SOCK_DGRAM, 0);
                        if (s > 0) {
                                struct ifmediareq ifmr;
                                memset(&ifmr, 0, sizeof(ifmr));
                                strncpy(ifmr.ifm_name, interface, sizeof(ifmr.ifm_name));
                                // try SIOCGIFMEDIA - if not supported, assume the interface is UP (loopback or other virtual interface)
                                if (ioctl(s, SIOCGIFMEDIA, (caddr_t)&ifmr) >= 0) {
                                        if (ifmr.ifm_status & IFM_AVALID && ifmr.ifm_status & IFM_ACTIVE) {
                                                stats->state.now = 1LL;
                                                stats->duplex.now = ifmr.ifm_active & 0x00100000 ? 1LL : 0LL;
                                        } else {
                                                stats->state.now = 0LL;
                                                stats->duplex.now = -1LL;
                                        }
                                }
                                close(s);
                        } else {
                                stats->state.now = -1LL;
                                stats->duplex.now = -1LL;
                        }
                        struct if_data *data = (struct if_data *)a->ifa_data;
                        stats->timestamp.last = stats->timestamp.now;
                        stats->timestamp.now = Time_milli();
                        stats->speed.last = stats->speed.now;
                        stats->speed.now = data->ifi_baudrate;
                        stats->ipackets.last = stats->ipackets.now;
                        stats->ipackets.now = data->ifi_ipackets;
                        stats->ibytes.last = stats->ibytes.now;
                        stats->ibytes.now = data->ifi_ibytes;
                        stats->ierrors.last = stats->ierrors.now;
                        stats->ierrors.now = data->ifi_ierrors;
                        stats->opackets.last = stats->opackets.now;
                        stats->opackets.now = data->ifi_opackets;
                        stats->obytes.last = stats->obytes.now;
                        stats->obytes.now = data->ifi_obytes;
                        stats->oerrors.last = stats->oerrors.now;
                        stats->oerrors.now = data->ifi_oerrors;
                        return;
                }
        }
#elif defined LINUX
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
                        stats->state.last = stats->state.now;
                        stats->state.now = Str_isEqual(buf, "up") ? 1LL : 0LL;
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
                        stats->speed.last = stats->speed.now;
                        stats->speed.now = speed * 1000000; // mbps -> bps
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
                        stats->duplex.last = stats->duplex.now;
                        stats->duplex.now = Str_isEqual(buf, "full") ? 1LL : 0LL;
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
                while (fscanf(f, " %256[^:]: %lld %lld %lld %*s %*s %*s %*s %*s %lld %lld %lld %*s %*s %*s %*s %*s\n", buf, &ibytes, &ipackets, &ierrors, &obytes, &opackets, &oerrors) != 7 || ! Str_isEqual(buf, interface)) {
                        stats->timestamp.last = stats->timestamp.now;
                        stats->timestamp.now = Time_milli();
                        stats->ipackets.last = stats->ipackets.now;
                        stats->ipackets.now = ipackets;
                        stats->ibytes.last = stats->ibytes.now;
                        stats->ibytes.now = ibytes;
                        stats->ierrors.last = stats->ierrors.now;
                        stats->ierrors.now = ierrors;
                        stats->opackets.last = stats->opackets.now;
                        stats->opackets.now = opackets;
                        stats->obytes.last = stats->obytes.now;
                        stats->obytes.now = obytes;
                        stats->oerrors.last = stats->oerrors.now;
                        stats->oerrors.now = oerrors;
                        fclose(f);
                        return;
                }
                fclose(f);
        } else {
                THROW(AssertException, "Cannot read /proc/net/dev -- %s", System_getError(errno));
        }
#elif defined SOLARIS
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
                                stats->ipackets.last = stats->ipackets.now;
                                stats->opackets.last = stats->opackets.now;
                                stats->ipackets.now = _getKstatValue(ksp, "ipackets");
                                stats->opackets.now = _getKstatValue(ksp, "opackets");
                                stats->timestamp.last = stats->timestamp.now;
                                stats->timestamp.now = Time_milli();
                                kstat_close(kc);
                                return;
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
                                stats->state.last = stats->state.now;
                                stats->speed.last = stats->speed.now;
                                stats->duplex.last = stats->duplex.now;
                                stats->ipackets.last = stats->ipackets.now;
                                stats->ibytes.last = stats->ibytes.now;
                                stats->ierrors.last = stats->ierrors.now;
                                stats->opackets.last = stats->opackets.now;
                                stats->obytes.last = stats->obytes.now;
                                stats->oerrors.last = stats->oerrors.now;
                                stats->state.now = _getKstatValue(ksp, "link_state") ? 1LL : 0LL;
                                stats->speed.now = _getKstatValue(ksp, "ifspeed");
                                stats->duplex.now = _getKstatValue(ksp, "link_duplex") == 2 ? 1LL : 0LL;
                                stats->ipackets.now = _getKstatValue(ksp, "ipackets64");
                                stats->ibytes.now = _getKstatValue(ksp, "rbytes64");
                                stats->ierrors.now = _getKstatValue(ksp, "ierrors");
                                stats->opackets.now = _getKstatValue(ksp, "opackets64");
                                stats->obytes.now = _getKstatValue(ksp, "obytes64");
                                stats->oerrors.now = _getKstatValue(ksp, "oerrors");
                                stats->timestamp.last = stats->timestamp.now;
                                stats->timestamp.now = Time_milli();
                                kstat_close(kc);
                                return;
                        } else {
                                kstat_close(kc);
                                THROW(AssertException, "Cannot get kstat data -- %s", System_getError(errno));
                        }
                }
        }
#endif
        THROW(AssertException, "Cannot udate network statistics -- interface %s not found", interface);
}


static const char *_findInterfaceForAddress(const char *address) {
#ifdef HAVE_IFADDRS_H
        for (struct ifaddrs *a = _stats.addrs; a != NULL; a = a->ifa_next) {
                if (a->ifa_addr == NULL)
                        continue;
                int s;
                char host[NI_MAXHOST];
                if (a->ifa_addr->sa_family == AF_INET)
                        s = getnameinfo(a->ifa_addr, sizeof(struct sockaddr_in), host, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);
                else if (a->ifa_addr->sa_family == AF_INET6)
                        s = getnameinfo(a->ifa_addr, sizeof(struct sockaddr_in6), host, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);
                else
                        continue;
                if (s != 0)
                        THROW(AssertException, "Cannot translate address to name -- %s", gai_strerror(s));
                if (Str_isEqual(address, host))
                        return a->ifa_name;
        }
        THROW(AssertException, "Address %s not found", address);
#else
        THROW(AssertException, "Network monitoring by IP address is not supported on this platform, please use 'check network <foo> with interface <bar>' instead");
#endif
        return NULL; // Will be never reached
}


/* ---------------------------------------------------------------- Public */


int NetStatistics_isGetByAddressSupported() {
#ifdef HAVE_IFADDRS_H
        return true;
#else
        return false;
#endif
}


void NetStatistics_getByAddress(const char *address, NetStatistics_T *stats) {
        assert(address);
        assert(stats);
        _refreshStats();
        _updateStats(_findInterfaceForAddress(address), stats);
}


void NetStatistics_getByInterface(const char *interface, NetStatistics_T *stats) {
        assert(interface);
        assert(stats);
        _refreshStats();
        _updateStats(interface, stats);
}

