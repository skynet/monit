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


#define T NetStatistics_T


static struct {
        struct ifaddrs *addrs;
        time_t timestamp;
} _stats = {};


typedef struct NetStatisticsData_T {
        long long last;
        long long now;
        long long minute[60];
        long long hour[24];
} NetStatisticsData_T;


struct T {
        char *object;
        const char *(*resolve)(const char *object); // Resolve Object -> Interface, set during NetStatistics_T instantiation by constructor (currently we implement only IPAddress -> Interface lookup)

        struct {
                long long last;
                long long now;
        } timestamp;

        int state;       // State (0 = down, 1 = up)
        int duplex;      // Duplex (0 = half, 1 = full)
        long long speed; // Speed [bps]

        NetStatisticsData_T ipackets;  // Packets received on interface
        NetStatisticsData_T ierrors;   // Input errors on interface
        NetStatisticsData_T ibytes;    // Total number of octets received
        NetStatisticsData_T opackets;  // Packets sent on interface
        NetStatisticsData_T oerrors;   // Output errors on interface
        NetStatisticsData_T obytes;    // Total number of octets sent
};


/* ----------------------------------------------------- Static destructor */


static void __attribute__ ((destructor)) _destructor() {
#ifdef HAVE_IFADDRS_H
        if (_stats.addrs)
                freeifaddrs(_stats.addrs);
#endif
}


/* --------------------------------------------------------------- Private */


static void _resetData(NetStatisticsData_T *data, long long value) {
        for (int i = 0; i < 60; i++)
                data->minute[i] = value;
        for (int i = 0; i < 24; i++)
                data->hour[i] = value;
}


static void _reset(T S) {
        S->timestamp.last = 0LL;
        S->timestamp.now = 0LL;
        S->state = -1;
        S->duplex = -1;
        S->speed = 0LL;
        _resetData(&(S->ibytes), -1LL);
        _resetData(&(S->ipackets), -1LL);
        _resetData(&(S->ierrors), -1LL);
        _resetData(&(S->obytes), -1LL);
        _resetData(&(S->opackets), -1LL);
        _resetData(&(S->oerrors), -1LL);
}


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
        return -1LL;
}
#endif


static long long _deltaSecond(T S, NetStatisticsData_T *data) {
        if (S->timestamp.last > 0 && S->timestamp.now > S->timestamp.last)
                if (data->last > -1 && data->now > data->last)
                        return (long long)((data->now - data->last) * 1000. / (S->timestamp.now - S->timestamp.last));
        return 0LL;
}


static long long _deltaMinute(T S, NetStatisticsData_T *data, int count) {
        assert(count > 0);
        assert(count <= 60);
        int stop = Time_minutes(S->timestamp.now / 1000.);
        int delta = stop - count;
        int start = delta < 0 ? 60 + delta + 1 : delta;
        return data->minute[start] > -1LL ? data->minute[stop] - data->minute[start] : 0LL;
}


static long long _deltaHour(T S, NetStatisticsData_T *data, int count) {
        assert(count > 0);
        assert(count <= 24);
        int stop = Time_hour(S->timestamp.now / 1000.);
        int delta = stop - count;
        int start = delta < 0 ? 24 + delta + 1 : delta;
        return data->hour[start] > -1LL ? data->hour[stop] - data->hour[start] : 0LL;
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
        return NULL;
}


static const char *_returnInterface(const char *interface) {
        return interface;
}


static void _updateHistory(T S) {
        time_t now = S->timestamp.now / 1000.;
        int minute = Time_minutes(now);
        int hour =  Time_hour(now);
        if (S->timestamp.last == 0LL) {
                // Initialize the history on first update, so we can start accounting for total data immediately. Any delta will show difference between the very first value and then given point in time, until regular update cycle
                _resetData(&(S->ibytes), S->ibytes.now);
                _resetData(&(S->ipackets), S->ipackets.now);
                _resetData(&(S->ierrors), S->ierrors.now);
                _resetData(&(S->obytes), S->obytes.now);
                _resetData(&(S->opackets), S->opackets.now);
                _resetData(&(S->oerrors), S->oerrors.now);
        } else {
                // Update relative values only
                S->ibytes.minute[minute] = S->ibytes.hour[hour] = S->ibytes.now;
                S->ipackets.minute[minute] = S->ipackets.hour[hour] = S->ipackets.now;
                S->ierrors.minute[minute] = S->ierrors.hour[hour] = S->ierrors.now;
                S->obytes.minute[minute] = S->obytes.hour[hour] = S->obytes.now;
                S->opackets.minute[minute] = S->opackets.hour[hour] = S->opackets.now;
                S->oerrors.minute[minute] = S->oerrors.hour[hour] = S->oerrors.now;
        }
}


static void _updateCache() {
#ifdef HAVE_IFADDRS_H
        time_t now = Time_now();
        if (_stats.timestamp != now) {
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
#endif
}


/* ---------------------------------------------------------------- Public */


T NetStatistics_createForAddress(const char *address) {
        assert(address);
        T S;
        NEW(S);
        _reset(S);
        S->object = Str_dup(address);
        S->resolve = _findInterfaceForAddress;
        return S;
}


T NetStatistics_createForInterface(const char *interface) {
        assert(interface);
        T S;
        NEW(S);
        _reset(S);
        S->object = Str_dup(interface);
        S->resolve = _returnInterface;
        return S;
}


void NetStatistics_free(T *S) {
        FREE((*S)->object);
        FREE(*S);
}


void NetStatistics_reset(T S) {
        _reset(S);
}


int NetStatistics_isGetByAddressSupported() {
#ifdef HAVE_IFADDRS_H
        return true;
#else
        return false;
#endif
}


#if defined DARWIN || defined FREEBSD || defined OPENBSD || defined NETBSD


void NetStatistics_update(T S) {
        _updateCache();
        const char *interface = S->resolve(S->object);
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
                        _updateHistory(S);
                        return;
                }
        }
        THROW(AssertException, "Cannot udate network statistics -- interface %s not found", interface);
}


#elif defined LINUX


void NetStatistics_update(T S) {
        _updateCache();
        const char *interface = S->resolve(S->object);
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
                                _updateHistory(S);
                                return;
                        }
                }
                fclose(f);
        } else {
                THROW(AssertException, "Cannot read /proc/net/dev -- %s", System_getError(errno));
        }
        THROW(AssertException, "Cannot udate network statistics -- interface %s not found", interface);
}


#elif defined SOLARIS


void NetStatistics_update(T S) {
        _updateCache();
        const char *interface = S->resolve(S->object);
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
                                _updateHistory(S);
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
                                _updateHistory(S);
                                return;
                        } else {
                                kstat_close(kc);
                                THROW(AssertException, "Cannot get kstat data -- %s", System_getError(errno));
                        }
                }
        }
        THROW(AssertException, "Cannot udate network statistics -- interface %s not found", interface);
}


#else


void NetStatistics_update(T S) {
        THROW(AssertException, "Cannot udate network statistics -- platform not supported");
}


#endif


long long NetStatistics_getBytesInPerSecond(T S) {
        assert(S);
        return _deltaSecond(S, &(S->ibytes));
}


long long NetStatistics_getBytesInPerMinute(T S, int count) {
        assert(S);
        return _deltaMinute(S, &(S->ibytes), count);
}


long long NetStatistics_getBytesInPerHour(T S, int count) {
        assert(S);
        return _deltaHour(S, &(S->ibytes), count);
}

long long NetStatistics_getPacketsInPerSecond(T S) {
        assert(S);
        return _deltaSecond(S, &(S->ipackets));
}


long long NetStatistics_getPacketsInPerMinute(T S, int count) {
        assert(S);
        return _deltaMinute(S, &(S->ipackets), count);
}


long long NetStatistics_getPacketsInPerHour(T S, int count) {
        assert(S);
        return _deltaHour(S, &(S->ipackets), count);
}

long long NetStatistics_getErrorsInPerSecond(T S) {
        assert(S);
        return _deltaSecond(S, &(S->ierrors));
}


long long NetStatistics_getErrorsInPerMinute(T S, int count) {
        assert(S);
        return _deltaMinute(S, &(S->ierrors), count);
}


long long NetStatistics_getErrorsInPerHour(T S, int count) {
        assert(S);
        return _deltaHour(S, &(S->ierrors), count);
}


long long NetStatistics_getBytesOutPerSecond(T S) {
        assert(S);
        return _deltaSecond(S, &(S->obytes));
}


long long NetStatistics_getBytesOutPerMinute(T S, int count) {
        assert(S);
        return _deltaMinute(S, &(S->obytes), count);
}


long long NetStatistics_getBytesOutPerHour(T S, int count) {
        assert(S);
        return _deltaHour(S, &(S->obytes), count);
}


long long NetStatistics_getPacketsOutPerSecond(T S) {
        assert(S);
        return _deltaSecond(S, &(S->opackets));
}


long long NetStatistics_getPacketsOutPerMinute(T S, int count) {
        assert(S);
        return _deltaMinute(S, &(S->opackets), count);
}


long long NetStatistics_getPacketsOutPerHour(T S, int count) {
        assert(S);
        return _deltaHour(S, &(S->opackets), count);
}


long long NetStatistics_getErrorsOutPerSecond(T S) {
        assert(S);
        return _deltaSecond(S, &(S->oerrors));
}


long long NetStatistics_getErrorsOutPerMinute(T S, int count) {
        assert(S);
        return _deltaMinute(S, &(S->oerrors), count);
}


long long NetStatistics_getErrorsOutPerHour(T S, int count) {
        assert(S);
        return _deltaHour(S, &(S->oerrors), count);
}


int NetStatistics_getState(T S) {
        assert(S);
        return S->state;
}


long long NetStatistics_getSpeed(T S) {
        assert(S);
        return S->speed;
}


int NetStatistics_getDuplex(T S) {
        assert(S);
        return S->duplex;
}

