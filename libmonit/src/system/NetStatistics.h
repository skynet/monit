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


#ifndef NETSTATISTICS_INCLUDED
#define NETSTATISTICS_INCLUDED


/**
 * Facade for system specific network statistics.
 *
 * @author http://www.tildeslash.com/
 * @see http://www.mmonit.com/
 * @file
 */


typedef struct NetStatisticsData_T {
        long long last;
        long long now;
} NetStatisticsData_T;


typedef struct NetStatistics_T {
        NetStatisticsData_T timestamp; // Timestamp

        NetStatisticsData_T state;     // State (0 = down, 1 = up)
        NetStatisticsData_T speed;     // Speed [bps]
        NetStatisticsData_T duplex;    // Duplex (0 = half, 1 = full)

        NetStatisticsData_T ipackets;  // Packets received on interface
        NetStatisticsData_T ierrors;   // Input errors on interface
        NetStatisticsData_T ibytes;    // Total number of octets received
        NetStatisticsData_T opackets;  // Packets sent on interface
        NetStatisticsData_T oerrors;   // Output errors on interface
        NetStatisticsData_T obytes;    // Total number of octets sent
} NetStatistics_T;


/**
 * Update network interface statistics.
 * @param address IP address (e.g. "127.0.0.1" or "::1")
 * @return true if succeeded, false if failed (statistics cannot be fetched or the address is invalid)
 */
int NetStatistics_getByAddress(const char *address, NetStatistics_T *stats);


/**
 * Update network interface statistics.
 * @param interface Network interface name (e.g. "eth0")
 * @return true if succeeded, false if failed (statistics cannot be fetched or the interface is invalid)
 */
int NetStatistics_getByInterface(const char *interface, NetStatistics_T *stats);


#endif
