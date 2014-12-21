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


#define T NetStatistics_T
typedef struct T *T;


/**
 * Test if network statistics by IP address is supported.
 * @return true if supported, false if not
 */
int NetStatistics_isGetByAddressSupported();


/**
 * Get network statistics object for IP address. The object must be destroyed
 * with NetStatistics_free() if no longer necessary.
 * @param address IP address (e.g. "127.0.0.1" or "::1")
 * @return Network statistics object. Use NetStatistics_update() to get the data.
 */
T NetStatistics_createForAddress(const char *address);


/**
 * Get network statistics object for interface name. The object must be destroyed
 * with NetStatistics_free() if no longer necessary.
 * @param interface Network interface name (e.g. "eth0")
 * @return Network statistics object. Use NetStatistics_update() to get the data.
 */
T NetStatistics_createForInterface(const char *interface);


/**
 * Destroy a network statistics object and release allocated resources. 
 * @param S A network statistics object reference
 */
void NetStatistics_free(T *S);


/**
 * Reset a network statistics object data.
 * @param S A network statistics object
 */
void NetStatistics_reset(T S);


/**
 * Update network statistics for object.
 * @param S A network statistics object
 * @exception AssertException If statistics cannot be fetched or the address/interface
 * is invalid.
 */
void NetStatistics_update(T S);


/**
 * Get incoming bytes per second statistics.
 * @param S A network statistics object
 * @return Incoming bytes per second statistics.
 */
long long NetStatistics_getBytesInPerSecond(T S);


/**
 * Get incoming bytes per minute statistics.
 * @param S A network statistics object
 * @param count Number of minutes, the returned statistics will be for range given by 'now - count' (count max = 60m)
 * @return Incoming bytes per minute statistics.
 */
long long NetStatistics_getBytesInPerMinute(T S, int count);


/**
 * Get total incoming bytes statistics.
 * @param S A network statistics object
 * @return Incoming bytes total.
 */
long long NetStatistics_getBytesInTotal(T S);


/**
 * Get incoming link saturation.
 * @param S A network statistics object
 * @return Incoming link saturation percent or -1 the link has unknown speed.
 */
double NetStatistics_getSaturationInPerSecond(T S);


/**
 * Get incoming bytes per hour statistics.
 * @param S A network statistics object
 * @param count Number of hours, the returned statistics will be for range given by 'now - count' (count max = 24h)
 * @return Incoming bytes per hour statistics.
 */
long long NetStatistics_getBytesInPerHour(T S, int count);


/**
 * Get incoming packets per second statistics.
 * @param S A network statistics object
 * @return Incoming packets per second statistics.
 */
long long NetStatistics_getPacketsInPerSecond(T S);


/**
 * Get incoming packets per minute statistics.
 * @param S A network statistics object
 * @param count Number of minutes, the returned statistics will be for range given by 'now - count' (count max = 60m)
 * @return Incoming packets per minute statistics.
 */
long long NetStatistics_getPacketsInPerMinute(T S, int count);


/**
 * Get incoming packets per hour statistics.
 * @param S A network statistics object
 * @param count Number of hours, the returned statistics will be for range given by 'now - count' (count max = 24h)
 * @return Incoming packets per hour statistics.
 */
long long NetStatistics_getPacketsInPerHour(T S, int count);


/**
 * Get total incoming packets statistics.
 * @param S A network statistics object
 * @return Incoming packets total.
 */
long long NetStatistics_getPacketsInTotal(T S);


/**
 * Get incoming errors per second statistics.
 * @param S A network statistics object
 * @return Incoming errors per second statistics.
 */
long long NetStatistics_getErrorsInPerSecond(T S);


/**
 * Get incoming errors per minute statistics.
 * @param S A network statistics object
 * @param count Number of minutes, the returned statistics will be for range given by 'now - count' (count max = 60m)
 * @return Incoming errors per minute statistics.
 */
long long NetStatistics_getErrorsInPerMinute(T S, int count);


/**
 * Get incoming errors per hour statistics.
 * @param S A network statistics object
 * @param count Number of hours, the returned statistics will be for range given by 'now - count' (count max = 24h)
 * @return Incoming errors per hour statistics.
 */
long long NetStatistics_getErrorsInPerHour(T S, int count);


/**
 * Get total incoming errors statistics.
 * @param S A network statistics object
 * @return Incoming errors total.
 */
long long NetStatistics_getErrorsInTotal(T S);


/**
 * Get outgoing bytes per second statistics.
 * @param S A network statistics object
 * @return Outgoing bytes per second statistics.
 */
long long NetStatistics_getBytesOutPerSecond(T S);


/**
 * Get outgoing bytes per minute statistics.
 * @param S A network statistics object
 * @param count Number of minutes, the returned statistics will be for range given by 'now - count' (count max = 60m)
 * @return Outgoing bytes per minute statistics.
 */
long long NetStatistics_getBytesOutPerMinute(T S, int count);


/**
 * Get outgoing bytes per hour statistics.
 * @param S A network statistics object
 * @param count Number of hours, the returned statistics will be for range given by 'now - count' (count max = 24h)
 * @return Outgoing bytes per hour statistics.
 */
long long NetStatistics_getBytesOutPerHour(T S, int count);


/**
 * Get total outgoing bytes statistics.
 * @param S A network statistics object
 * @return Outgoing bytes total.
 */
long long NetStatistics_getBytesOutTotal(T S);


/**
 * Get outgoing link saturation.
 * @param S A network statistics object
 * @return Outgoing link saturation percent or -1 the link has unknown speed.
 */
double NetStatistics_getSaturationOutPerSecond(T S);


/**
 * Get outgoing packets per second statistics.
 * @param S A network statistics object
 * @return Outgoing packets per second statistics.
 */
long long NetStatistics_getPacketsOutPerSecond(T S);


/**
 * Get outgoing packets per minute statistics.
 * @param S A network statistics object
 * @param count Number of minutes, the returned statistics will be for range given by 'now - count' (count max = 60m)
 * @return Outgoing packets per minute statistics.
 */
long long NetStatistics_getPacketsOutPerMinute(T S, int count);


/**
 * Get outgoing packets per hour statistics.
 * @param S A network statistics object
 * @param count Number of hours, the returned statistics will be for range given by 'now - count' (count max = 24h)
 * @return Outgoing packets per hour statistics.
 */
long long NetStatistics_getPacketsOutPerHour(T S, int count);


/**
 * Get total outgoing packets statistics.
 * @param S A network statistics object
 * @return Outgoing packets total.
 */
long long NetStatistics_getPacketsOutTotal(T S);


/**
 * Get outgoing errors per second statistics.
 * @param S A network statistics object
 * @return Outgoing errors per second.
 */
long long NetStatistics_getErrorsOutPerSecond(T S);


/**
 * Get outgoing errors per minute statistics.
 * @param S A network statistics object
 * @param count Number of minutes, the returned statistics will be for range given by 'now - count' (count max = 60m)
 * @return Outgoing errors per minute.
 */
long long NetStatistics_getErrorsOutPerMinute(T S, int count);


/**
 * Get outgoing errors per hour statistics.
 * @param S A network statistics object
 * @param count Number of hours, the returned statistics will be for range given by 'now - count' (count max = 24h)
 * @return Outgoing errors per hour.
 */
long long NetStatistics_getErrorsOutPerHour(T S, int count);


/**
 * Get total outgoing errors statistics.
 * @param S A network statistics object
 * @return Outgoing errors total
 */
long long NetStatistics_getErrorsOutTotal(T S);


/**
 * Get interface state.
 * @param S A network statistics object
 * @return Interface state (0 = down, 1 = up)
 */
int NetStatistics_getState(T S);


/**
 * Get interface speed (note: not all interface types support speed)
 * @param S A network statistics object
 * @return Interface speed [bps] (-1 = N/A)
 */
long long NetStatistics_getSpeed(T S);


/**
 * Get interface duplex state (note: not all interface types support duplex)
 * @param S A network statistics object
 * @return Duplex state (-1 = N/A, 0 = half, 1 = full)
 */
int NetStatistics_getDuplex(T S);


#undef T
#endif
