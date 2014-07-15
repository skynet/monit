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


#ifndef TIME_INCLUDED
#define TIME_INCLUDED


/**
 * <b>Time</b> is an abstraction of date and time. Time is stored internally 
 * as the number of seconds and microseconds since the epoch, <i>January 1, 
 * 1970 00:00 UTC</i>. 
 *
 * @author http://www.tildeslash.com/
 * @see http://www.mmonit.com/
 * @file
 */


/** @name class methods */
//@{ 


/**
 * Factory method for building a specific time. Time is normalized and
 * built in the local time zone.
 * @param year the year ~ (1970..2037) for this time
 * @param month the month (January=1..December=12)
 * @param day the day of the month (1..31)
 * @param hour the hour (0..23)
 * @param min the minutes (0..59)
 * @param sec the seconds of the minute (0..61). Yes, seconds can range
 * from 0 to 61. This allows the system to inject leap seconds.
 * @return A time_t representing the specified time
 * @exception AssertException If a parameter is outside the valid range
 */
time_t Time_build(int year, int month, int day, int hour, int min, int sec);


/**
 * Returns the time since the epoch measured in seconds.
 * @return A time_t representing the systems notion of seconds since the 
 * <strong>epoch</strong> (January 1, 1970, 00:00:00 GMT) in Coordinated
 * Universal Time (UTC).
 * @exception AssertException If time could not be obtained
 */
time_t Time_now(void);


/**
 * Returns the time since the epoch measured in milliseconds.
 * @return A 64 bits long representing the systems notion of milliseconds 
 * since the <strong>epoch</strong> (January 1, 1970, 00:00:00 GMT) in 
 * Coordinated Universal Time (UTC).
 * @exception AssertException If time could not be obtained
 */
long long int Time_milli(void);


/**
 * Returns the second of the minute for time.
 * @param time Number of seconds since the EPOCH
 * @return The second of the minute (0..61) 
 */
int Time_seconds(time_t time);


/**
 * Returns the minute of the hour for time.
 * @param time Number of seconds since the EPOCH
 * @return The minute of the hour (0..59)  
 */
int Time_minutes(time_t time);


/**
 * Returns the hour of the day for time.
 * @param time Number of seconds since the EPOCH
 * @return The hour of the day (0..23)  
 */
int Time_hour(time_t time);


/**
 * Returns the day of week expressed as number of days since Sunday.
 * @param time Number of seconds since the EPOCH
 * @return The day of the week (Sunday=0..Saturday=6)
 */
int Time_weekday(time_t time);


/**
 * Returns the day of the month for time.
 * @param time Number of seconds since the EPOCH
 * @return The day of the month (1..31)
 */
int Time_day(time_t time);


/**
 * Returns the month of the year.
 * @param time Number of seconds since the EPOCH
 * @return The month of the year (January=1..December=12)
 */
int Time_month(time_t time);


/**
 * Returns the year of time.
 * @param time Number of seconds since the EPOCH
 * @return The year of time in the range ~ (1970..2037) 
 */
int Time_year(time_t time);


/**
 * Returns a RFC1123 date string for the given UTC time. The returned string
 * is computed in the local timezone. The result buffer must be large enough
 * to hold at least 26 bytes. Example:
 * <pre>
 *  Time_string(1253052085, buf) -> "Wed, 16 Sep 2009 12:01:25"
 * </pre>
 * @param time Number of time seconds since the EPOCH in UTC
 * @param result The buffer to write the date string too
 * @return a pointer to the result buffer
 */
char *Time_string(time_t time, char result[26]);


/**
 * Returns a RFC1123 date string for the given UTC time. The returned string
 * represent the specified time in GMT timezone. The submitted result buffer 
 * must be large enough to hold at least 30 bytes. Example:
 * <pre>
 *  Time_gmtstring(1253052085, buf) -> "Tue, 15 Sep 2009 22:01:25 GMT"
 * </pre>
 * @param time Number of time seconds since the EPOCH in UTC
 * @param result The buffer to write the date string too
 * @return a pointer to the result buffer
 */
char *Time_gmtstring(time_t time, char result[30]);


/**
 * Returns a uptime formated string for the given seconds. That is, convert
 * <code>sec</code> to days, hours and minutes and return a string on the 
 * form, <code>7d, 17h, 34m</code>. The submitted result buffer must be
 * large enough to hold at least 24 bytes. 
 * @param sec Number of seconds to split up into, days, hours, minutes and 
 * seconds.
 * @param result The buffer to write the uptime string too
 * @return a pointer to the result buffer or NULL if <code>result</code>
 * was NULL
 */
char *Time_uptime(time_t sec, char result[24]);


/**
 * Returns 1 if the given time is in the range of the specified cron
 * format string, otherwise 0. The cron string consists of 5 fields separated
 * with white-space. All fields are required:
 *
 * <table>
 * <tr>
 * <th>Name</th>
 * <th>Allowed values</th>
 * <th>Special characters</th>
 * </tr>
 * <tr>
 * <td>Minutes</td>
 * <td>0-59</td>
 * <td>* , -</td>
 * </tr>
 * <tr>
 * <td>Hours</td>
 * <td>0-23</td>
 * <td>* , -</td>
 * </tr>
 * <tr>
 * <td>Day of month</td>
 * <td>1-31</td>
 * <td>* , -</td>
 * </tr>
 * <tr>
 * <td>Month</td>
 * <td>1-12 (1=jan, 12=dec)</td>
 * <td>* , -</td>
 * </tr>
 * <tr>
 * <td>Day of week</td>
 * <td>0-6 (0=sunday, 6=saturday)</td>
 * <td>* , -</td>
 * </tr>
 * </table>
 * <h3>Special characters</h3>
 * <ul>
 * <li>* The asterisk indicates that the expression will match 
 * for all values of the field; e.g., using an asterisk in the 4th 
 * field (month) would indicate every month.
 * <li>- (hyphen) Hyphens are used to define ranges. For example, 
 * 8-9 in the hour field indicate between 8AM and 9AM. Note that
 * range is from time1 until and including time2. That is, from 8AM
 * and until 10AM unless minutes are set. Another example, 1-5 in the
 * weekday field, specify from monday to friday (including friday).
 * <li>, (comma) Comma are used to specify a sequence. For example, 
 * 17,18 in the day field indicate the 17th and 18th day of the month. 
 * A sequence can also include ranges. For example, using
 * 1-5,0 in the weekday field indicate monday to friday and sunday.
 * </ul>
 * <h3>Example</h3>
 * <ul>
 * <li><code>"* 9-10 * * 1-5"</code> Matches 9AM-10AM every weekday 
 * <li><code>"* 0-5,23 * * 0,6"</code> Matches between 0AM-5AM and 11PM each saturday and sunday
 * </ul>
 * @param cron A crontab format string. e.g. "* 8-9 * * *"
 * @param time The time to test if in range of the cron format
 * @return 1 if time is in cron range, otherwise 0.
 */
int Time_incron(const char *cron, time_t time);


/**
 * This method suspend the calling process or Thread for
 * <code>u</code> micro seconds.
 * @param u Micro seconds to sleep
 */
void Time_usleep(long u);

//@}

#undef T
#endif
