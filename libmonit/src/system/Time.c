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
#include <string.h>
#include <sys/time.h>
#include <time.h>
#include <ctype.h>
#include <stdarg.h>
#include <unistd.h>

#include "Str.h"
#include "system/System.h"
#include "system/Time.h"


/**
 * Implementation of the Time interface
 *
 * @author http://www.tildeslash.com/
 * @see http://www.mmonit.com/
 * @file
 */


/* ----------------------------------------------------------- Definitions */


#define TEST_RANGE(v, f, t) \
        do { \
                if (v < f || v > t) \
                        THROW(AssertException, "#v is outside the range (%d..%d)", f, t); \
        } while (0)
static const char days[] = "SunMonTueWedThuFriSat";
static const char months[] = "JanFebMarAprMayJunJulAugSepOctNovDec";


/* --------------------------------------------------------------- Private */



/* ----------------------------------------------------------------- Class */


time_t Time_build(int year, int month, int day, int hour, int min, int sec) {
        struct tm tm = {.tm_isdst = -1};
        TEST_RANGE(year, 1970, 2037);
        TEST_RANGE(month, 1, 12);
        TEST_RANGE(day, 1, 31);
        TEST_RANGE(hour, 0, 23);
        TEST_RANGE(min, 0, 59);
        TEST_RANGE(sec, 0, 61);
        tm.tm_year = (year - 1900);
        tm.tm_mon  = (month - 1);
        tm.tm_mday = day;
        tm.tm_hour = hour;
        tm.tm_min  = min;
        tm.tm_sec  = sec;
        return mktime(&tm);
}


time_t Time_now(void) {
	struct timeval t;
	if (gettimeofday(&t, NULL) != 0)
                THROW(AssertException, "%s", System_getLastError());
	return t.tv_sec;
}


long long int Time_milli(void) {
	struct timeval t;
	if (gettimeofday(&t, NULL) != 0)
                THROW(AssertException, "%s", System_getLastError());
	return (long long int)t.tv_sec * 1000  +  (long long int)t.tv_usec / 1000;
}


int Time_seconds(time_t time) {
        struct tm tm;
        localtime_r(&time, &tm);
        return tm.tm_sec;
}


int Time_minutes(time_t time) {
        struct tm tm;
        localtime_r(&time, &tm);
        return tm.tm_min;
}


int Time_hour(time_t time) {
        struct tm tm;
        localtime_r(&time, &tm);
        return tm.tm_hour;
}


int Time_weekday(time_t time) {
        struct tm tm;
        localtime_r(&time, &tm);
        return tm.tm_wday;
}


int Time_day(time_t time) {
        struct tm tm;
        localtime_r(&time, &tm);
        return tm.tm_mday;
}


int Time_month(time_t time) {
        struct tm tm;
        localtime_r(&time, &tm);
        return (tm.tm_mon + 1);
}


int Time_year(time_t time) {
        struct tm tm;
        localtime_r(&time, &tm);
        return (tm.tm_year + 1900);
}


char *Time_string(time_t time, char *result) {
#define i2a(i) (x[0]=(i/10)+'0', x[1]=(i%10)+'0')
        if (result) {
                char x[2];
                struct tm ts;
                localtime_r((const time_t *)&time, &ts);
                memcpy(result, "aaa, xx aaa xxxx xx:xx:xx\0", 26);
                /*              0    5  8   1214 17 20 2326 */
                memcpy(result, days + 3 * ts.tm_wday, 3);
                i2a(ts.tm_mday);
                result[5] = x[0];
                result[6] = x[1];
                memcpy(result + 8, months + 3 * ts.tm_mon, 3);
                i2a((ts.tm_year + 1900) / 100);
                result[12] = x[0];
                result[13] = x[1];
                i2a((ts.tm_year + 1900) % 100);
                result[14] = x[0];
                result[15] = x[1];
                i2a(ts.tm_hour);
                result[17] = x[0];
                result[18] = x[1];
                i2a(ts.tm_min);
                result[20] = x[0];
                result[21] = x[1];
                i2a(ts.tm_sec);
                result[23] = x[0];
                result[24] = x[1];
        }
	return result;     
}


char *Time_gmtstring(time_t time, char *result) {
        if (result) {
                char x[2];
                struct tm ts;
                /* This implementation needs to be fast and is around 50%
                 faster than strftime */
                gmtime_r(&time, &ts);
                memcpy(result, "aaa, xx aaa xxxx xx:xx:xx GMT\0", 30);
                /*              0    5  8   1214 17 20 23    29 */
                memcpy(result, days + 3 * ts.tm_wday, 3);
                i2a(ts.tm_mday);
                result[5] = x[0];
                result[6] = x[1];
                memcpy(result + 8, months + 3 * ts.tm_mon, 3);
                i2a((ts.tm_year + 1900) / 100);
                result[12] = x[0];
                result[13] = x[1];
                i2a((ts.tm_year + 1900) % 100);
                result[14] = x[0];
                result[15] = x[1];
                i2a(ts.tm_hour);
                result[17] = x[0];
                result[18] = x[1];
                i2a(ts.tm_min);
                result[20] = x[0];
                result[21] = x[1];
                i2a(ts.tm_sec);
                result[23] = x[0];
                result[24] = x[1];
        }
	return result;     
}


char *Time_uptime(time_t sec, char *result) {
        // Write max 24 bytes to result
        if (result) {
                int n = 0;
                time_t r = 0;
                result[0] = 0;
                if (sec > 0) {
                        if ((r = sec/86400) > 0) {
                                n = snprintf(result, 24, "%ldd", r);
                                sec -= r * 86400;
                        }
                        if((r = sec/3600) > 0) {
                                n += snprintf(result + n, (24 - n), "%s%ldh", n ? ", " : "", r);
                                sec -= r * 3600;
                        }
                        r = sec/60;
                        snprintf(result + n, (24 - n), "%s%ldm", n ? ", " : "", r);
                }
        }
        return result;
}


/* 
 cron string is on format "minute hour day month wday"
 where fields may have a numeric type, an asterix, a 
 sequence of numbers or a range 
 */
int Time_incron(const char *cron, time_t time) {
        assert(cron);
#define YYCTYPE char
#define YYCURSOR cron
#define YYLIMIT  end
#define YYMARKER m
#define YYTOKEN  t
#define YYFILL(n)   ((void)0)
	const char *m;
	const char *t;
	const char *end = cron + strlen(cron);
        int n = 0;
        int found = 0;
        int fields[] = {Time_minutes(time), Time_hour(time), Time_day(time), Time_month(time), Time_weekday(time)};
parse:
        if (YYCURSOR >= YYLIMIT)
                return found == 5;
        YYTOKEN = YYCURSOR;
	
        {
                YYCTYPE yych;
                static const unsigned char yybm[] = {
                        0,   0,   0,   0,   0,   0,   0,   0, 
                        0,   0,   0,   0,   0,   0,   0,   0, 
                        0,   0,   0,   0,   0,   0,   0,   0, 
                        0,   0,   0,   0,   0,   0,   0,   0, 
                        0,   0,   0,   0,   0,   0,   0,   0, 
                        0,   0,   0,   0,   0,   0,   0,   0, 
                        128, 128, 128, 128, 128, 128, 128, 128, 
                        128, 128,   0,   0,   0,   0,   0,   0, 
                        0,   0,   0,   0,   0,   0,   0,   0, 
                        0,   0,   0,   0,   0,   0,   0,   0, 
                        0,   0,   0,   0,   0,   0,   0,   0, 
                        0,   0,   0,   0,   0,   0,   0,   0, 
                        0,   0,   0,   0,   0,   0,   0,   0, 
                        0,   0,   0,   0,   0,   0,   0,   0, 
                        0,   0,   0,   0,   0,   0,   0,   0, 
                        0,   0,   0,   0,   0,   0,   0,   0, 
                        0,   0,   0,   0,   0,   0,   0,   0, 
                        0,   0,   0,   0,   0,   0,   0,   0, 
                        0,   0,   0,   0,   0,   0,   0,   0, 
                        0,   0,   0,   0,   0,   0,   0,   0, 
                        0,   0,   0,   0,   0,   0,   0,   0, 
                        0,   0,   0,   0,   0,   0,   0,   0, 
                        0,   0,   0,   0,   0,   0,   0,   0, 
                        0,   0,   0,   0,   0,   0,   0,   0, 
                        0,   0,   0,   0,   0,   0,   0,   0, 
                        0,   0,   0,   0,   0,   0,   0,   0, 
                        0,   0,   0,   0,   0,   0,   0,   0, 
                        0,   0,   0,   0,   0,   0,   0,   0, 
                        0,   0,   0,   0,   0,   0,   0,   0, 
                        0,   0,   0,   0,   0,   0,   0,   0, 
                        0,   0,   0,   0,   0,   0,   0,   0, 
                        0,   0,   0,   0,   0,   0,   0,   0, 
                };
                if ((YYLIMIT - YYCURSOR) < 3) YYFILL(3);
                yych = *YYCURSOR;
                if (yych <= ' ') {
                        if (yych <= '\f') {
                                if (yych <= 0x08) goto yy70;
                                if (yych >= '\v') goto yy70;
                        } else {
                                if (yych <= '\r') goto yy62;
                                if (yych <= 0x1F) goto yy70;
                        }
                } else {
                        if (yych <= '+') {
                                if (yych == '*') goto yy64;
                                goto yy70;
                        } else {
                                if (yych <= ',') goto yy66;
                                if (yych <= '/') goto yy70;
                                if (yych <= '9') goto yy68;
                                goto yy70;
                        }
                }
        yy62:
                ++YYCURSOR;
                {
                        goto parse;
                }
        yy64:
                ++YYCURSOR;
                {
                        n++;
                        found++;
                        goto parse;
                }
        yy66:
                ++YYCURSOR;
                {
                        n--; // backtrack on field advance
                        assert(n < 5 && n >= 0);
                        goto parse;
                }
        yy68:
                yych = *(YYMARKER = ++YYCURSOR);
                goto yy73;
        yy69:
                {
                        int v = Str_parseInt(YYTOKEN);
                        if (fields[n] == v)
                                found++;
                        n++;
                        goto parse;
                }
        yy70:
                ++YYCURSOR;
                {
                        return false;
                }
        yy72:
                YYMARKER = ++YYCURSOR;
                if ((YYLIMIT - YYCURSOR) < 2) YYFILL(2);
                yych = *YYCURSOR;
        yy73:
                if (yybm[0+yych] & 128) {
                        goto yy72;
                }
                if (yych != '-') goto yy69;
                yych = *++YYCURSOR;
                if (yych <= '/') goto yy75;
                if (yych <= '9') goto yy76;
        yy75:
                YYCURSOR = YYMARKER;
                goto yy69;
        yy76:
                ++YYCURSOR;
                if (YYLIMIT <= YYCURSOR) YYFILL(1);
                yych = *YYCURSOR;
                if (yych <= '/') goto yy78;
                if (yych <= '9') goto yy76;
        yy78:
                {
                        int from = Str_parseInt(YYTOKEN);
                        int to = Str_parseInt(strchr(YYTOKEN, '-') + 1);
                        if ((fields[n] <= to) && (fields[n] >= from))
                                found++;
                        n++;
                        goto parse;
                }
        }
	return found == 5;
}


void Time_usleep(long u) {
#ifdef NETBSD
        // usleep is broken on NetBSD (at least in version 5.1)
        struct timespec t = {u / 1000000, (u % 1000000) * 1000};
        nanosleep(&t, NULL);
#else
        usleep((useconds_t)u);
#endif
}

