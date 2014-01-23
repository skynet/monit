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


#define CTIME       "%a %b %d %H:%M:%S %z %Y"
#define RFC822      "%a, %d %b %Y %H:%M:%S %z"
#define RFC1123     "%a, %d %b %Y %H:%M:%S GMT"

#define TEST_RANGE(v, f, t) \
        do { \
                if (v < f || v > t) \
                        THROW(AssertException, "#v is outside the range (%d..%d)", f, t); \
        } while (0)

static const char days[] = "SunMonTueWedThuFriSat";
static const char months[] = "JanFebMarAprMayJunJulAugSepOctNovDec";
#define MONTHS_LEN 36


/* --------------------------------------------------------------- Private */


static time_t parseDate(const char *date) {
#define YYCTYPE     char
#define YYCURSOR    date
#define YYLIMIT     end
#define YYMARKER    m
#define YYFILL(n)   ((void)0)  
	const char *t;
	const char *m;
	struct tm time = {0};
	const char *end = date + strlen(date);
	time.tm_mon   = -1;
	time.tm_year  = -1;
	time.tm_mday  = -1;
	time.tm_isdst = -1;
	for (;;) {
		if (YYCURSOR >= YYLIMIT) {
			if (time.tm_mon== -1 || time.tm_year== -1 || time.tm_mday== -1)
				return -1;
			return mktime(&time);
		}
		t = YYCURSOR;
                {
                        YYCTYPE yych;
                        unsigned int yyaccept = 0;

                        if ((YYLIMIT - YYCURSOR) < 8) YYFILL(8);
                        yych = *YYCURSOR;
                        switch (yych) {
                                case '0':
                                case '1':
                                case '2':
                                case '3':
                                case '4':
                                case '5':
                                case '6':
                                case '7':
                                case '8':
                                case '9':	goto yy11;
                                case 'A':
                                case 'a':	goto yy6;
                                case 'D':
                                case 'd':	goto yy10;
                                case 'F':
                                case 'f':	goto yy4;
                                case 'J':
                                case 'j':	goto yy2;
                                case 'M':
                                case 'm':	goto yy5;
                                case 'N':
                                case 'n':	goto yy9;
                                case 'O':
                                case 'o':	goto yy8;
                                case 'S':
                                case 's':	goto yy7;
                                default:	goto yy12;
                        }
                yy2:
                        yyaccept = 0;
                        yych = *(YYMARKER = ++YYCURSOR);
                        if (yych <= 'U') {
                                if (yych == 'A') goto yy53;
                                if (yych >= 'U') goto yy52;
                        } else {
                                if (yych <= 'a') {
                                        if (yych >= 'a') goto yy53;
                                } else {
                                        if (yych == 'u') goto yy52;
                                }
                        }
                yy3:
                        {
                                continue;
                        }
                yy4:
                        yyaccept = 0;
                        yych = *(YYMARKER = ++YYCURSOR);
                        if (yych == 'E') goto yy49;
                        if (yych == 'e') goto yy49;
                        goto yy3;
                yy5:
                        yyaccept = 0;
                        yych = *(YYMARKER = ++YYCURSOR);
                        if (yych == 'A') goto yy44;
                        if (yych == 'a') goto yy44;
                        goto yy3;
                yy6:
                        yyaccept = 0;
                        yych = *(YYMARKER = ++YYCURSOR);
                        if (yych <= 'U') {
                                if (yych == 'P') goto yy39;
                                if (yych <= 'T') goto yy3;
                                goto yy38;
                        } else {
                                if (yych <= 'p') {
                                        if (yych <= 'o') goto yy3;
                                        goto yy39;
                                } else {
                                        if (yych == 'u') goto yy38;
                                        goto yy3;
                                }
                        }
                yy7:
                        yyaccept = 0;
                        yych = *(YYMARKER = ++YYCURSOR);
                        if (yych == 'E') goto yy35;
                        if (yych == 'e') goto yy35;
                        goto yy3;
                yy8:
                        yyaccept = 0;
                        yych = *(YYMARKER = ++YYCURSOR);
                        if (yych == 'C') goto yy32;
                        if (yych == 'c') goto yy32;
                        goto yy3;
                yy9:
                        yyaccept = 0;
                        yych = *(YYMARKER = ++YYCURSOR);
                        if (yych == 'O') goto yy29;
                        if (yych == 'o') goto yy29;
                        goto yy3;
                yy10:
                        yyaccept = 0;
                        yych = *(YYMARKER = ++YYCURSOR);
                        if (yych == 'E') goto yy26;
                        if (yych == 'e') goto yy26;
                        goto yy3;
                yy11:
                        yych = *++YYCURSOR;
                        if (yych <= '/') goto yy3;
                        if (yych <= '9') goto yy13;
                        goto yy3;
                yy12:
                        yych = *++YYCURSOR;
                        goto yy3;
                yy13:
                        yyaccept = 1;
                        yych = *(YYMARKER = ++YYCURSOR);
                        if (yych <= '/') goto yy14;
                        if (yych <= '9') goto yy15;
                        if (yych <= ':') goto yy17;
                yy14:
                        {
                                if (sscanf(t, "%d", &time.tm_mday) != 1)
                                        time.tm_mday = -1;
                                continue;
                        }
                yy15:
                        yych = *++YYCURSOR;
                        if (yych <= '/') goto yy16;
                        if (yych <= '9') goto yy24;
                yy16:
                        YYCURSOR = YYMARKER;
                        if (yyaccept <= 0) {
                                goto yy3;
                        } else {
                                goto yy14;
                        }
                yy17:
                        yych = *++YYCURSOR;
                        if (yych <= '/') goto yy16;
                        if (yych >= ':') goto yy16;
                        yych = *++YYCURSOR;
                        if (yych <= '/') goto yy16;
                        if (yych >= ':') goto yy16;
                        yych = *++YYCURSOR;
                        if (yych != ':') goto yy16;
                        yych = *++YYCURSOR;
                        if (yych <= '/') goto yy16;
                        if (yych >= ':') goto yy16;
                        yych = *++YYCURSOR;
                        if (yych <= '/') goto yy16;
                        if (yych >= ':') goto yy16;
                        ++YYCURSOR;
                        {
                                sscanf(t, "%d:%d:%d", &time.tm_hour, &time.tm_min, &time.tm_sec);
                                continue;
                        }
                yy24:
                        ++YYCURSOR;
                        {
                                if (sscanf(t, "%d", &time.tm_year) == 1)
                                        time.tm_year -=1900;
                                else
                                        time.tm_year = -1;
                                continue;
                        }
                yy26:
                        yych = *++YYCURSOR;
                        if (yych == 'C') goto yy27;
                        if (yych != 'c') goto yy16;
                yy27:
                        ++YYCURSOR;
                        {
                                time.tm_mon = 11;
                                continue;
                        }
                yy29:
                        yych = *++YYCURSOR;
                        if (yych == 'V') goto yy30;
                        if (yych != 'v') goto yy16;
                yy30:
                        ++YYCURSOR;
                        {
                                time.tm_mon = 10;
                                continue;
                        }
                yy32:
                        yych = *++YYCURSOR;
                        if (yych == 'T') goto yy33;
                        if (yych != 't') goto yy16;
                yy33:
                        ++YYCURSOR;
                        {
                                time.tm_mon = 9;
                                continue;
                        }
                yy35:
                        yych = *++YYCURSOR;
                        if (yych == 'P') goto yy36;
                        if (yych != 'p') goto yy16;
                yy36:
                        ++YYCURSOR;
                        {
                                time.tm_mon = 8;
                                continue;
                        }
                yy38:
                        yych = *++YYCURSOR;
                        if (yych == 'G') goto yy42;
                        if (yych == 'g') goto yy42;
                        goto yy16;
                yy39:
                        yych = *++YYCURSOR;
                        if (yych == 'R') goto yy40;
                        if (yych != 'r') goto yy16;
                yy40:
                        ++YYCURSOR;
                        {
                                time.tm_mon = 3;
                                continue;
                        }
                yy42:
                        ++YYCURSOR;
                        {
                                time.tm_mon = 7;
                                continue;
                        }
                yy44:
                        yych = *++YYCURSOR;
                        if (yych <= 'Y') {
                                if (yych == 'R') goto yy45;
                                if (yych <= 'X') goto yy16;
                                goto yy47;
                        } else {
                                if (yych <= 'r') {
                                        if (yych <= 'q') goto yy16;
                                } else {
                                        if (yych == 'y') goto yy47;
                                        goto yy16;
                                }
                        }
                yy45:
                        ++YYCURSOR;
                        {
                                time.tm_mon = 2;
                                continue;
                        }
                yy47:
                        ++YYCURSOR;
                        {
                                time.tm_mon = 4;
                                continue;
                        }
                yy49:
                        yych = *++YYCURSOR;
                        if (yych == 'B') goto yy50;
                        if (yych != 'b') goto yy16;
                yy50:
                        ++YYCURSOR;
                        {
                                time.tm_mon = 1;
                                continue;
                        }
                yy52:
                        yych = *++YYCURSOR;
                        if (yych <= 'N') {
                                if (yych == 'L') goto yy58;
                                if (yych <= 'M') goto yy16;
                                goto yy56;
                        } else {
                                if (yych <= 'l') {
                                        if (yych <= 'k') goto yy16;
                                        goto yy58;
                                } else {
                                        if (yych == 'n') goto yy56;
                                        goto yy16;
                                }
                        }
                yy53:
                        yych = *++YYCURSOR;
                        if (yych == 'N') goto yy54;
                        if (yych != 'n') goto yy16;
                yy54:
                        ++YYCURSOR;
                        {
                                time.tm_mon = 0;
                                continue;
                        }
                yy56:
                        ++YYCURSOR;
                        {
                                time.tm_mon = 5;
                                continue;
                        }
                yy58:
                        ++YYCURSOR;
                        {
                                time.tm_mon = 6;
                                continue;
                        }
                }
	}
	return -1;
}


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


time_t Time_parse(const char *date) {
	if (STR_DEF(date))
		return parseDate(date);
	return -1;
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


time_t Time_gmt(time_t localtime) {
	struct tm r;
	gmtime_r(&localtime, &r);
	return mktime(&r);
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


time_t Time_add(time_t time, int years, int months, int days) {
        struct tm tm;
        localtime_r(&time, &tm);
        tm.tm_year += years;
        tm.tm_mon += months;
        tm.tm_mday += days;
        tm.tm_isdst = -1;
        return mktime(&tm);
}


int Time_daysBetween(time_t to, time_t from) {
        double t = difftime(to, from);
        if (t < 0) t *= -1;
	return ((t + (86400L/2))/86400L);
}


char *Time_string(time_t time, char *result) {
#define i2a(i) (x[0]=(i/10)+'0', x[1]=(i%10)+'0')
        if (result) {
                char x[2];
                struct tm ts;
                /* This implementation needs to be fast and is around 50%
                   faster than strftime */
                localtime_r((const time_t *)&time, &ts);
                memcpy(result, "aaa, xx aaa xxxx xx:xx:xx\0", 26);
                /*              0    5  8   1214 17 20 2326 */
                memcpy(result, days+3*ts.tm_wday, 3);
                i2a(ts.tm_mday);
                result[5] = x[0];
                result[6] = x[1];
                memcpy(result + 8, months+3*ts.tm_mon, 3);
                i2a((ts.tm_year+1900)/100);
                result[12] = x[0];
                result[13] = x[1];
                i2a((ts.tm_year+1900)%100);
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
                memcpy(result, days+3*ts.tm_wday, 3);
                i2a(ts.tm_mday);
                result[5] = x[0];
                result[6] = x[1];
                memcpy(result + 8, months+3*ts.tm_mon, 3);
                i2a((ts.tm_year+1900)/100);
                result[12] = x[0];
                result[13] = x[1];
                i2a((ts.tm_year+1900)%100);
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


char *Time_fmt(char *result, int size, const char *format, time_t time) {
        struct tm tm;
        assert(result);
        assert(format);
        localtime_r((const time_t *)&time, &tm);
        if (strftime(result, size, format, &tm) == 0) 
                *result = 0;
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
#undef YYCURSOR 
#undef YYLIMIT  
#undef YYMARKER 
#define YYCURSOR cron
#define YYLIMIT  end
#define YYMARKER m
#define YYTOKEN  t
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

