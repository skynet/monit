#include "Config.h"

#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>
#include <stdarg.h>
#include <stdlib.h>

#include "Bootstrap.h"
#include "Str.h"
#include "system/Time.h"

/**
 * Time.c unity tests.
 */


int main(void) {

        Bootstrap(); // Need to initialize library

        printf("============> Start Time Tests\n\n");

        printf("=> Test1: Parse String\n");
        {
                long r;
                char d1[STRLEN];
                char s[] = " Thu, 17 Oct 2002 19:10:01; ";
                char y[] = "Year: 2011 Day: 14 Month: June";
                printf("\tParsing a null date string: %ld\n", Time_parse(NULL));
                assert(Time_parse(NULL) == -1);
                r = Time_parse(s);
                printf("\tParsed datestring has value: %ld\n", r);
                assert(r == 1034874601);
                printf("\tWhich transform to the local date: %s\n", Time_fmt(d1, STRLEN, "%a, %d %b %Y %H:%M:%S %z", r));
                r = Time_parse(y);
                printf("\tSecond parsed datestring has value: %ld\n", r);
                assert(r == 1308002400);
                printf("\tWhich transform to the local date: %s\n", Time_fmt(d1, STRLEN, "%a, %d %b %Y %H:%M:%S %z", r));
        }
        printf("=> Test1: OK\n\n");

        printf("=> Test2: check string ouput\n");
        {
                char result[30];
                Time_string(1267441200, result); /* 01 Mar 2010 12:00:00 */
                printf("\tResult: local unix time 1267441200 to localtime:\n\t %s\n", result);
                assert(Str_isEqual(result, "Mon, 01 Mar 2010 12:00:00"));
                Time_gmtstring(1267441200, result); /* 01 Mar 2010 12:00:00 GMT */
                printf("\tResult: local unix time 1267441200 to UTC:\n\t %s\n", result);
                assert(Str_isEqual("Mon, 01 Mar 2010 11:00:00 GMT", result));
        }
        printf("=> Test2: OK\n\n");

        printf("=> Test3: check current time\n");
        {
                struct timeval tv;
                assert(!gettimeofday(&tv, NULL));
                assert(Time_now() == tv.tv_sec);
        }
        printf("=> Test3: OK\n\n");

        printf("=> Test4: convert CEST time_t to GMT\n");
        {
                assert(Time_gmt(1267441200) == 1267437600);
        }
        printf("=> Test4: OK\n\n");

        printf("=> Test5: sleep 1s\n");
        {
                time_t now;
                now = Time_now();
                Time_usleep(1000000);
                assert((now + 1) == Time_now());
        }
        printf("=> Test5: OK\n\n");

        printf("=> Test6: uptime\n");
        {
                time_t days = 668040;
                time_t hours = 63240;
                time_t min = 2040;
                char result[24];
                printf("\tResult: uptime days: %s\n", Time_uptime(days, result));
                assert(Str_isEqual(result, "7d, 17h, 34m"));
                printf("\tResult: uptime hours: %s\n", Time_uptime(hours, result));
                assert(Str_isEqual(result, "17h, 34m"));
                printf("\tResult: uptime min: %s\n", Time_uptime(min, result));
                assert(Str_isEqual(result, "34m"));
                printf("\tResult: uptime 0: %s\n", Time_uptime(0, result));
                assert(Str_isEqual(result, ""));
                assert(Time_uptime(0, NULL) == NULL);
        }
        printf("=> Test6: OK\n\n");

        printf("=> Test7: fmt\n");
        {

                char result[STRLEN];
                Time_fmt(result, STRLEN, "%D %T", 1267441200);
                printf("\tResult: 1267441200 -> %s\n", result);
                assert(Str_isEqual(result, "03/01/10 12:00:00"));
                Time_fmt(result, STRLEN, "%D", 1267441200);
                printf("\tResult: 1267441200 -> %s\n", result);
                assert(Str_startsWith(result, "03/01/10"));
        }
        printf("=> Test7: OK\n\n");

        printf("=> Test8: Time attributes\n");
        {
                char b[STRLEN];
                time_t time = 730251059; // Sun, 21. Feb 1993 00:30:59
                printf("\tResult: %s (winter time)\n", Time_string(time, b));
                assert(Time_seconds(time) == 59);
                assert(Time_minutes(time) == 30);
                assert(Time_hour(time) == 0);
                assert(Time_weekday(time) == 0);
                assert(Time_day(time) == 21);
                assert(Time_month(time) == 2);
                assert(Time_year(time) == 1993);
                time = 1253045894; // Tue, 15 Sep 2009 22:18:14 +0200
                printf("\tResult: %s (DTS/summer time)\n", Time_string(time, b));
                assert(Str_startsWith(b, "Tue, 15 Sep 2009 22:18:14"));
        }
        printf("=> Test8: OK\n\n");

        printf("=> Test9: Time_add\n");
        {
                char b[STRLEN];
                time_t t = 730251059; // Sun, 21. Feb 1993 00:30:59
                time_t time = Time_add(t, -1, -1, 8); // Wed, 29 Jan 1992 00:30:59
                printf("\tResult: %s\n", Time_string(time, b));
                assert(Time_seconds(time) == 59);
                assert(Time_minutes(time) == 30);
                assert(Time_hour(time) == 0);
                assert(Time_day(time) == 29);
                assert(Time_month(time) == 1);
                assert(Time_year(time) == 1992);
        }
        printf("=> Test9: OK\n\n");

        printf("=> Test10: Time_build\n");
        {
                time_t time = Time_build(2001, 1, 29, 12, 0, 0);
                assert(Time_seconds(time) == 0);
                assert(Time_minutes(time) == 0);
                assert(Time_hour(time) == 12);
                assert(Time_day(time) == 29);
                assert(Time_month(time) == 1);
                assert(Time_year(time) == 2001);
                // Verify assert on out of range
                TRY
                {
                        Time_build(1969, 1, 29, 12, 0, 0);
                        printf("Test failed\n");
                        exit(1);
                }
                CATCH (AssertException)
                END_TRY;
                TRY
                {
                        Time_build(1970, 0, 29, 12, 0, 0);
                        printf("Test failed\n");
                        exit(1);
                }
                CATCH (AssertException)
                END_TRY;
        }
        printf("=> Test10: OK\n\n");

        printf("=> Test11: Time_daysBetween\n");
        {
                time_t from = Time_build(2001, 1, 29, 0, 0, 0);
                time_t to = from;
                assert(Time_daysBetween(from, to) == 0);
                assert(Time_daysBetween(from, Time_build(2001, 1, 30, 0, 0, 0)) == 1);
                assert(Time_daysBetween(from, Time_build(2001, 1, 28, 0, 0, 0)) == 1);
                assert(Time_daysBetween(Time_build(2001, 1, 1, 0, 0, 0), Time_build(2002, 1, 1, 0, 0, 0)) == 365);
        }
        printf("=> Test11: OK\n\n");

        printf("=> Test12: Time_incron\n");
        {
                const char *exactmatch = "27 11 5 7 2";
                const char *matchall = "* * * * *";
                const char *invalid1 = "a bc d";
                const char *invalid2 = "* * * *  "; // Too few fields
                const char *invalid3 = "* * * * * * "; // Too many fields
                const char *range1 = "* 10-11 1-5 * 1-5";
                const char *rangeoutside = "1-10 9-10 1-5 * 1-5";
                const char *sequence = "* 10,11 1-3,5,6 * *";
                const char *sequenceoutside = "* 10,11,12 4,5,6 * 0,6";
                time_t time = Time_build(2011, 7, 5, 11, 27, 5);
                assert(Time_incron(exactmatch, time));
                assert(Time_incron(matchall, time));
                assert(! Time_incron(invalid1, time));
                assert(! Time_incron(invalid2, time));
                assert(! Time_incron(invalid3, time));
                assert(Time_incron(range1, time));
                assert(! Time_incron(rangeoutside, time));
                assert(Time_incron(sequence, time));
                assert(! Time_incron(sequenceoutside, time));
        }
        printf("=> Test12: OK\n\n");

        printf("============> Time Tests: OK\n\n");

        return 0;
}


