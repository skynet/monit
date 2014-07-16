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

        setenv("TZ", "CET", 1);
        tzset();
        
        Bootstrap(); // Need to initialize library

        printf("============> Start Time Tests\n\n");


        printf("=> Test1: check string ouput\n");
        {
                char result[30];
                Time_string(1267441200, result); /* 01 Mar 2010 12:00:00 */
                printf("\tResult: unix time 1267441200 to localtime:\n\t %s\n", result);
                assert(Str_isEqual(result, "Mon, 01 Mar 2010 12:00:00"));
                Time_gmtstring(1267441200, result); /* 01 Mar 2010 12:00:00 GMT */
                printf("\tResult: unix time 1267441200 to UTC:\n\t %s\n", result);
                assert(Str_isEqual("Mon, 01 Mar 2010 11:00:00 GMT", result));
        }
        printf("=> Test1: OK\n\n");

        printf("=> Test2: check current time\n");
        {
                struct timeval tv;
                assert(!gettimeofday(&tv, NULL));
                assert(Time_now() == tv.tv_sec);
        }
        printf("=> Test2: OK\n\n");

        printf("=> Test3: sleep 1s\n");
        {
                time_t now;
                now = Time_now();
                Time_usleep(1000000);
                assert((now + 1) == Time_now());
        }
        printf("=> Test3: OK\n\n");

        printf("=> Test4: uptime\n");
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
        printf("=> Test4: OK\n\n");

        printf("=> Test5: Time attributes\n");
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
        printf("=> Test5: OK\n\n");

        printf("=> Test6: Time_build\n");
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
        printf("=> Test6: OK\n\n");

        printf("=> Test7: Time_incron\n");
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
        printf("=> Test7: OK\n\n");

        printf("============> Time Tests: OK\n\n");

        return 0;
}


