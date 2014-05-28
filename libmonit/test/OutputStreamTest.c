#include "Config.h"

#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <time.h>
#include <stdlib.h>

#include "Bootstrap.h"
#include "OutputStream.h"
#include "File.h"
#include "Str.h"

/**
 * OutputStream.c unit tests. 
 */

#define STDOUT  1
#define TIMEOUT 50

int main(void) {
        OutputStream_T out = NULL;

        Bootstrap(); // Need to initialize library

        printf("============> Start OutputStream Tests\n\n");

        printf("=> Test0: create/destroy the file input stream\n");
        {
                out = OutputStream_new(STDOUT);
                assert(!OutputStream_isClosed(out));
                OutputStream_free(&out);
                assert(out == NULL);
        }
        printf("=> Test0: OK\n\n");

        printf("=> Test1: get/set timeout\n");
        {
                out = OutputStream_new(STDOUT);
                printf("\tCurrent timeout: %ldms\n", (long)OutputStream_getTimeout(out));
                OutputStream_setTimeout(out, TIMEOUT);
                assert(OutputStream_getTimeout(out) == TIMEOUT);
                printf("\tTimeout set to:  %dms\n", TIMEOUT);
                OutputStream_free(&out);
        }
        printf("=> Test1: OK\n\n");

        printf("=> Test2: write buffer bytes, test flush and status\n");
        {
                int bytes = strlen("line1\nline2\nline3\n");
                char data[] = "line1\nline2\nline3\n";
                out = OutputStream_new(STDOUT);
                assert(0 == OutputStream_buffered(out));
                assert(bytes == OutputStream_write(out, data, (int)strlen(data)));
                assert(bytes == OutputStream_buffered(out));
                assert(0 == OutputStream_getBytesWritten(out));
                OutputStream_flush(out);
                assert(bytes == OutputStream_getBytesWritten(out));
                // Test writing lower bytes
                OutputStream_clear(out);
                char b[] = {0,0,0,0};
                assert(OutputStream_write(out, b, 4) == 4);
                OutputStream_free(&out);
        }
        printf("=> Test2: OK\n\n");

        printf("=> Test3: printf format\n");
        {
                out = OutputStream_new(STDOUT);
                // Test supported format specifiers
                assert(OutputStream_print(out, "%s", "hello") == 5);
                assert(OutputStream_print(out, "%c", 'h') == 1);
                assert(OutputStream_print(out, "%d", 12345) == 5);
                assert(OutputStream_print(out, "%i", -12345) == 6);
                assert(OutputStream_print(out, "%u", 12345) == 5);
                assert(OutputStream_print(out, "%o", 8) == 2);          //10
                assert(OutputStream_print(out, "%x", 255) == 2);        //ff
                assert(OutputStream_print(out, "%e", 12.34) == 12);     //1.234000e+01
                assert(OutputStream_print(out, "%f", -12.34) == 10);    //-12.340000
                assert(OutputStream_print(out, "%g", 12.34) == 6);      //012.34
                OutputStream_print(out, "%p", out);
                assert(OutputStream_print(out, "%%hello%%") == 7);
                // Length modifier
                assert(OutputStream_print(out, "%ld", 32767L) == 5);
                assert(OutputStream_print(out, "%li", -32767L) == 6);
                assert(OutputStream_print(out, "%lu", 32767L) == 5);
                assert(OutputStream_print(out, "%lo", 32767L) == 5); //77777
                assert(OutputStream_print(out, "%lx", 32767L) == 4); //7fff
                // Test width and precision 
                assert(OutputStream_print(out, "%16.16s\n%16.16s\n", "hello", "world") == 34);
                assert(OutputStream_print(out, "%-16.16s\n%-16.16s\n", "hello", "world") == 34);
                assert(OutputStream_print(out, "%.2f", 12.3456789) == 5); //12.35
                assert(OutputStream_print(out, "%02d", 3) == 2); // 03
                OutputStream_clear(out);
                OutputStream_free(&out);
        }
        printf("=> Test3: OK\n\n");

        printf("=> Test4: write two concatenated lines\n");
        {
                int i = 0;
                out = OutputStream_new(STDOUT);
                while (i++ < 2) {
                        OutputStream_print(out, "line%d", i);
                }
                OutputStream_print(out, "\n");
                OutputStream_flush(out);
                OutputStream_free(&out);
        }
        printf("=> Test4: OK\n\n");

        printf("=> Test5: output reset - just the line[5-9] should show\n");
        {
                int i = 0;
                out = OutputStream_new(STDOUT);
                while (i++ < 9) {
                        OutputStream_print(out, "line%d\n", i);
                        if (i == 4) {
                                OutputStream_clear(out);
                        }
                }
                OutputStream_flush(out);
                OutputStream_free(&out);
        }
        printf("=> Test5: OK\n\n");

        printf("=> Test6: wrong descriptor - expecting write fail\n");
        {
                out = OutputStream_new(999);
                TRY
                        OutputStream_print(out, "Should not show");
                        assert(OutputStream_flush(out) != -1);
                        printf("Test6: Failed");
                        exit(1); // Should not come here
                CATCH(AssertException)
                        // Passed
                END_TRY;
                OutputStream_free(&out);
        }
        printf("=> Test6: OK\n\n");

        printf("=> Test7: printf large buffer\n");
        {
                // Note, test assume OutputStream buffer is 1500
                char a[1024];
                memset(a, 'x', 1024);
                a[1023] = 0;
                out = OutputStream_new(STDOUT);
                // Test fit into buffer
                assert(OutputStream_print(out, "data: %s\n", a) == 1030);
                assert(OutputStream_flush(out) == 1030);
                // Test when data is larger than OutputStream buffer
                char b[2048];
                memset(b, 'y', 2048);
                b[2047] = 0;
                assert(OutputStream_print(out, "data: %s\n", b) == 2054);
                OutputStream_free(&out);
        }
        printf("=> Test7: OK\n\n");

        printf("============> OutputStream Tests: OK\n\n");

        return 0;
}

